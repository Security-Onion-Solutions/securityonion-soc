// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

func queryNetMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	res := make(map[string][]model.MetricSample)
	if nodeId != "" {
		res["traffic_man_in"] = make([]model.MetricSample, 0)
		res["traffic_man_out"] = make([]model.MetricSample, 0)
		res["traffic_mon_in"] = make([]model.MetricSample, 0)
	}

	timeWindow := "2 minutes"
	qNet := fmt.Sprintf(`
		WITH traffic_diff AS (
			SELECT 
				tag.tags->>'host' as host,
				tag.tags->>'interface' as interface,
				m.time,
				(m.fields->>'bytes_recv')::bigint as bytes_recv,
				(m.fields->>'bytes_sent')::bigint as bytes_sent,
				LAG((m.fields->>'bytes_recv')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_recv,
				LAG((m.fields->>'bytes_sent')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_sent,
				LAG(m.time) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_time
			FROM telegraf.net m
			JOIN telegraf.net_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND m.time >= (%s AT TIME ZONE 'UTC') - INTERVAL '%s' AND m.time <= (%s AT TIME ZONE 'UTC') AND m.fields->>'bytes_recv' IS NOT NULL AND m.fields->>'bytes_sent' IS NOT NULL
		),
		rates AS (
			SELECT 
				host,
				interface,
				time,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND bytes_recv >= prev_recv 
					THEN ((bytes_recv - prev_recv) * 8.0 / (1000.0 * 1000.0)) / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as recv_rate_mbps,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND bytes_sent >= prev_sent 
					THEN ((bytes_sent - prev_sent) * 8.0 / (1000.0 * 1000.0)) / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as sent_rate_mbps
			FROM traffic_diff
			WHERE time >= (%s AT TIME ZONE 'UTC')
		)
		SELECT 
			to_timestamp(floor(extract(epoch from time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
			host,
			interface,
			AVG(recv_rate_mbps) as recv_avg,
			AVG(sent_rate_mbps) as sent_avg
		FROM rates
		GROUP BY bucket, host, interface
		ORDER BY bucket ASC`, hostFilter, startPlaceholder, timeWindow, endPlaceholder, startPlaceholder)

	manint := make(map[string]string)
	monint := make(map[string]string)
	qConf := `
		SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host', m.fields->>'manint', m.fields->>'monint' 
		FROM telegraf.node_config m 
		JOIN telegraf.node_config_tag tag ON m.tag_id = tag.tag_id 
		WHERE m.fields->>'manint' IS NOT NULL OR m.fields->>'monint' IS NOT NULL
		ORDER BY tag.tags->>'host', m.time DESC`
	if rowsConf, errConf := s.db.Query(ctx, qConf); errConf == nil {
		for rowsConf.Next() {
			var host string
			var man, mon *string
			if err := rowsConf.Scan(&host, &man, &mon); err == nil {
				if man != nil {
					manint[host] = *man
				}
				if mon != nil {
					monint[host] = *mon
				}
			}
		}
		rowsConf.Close()
	}

	log.WithFields(log.Fields{
		"query": qNet,
		"args":  args,
	}).Debug("GetTimeSeriesMetrics qNet")
	rows, err := s.db.Query(ctx, qNet, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics net")
		if s.isMissingRelationError(err) {
			return res, nil
		}
		return nil, err
	}
	defer rows.Close()

	if nodeId != "" {
		trafficManIn := make(map[time.Time]float64)
		trafficManOut := make(map[time.Time]float64)
		trafficMonIn := make(map[time.Time]float64)

		for rows.Next() {
			var bucket time.Time
			var host string
			var iface string
			var recv, sent float64
			if err := rows.Scan(&bucket, &host, &iface, &recv, &sent); err == nil {
				man := manint[nodeId]
				mon := monint[nodeId]

				isMan := false
				if man != "" {
					isMan = (iface == man)
				} else {
					isMan = (iface == "eth0" || iface == "ens18" || strings.Contains(iface, "man"))
				}

				isMon := false
				if mon != "" {
					isMon = (iface == mon)
				} else {
					isMon = (iface == "eth1" || iface == "ens19" || strings.Contains(iface, "mon"))
				}

				if isMan {
					trafficManIn[bucket] += recv
					trafficManOut[bucket] += sent
				}
				if isMon {
					trafficMonIn[bucket] += recv
				}
			}
		}
		res["traffic_man_in"] = mapToSamples(trafficManIn)
		res["traffic_man_out"] = mapToSamples(trafficManOut)
		res["traffic_mon_in"] = mapToSamples(trafficMonIn)
	} else {
		// All Hosts
		trafficManIn := make(map[string]map[time.Time]float64)
		trafficManOut := make(map[string]map[time.Time]float64)
		trafficMonIn := make(map[string]map[time.Time]float64)

		for rows.Next() {
			var bucket time.Time
			var host string
			var iface string
			var recv, sent float64
			if err := rows.Scan(&bucket, &host, &iface, &recv, &sent); err == nil {
				man := manint[host]
				mon := monint[host]

				isMan := false
				isMon := false
				if man != "" {
					if iface == man {
						isMan = true
					}
				} else {
					if iface == "eth0" || iface == "ens18" || strings.Contains(iface, "man") {
						isMan = true
					}
				}
				if mon != "" {
					if iface == mon {
						isMon = true
					}
				} else {
					if iface == "eth1" || iface == "ens19" || strings.Contains(iface, "mon") {
						isMon = true
					}
				}

				if isMan {
					if _, ok := trafficManIn[host]; !ok {
						trafficManIn[host] = make(map[time.Time]float64)
						trafficManOut[host] = make(map[time.Time]float64)
					}
					trafficManIn[host][bucket] += recv
					trafficManOut[host][bucket] += sent
				}
				if isMon {
					if _, ok := trafficMonIn[host]; !ok {
						trafficMonIn[host] = make(map[time.Time]float64)
					}
					trafficMonIn[host][bucket] += recv
				}
			}
		}

		for host, buckets := range trafficManIn {
			res[host+"::traffic_man_in"] = mapToSamples(buckets)
		}
		for host, buckets := range trafficManOut {
			res[host+"::traffic_man_out"] = mapToSamples(buckets)
		}
		for host, buckets := range trafficMonIn {
			res[host+"::traffic_mon_in"] = mapToSamples(buckets)
		}
	}

	return res, nil
}

func queryNetDropsMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	res := make(map[string][]model.MetricSample)
	if nodeId != "" {
		res["traffic_mon_drops"] = make([]model.MetricSample, 0)
	}

	timeWindow := "2 minutes"
	qNet := fmt.Sprintf(`
		WITH traffic_diff AS (
			SELECT 
				tag.tags->>'host' as host,
				tag.tags->>'interface' as interface,
				m.time,
				(m.fields->>'drop_in')::bigint as drop_in,
				LAG((m.fields->>'drop_in')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_drop,
				LAG(m.time) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'interface' ORDER BY m.time) as prev_time
			FROM telegraf.net m
			JOIN telegraf.net_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND m.time >= (%s AT TIME ZONE 'UTC') - INTERVAL '%s' AND m.time <= (%s AT TIME ZONE 'UTC') AND m.fields->>'drop_in' IS NOT NULL
		),
		rates AS (
			SELECT 
				host,
				interface,
				time,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND drop_in >= prev_drop 
					THEN (drop_in - prev_drop)::float / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as drop_rate
			FROM traffic_diff
			WHERE time >= (%s AT TIME ZONE 'UTC')
		)
		SELECT 
			to_timestamp(floor(extract(epoch from time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
			host,
			interface,
			AVG(drop_rate) as drop_avg
		FROM rates
		GROUP BY bucket, host, interface
		ORDER BY bucket ASC`, hostFilter, startPlaceholder, timeWindow, endPlaceholder, startPlaceholder)

	monint := make(map[string]string)
	qConf := `
		SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host', m.fields->>'monint' 
		FROM telegraf.node_config m 
		JOIN telegraf.node_config_tag tag ON m.tag_id = tag.tag_id 
		WHERE m.fields->>'monint' IS NOT NULL
		ORDER BY tag.tags->>'host', m.time DESC`
	if rowsConf, errConf := s.db.Query(ctx, qConf); errConf == nil {
		for rowsConf.Next() {
			var host string
			var mon *string
			if err := rowsConf.Scan(&host, &mon); err == nil {
				if mon != nil {
					monint[host] = *mon
				}
			}
		}
		rowsConf.Close()
	}

	rows, err := s.db.Query(ctx, qNet, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics net_drops")
		if s.isMissingRelationError(err) {
			return res, nil
		}
		return nil, err
	}
	defer rows.Close()

	if nodeId != "" {
		trafficMonDrops := make(map[time.Time]float64)

		for rows.Next() {
			var bucket time.Time
			var host string
			var iface string
			var drop float64
			if err := rows.Scan(&bucket, &host, &iface, &drop); err == nil {
				mon := monint[nodeId]
				isMon := false
				if mon != "" {
					isMon = (iface == mon)
				} else {
					isMon = (iface == "eth1" || iface == "ens19" || strings.Contains(iface, "mon"))
				}

				if isMon {
					trafficMonDrops[bucket] += drop
				}
			}
		}
		res["traffic_mon_drops"] = mapToSamples(trafficMonDrops)
	} else {
		trafficMonDrops := make(map[string]map[time.Time]float64)

		for rows.Next() {
			var bucket time.Time
			var host string
			var iface string
			var drop float64
			if err := rows.Scan(&bucket, &host, &iface, &drop); err == nil {
				mon := monint[host]

				isMon := false
				if mon != "" {
					if iface == mon {
						isMon = true
					}
				} else {
					if iface == "eth1" || iface == "ens19" || strings.Contains(iface, "mon") {
						isMon = true
					}
				}

				if isMon {
					if _, ok := trafficMonDrops[host]; !ok {
						trafficMonDrops[host] = make(map[time.Time]float64)
					}
					trafficMonDrops[host][bucket] += drop
				}
			}
		}

		for host, buckets := range trafficMonDrops {
			res[host+"::traffic_mon_drops"] = mapToSamples(buckets)
		}
	}

	return res, nil
}

func mapToSamples(m map[time.Time]float64) []model.MetricSample {
	samples := make([]model.MetricSample, 0)
	for t, val := range m {
		samples = append(samples, model.MetricSample{
			Timestamp: t,
			Value:     val,
		})
	}
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].Timestamp.Before(samples[j].Timestamp)
	})
	return samples
}
