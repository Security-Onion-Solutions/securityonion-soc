// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

func (s *Store) GetTimeSeriesMetrics(ctx context.Context, nodeId string, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error) {
	duration := endTime.Sub(startTime)
	intervalSeconds := 60
	if duration > 24*time.Hour {
		intervalSeconds = 3600
	} else if duration > 6*time.Hour {
		intervalSeconds = 300
	}

	res := make(map[string][]model.MetricSample)

	// Pre-populate empty samples dynamically for requested metricType keys to avoid nil map responses
	keysMap := make(map[string][]string)
	for mType, cfg := range MetricConfigs {
		keysMap[mType] = cfg.Keys
	}

	if keys, ok := keysMap[metricType]; ok {
		for _, k := range keys {
			res[k] = make([]model.MetricSample, 0)
		}
	}

	var hostFilter string
	var args []interface{}
	args = append(args, intervalSeconds, startTime, endTime)

	if nodeId != "" {
		hostFilter = "tag.tags->>'host' = $4"
		args = append(args, nodeId)
	} else {
		hostFilter = "1=1"
	}

	startPlaceholder := "$2"
	endPlaceholder := "$3"

	// Match and execute based on our unified lookup config map
	if cfg, ok := MetricConfigs[metricType]; ok {
		if cfg.CustomHandler != nil {
			return cfg.CustomHandler(ctx, s, nodeId, hostFilter, startPlaceholder, endPlaceholder, args)
		}

		for i, fld := range cfg.Fields {
			table := cfg.Tables[0]
			if i < len(cfg.Tables) {
				table = cfg.Tables[i]
			}
			filter := ""
			if i < len(cfg.Filters) {
				filter = cfg.Filters[i]
			}
			samples, err := s.queryGenericMetric(ctx, table, fld, hostFilter, startPlaceholder, endPlaceholder, filter, cfg.Factor, cfg.Aggregate, args)
			if err != nil {
				return nil, err
			}
			res[cfg.Keys[i]] = samples
		}
		return res, nil
	}

	return res, nil
}

func (s *Store) queryGenericMetric(ctx context.Context, table, field, hostFilter, startPlaceholder, endPlaceholder string, filter string, factor float64, aggregate string, args []interface{}) ([]model.MetricSample, error) {
	agg := "AVG"
	if aggregate != "" {
		agg = aggregate
	}

	whereClause := fmt.Sprintf("%s AND m.time >= %s AT TIME ZONE 'UTC' AND m.time <= %s AT TIME ZONE 'UTC' AND m.fields->>'%s' IS NOT NULL", hostFilter, startPlaceholder, endPlaceholder, field)
	if filter != "" {
		whereClause = fmt.Sprintf("%s AND %s", whereClause, filter)
	}

	valExpr := fmt.Sprintf("(m.fields->>'%s')::double precision", field)
	if table == "cpu" && field == "usage_idle" {
		valExpr = "((m.fields->>'usage_idle')::double precision * -1.0 + 100.0)"
	}

	q := fmt.Sprintf(`
		SELECT 
			to_timestamp(floor(extract(epoch from m.time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
			%s(%s) AS val
		FROM telegraf.%s m
		JOIN telegraf.%s_tag tag ON m.tag_id = tag.tag_id
		WHERE %s
		GROUP BY bucket
		ORDER BY bucket ASC`, agg, valExpr, table, table, whereClause)

	samples, err := s.runMetricQuery(ctx, q, args...)
	if err != nil {
		return nil, err
	}

	if factor != 0.0 && factor != 1.0 {
		for i := range samples {
			samples[i].Value = samples[i].Value * factor
		}
	}

	return samples, nil
}

func (s *Store) runMetricQuery(ctx context.Context, sqlQuery string, args ...interface{}) ([]model.MetricSample, error) {
	log.WithFields(log.Fields{
		"query": sqlQuery,
		"args":  args,
	}).Debug("GetTimeSeriesMetrics runMetricQuery")
	rows, err := s.db.Query(ctx, sqlQuery, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics metric")
		if s.isMissingRelationError(err) {
			return []model.MetricSample{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	samples := make([]model.MetricSample, 0)
	for rows.Next() {
		var bucket time.Time
		var val float64
		if err := rows.Scan(&bucket, &val); err == nil {
			samples = append(samples, model.MetricSample{
				Timestamp: bucket,
				Value:     val,
			})
		}
	}
	return samples, nil
}

func queryNetMetric(ctx context.Context, s *Store, nodeId string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	res := map[string][]model.MetricSample{
		"traffic_man_in":  make([]model.MetricSample, 0),
		"traffic_man_out": make([]model.MetricSample, 0),
		"traffic_mon_in":  make([]model.MetricSample, 0),
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
			interface,
			SUM(recv_rate_mbps) as recv_avg,
			SUM(sent_rate_mbps) as sent_avg
		FROM rates
		GROUP BY bucket, interface
		ORDER BY bucket ASC`, hostFilter, startPlaceholder, timeWindow, endPlaceholder, startPlaceholder)

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

	manint := make(map[string]string)
	monint := make(map[string]string)
	qConf := `
		SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host', m.fields->>'manint', m.fields->>'monint' 
		FROM telegraf.node_config m 
		JOIN telegraf.node_config_tag tag ON m.tag_id = tag.tag_id 
		WHERE m.fields->>'manint' IS NOT NULL AND m.fields->>'monint' IS NOT NULL
		ORDER BY tag.tags->>'host', m.time DESC`
	if rowsConf, errConf := s.db.Query(ctx, qConf); errConf == nil {
		for rowsConf.Next() {
			var host, man, mon string
			if err := rowsConf.Scan(&host, &man, &mon); err == nil {
				manint[host] = man
				monint[host] = mon
			}
		}
		rowsConf.Close()
	}

	trafficManIn := make(map[time.Time]float64)
	trafficManOut := make(map[time.Time]float64)
	trafficMonIn := make(map[time.Time]float64)

	for rows.Next() {
		var bucket time.Time
		var iface string
		var recv, sent float64
		if err := rows.Scan(&bucket, &iface, &recv, &sent); err == nil {
			isMan := false
			isMon := false
			if nodeId != "" {
				man := manint[nodeId]
				if man == "" {
					man = "eth0"
				}
				mon := monint[nodeId]
				if mon == "" {
					mon = "eth1"
				}
				if iface == man {
					isMan = true
				}
				if iface == mon {
					isMon = true
				}
			} else {
				if iface == "eth0" || strings.Contains(iface, "man") {
					isMan = true
				} else if iface == "eth1" || strings.Contains(iface, "mon") {
					isMon = true
				}
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
	return res, nil
}

func queryNetDropsMetric(ctx context.Context, s *Store, nodeId string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	res := map[string][]model.MetricSample{
		"traffic_mon_drops": make([]model.MetricSample, 0),
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
			interface,
			SUM(drop_rate) as drop_avg
		FROM rates
		GROUP BY bucket, interface
		ORDER BY bucket ASC`, hostFilter, startPlaceholder, timeWindow, endPlaceholder, startPlaceholder)

	rows, err := s.db.Query(ctx, qNet, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics net_drops")
		if s.isMissingRelationError(err) {
			return res, nil
		}
		return nil, err
	}
	defer rows.Close()

	monint := make(map[string]string)
	qConf := `
		SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host', m.fields->>'monint' 
		FROM telegraf.node_config m 
		JOIN telegraf.node_config_tag tag ON m.tag_id = tag.tag_id 
		WHERE m.fields->>'monint' IS NOT NULL
		ORDER BY tag.tags->>'host', m.time DESC`
	if rowsConf, errConf := s.db.Query(ctx, qConf); errConf == nil {
		for rowsConf.Next() {
			var host, mon string
			if err := rowsConf.Scan(&host, &mon); err == nil {
				monint[host] = mon
			}
		}
		rowsConf.Close()
	}

	trafficMonDrops := make(map[time.Time]float64)

	for rows.Next() {
		var bucket time.Time
		var iface string
		var drop float64
		if err := rows.Scan(&bucket, &iface, &drop); err == nil {
			isMon := false
			if nodeId != "" {
				mon := monint[nodeId]
				if mon == "" {
					mon = "eth1"
				}
				if iface == mon {
					isMon = true
				}
			} else {
				if iface == "eth1" || strings.Contains(iface, "mon") {
					isMon = true
				}
			}

			if isMon {
				trafficMonDrops[bucket] += drop
			}
		}
	}

	res["traffic_mon_drops"] = mapToSamples(trafficMonDrops)
	return res, nil
}

func queryContainerNetInMetric(ctx context.Context, s *Store, nodeId string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	res := map[string][]model.MetricSample{
		"container_net_in": make([]model.MetricSample, 0),
	}

	timeWindow := "2 minutes"
	qNet := fmt.Sprintf(`
		WITH traffic_diff AS (
			SELECT 
				tag.tags->>'host' as host,
				tag.tags->>'container_name' as container,
				m.time,
				(m.fields->>'rx_bytes')::bigint as rx_bytes,
				LAG((m.fields->>'rx_bytes')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'container_name' ORDER BY m.time) as prev_recv,
				LAG(m.time) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'container_name' ORDER BY m.time) as prev_time
			FROM telegraf.docker_container_net m
			JOIN telegraf.docker_container_net_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND m.time >= (%s AT TIME ZONE 'UTC') - INTERVAL '%s' AND m.time <= (%s AT TIME ZONE 'UTC') AND m.fields->>'rx_bytes' IS NOT NULL
		),
		rates AS (
			SELECT 
				host,
				time,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND rx_bytes >= prev_recv 
					THEN ((rx_bytes - prev_recv) * 8.0 / (1000.0 * 1000.0)) / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as recv_rate_mbps
			FROM traffic_diff
			WHERE time >= (%s AT TIME ZONE 'UTC')
		)
		SELECT 
			to_timestamp(floor(extract(epoch from time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
			SUM(recv_rate_mbps) as recv_avg
		FROM rates
		GROUP BY bucket
		ORDER BY bucket ASC`, hostFilter, startPlaceholder, timeWindow, endPlaceholder, startPlaceholder)

	samples, err := s.runMetricQuery(ctx, qNet, args...)
	if err != nil {
		return nil, err
	}
	res["container_net_in"] = samples
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
