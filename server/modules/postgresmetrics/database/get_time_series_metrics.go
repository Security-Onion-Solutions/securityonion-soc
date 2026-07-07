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
	if metricType == "cpu" {
		res["cpu_used"] = make([]model.MetricSample, 0)
	} else if metricType == "memory" {
		res["memory_used"] = make([]model.MetricSample, 0)
	} else if metricType == "load" {
		res["load1"] = make([]model.MetricSample, 0)
		res["load5"] = make([]model.MetricSample, 0)
		res["load15"] = make([]model.MetricSample, 0)
	} else if metricType == "disk" {
		res["disk_used_root"] = make([]model.MetricSample, 0)
		res["disk_used_nsm"] = make([]model.MetricSample, 0)
	} else if metricType == "eps" {
		res["consumption_eps"] = make([]model.MetricSample, 0)
		res["production_eps"] = make([]model.MetricSample, 0)
	} else if metricType == "net" {
		res["traffic_man_in"] = make([]model.MetricSample, 0)
		res["traffic_man_out"] = make([]model.MetricSample, 0)
		res["traffic_mon_in"] = make([]model.MetricSample, 0)
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

	switch metricType {
	case "cpu":
		q := fmt.Sprintf(`
			SELECT 
				to_timestamp(floor(extract(epoch from m.time) / $1) * $1) AS bucket,
				AVG(100.0 - (m.fields->>'usage_idle')::double precision) AS val
			FROM telegraf.cpu m
			JOIN telegraf.cpu_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND tag.tags->>'cpu' = 'cpu-total' AND m.time >= %s AND m.time <= %s AND m.fields->>'usage_idle' IS NOT NULL
			GROUP BY bucket
			ORDER BY bucket ASC`, hostFilter, startPlaceholder, endPlaceholder)

		samples, err := s.runMetricQuery(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		res["cpu_used"] = samples

	case "memory":
		q := fmt.Sprintf(`
			SELECT 
				to_timestamp(floor(extract(epoch from m.time) / $1) * $1) AS bucket,
				AVG((m.fields->>'used_percent')::double precision) AS val
			FROM telegraf.mem m
			JOIN telegraf.mem_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND m.time >= %s AND m.time <= %s AND m.fields->>'used_percent' IS NOT NULL
			GROUP BY bucket
			ORDER BY bucket ASC`, hostFilter, startPlaceholder, endPlaceholder)

		samples, err := s.runMetricQuery(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		res["memory_used"] = samples

	case "load":
		for _, loadFld := range []string{"load1", "load5", "load15"} {
			q := fmt.Sprintf(`
				SELECT 
					to_timestamp(floor(extract(epoch from m.time) / $1) * $1) AS bucket,
					AVG((m.fields->>'%s')::double precision) AS val
				FROM telegraf.system m
				JOIN telegraf.system_tag tag ON m.tag_id = tag.tag_id
				WHERE %s AND m.time >= %s AND m.time <= %s AND m.fields->>'%s' IS NOT NULL
				GROUP BY bucket
				ORDER BY bucket ASC`, loadFld, hostFilter, startPlaceholder, endPlaceholder, loadFld)

			samples, err := s.runMetricQuery(ctx, q, args...)
			if err != nil {
				return nil, err
			}
			res[loadFld] = samples
		}

	case "disk":
		paths := []string{"/", "/nsm"}
		for _, p := range paths {
			pathFilter := fmt.Sprintf("tag.tags->>'path' = '%s'", p)
			q := fmt.Sprintf(`
				SELECT 
					to_timestamp(floor(extract(epoch from m.time) / $1) * $1) AS bucket,
					AVG((m.fields->>'used_percent')::double precision) AS val
				FROM telegraf.disk m
				JOIN telegraf.disk_tag tag ON m.tag_id = tag.tag_id
				WHERE %s AND %s AND m.time >= %s AND m.time <= %s AND m.fields->>'used_percent' IS NOT NULL
				GROUP BY bucket
				ORDER BY bucket ASC`, hostFilter, pathFilter, startPlaceholder, endPlaceholder)

			samples, err := s.runMetricQuery(ctx, q, args...)
			if err != nil {
				return nil, err
			}
			key := "disk_used_root"
			if p == "/nsm" {
				key = "disk_used_nsm"
			}
			res[key] = samples
		}

	case "eps":
		qCons := fmt.Sprintf(`
			SELECT 
				to_timestamp(floor(extract(epoch from m.time) / $1) * $1) AS bucket,
				SUM((m.fields->>'eps')::double precision) AS val
			FROM telegraf.consumptioneps m
			JOIN telegraf.consumptioneps_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND m.time >= %s AND m.time <= %s AND m.fields->>'eps' IS NOT NULL
			GROUP BY bucket
			ORDER BY bucket ASC`, hostFilter, startPlaceholder, endPlaceholder)

		samplesCons, err := s.runMetricQuery(ctx, qCons, args...)
		if err != nil {
			return nil, err
		}
		res["consumption_eps"] = samplesCons

		qProd := fmt.Sprintf(`
			SELECT 
				to_timestamp(floor(extract(epoch from m.time) / $1) * $1) AS bucket,
				SUM((m.fields->>'eps')::double precision) AS val
			FROM telegraf.fbstats m
			JOIN telegraf.fbstats_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND m.time >= %s AND m.time <= %s AND m.fields->>'eps' IS NOT NULL
			GROUP BY bucket
			ORDER BY bucket ASC`, hostFilter, startPlaceholder, endPlaceholder)

		samplesProd, err := s.runMetricQuery(ctx, qProd, args...)
		if err != nil {
			return nil, err
		}
		res["production_eps"] = samplesProd

	case "net":
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
				WHERE %s AND m.time >= (%s)::timestamp - INTERVAL '%s' AND m.time <= (%s)::timestamp AND m.fields->>'bytes_recv' IS NOT NULL AND m.fields->>'bytes_sent' IS NOT NULL
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
				WHERE time >= (%s)::timestamp
			)
			SELECT 
				to_timestamp(floor(extract(epoch from time) / $1) * $1) AS bucket,
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
	}

	return res, nil
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
