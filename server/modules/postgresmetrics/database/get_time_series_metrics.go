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

func (s *Store) GetTimeSeriesMetrics(ctx context.Context, nodeId, container, metricType string, startTime, endTime time.Time) (map[string][]model.MetricSample, error) {
	duration := endTime.Sub(startTime)
	intervalSeconds := 60
	if duration > 24*time.Hour {
		intervalSeconds = 3600
	} else if duration > 6*time.Hour {
		intervalSeconds = 300
	}

	res := make(map[string][]model.MetricSample)

	// Pre-populate empty samples dynamically for requested metricType keys to avoid nil map responses
	// Only do this when nodeId is not empty (single host), since for "All Hosts" the keys are dynamic.
	if nodeId != "" {
		keysMap := make(map[string][]string)
		for mType, cfg := range MetricConfigs {
			keysMap[mType] = cfg.Keys
		}

		if keys, ok := keysMap[metricType]; ok {
			for _, k := range keys {
				res[k] = make([]model.MetricSample, 0)
			}
		}
	}

	var hostFilter string
	var args []interface{}
	args = append(args, intervalSeconds, startTime, endTime)

	if nodeId != "" {
		hostFilter = "(tag.tags->>'node_name' = $4 OR tag.tags->>'node_host' = $4 OR tag.tags->>'host' = $4 OR tag.tags->>'es_host' = $4)"
		args = append(args, nodeId)
	} else {
		hostFilter = "1=1"
	}

	startPlaceholder := "$2"
	endPlaceholder := "$3"

	// Match and execute based on our unified lookup config map
	if cfg, ok := MetricConfigs[metricType]; ok {
		if cfg.CustomHandler != nil {
			return cfg.CustomHandler(ctx, s, nodeId, container, hostFilter, startPlaceholder, endPlaceholder, args)
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

			if nodeId == "" {
				// All hosts! Query grouped by host.
				hostSamplesMap, err := s.queryGenericMetricGrouped(ctx, table, fld, hostFilter, startPlaceholder, endPlaceholder, filter, cfg.Factor, cfg.Aggregate, args)
				if err != nil {
					return nil, err
				}
				for host, samples := range hostSamplesMap {
					var key string
					if len(cfg.Keys) > 1 {
						key = host + "::" + cfg.Keys[i]
					} else {
						key = host
					}
					res[key] = samples
				}
			} else {
				// Single host.
				samples, err := s.queryGenericMetric(ctx, table, fld, hostFilter, startPlaceholder, endPlaceholder, filter, cfg.Factor, cfg.Aggregate, args)
				if err != nil {
					return nil, err
				}
				res[cfg.Keys[i]] = samples
			}
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

func (s *Store) queryGenericMetricGrouped(ctx context.Context, table, field, hostFilter, startPlaceholder, endPlaceholder string, filter string, factor float64, aggregate string, args []interface{}) (map[string][]model.MetricSample, error) {
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
			COALESCE(NULLIF(tag.tags->>'node_name', ''), NULLIF(tag.tags->>'node_host', ''), NULLIF(tag.tags->>'host', ''), NULLIF(tag.tags->>'es_host', ''), '') AS host,
			%s(%s) AS val
		FROM telegraf.%s m
		JOIN telegraf.%s_tag tag ON m.tag_id = tag.tag_id
		WHERE %s
		GROUP BY bucket, host
		ORDER BY bucket ASC`, agg, valExpr, table, table, whereClause)

	log.WithFields(log.Fields{
		"query": q,
		"args":  args,
	}).Debug("GetTimeSeriesMetrics queryGenericMetricGrouped")

	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics metric grouped")
		if s.isMissingRelationError(err) {
			return make(map[string][]model.MetricSample), nil
		}
		return nil, err
	}
	defer rows.Close()

	res := make(map[string][]model.MetricSample)
	for rows.Next() {
		var bucket time.Time
		var host string
		var val float64
		if err := rows.Scan(&bucket, &host, &val); err == nil {
			if factor != 0.0 && factor != 1.0 {
				val = val * factor
			}
			res[host] = append(res[host], model.MetricSample{
				Timestamp: bucket,
				Value:     val,
			})
		}
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

func queryContainerNetInMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	timeWindow := "2 minutes"
	whereClause := fmt.Sprintf("%s AND m.time >= (%s AT TIME ZONE 'UTC') - INTERVAL '%s' AND m.time <= (%s AT TIME ZONE 'UTC') AND m.fields->>'rx_bytes' IS NOT NULL", hostFilter, startPlaceholder, timeWindow, endPlaceholder)
	if container != "" && container != "all" {
		placeholderIdx := len(args) + 1
		whereClause = fmt.Sprintf("%s AND tag.tags->>'container_name' = $%d", whereClause, placeholderIdx)
		args = append(args, container)
	}

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
			WHERE %s
		),
		rates AS (
			SELECT 
				host,
				container,
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
			COALESCE(host, '') as host,
			container,
			AVG(recv_rate_mbps) as recv_avg
		FROM rates
		GROUP BY bucket, host, container
		ORDER BY bucket ASC`, whereClause, startPlaceholder)

	rows, err := s.db.Query(ctx, qNet, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics container_net_in")
		if s.isMissingRelationError(err) {
			return make(map[string][]model.MetricSample), nil
		}
		return nil, err
	}
	defer rows.Close()

	res := make(map[string][]model.MetricSample)
	for rows.Next() {
		var bucket time.Time
		var host string
		var containerName string
		var val float64
		if err := rows.Scan(&bucket, &host, &containerName, &val); err == nil {
			var key string
			if nodeId == "" {
				key = host + "::" + containerName
			} else {
				key = containerName
			}
			res[key] = append(res[key], model.MetricSample{
				Timestamp: bucket,
				Value:     val,
			})
		}
	}
	return res, nil
}

func (s *Store) queryContainerMetric(ctx context.Context, table, field, nodeId, container, hostFilter, startPlaceholder, endPlaceholder string, factor float64, aggregate string, args []interface{}) (map[string][]model.MetricSample, error) {
	agg := "AVG"
	if aggregate != "" {
		agg = aggregate
	}

	whereClause := fmt.Sprintf("%s AND m.time >= %s AT TIME ZONE 'UTC' AND m.time <= %s AT TIME ZONE 'UTC' AND m.fields->>'%s' IS NOT NULL AND tag.tags->>'container_name' IS NOT NULL", hostFilter, startPlaceholder, endPlaceholder, field)
	if container != "" && container != "all" {
		placeholderIdx := len(args) + 1
		whereClause = fmt.Sprintf("%s AND tag.tags->>'container_name' = $%d", whereClause, placeholderIdx)
		args = append(args, container)
	}

	valExpr := fmt.Sprintf("(m.fields->>'%s')::double precision", field)

	q := fmt.Sprintf(`
		SELECT 
			to_timestamp(floor(extract(epoch from m.time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
			COALESCE(tag.tags->>'host', '') AS host,
			tag.tags->>'container_name' AS container,
			%s(%s) AS val
		FROM telegraf.%s m
		JOIN telegraf.%s_tag tag ON m.tag_id = tag.tag_id
		WHERE %s
		GROUP BY bucket, host, container
		ORDER BY bucket ASC`, agg, valExpr, table, table, whereClause)

	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics container metric")
		if s.isMissingRelationError(err) {
			return make(map[string][]model.MetricSample), nil
		}
		return nil, err
	}
	defer rows.Close()

	res := make(map[string][]model.MetricSample)
	for rows.Next() {
		var bucket time.Time
		var host string
		var containerName string
		var val float64
		if err := rows.Scan(&bucket, &host, &containerName, &val); err == nil {
			if factor != 0.0 && factor != 1.0 {
				val = val * factor
			}
			var key string
			if nodeId == "" {
				key = host + "::" + containerName
			} else {
				key = containerName
			}
			res[key] = append(res[key], model.MetricSample{
				Timestamp: bucket,
				Value:     val,
			})
		}
	}
	return res, nil
}

func queryContainerCpuMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	return s.queryContainerMetric(ctx, "docker_container_cpu", "usage_percent", nodeId, container, hostFilter, startPlaceholder, endPlaceholder, 1.0, "AVG", args)
}

func queryContainerMemMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	return s.queryContainerMetric(ctx, "docker_container_mem", "usage_percent", nodeId, container, hostFilter, startPlaceholder, endPlaceholder, 1.0, "AVG", args)
}

func queryContainerUptimeMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	return s.queryContainerMetric(ctx, "docker_container_status", "uptime_ns", nodeId, container, hostFilter, startPlaceholder, endPlaceholder, 1.0/1000000000.0, "AVG", args)
}

func queryKafkaEpsMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	res := make(map[string][]model.MetricSample)
	if nodeId != "" {
		res["kafka_eps"] = make([]model.MetricSample, 0)
	}

	timeWindow := "2 minutes"
	qKafka := fmt.Sprintf(`
		WITH msg_diff AS (
			SELECT 
				tag.tags->>'host' as host,
				COALESCE(tag.tags->>'topic', '') as topic,
				m.time,
				(m.fields->>'MessagesInPerSec.Count')::bigint as msg_count,
				LAG((m.fields->>'MessagesInPerSec.Count')::bigint) OVER (PARTITION BY tag.tags->>'host', COALESCE(tag.tags->>'topic', '') ORDER BY m.time) as prev_count,
				LAG(m.time) OVER (PARTITION BY tag.tags->>'host', COALESCE(tag.tags->>'topic', '') ORDER BY m.time) as prev_time
			FROM telegraf.kafka_topic m
			JOIN telegraf.kafka_topic_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND m.time >= (%s AT TIME ZONE 'UTC') - INTERVAL '%s' AND m.time <= (%s AT TIME ZONE 'UTC') AND m.fields->>'MessagesInPerSec.Count' IS NOT NULL
		),
		rates AS (
			SELECT 
				host,
				topic,
				time,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND msg_count >= prev_count 
					THEN (msg_count - prev_count)::float / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as eps
			FROM msg_diff
			WHERE time >= (%s AT TIME ZONE 'UTC')
		),
		bucketed AS (
			SELECT 
				to_timestamp(floor(extract(epoch from time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
				host,
				topic,
				AVG(eps) as topic_eps
			FROM rates
			GROUP BY bucket, host, topic
		)
		SELECT 
			bucket,
			host,
			SUM(topic_eps) as eps_total
		FROM bucketed
		GROUP BY bucket, host
		ORDER BY bucket ASC`, hostFilter, startPlaceholder, timeWindow, endPlaceholder, startPlaceholder)

	rows, err := s.db.Query(ctx, qKafka, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics kafka_eps")
		if s.isMissingRelationError(err) {
			return res, nil
		}
		return nil, err
	}
	defer rows.Close()

	if nodeId != "" {
		samples := make([]model.MetricSample, 0)
		for rows.Next() {
			var bucket time.Time
			var host string
			var val float64
			if err := rows.Scan(&bucket, &host, &val); err == nil {
				samples = append(samples, model.MetricSample{
					Timestamp: bucket,
					Value:     val,
				})
			}
		}
		res["kafka_eps"] = samples
	} else {
		hostSamples := make(map[string][]model.MetricSample)
		for rows.Next() {
			var bucket time.Time
			var host string
			var val float64
			if err := rows.Scan(&bucket, &host, &val); err == nil {
				hostSamples[host] = append(hostSamples[host], model.MetricSample{
					Timestamp: bucket,
					Value:     val,
				})
			}
		}
		for host, samples := range hostSamples {
			res[host] = samples
		}
	}

	return res, nil
}

func queryElasticIngestTimeMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	res := make(map[string][]model.MetricSample)

	timeWindow := "2 minutes"
	qIngest := fmt.Sprintf(`
		WITH proc_times AS (
			SELECT 
				tag.tags->>'host' as host,
				substring(kv.key from '^ingest_processor_stats_(.*)_time_in_millis$') as processor,
				m.time,
				(kv.value)::bigint as time_ms,
				LAG((kv.value)::bigint) OVER (PARTITION BY tag.tags->>'host', kv.key ORDER BY m.time) as prev_ms,
				LAG(m.time) OVER (PARTITION BY tag.tags->>'host', kv.key ORDER BY m.time) as prev_time
			FROM telegraf.elasticsearch_clusterstats_nodes m
			JOIN telegraf.elasticsearch_clusterstats_nodes_tag tag ON m.tag_id = tag.tag_id
			CROSS JOIN LATERAL jsonb_each_text(m.fields) AS kv(key, value)
			WHERE %s 
			  AND m.time >= (%s AT TIME ZONE 'UTC') - INTERVAL '%s' 
			  AND m.time <= (%s AT TIME ZONE 'UTC')
			  AND kv.key LIKE 'ingest_processor_stats_%%_time_in_millis'
			  AND kv.key != 'ingest_processor_stats_pipeline_time_in_millis'
			  AND kv.value IS NOT NULL AND kv.value != ''
		),
		rates AS (
			SELECT 
				host,
				processor,
				time,
				CASE 
					WHEN prev_time IS NOT NULL AND time > prev_time AND time_ms >= prev_ms 
					THEN (time_ms - prev_ms)::float / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as ms_per_sec
			FROM proc_times
			WHERE time >= (%s AT TIME ZONE 'UTC')
		)
		SELECT 
			to_timestamp(floor(extract(epoch from time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
			host,
			processor,
			AVG(ms_per_sec) as rate_avg
		FROM rates
		GROUP BY bucket, host, processor
		ORDER BY bucket ASC, processor ASC`, hostFilter, startPlaceholder, timeWindow, endPlaceholder, startPlaceholder)

	rows, err := s.db.Query(ctx, qIngest, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics elastic_ingest_time")
		if s.isMissingRelationError(err) {
			return res, nil
		}
		return nil, err
	}
	defer rows.Close()

	if nodeId != "" {
		hostSamples := make(map[string][]model.MetricSample)
		for rows.Next() {
			var bucket time.Time
			var host string
			var processor string
			var val float64
			if err := rows.Scan(&bucket, &host, &processor, &val); err == nil {
				hostSamples[processor] = append(hostSamples[processor], model.MetricSample{
					Timestamp: bucket,
					Value:     val,
				})
			}
		}
		for proc, samples := range hostSamples {
			res[proc] = samples
		}
	} else {
		hostSamples := make(map[string][]model.MetricSample)
		for rows.Next() {
			var bucket time.Time
			var host string
			var processor string
			var val float64
			if err := rows.Scan(&bucket, &host, &processor, &val); err == nil {
				key := host + "::" + processor
				hostSamples[key] = append(hostSamples[key], model.MetricSample{
					Timestamp: bucket,
					Value:     val,
				})
			}
		}
		for key, samples := range hostSamples {
			res[key] = samples
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
