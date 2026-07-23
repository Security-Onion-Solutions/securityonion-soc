// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

func queryContainerMetric(ctx context.Context, s *Store, table, field, nodeId, container, hostFilter, startPlaceholder, endPlaceholder string, factor float64, aggregate string, args []interface{}) (map[string][]model.MetricSample, error) {
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
	return queryContainerMetric(ctx, s, "docker_container_cpu", "usage_percent", nodeId, container, hostFilter, startPlaceholder, endPlaceholder, 1.0, "AVG", args)
}

func queryContainerMemMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	return queryContainerMetric(ctx, s, "docker_container_mem", "usage_percent", nodeId, container, hostFilter, startPlaceholder, endPlaceholder, 1.0, "AVG", args)
}

func queryContainerUptimeMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	return queryContainerMetric(ctx, s, "docker_container_status", "uptime_ns", nodeId, container, hostFilter, startPlaceholder, endPlaceholder, 1.0/1000000000.0, "AVG", args)
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
