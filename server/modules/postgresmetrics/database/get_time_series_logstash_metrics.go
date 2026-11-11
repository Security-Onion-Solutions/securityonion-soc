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

// Logstash events without a pipeline tag still count toward EPS, so they need a visible series name.
const unknownPipelineName = "unknown"

func queryLogstashEpsMetric(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	timeWindow := "2 minutes"
	qLogstash := fmt.Sprintf(`
		WITH event_diff AS (
			SELECT 
				tag.tags->>'host' as host,
				COALESCE(tag.tags->>'pipeline', '') as pipeline,
				m.time,
				(m.fields->>'in')::bigint as in_count,
				LAG((m.fields->>'in')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'pipeline' ORDER BY m.time) as prev_count,
				LAG(m.time) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'pipeline' ORDER BY m.time) as prev_time
			FROM telegraf.logstash_events m
			JOIN telegraf.logstash_events_tag tag ON m.tag_id = tag.tag_id
			WHERE %s AND m.time >= (%s AT TIME ZONE 'UTC') - INTERVAL '%s' AND m.time <= (%s AT TIME ZONE 'UTC') AND m.fields->>'in' IS NOT NULL
		),
		rates AS (
			SELECT 
				host,
				pipeline,
				time,
				CASE 
					WHEN prev_count IS NOT NULL AND time > prev_time AND in_count >= prev_count 
					THEN (in_count - prev_count)::float / EXTRACT(EPOCH FROM (time - prev_time))
					ELSE 0.0
				END as eps
			FROM event_diff
			WHERE time >= (%s AT TIME ZONE 'UTC')
		)
		SELECT 
			to_timestamp(floor(extract(epoch from time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
			COALESCE(host, '') as host,
			pipeline,
			AVG(eps) as eps_avg
		FROM rates
		GROUP BY bucket, host, pipeline
		ORDER BY bucket ASC`, hostFilter, startPlaceholder, timeWindow, endPlaceholder, startPlaceholder)

	rows, err := s.db.Query(ctx, qLogstash, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics logstash_eps")
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
		var pipeline string
		var val float64
		if err := rows.Scan(&bucket, &host, &pipeline, &val); err == nil {
			if pipeline == "" {
				pipeline = unknownPipelineName
			}
			key := pipeline
			if nodeId == "" {
				key = host + "::" + pipeline
			}
			res[key] = append(res[key], model.MetricSample{
				Timestamp: bucket,
				Value:     val,
			})
		}
	}
	return res, nil
}
