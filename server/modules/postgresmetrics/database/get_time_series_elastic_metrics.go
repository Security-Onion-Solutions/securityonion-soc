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
