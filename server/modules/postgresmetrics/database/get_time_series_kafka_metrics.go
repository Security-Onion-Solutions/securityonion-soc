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
