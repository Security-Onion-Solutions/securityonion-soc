// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

// Names are written into the SQL text, so only plain identifiers are allowed.
var tagRateIdentifierRegex = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func queryTagRateMetric(ctx context.Context, s *Store, table, field, seriesTag string, factor, max float64, nodeId, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	res := make(map[string][]model.MetricSample)

	timeWindow := "2 minutes"
	rate := fmt.Sprintf("delta / seconds * %s", strconv.FormatFloat(factor, 'f', -1, 64))
	if max > 0 {
		rate = fmt.Sprintf("LEAST(%s, %s)", rate, strconv.FormatFloat(max, 'f', -1, 64))
	}

	q := fmt.Sprintf(`
		SELECT
			to_timestamp(floor(extract(epoch from time AT TIME ZONE 'UTC') / $1) * $1) AS bucket,
			host,
			series,
			AVG(CASE
				WHEN delta IS NULL OR seconds IS NULL OR seconds <= 0 OR delta < 0 THEN 0.0
				ELSE %s
			END) AS rate
		FROM (
			SELECT
				m.time,
				tag.tags->>'host' AS host,
				tag.tags->>'%s' AS series,
				(m.fields->>'%s')::double precision - LAG((m.fields->>'%s')::double precision) OVER w AS delta,
				EXTRACT(EPOCH FROM (m.time - LAG(m.time) OVER w)) AS seconds
			FROM telegraf.%s m
			JOIN telegraf.%s_tag tag USING (tag_id)
			WHERE %s AND m.fields->>'%s' IS NOT NULL AND tag.tags->>'%s' IS NOT NULL
				AND m.time >= (%s AT TIME ZONE 'UTC') - INTERVAL '%s' AND m.time <= (%s AT TIME ZONE 'UTC')
			WINDOW w AS (PARTITION BY tag.tags->>'host', tag.tags->>'%s' ORDER BY m.time)
		) deltas
		WHERE time >= (%s AT TIME ZONE 'UTC')
		GROUP BY bucket, host, series
		ORDER BY bucket ASC`,
		rate, seriesTag, field, field, table, table, hostFilter, field, seriesTag,
		startPlaceholder, timeWindow, endPlaceholder, seriesTag, startPlaceholder)

	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		s.handleQueryError(err, "GetTimeSeriesMetrics tag_rate")
		if s.isMissingRelationError(err) {
			return res, nil
		}
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var bucket time.Time
		var host, series string
		var val float64
		if err := rows.Scan(&bucket, &host, &series, &val); err == nil {
			key := series
			if nodeId == "" {
				key = host + "::" + series
			}
			res[key] = append(res[key], model.MetricSample{
				Timestamp: bucket,
				Value:     val,
			})
		}
	}

	for _, samples := range res {
		sort.Slice(samples, func(i, j int) bool {
			return samples[i].Timestamp.Before(samples[j].Timestamp)
		})
	}

	return res, nil
}

// tagRateHandler returns a CustomHandler that turns a cumulative counter into a per-second
// rate, one series per value of seriesTag. A max of 0 leaves the rate uncapped.
func tagRateHandler(table, field, seriesTag string, factor, max float64) func(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
	for _, name := range []string{table, field, seriesTag} {
		if !tagRateIdentifierRegex.MatchString(name) {
			panic(fmt.Sprintf("tagRateHandler: invalid identifier %q", name))
		}
	}

	return func(ctx context.Context, s *Store, nodeId, container string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error) {
		return queryTagRateMetric(ctx, s, table, field, seriesTag, factor, max, nodeId, hostFilter, startPlaceholder, endPlaceholder, args)
	}
}
