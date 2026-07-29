// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"
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
