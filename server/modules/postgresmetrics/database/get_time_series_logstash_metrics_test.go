// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/assert"
)

func TestStore_GetTimeSeriesLogstashMetrics(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()
	bucket := time.Now().Truncate(time.Minute)

	t.Run("query computes per-pipeline rate from cumulative counter", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "telegraf.logstash_events")
				assert.Contains(t, sql, "LAG((m.fields->>'in')::bigint) OVER (PARTITION BY tag.tags->>'host', tag.tags->>'pipeline' ORDER BY m.time)")
				assert.Contains(t, sql, "- INTERVAL '2 minutes'")
				assert.Contains(t, sql, "WHERE time >= ($2 AT TIME ZONE 'UTC')")
				assert.Contains(t, sql, "AVG(eps)")
				assert.Contains(t, sql, "tag.tags->>'host' = $4")
				assert.Contains(t, args, "node1")
				return &MockRows{}, nil
			},
		}
		s := New(mockDb)
		_, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "logstash_eps", startTime, endTime)
		assert.NoError(t, err)
	})

	t.Run("counter reset yields zero rate", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "WHEN prev_count IS NOT NULL AND time > prev_time AND in_count >= prev_count")
				assert.Contains(t, sql, "THEN (in_count - prev_count)::float / EXTRACT(EPOCH FROM (time - prev_time))")
				assert.Contains(t, sql, "ELSE 0.0")
				return &MockRows{
					rows: [][]interface{}{
						{bucket, "node1", "main", 0.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "logstash_eps", startTime, endTime)
		assert.NoError(t, err)
		assert.Equal(t, 0.0, res["main"][0].Value)
	})

	t.Run("single host returns one series per pipeline", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return &MockRows{
					rows: [][]interface{}{
						{bucket, "node1", "main", 120.0},
						{bucket, "node1", "search", 80.0},
						{bucket.Add(time.Minute), "node1", "main", 0.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "logstash_eps", startTime, endTime)
		assert.NoError(t, err)
		assert.Len(t, res, 2)
		assert.Len(t, res["main"], 2)
		assert.Equal(t, 120.0, res["main"][0].Value)
		assert.Equal(t, 0.0, res["main"][1].Value)
		assert.Len(t, res["search"], 1)
		assert.Equal(t, 80.0, res["search"][0].Value)
	})

	t.Run("all hosts keys series by host and pipeline", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "1=1")
				return &MockRows{
					rows: [][]interface{}{
						{bucket, "node1", "main", 10.0},
						{bucket, "node2", "main", 20.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "", "", "logstash_eps", startTime, endTime)
		assert.NoError(t, err)
		assert.Len(t, res, 2)
		assert.Equal(t, 10.0, res["node1::main"][0].Value)
		assert.Equal(t, 20.0, res["node2::main"][0].Value)
	})

	t.Run("missing table returns empty result", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return nil, &pgconn.PgError{Code: "42P01", Message: `relation "telegraf.logstash_events" does not exist`}
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "logstash_eps", startTime, endTime)
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Empty(t, res)
	})

	t.Run("row without pipeline tag is named unknown", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "COALESCE(tag.tags->>'pipeline', '') as pipeline")
				return &MockRows{
					rows: [][]interface{}{
						{bucket, "node1", "", 15.0},
						{bucket, "node1", "main", 25.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "logstash_eps", startTime, endTime)
		assert.NoError(t, err)
		assert.NotContains(t, res, "")
		assert.Equal(t, 15.0, res[unknownPipelineName][0].Value)
		assert.Equal(t, 25.0, res["main"][0].Value)

		res, err = s.GetTimeSeriesMetrics(ctx, "", "", "logstash_eps", startTime, endTime)
		assert.NoError(t, err)
		assert.Equal(t, 15.0, res["node1::"+unknownPipelineName][0].Value)
	})
}
