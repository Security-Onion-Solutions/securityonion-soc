// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/assert"
)

func TestStore_GetTimeSeriesMetrics(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

	t.Run("successful query", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), 25.5},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "host1", "", "cpu", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "cpu_used")
		assert.Len(t, res["cpu_used"], 1)
		assert.Equal(t, 25.5, res["cpu_used"][0].Value)
	})

	t.Run("missing relation error (42P01) returns empty slice and no error", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return nil, &pgconn.PgError{
					Severity: "ERROR",
					Code:     "42P01",
					Message:  `relation "telegraf.fbstats" does not exist`,
				}
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "host1", "", "eps", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "consumption_eps")
		assert.Len(t, res["consumption_eps"], 0)
		assert.Contains(t, res, "production_eps")
		assert.Len(t, res["production_eps"], 0)
	})

	t.Run("other database error returns the error", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return nil, &pgconn.PgError{
					Severity: "ERROR",
					Code:     "42P02",
					Message:  "some other error",
				}
			},
		}
		s := New(mockDb)
		_, err := s.GetTimeSeriesMetrics(ctx, "host1", "", "cpu", startTime, endTime)
		assert.Error(t, err)
		var pgErr *pgconn.PgError
		assert.True(t, errors.As(err, &pgErr))
		assert.Equal(t, "42P02", pgErr.Code)
	})

	t.Run("All Hosts query groups by host and formats keys", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "host-a", 33.3},
						{time.Now(), "host-b", 44.4},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "", "", "cpu", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "host-a")
		assert.Contains(t, res, "host-b")
		assert.Len(t, res["host-a"], 1)
		assert.Equal(t, 33.3, res["host-a"][0].Value)
	})

	t.Run("Container query filters by container", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				// Assert that the container name was passed in the query args
				assert.Contains(t, args, "so-redis")
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "host-a", "so-redis", 12.3},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "", "so-redis", "container_cpu", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "host-a::so-redis")
		assert.Len(t, res["host-a::so-redis"], 1)
		assert.Equal(t, 12.3, res["host-a::so-redis"][0].Value)
	})

	t.Run("elasticsearch_docs handles host tag fallback and query execution", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "COALESCE(NULLIF(tag.tags->>'node_name', ''), NULLIF(tag.tags->>'node_host', ''), NULLIF(tag.tags->>'host', ''), NULLIF(tag.tags->>'es_host', ''), '')")
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "host-a", 1119559.0},
						{time.Now(), "host-b", 396741.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "", "", "elasticsearch_docs", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "host-a")
		assert.Contains(t, res, "host-b")
		assert.Equal(t, 1119559.0, res["host-a"][0].Value)
		assert.Equal(t, 396741.0, res["host-b"][0].Value)
	})

	t.Run("net metric loads nodes with manint only", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				if strings.Contains(sql, "FROM telegraf.node_config m") {
					return &MockRows{
						rows: [][]interface{}{
							{"manager", "ens18", nil},
							{"search", "ens18", nil},
						},
					}, nil
				}
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "manager", "ens18", 100.0, 50.0},
						{time.Now(), "search", "ens18", 200.0, 80.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "", "", "net", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "manager::traffic_man_in")
		assert.Contains(t, res, "search::traffic_man_in")
	})

	t.Run("kafka_eps metric calculates rate derivative", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "telegraf.kafka_topic")
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "node1", 500.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "kafka_eps", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "kafka_eps")
		assert.Len(t, res["kafka_eps"], 1)
		assert.Equal(t, 500.0, res["kafka_eps"][0].Value)
	})

	t.Run("net_drops metric calculates average drops rate", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				if strings.Contains(sql, "FROM telegraf.node_config m") {
					return &MockRows{
						rows: [][]interface{}{
							{"node1", "ens19"},
						},
					}, nil
				}
				assert.Contains(t, sql, "AVG(drop_rate)")
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "node1", "ens19", 2.5},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "net_drops", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "traffic_mon_drops")
		assert.Len(t, res["traffic_mon_drops"], 1)
		assert.Equal(t, 2.5, res["traffic_mon_drops"][0].Value)
	})

	t.Run("elastic_ingest_time breaks down ingest rate by processor function", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "ingest_processor_stats_")
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "node1", "grok", 454.4},
						{time.Now(), "node1", "set", 240.3},
						{time.Now(), "node1", "script", 92.8},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "elastic_ingest_time", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "grok")
		assert.Contains(t, res, "set")
		assert.Contains(t, res, "script")
		assert.Equal(t, 454.4, res["grok"][0].Value)
		assert.Equal(t, 240.3, res["set"][0].Value)
		assert.Equal(t, 92.8, res["script"][0].Value)
	})
}
