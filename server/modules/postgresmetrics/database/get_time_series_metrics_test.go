// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"errors"
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
		res, err := s.GetTimeSeriesMetrics(ctx, "host1", "cpu", startTime, endTime)
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
		res, err := s.GetTimeSeriesMetrics(ctx, "", "eps", startTime, endTime)
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
		_, err := s.GetTimeSeriesMetrics(ctx, "", "cpu", startTime, endTime)
		assert.Error(t, err)
		var pgErr *pgconn.PgError
		assert.True(t, errors.As(err, &pgErr))
		assert.Equal(t, "42P02", pgErr.Code)
	})
}
