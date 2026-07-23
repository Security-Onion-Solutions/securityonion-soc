// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/assert"
)

func TestStore_GetTimeSeriesElasticMetrics(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

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
