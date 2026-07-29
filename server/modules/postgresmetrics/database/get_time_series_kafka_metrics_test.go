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

func TestStore_GetTimeSeriesKafkaMetrics(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

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
}
