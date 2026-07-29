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

func TestStore_GetTimeSeriesContainerMetrics(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

	t.Run("Container query filters by container", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
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

	t.Run("Container mem metric", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "docker_container_mem")
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "host-a", "so-redis", 45.6},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "", "so-redis", "container_mem", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "host-a::so-redis")
		assert.Equal(t, 45.6, res["host-a::so-redis"][0].Value)
	})

	t.Run("Container uptime metric", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "docker_container_status")
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "host-a", "so-redis", 10000000000.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "", "so-redis", "container_uptime", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "host-a::so-redis")
		assert.Equal(t, 10.0, res["host-a::so-redis"][0].Value)
	})

	t.Run("Container net in metric", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "docker_container_net")
				return &MockRows{
					rows: [][]interface{}{
						{time.Now(), "host-a", "so-redis", 5.5},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res, err := s.GetTimeSeriesMetrics(ctx, "", "so-redis", "container_net_in", startTime, endTime)
		assert.NoError(t, err)
		assert.Contains(t, res, "host-a::so-redis")
		assert.Equal(t, 5.5, res["host-a::so-redis"][0].Value)
	})
}
