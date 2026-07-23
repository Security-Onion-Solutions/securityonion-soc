// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/assert"
)

func TestStore_GetTimeSeriesNetMetrics(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

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
}
