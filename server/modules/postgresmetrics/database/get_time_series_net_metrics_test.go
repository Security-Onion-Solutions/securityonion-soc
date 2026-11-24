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

	"github.com/apex/log"
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
		queries := 0
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				queries++
				assert.Contains(t, sql, "AVG(r.drop_rate)")
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
		assert.Equal(t, 1, queries)
		assert.Contains(t, res, "traffic_mon_drops")
		assert.Len(t, res["traffic_mon_drops"], 1)
		assert.Equal(t, 2.5, res["traffic_mon_drops"][0].Value)
	})

	for _, nodeId := range []string{"node1", ""} {
		t.Run("net_drops joins the reported monitor interface for node '"+nodeId+"'", func(t *testing.T) {
			var captured string
			mockDb := &MockDB{
				QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
					captured = sql
					return &MockRows{
						rows: [][]interface{}{
							{time.Now(), "node1", "eth5", 3.0},
						},
					}, nil
				},
			}
			s := New(mockDb)
			res, err := s.GetTimeSeriesMetrics(ctx, nodeId, "", "net_drops", startTime, endTime)
			assert.NoError(t, err)

			assert.Contains(t, captured, "WITH node_interfaces AS (")
			assert.Contains(t, captured, "m.time >= ($2 AT TIME ZONE 'UTC') - INTERVAL '20 minutes' AND m.fields->>'monint'")
			assert.Contains(t, captured, "JOIN node_interfaces ni ON ni.host = r.host AND r.interface = ni.monint")
			assert.NotContains(t, captured, "eth1")
			assert.NotContains(t, captured, "ens19")
			assert.NotContains(t, captured, "%mon%")

			if nodeId == "" {
				assert.Len(t, res["node1::traffic_mon_drops"], 1)
				assert.Equal(t, 3.0, res["node1::traffic_mon_drops"][0].Value)
			} else {
				assert.Len(t, res["traffic_mon_drops"], 1)
				assert.Equal(t, 3.0, res["traffic_mon_drops"][0].Value)
			}
		})
	}

	t.Run("net_drops template expands cleanly and binds the chart start time", func(t *testing.T) {
		for _, nodeId := range []string{"node1", ""} {
			var captured string
			var capturedArgs []any
			mockDb := &MockDB{
				QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
					captured = sql
					capturedArgs = args
					return &MockRows{
						rows: [][]interface{}{
							{time.Now(), "node1", "eth5", 3.0},
						},
					}, nil
				},
			}
			s := New(mockDb)
			_, err := s.GetTimeSeriesMetrics(ctx, nodeId, "", "net_drops", startTime, endTime)
			assert.NoError(t, err)
			assert.NotContains(t, captured, "%!")
			assert.Equal(t, startTime, capturedArgs[1])
		}
	})

	t.Run("net_drops query error is returned and logged", func(t *testing.T) {
		h := captureLogs(t)
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return nil, errors.New("db error")
			},
		}
		s := New(mockDb)
		_, err := s.GetTimeSeriesMetrics(ctx, "node1", "", "net_drops", startTime, endTime)
		assert.Error(t, err)

		logged := false
		for _, entry := range h.Entries {
			if entry.Level == log.WarnLevel && strings.Contains(entry.Message, "GetTimeSeriesMetrics net_drops query failed") {
				logged = true
			}
		}
		assert.True(t, logged)
	})
}
