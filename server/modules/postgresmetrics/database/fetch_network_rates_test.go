// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/assert"
)

func captureLogs(t *testing.T) *memory.Handler {
	h := memory.New()
	logger := log.Log.(*log.Logger)
	originalHandler := logger.Handler
	originalLevel := logger.Level
	logger.Handler = h
	logger.Level = log.DebugLevel
	t.Cleanup(func() {
		logger.Handler = originalHandler
		logger.Level = originalLevel
	})
	return h
}

func networkRatesMock(confRows *MockRows, confErr error, rateRows [][]interface{}, confSql *string, confArgs *[]any) *MockDB {
	return &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			if contains(sql, "telegraf.node_config") {
				if confSql != nil {
					*confSql = sql
				}
				if confArgs != nil {
					*confArgs = args
				}
				if confErr != nil {
					return nil, confErr
				}
				return confRows, nil
			}
			if contains(sql, "telegraf.net") {
				return &MockRows{rows: rateRows}, nil
			}
			return &MockRows{}, nil
		},
	}
}

func TestStore_FetchNetworkRates(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	bytesToMb := 8.0 / (1000.0 * 1000.0)
	timestamptzBound := "($1::timestamptz AT TIME ZONE 'UTC') - INTERVAL '" + nodeConfigLookback + "'"

	t.Run("successful rates query", func(t *testing.T) {
		var confSql string
		var confArgs []any
		mockDb := networkRatesMock(&MockRows{rows: [][]interface{}{{"host1", "eth0", "eth1"}}}, nil, [][]interface{}{
			{"host1", "eth0", 1000000.0, 500000.0, 0.0},
			{"host1", "eth1", 2000000.0, 0.0, 5.0},
		}, &confSql, &confArgs)
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.NoError(t, err)

		assert.Equal(t, 1000000.0*bytesToMb, rates.TrafficManInMbs["host1"])
		assert.Equal(t, 500000.0*bytesToMb, rates.TrafficManOutMbs["host1"])
		assert.Equal(t, 2000000.0*bytesToMb, rates.TrafficMonInMbs["host1"])
		assert.Equal(t, 5.0, rates.TrafficMonInDropsPps["host1"])

		assert.Contains(t, confSql, "m.time >= "+timestamptzBound+" AND m.fields->>'manint'")
		assert.Contains(t, confSql, "m.time >= "+timestamptzBound+" AND m.fields->>'monint'")
		assert.Contains(t, confSql, "SELECT host, manint, monint FROM node_interfaces")
		assert.Equal(t, []any{startTime}, confArgs)
	})

	t.Run("interface lookup applies fixed lookback when window is shorter than node_config interval", func(t *testing.T) {
		shortStartTime := time.Now().Add(-120 * time.Second)
		var confSql string
		var confArgs []any
		var ratesArgs []any
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				if contains(sql, "telegraf.node_config") {
					confSql = sql
					confArgs = args
					return &MockRows{rows: [][]interface{}{{"sensor1", "eth0", "eth1"}}}, nil
				}
				ratesArgs = args
				return &MockRows{rows: [][]interface{}{
					{"sensor1", "eth0", 1000000.0, 500000.0, 0.0},
					{"sensor1", "eth1", 2000000.0, 0.0, 7.0},
				}}, nil
			},
		}
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, shortStartTime)
		assert.NoError(t, err)

		assert.Equal(t, 7.0, rates.TrafficMonInDropsPps["sensor1"])
		assert.Equal(t, 2000000.0*bytesToMb, rates.TrafficMonInMbs["sensor1"])

		assert.Contains(t, confSql, timestamptzBound)
		assert.NotContains(t, confSql, "$1 - INTERVAL")
		assert.NotContains(t, confSql, "m.time >= $1 AND")
		assert.Equal(t, []any{shortStartTime}, confArgs)
		assert.Equal(t, []any{shortStartTime.Add(-2 * time.Minute)}, ratesArgs)
	})

	t.Run("host without monint uses manint and reports zero monitor values", func(t *testing.T) {
		mockDb := networkRatesMock(&MockRows{rows: [][]interface{}{{"mgr", "ens18", ""}}}, nil, [][]interface{}{
			{"mgr", "ens18", 1000000.0, 500000.0, 0.0},
			{"mgr", "eth0", 3000000.0, 3000000.0, 0.0},
			{"mgr", "eth1", 2000000.0, 0.0, 5.0},
		}, nil, nil)
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.NoError(t, err)

		assert.Equal(t, 1000000.0*bytesToMb, rates.TrafficManInMbs["mgr"])
		assert.Equal(t, 500000.0*bytesToMb, rates.TrafficManOutMbs["mgr"])
		assert.Contains(t, rates.TrafficMonInMbs, "mgr")
		assert.Contains(t, rates.TrafficMonInDropsPps, "mgr")
		assert.Equal(t, 0.0, rates.TrafficMonInMbs["mgr"])
		assert.Equal(t, 0.0, rates.TrafficMonInDropsPps["mgr"])
	})

	t.Run("host reporting only monint gets eth0 management and monint monitor values", func(t *testing.T) {
		mockDb := networkRatesMock(&MockRows{rows: [][]interface{}{{"mgr", "", "eth1"}}}, nil, [][]interface{}{
			{"mgr", "eth0", 1000000.0, 500000.0, 0.0},
			{"mgr", "eth1", 2000000.0, 0.0, 5.0},
		}, nil, nil)
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.NoError(t, err)

		assert.Equal(t, 1000000.0*bytesToMb, rates.TrafficManInMbs["mgr"])
		assert.Equal(t, 500000.0*bytesToMb, rates.TrafficManOutMbs["mgr"])
		assert.Equal(t, 2000000.0*bytesToMb, rates.TrafficMonInMbs["mgr"])
		assert.Equal(t, 5.0, rates.TrafficMonInDropsPps["mgr"])
	})

	t.Run("host absent from interface rows has zero monitor values and eth0 management", func(t *testing.T) {
		mockDb := networkRatesMock(&MockRows{}, nil, [][]interface{}{
			{"mgr", "eth0", 1000000.0, 500000.0, 0.0},
			{"mgr", "eth1", 1000.0, 0.0, 5.0},
		}, nil, nil)
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.NoError(t, err)

		assert.Equal(t, 1000000.0*bytesToMb, rates.TrafficManInMbs["mgr"])
		assert.Equal(t, 500000.0*bytesToMb, rates.TrafficManOutMbs["mgr"])
		assert.Contains(t, rates.TrafficMonInMbs, "mgr")
		assert.Contains(t, rates.TrafficMonInDropsPps, "mgr")
		assert.Equal(t, 0.0, rates.TrafficMonInMbs["mgr"])
		assert.Equal(t, 0.0, rates.TrafficMonInDropsPps["mgr"])
	})

	t.Run("interface query failure returns error and no rates", func(t *testing.T) {
		ratesQueried := false
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				if contains(sql, "telegraf.node_config") {
					return nil, errors.New("db error")
				}
				ratesQueried = true
				return &MockRows{}, nil
			},
		}
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.Error(t, err)
		assert.Nil(t, rates)
		assert.False(t, ratesQueried)
	})

	t.Run("missing node_config relation is not a failure", func(t *testing.T) {
		missing := fmt.Errorf("query failed: %w", &pgconn.PgError{Code: "42P01"})
		mockDb := networkRatesMock(nil, missing, [][]interface{}{
			{"host1", "eth0", 1000000.0, 500000.0, 0.0},
			{"host1", "eth1", 2000000.0, 0.0, 5.0},
		}, nil, nil)
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.NoError(t, err)
		assert.Equal(t, 1000000.0*bytesToMb, rates.TrafficManInMbs["host1"])
		assert.Equal(t, 500000.0*bytesToMb, rates.TrafficManOutMbs["host1"])
		assert.Equal(t, 0.0, rates.TrafficMonInMbs["host1"])
		assert.Equal(t, 0.0, rates.TrafficMonInDropsPps["host1"])
	})

	t.Run("interface rows error is returned", func(t *testing.T) {
		confRows := &MockRows{rows: [][]interface{}{{"host1", "eth0", "eth1"}}, err: errors.New("rows error")}
		mockDb := networkRatesMock(confRows, nil, [][]interface{}{{"host1", "eth0", 1.0, 1.0, 0.0}}, nil, nil)
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.Error(t, err)
		assert.Nil(t, rates)
	})

	t.Run("unreadable interface row is logged and skipped", func(t *testing.T) {
		h := captureLogs(t)
		confRows := &MockRows{rows: [][]interface{}{{"bad"}, {"host1", "eth0", "eth1"}}}
		mockDb := networkRatesMock(confRows, nil, [][]interface{}{
			{"host1", "eth1", 2000000.0, 0.0, 5.0},
		}, nil, nil)
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.NoError(t, err)
		assert.Equal(t, 5.0, rates.TrafficMonInDropsPps["host1"])

		warned := false
		for _, entry := range h.Entries {
			if entry.Level == log.WarnLevel && strings.Contains(entry.Message, "node interface row") {
				warned = true
			}
		}
		assert.True(t, warned)
	})

	t.Run("network rates error", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				if contains(sql, "telegraf.node_config") {
					return &MockRows{
						rows: [][]interface{}{
							{"host1", "eth0", "eth1"},
						},
					}, nil
				}
				return nil, errors.New("db error")
			},
		}
		s := New(mockDb)
		_, err := s.FetchNetworkRates(ctx, startTime)
		assert.Error(t, err)
	})
}

func TestNodeInterfacesCTE(t *testing.T) {
	sql := fmt.Sprintf(nodeInterfacesCTE, "BOUND")

	assert.Contains(t, sql, "SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host' AS host, m.fields->>'manint' AS manint")
	assert.Contains(t, sql, "SELECT DISTINCT ON (tag.tags->>'host') tag.tags->>'host' AS host, m.fields->>'monint' AS monint")
	assert.Contains(t, sql, "WHERE m.time >= BOUND AND m.fields->>'manint' IS NOT NULL AND m.fields->>'manint' <> ''")
	assert.Contains(t, sql, "WHERE m.time >= BOUND AND m.fields->>'monint' IS NOT NULL AND m.fields->>'monint' <> ''")
	assert.Contains(t, sql, "FULL OUTER JOIN")
	assert.Contains(t, sql, "ON man.host = mon.host")
	assert.Contains(t, sql, "COALESCE(man.host, mon.host) AS host")
	assert.Contains(t, sql, "COALESCE(man.manint, '') AS manint")
	assert.Contains(t, sql, "COALESCE(mon.monint, '') AS monint")
	assert.NotContains(t, sql, "%!")
	assert.Equal(t, "20 minutes", nodeConfigLookback)
}
