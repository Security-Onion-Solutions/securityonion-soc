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

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/assert"
)

func TestStore_FetchNetworkRates(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)

	t.Run("successful rates query", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				if contains(sql, "telegraf.node_config") {
					return &MockRows{
						rows: [][]interface{}{
							{"host1", "eth0", "eth1"},
						},
					}, nil
				}
				if contains(sql, "telegraf.net") {
					return &MockRows{
						rows: [][]interface{}{
							{"host1", "eth0", 1000000.0, 500000.0, 0.0},
							{"host1", "eth1", 2000000.0, 0.0, 5.0},
						},
					}, nil
				}
				return &MockRows{}, nil
			},
		}
		s := New(mockDb)
		rates, err := s.FetchNetworkRates(ctx, startTime)
		assert.NoError(t, err)

		bytesToMb := 8.0 / (1000.0 * 1000.0)
		assert.Equal(t, 1000000.0*bytesToMb, rates.TrafficManInMbs["host1"])
		assert.Equal(t, 500000.0*bytesToMb, rates.TrafficManOutMbs["host1"])
		assert.Equal(t, 2000000.0*bytesToMb, rates.TrafficMonInMbs["host1"])
		assert.Equal(t, 5.0*bytesToMb, rates.TrafficMonInDropsMbs["host1"])
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
