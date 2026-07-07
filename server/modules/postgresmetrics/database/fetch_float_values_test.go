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

func TestStore_FetchFloatValues(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)

	t.Run("without tags", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "telegraf.cpu")
				assert.Contains(t, sql, "usage_idle")
				assert.NotContains(t, sql, "tag.tags->>'path'")
				return &MockRows{
					rows: [][]interface{}{
						{"host1", 95.5},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res := s.FetchFloatValues(ctx, "cpu", "usage_idle", "", "", startTime, 2.0)
		assert.Len(t, res, 1)
		assert.Equal(t, 191.0, res["host1"]) // 95.5 * 2.0
	})

	t.Run("with tags", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "tag.tags->>'path'")
				return &MockRows{
					rows: [][]interface{}{
						{"host1", 45.0},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res := s.FetchFloatValues(ctx, "disk", "used_percent", "path", "/", startTime)
		assert.Len(t, res, 1)
		assert.Equal(t, 45.0, res["host1"])
	})

	t.Run("query error", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return nil, errors.New("db error")
			},
		}
		s := New(mockDb)
		res := s.FetchFloatValues(ctx, "cpu", "usage_idle", "", "", startTime)
		assert.Empty(t, res)
	})
}
