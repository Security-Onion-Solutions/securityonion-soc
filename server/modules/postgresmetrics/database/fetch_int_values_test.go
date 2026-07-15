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

func TestStore_FetchIntValues(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)

	t.Run("without tags", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "telegraf.raid")
				return &MockRows{
					rows: [][]interface{}{
						{"host1", 1},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res := s.FetchIntValues(ctx, "raid", "nsmraid", "", "", startTime)
		assert.Len(t, res, 1)
		assert.Equal(t, 1, res["host1"])
	})

	t.Run("with tags", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				assert.Contains(t, sql, "tag.tags->>'foo'")
				return &MockRows{
					rows: [][]interface{}{
						{"host1", 2},
					},
				}, nil
			},
		}
		s := New(mockDb)
		res := s.FetchIntValues(ctx, "sostatus", "status", "foo", "bar", startTime)
		assert.Len(t, res, 1)
		assert.Equal(t, 2, res["host1"])
	})

	t.Run("query error", func(t *testing.T) {
		mockDb := &MockDB{
			QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
				return nil, errors.New("db error")
			},
		}
		s := New(mockDb)
		res := s.FetchIntValues(ctx, "raid", "nsmraid", "", "", startTime)
		assert.Empty(t, res)
	})
}