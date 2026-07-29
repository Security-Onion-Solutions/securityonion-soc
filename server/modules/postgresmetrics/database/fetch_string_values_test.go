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

func TestStore_FetchStringValues(t *testing.T) {
	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)

	mockDb := &MockDB{
		QueryFunc: func(ctx context.Context, sql string, args ...any) (db.Rows, error) {
			assert.Contains(t, sql, "telegraf.elasticsearch_cluster_health")
			assert.Contains(t, sql, "m.fields->>'status'")
			return &MockRows{
				rows: [][]interface{}{
					{"host1", "green"},
				},
			}, nil
		},
	}
	s := New(mockDb)
	res := s.FetchStringValues(ctx, "elasticsearch_cluster_health", "status", "", "", startTime)
	assert.Len(t, res, 1)
	assert.Equal(t, "green", res["host1"])
}