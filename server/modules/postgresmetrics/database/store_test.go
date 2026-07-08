// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/assert"
)

func TestStore_HandleQueryError(t *testing.T) {
	h := memory.New()
	originalHandler := log.Log.(*log.Logger).Handler
	originalLevel := log.Log.(*log.Logger).Level
	log.Log.(*log.Logger).Handler = h
	log.Log.(*log.Logger).Level = log.DebugLevel
	defer func() {
		log.Log.(*log.Logger).Handler = originalHandler
		log.Log.(*log.Logger).Level = originalLevel
	}()

	tests := []struct {
		name          string
		err           error
		operation     string
		expectedLevel log.Level
		expectedMsg   string
	}{
		{
			name:          "standard error",
			err:           errors.New("connection reset"),
			operation:     "FetchIntValues",
			expectedLevel: log.WarnLevel,
			expectedMsg:   "Postgres metrics: FetchIntValues query failed: connection reset",
		},
		{
			name: "direct 42P01 PgError",
			err: &pgconn.PgError{
				Severity: "ERROR",
				Code:     "42P01",
				Message:  `relation "telegraf.raid" does not exist`,
			},
			operation:     "FetchIntValues",
			expectedLevel: log.DebugLevel,
			expectedMsg:   "Postgres metrics: relation in FetchIntValues does not exist; skipping",
		},
		{
			name: "wrapped 42P01 PgError",
			err: fmt.Errorf("query failed: %w", &pgconn.PgError{
				Severity: "ERROR",
				Code:     "42P01",
				Message:  `relation "telegraf.raid" does not exist`,
			}),
			operation:     "FetchIntValues",
			expectedLevel: log.DebugLevel,
			expectedMsg:   "Postgres metrics: relation in FetchIntValues does not exist; skipping",
		},
		{
			name: "direct other PgError",
			err: &pgconn.PgError{
				Severity: "ERROR",
				Code:     "42P02",
				Message:  "some other error",
			},
			operation:     "FetchIntValues",
			expectedLevel: log.WarnLevel,
			expectedMsg:   "Postgres metrics: FetchIntValues query failed: ERROR: some other error (SQLSTATE 42P02)",
		},
		{
			name: "wrapped other PgError",
			err: fmt.Errorf("query failed: %w", &pgconn.PgError{
				Severity: "ERROR",
				Code:     "42P02",
				Message:  "some other error",
			}),
			operation:     "FetchIntValues",
			expectedLevel: log.WarnLevel,
			expectedMsg:   "Postgres metrics: FetchIntValues query failed: query failed: ERROR: some other error (SQLSTATE 42P02)",
		},
	}

	s := &Store{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.Entries = nil
			s.handleQueryError(tt.err, tt.operation)
			assert.Len(t, h.Entries, 1)
			assert.Equal(t, tt.expectedLevel, h.Entries[0].Level)
			assert.Equal(t, tt.expectedMsg, h.Entries[0].Message)
		})
	}
}

func TestStore_IsMissingRelationError(t *testing.T) {
	s := &Store{}

	assert.False(t, s.isMissingRelationError(errors.New("generic error")))

	assert.True(t, s.isMissingRelationError(&pgconn.PgError{
		Severity: "ERROR",
		Code:     "42P01",
		Message:  `relation "telegraf.raid" does not exist`,
	}))

	assert.True(t, s.isMissingRelationError(fmt.Errorf("query failed: %w", &pgconn.PgError{
		Severity: "ERROR",
		Code:     "42P01",
		Message:  `relation "telegraf.raid" does not exist`,
	})))

	assert.False(t, s.isMissingRelationError(&pgconn.PgError{
		Severity: "ERROR",
		Code:     "42P02",
		Message:  "some other error",
	}))

	assert.False(t, s.isMissingRelationError(fmt.Errorf("query failed: %w", &pgconn.PgError{
		Severity: "ERROR",
		Code:     "42P02",
		Message:  "some other error",
	})))
}

type MockRow struct {
	values []interface{}
	err    error
}

func (m *MockRow) Scan(dest ...interface{}) error {
	if m.err != nil {
		return m.err
	}
	if len(dest) != len(m.values) {
		return errors.New("mismatch scan count")
	}
	for i, val := range m.values {
		switch d := dest[i].(type) {
		case *string:
			*d = val.(string)
		case *int:
			*d = val.(int)
		case *float64:
			*d = val.(float64)
		case *time.Time:
			*d = val.(time.Time)
		default:
			return errors.New("unsupported scan destination type")
		}
	}
	return nil
}

type MockRows struct {
	rows  [][]interface{}
	index int
	err   error
}

func (m *MockRows) Close() {}
func (m *MockRows) Err() error { return m.err }
func (m *MockRows) Next() bool {
	m.index++
	return m.index <= len(m.rows)
}
func (m *MockRows) Scan(dest ...interface{}) error {
	row := m.rows[m.index-1]
	if len(dest) != len(row) {
		return errors.New("mismatch scan count")
	}
	for i, val := range row {
		switch d := dest[i].(type) {
		case *string:
			*d = val.(string)
		case *int:
			*d = val.(int)
		case *float64:
			*d = val.(float64)
		case *time.Time:
			*d = val.(time.Time)
		default:
			return errors.New("unsupported scan destination type")
		}
	}
	return nil
}

type MockDB struct {
	QueryFunc func(ctx context.Context, sql string, args ...any) (db.Rows, error)
}

func (m *MockDB) Exec(ctx context.Context, sql string, args ...any) error { return nil }
func (m *MockDB) QueryRow(ctx context.Context, sql string, args ...any) db.Row { return nil }
func (m *MockDB) Query(ctx context.Context, sql string, args ...any) (db.Rows, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, sql, args...)
	}
	return &MockRows{}, nil
}
func (m *MockDB) Begin(ctx context.Context) (db.Tx, error) { return nil, nil }
func (m *MockDB) Migrate(ctx context.Context, fs embed.FS, module string) error { return nil }
func (m *MockDB) Close() {}

func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
