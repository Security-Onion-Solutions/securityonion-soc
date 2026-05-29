// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package mock

import (
	"context"
	"embed"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/stretchr/testify/mock"
)

type MockDB struct {
	mock.Mock
}

func (m *MockDB) Exec(ctx context.Context, sql string, args ...any) error {
	argsIn := append([]any{ctx, sql}, args...)
	return m.Called(argsIn...).Error(0)
}

func (m *MockDB) QueryRow(ctx context.Context, sql string, args ...any) db.Row {
	argsIn := append([]any{ctx, sql}, args...)
	return m.Called(argsIn...).Get(0).(db.Row)
}

func (m *MockDB) Query(ctx context.Context, sql string, args ...any) (db.Rows, error) {
	argsIn := append([]any{ctx, sql}, args...)
	call := m.Called(argsIn...)
	return call.Get(0).(db.Rows), call.Error(1)
}

func (m *MockDB) Begin(ctx context.Context) (db.Tx, error) {
	call := m.Called(ctx)
	return call.Get(0).(db.Tx), call.Error(1)
}

func (m *MockDB) Migrate(ctx context.Context, fs embed.FS, module string) error {
	return m.Called(ctx, fs, module).Error(0)
}

func (m *MockDB) Close() {
	m.Called()
}

type MockRow struct {
	mock.Mock
}

func (m *MockRow) Scan(dest ...any) error {
	return m.Called(dest...).Error(0)
}

type MockRows struct {
	mock.Mock
}

func (m *MockRows) Close() {
	m.Called()
}

func (m *MockRows) Err() error {
	return m.Called().Error(0)
}

func (m *MockRows) Next() bool {
	return m.Called().Bool(0)
}

func (m *MockRows) Scan(dest ...any) error {
	return m.Called(dest...).Error(0)
}

type MockTx struct {
	mock.Mock
}

func (m *MockTx) Commit(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *MockTx) Rollback(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *MockTx) Exec(ctx context.Context, sql string, args ...any) error {
	argsIn := append([]any{ctx, sql}, args...)
	return m.Called(argsIn...).Error(0)
}

func (m *MockTx) QueryRow(ctx context.Context, sql string, args ...any) db.Row {
	argsIn := append([]any{ctx, sql}, args...)
	return m.Called(argsIn...).Get(0).(db.Row)
}

func (m *MockTx) Query(ctx context.Context, sql string, args ...any) (db.Rows, error) {
	argsIn := append([]any{ctx, sql}, args...)
	call := m.Called(argsIn...)
	return call.Get(0).(db.Rows), call.Error(1)
}
