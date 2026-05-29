// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package db

import (
	"context"
	"embed"
)

// DB defines the generic interface for database operations.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	Begin(ctx context.Context) (Tx, error)
	Migrate(ctx context.Context, fs embed.FS, module string) error
	Close()
}

// Row is a generic interface for a single row result.
type Row interface {
	Scan(dest ...any) error
}

// Rows is a generic interface for multiple row results.
type Rows interface {
	Close()
	Err() error
	Next() bool
	Scan(dest ...any) error
}

// Tx is a generic interface for a database transaction.
type Tx interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	Exec(ctx context.Context, sql string, args ...any) error
	QueryRow(ctx context.Context, sql string, args ...any) Row
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}
