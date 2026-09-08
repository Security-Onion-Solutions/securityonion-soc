// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-onion-solutions/securityonion-soc/db"
)

// DB wraps a pgxpool.Pool and provides migration support.
type DB struct {
	pool         *pgxpool.Pool
	mu           sync.Mutex
	tableCreated bool
}

var _ db.DB = (*DB)(nil)

// Config holds the parameters required to open a Postgres connection pool.
type Config struct {
	Host     string
	Port     int
	Database string
	Username string
	Password string
	SSLMode  string
}

// DSN builds a libpq-style connection string from Config.
func (c Config) DSN() string {
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	port := c.Port
	if port == 0 {
		port = 5432
	}
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		c.Host, port, c.Database, c.Username, c.Password, sslMode,
	)
}

// Open connects to Postgres using the given Config and verifies connectivity.
func Open(ctx context.Context, cfg Config) (*DB, error) {
	pool, err := pgxpool.New(ctx, cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases all connections in the pool.
func (db *DB) Close() {
	db.pool.Close()
}

// Begin starts a new transaction.
func (db *DB) Begin(ctx context.Context) (db.Tx, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &postgresTx{tx: tx}, nil
}

// Pool returns the underlying connection pool for direct use.
func (db *DB) Pool() *pgxpool.Pool {
	return db.pool
}

// Exec executes a statement that returns no rows.
func (db *DB) Exec(ctx context.Context, sql string, args ...any) error {
	log.WithField("sql", sql).Debug("Executing SQL")
	_, err := db.pool.Exec(ctx, sql, args...)
	return err
}

// QueryRow executes a query expected to return at most one row.
func (db *DB) QueryRow(ctx context.Context, sql string, args ...any) db.Row {
	log.WithField("sql", sql).Debug("Executing SQL")
	return db.pool.QueryRow(ctx, sql, args...)
}

// Query executes a query that returns multiple rows.
func (db *DB) Query(ctx context.Context, sql string, args ...any) (db.Rows, error) {
	log.WithField("sql", sql).Debug("Executing SQL")
	return db.pool.Query(ctx, sql, args...)
}

type postgresTx struct {
	tx pgx.Tx
}

func (p *postgresTx) Commit(ctx context.Context) error {
	return p.tx.Commit(ctx)
}

func (p *postgresTx) Rollback(ctx context.Context) error {
	return p.tx.Rollback(ctx)
}

func (p *postgresTx) Exec(ctx context.Context, sql string, args ...any) error {
	log.WithField("sql", sql).Debug("Executing SQL")
	_, err := p.tx.Exec(ctx, sql, args...)
	return err
}

func (p *postgresTx) QueryRow(ctx context.Context, sql string, args ...any) db.Row {
	log.WithField("sql", sql).Debug("Executing SQL")
	return p.tx.QueryRow(ctx, sql, args...)
}

func (p *postgresTx) Query(ctx context.Context, sql string, args ...any) (db.Rows, error) {
	log.WithField("sql", sql).Debug("Executing SQL")
	return p.tx.Query(ctx, sql, args...)
}

// Migrate applies all pending migrations from the provided embedded FS.
// Each SQL file must be named <version>_<description>.sql where version is an integer.
// The migrations table is namespaced by module to allow multiple modules to share a DB.
func (db *DB) Migrate(ctx context.Context, fs embed.FS, module string) error {
	if err := db.ensureMigrationsTable(ctx); err != nil {
		return err
	}

	applied, err := db.appliedVersions(ctx, module)
	if err != nil {
		return err
	}

	files, err := fs.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("postgres: read migrations dir: %w", err)
	}

	type migration struct {
		version int
		name    string
	}
	var pending []migration
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		version, err := parseMigrationVersion(f.Name())
		if err != nil {
			return err
		}
		if !applied[version] {
			pending = append(pending, migration{version: version, name: f.Name()})
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].version < pending[j].version })

	for _, m := range pending {
		content, err := fs.ReadFile("migrations/" + m.name)
		if err != nil {
			return fmt.Errorf("postgres: read migration %s: %w", m.name, err)
		}
		log.WithFields(log.Fields{"module": module, "version": m.version, "file": m.name}).Info("Applying migration")
		if err := db.applyMigration(ctx, module, m.version, string(content)); err != nil {
			return fmt.Errorf("postgres: apply migration %s: %w", m.name, err)
		}
	}
	return nil
}

func (db *DB) ensureMigrationsTable(ctx context.Context) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.tableCreated {
		return nil
	}

	_, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS migrations (
			module     VARCHAR(128)  NOT NULL,
			version    INTEGER       NOT NULL,
			applied_at TIMESTAMPTZ   NOT NULL DEFAULT now(),
			PRIMARY KEY (module, version)
		)`)
	if err == nil {
		log.Info("Postgres migrations table created successfully")
		db.tableCreated = true
	}
	return err
}

func (db *DB) appliedVersions(ctx context.Context, module string) (map[int]bool, error) {
	rows, err := db.pool.Query(ctx, `SELECT version FROM migrations WHERE module = $1`, module)
	if err != nil {
		return nil, fmt.Errorf("postgres: query applied versions: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func (db *DB) applyMigration(ctx context.Context, module string, version int, sql string) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, sql); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO migrations (module, version, applied_at) VALUES ($1, $2, $3)`,
		module, version, time.Now().UTC(),
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// parseMigrationVersion extracts the leading integer version from a filename like "001_init.sql".
func parseMigrationVersion(filename string) (int, error) {
	parts := strings.SplitN(filename, "_", 2)
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("postgres: invalid migration filename %q: version must be an integer prefix", filename)
	}
	return v, nil
}
