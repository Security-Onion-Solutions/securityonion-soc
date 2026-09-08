// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigDSN_Defaults(t *testing.T) {
	cfg := Config{
		Host:     "localhost",
		Database: "testdb",
		Username: "user",
		Password: "pass",
	}
	dsn := cfg.DSN()
	assert.Contains(t, dsn, "host=localhost")
	assert.Contains(t, dsn, "port=5432")
	assert.Contains(t, dsn, "dbname=testdb")
	assert.Contains(t, dsn, "user=user")
	assert.Contains(t, dsn, "password=pass")
	assert.Contains(t, dsn, "sslmode=disable")
}

func TestConfigDSN_CustomSSLAndPort(t *testing.T) {
	cfg := Config{
		Host:     "db.example.com",
		Port:     5433,
		Database: "prod",
		Username: "admin",
		Password: "secret",
		SSLMode:  "require",
	}
	dsn := cfg.DSN()
	assert.Contains(t, dsn, "port=5433")
	assert.Contains(t, dsn, "sslmode=require")
}

func TestParseMigrationVersion_Valid(t *testing.T) {
	v, err := parseMigrationVersion("001_init.sql")
	assert.NoError(t, err)
	assert.Equal(t, 1, v)

	v, err = parseMigrationVersion("42_some_description.sql")
	assert.NoError(t, err)
	assert.Equal(t, 42, v)
}

func TestParseMigrationVersion_Invalid(t *testing.T) {
	_, err := parseMigrationVersion("abc_init.sql")
	assert.Error(t, err)
}

// TestOpen_Unreachable verifies that Open returns an error when the DB is not reachable,
// without panicking or blocking indefinitely.
func TestOpen_Unreachable(t *testing.T) {
	cfg := Config{
		Host:     "127.0.0.1",
		Port:     19999, // unlikely to be in use
		Database: "nodb",
		Username: "nobody",
		Password: "nopass",
		SSLMode:  "allow",
	}
	_, err := Open(context.Background(), cfg)
	assert.Error(t, err)
}

func TestDB_EnsureMigrationsTable_Concurrent_AlreadyCreated(t *testing.T) {
	db := &DB{
		tableCreated: true,
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.ensureMigrationsTable(context.Background())
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.True(t, db.tableCreated)
}
