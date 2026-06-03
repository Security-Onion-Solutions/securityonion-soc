// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"fmt"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type PostgresModule struct {
	server *server.Server
	db     *DB
}

func NewPostgresModule(srv *server.Server) *PostgresModule {
	return &PostgresModule{
		server: srv,
	}
}

func (mod *PostgresModule) PrerequisiteModules() []string {
	return nil
}

func (mod *PostgresModule) Init(cfg module.ModuleConfig) error {
	host := module.GetStringDefault(cfg, "host", "")
	if host == "" {
		log.Info("No host configured for postgres module; skipping database initialization")
		return nil
	}

	dbCfg := Config{
		Host:     host,
		Port:     module.GetIntDefault(cfg, "port", 5432),
		Database: module.GetStringDefault(cfg, "name", ""),
		Username: module.GetStringDefault(cfg, "user", ""),
		Password: module.GetStringDefault(cfg, "password", ""),
		SSLMode:  module.GetStringDefault(cfg, "sslMode", "allow"),
	}

	db, err := Open(context.Background(), dbCfg)
	if err != nil {
		return fmt.Errorf("postgres module: open failed: %w", err)
	}

	mod.db = db
	mod.server.DB = db
	log.Info("Postgres module initialized and connection pool established")
	return nil
}

func (mod *PostgresModule) Start() error {
	return nil
}

func (mod *PostgresModule) Stop() error {
	if mod.db != nil {
		mod.db.Close()
	}
	return nil
}

func (mod *PostgresModule) IsRunning() bool {
	return mod.db != nil
}
