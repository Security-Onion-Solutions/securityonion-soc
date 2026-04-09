// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/apex/log"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_PORT = 5432

type Postgres struct {
	config  module.ModuleConfig
	server  *server.Server
	pool    *pgxpool.Pool
	running bool
}

func NewPostgres(srv *server.Server) *Postgres {
	return &Postgres{
		server: srv,
	}
}

func (pg *Postgres) PrerequisiteModules() []string {
	return []string{"elastic"}
}

func (pg *Postgres) Init(cfg module.ModuleConfig) error {
	pg.config = cfg

	host := module.GetStringDefault(cfg, "hostUrl", "so-postgres")
	port := module.GetIntDefault(cfg, "port", DEFAULT_PORT)
	username := module.GetStringDefault(cfg, "username", "so_postgres")
	password := module.GetStringDefault(cfg, "password", "")
	dbname := module.GetStringDefault(cfg, "dbname", "securityonion")
	sslMode := module.GetStringDefault(cfg, "sslMode", "require")
	assistantEnabled := module.GetBoolDefault(cfg, "assistantEnabled", true)

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		username, password, host, port, dbname, sslMode)

	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return fmt.Errorf("unable to parse postgres connection string: %w", err)
	}

	pg.pool, err = pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return fmt.Errorf("unable to create postgres connection pool: %w", err)
	}

	if err := pg.pool.Ping(context.Background()); err != nil {
		return fmt.Errorf("unable to connect to postgres: %w", err)
	}

	log.Info("Connected to PostgreSQL")

	if err := pg.initSchema(context.Background()); err != nil {
		return fmt.Errorf("unable to initialize postgres schema: %w", err)
	}

	if assistantEnabled {
		if pg.server.Assistantstore != nil {
			existingStore := pg.server.Assistantstore
			assiststore := NewPostgresAssistantstore(pg.server, pg.pool)

			if err := migrateAssistantData(context.Background(), pg.pool, existingStore, assiststore); err != nil {
				log.WithError(err).Warn("Failed to migrate assistant data from Elasticsearch, continuing with existing postgres data")
			}

			pg.server.Assistantstore = assiststore
			log.Info("PostgreSQL Assistantstore enabled (replaced Elasticsearch)")
		} else {
			return errors.New("postgres assistantEnabled requires elastic module to be initialized first")
		}
	}

	return nil
}

func (pg *Postgres) Start() error {
	pg.running = true
	return nil
}

func (pg *Postgres) Stop() error {
	pg.running = false
	if pg.pool != nil {
		pg.pool.Close()
	}
	return nil
}

func (pg *Postgres) IsRunning() bool {
	return pg.running
}

func (pg *Postgres) initSchema(ctx context.Context) error {
	schema := `
		CREATE TABLE IF NOT EXISTS assistant_sessions (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL UNIQUE,
			user_id TEXT NOT NULL,
			title TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL DEFAULT '',
			entity_id TEXT NOT NULL DEFAULT '',
			tags JSONB NOT NULL DEFAULT '[]',
			create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			update_time TIMESTAMPTZ,
			delete_time TIMESTAMPTZ
		);

		CREATE INDEX IF NOT EXISTS idx_assistant_sessions_session_id ON assistant_sessions(session_id);
		CREATE INDEX IF NOT EXISTS idx_assistant_sessions_user_id ON assistant_sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_assistant_sessions_create_time ON assistant_sessions(create_time);

		CREATE TABLE IF NOT EXISTS assistant_messages (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL REFERENCES assistant_sessions(session_id) ON DELETE CASCADE,
			user_id TEXT NOT NULL,
			model TEXT NOT NULL DEFAULT '',
			tags JSONB NOT NULL DEFAULT '[]',
			message JSONB NOT NULL,
			create_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			update_time TIMESTAMPTZ
		);

		CREATE INDEX IF NOT EXISTS idx_assistant_messages_session_id ON assistant_messages(session_id);
		CREATE INDEX IF NOT EXISTS idx_assistant_messages_create_time ON assistant_messages(create_time);
		CREATE INDEX IF NOT EXISTS idx_assistant_messages_user_id ON assistant_messages(user_id);

		CREATE TABLE IF NOT EXISTS migrations (
			name TEXT PRIMARY KEY,
			completed_time TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`

	_, err := pg.pool.Exec(ctx, schema)
	return err
}
