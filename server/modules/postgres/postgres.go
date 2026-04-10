// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"fmt"

	"github.com/apex/log"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_PORT = 5432

type Postgres struct {
	config           module.ModuleConfig
	server           *server.Server
	pool             *pgxpool.Pool
	running          bool
	assistantEnabled bool
	esMigrationCfg   *esMigrationConfig
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
	adminUser := module.GetStringDefault(cfg, "adminUser", "postgres")
	adminPassword := module.GetStringDefault(cfg, "adminPassword", "")
	dbname := module.GetStringDefault(cfg, "dbname", "securityonion")
	sslMode := module.GetStringDefault(cfg, "sslMode", "require")
	assistantEnabled := module.GetBoolDefault(cfg, "assistantEnabled", true)

	// Use superuser for schema initialization (PG 15+ restricts CREATE TABLE on public schema)
	adminConnStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		host, port, adminUser, adminPassword, dbname, sslMode)

	adminPool, err := pgxpool.NewWithConfig(context.Background(), func() *pgxpool.Config {
		cfg, _ := pgxpool.ParseConfig(adminConnStr)
		return cfg
	}())
	if err != nil {
		return fmt.Errorf("unable to create postgres admin connection: %w", err)
	}

	if err := adminPool.Ping(context.Background()); err != nil {
		adminPool.Close()
		return fmt.Errorf("unable to connect to postgres as admin: %w", err)
	}

	log.Info("Connected to PostgreSQL as admin")

	if err := pg.initSchema(context.Background(), adminPool); err != nil {
		adminPool.Close()
		return fmt.Errorf("unable to initialize postgres schema: %w", err)
	}

	// Grant privileges to app user on all tables
	if _, err := adminPool.Exec(context.Background(),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO %q", username)); err != nil {
		adminPool.Close()
		return fmt.Errorf("unable to grant privileges to app user: %w", err)
	}

	adminPool.Close()

	// Now connect as the application user for normal operations
	appConnStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		host, port, username, password, dbname, sslMode)

	poolConfig, err := pgxpool.ParseConfig(appConnStr)
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

	log.Info("Connected to PostgreSQL as app user")

	pg.assistantEnabled = assistantEnabled

	// Capture elasticsearch config for migration (queries ES directly via HTTP,
	// bypassing the Assistantstore interface which requires a user context for RBAC)
	esHostUrl := module.GetStringDefault(cfg, "esHostUrl", "")
	esUsername := module.GetStringDefault(cfg, "esUsername", "")
	esPassword := module.GetStringDefault(cfg, "esPassword", "")
	if esHostUrl != "" {
		pg.esMigrationCfg = &esMigrationConfig{
			HostUrl:      esHostUrl,
			Username:     esUsername,
			Password:     esPassword,
			ChatIndex:    module.GetStringDefault(cfg, "esChatIndex", "*:so-assistant-chat"),
			SessionIndex: module.GetStringDefault(cfg, "esSessionIndex", "*:so-assistant-session"),
			SchemaPrefix: module.GetStringDefault(cfg, "esSchemaPrefix", "so_"),
		}
	}

	return nil
}

func (pg *Postgres) Start() error {
	pg.running = true

	// Deferred to Start() because module initialization order is not guaranteed —
	// by the time Start() runs, all modules have completed Init().
	if pg.assistantEnabled {
		assiststore := NewPostgresAssistantstore(pg.server, pg.pool)

		if err := migrateAssistantData(context.Background(), pg.pool, pg.esMigrationCfg, assiststore); err != nil {
			log.WithError(err).Warn("Failed to migrate assistant data from Elasticsearch, continuing with existing postgres data")
		}

		pg.server.Assistantstore = assiststore
		log.Info("PostgreSQL Assistantstore enabled")
	}

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

func (pg *Postgres) initSchema(ctx context.Context, adminPool *pgxpool.Pool) error {
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

	_, err := adminPool.Exec(ctx, schema)
	return err
}
