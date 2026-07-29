// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"context"
	"fmt"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgres"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics/database"
)

const DEFAULT_CACHE_EXPIRATION_MS = 30000
const DEFAULT_MAX_METRIC_AGE_SECONDS = 1200

type PostgresMetricsModule struct {
	config  module.ModuleConfig
	server  *server.Server
	metrics *PostgresMetrics
	dbConn  *postgres.DB
}

func NewPostgresMetricsModule(srv *server.Server) *PostgresMetricsModule {
	return &PostgresMetricsModule{
		server:  srv,
		metrics: NewPostgresMetrics(srv),
	}
}

func (mod *PostgresMetricsModule) PrerequisiteModules() []string {
	return []string{"postgres"}
}

func (mod *PostgresMetricsModule) Init(cfg module.ModuleConfig) error {
	mod.config = cfg

	cacheExpirationMs := module.GetIntDefault(cfg, "cacheExpirationMs", DEFAULT_CACHE_EXPIRATION_MS)
	maxMetricAgeSeconds := module.GetIntDefault(cfg, "maxMetricAgeSeconds", DEFAULT_MAX_METRIC_AGE_SECONDS)

	if mod.server != nil {
		if mod.server.Config.ClientParams.GridParams.MetricsDashboard == nil || len(mod.server.Config.ClientParams.GridParams.MetricsDashboard.Panels) == 0 {
			dash, err := database.GenerateDefaultMetricsDashboard()
			if err != nil {
				log.WithError(err).Error("postgresmetrics module: failed to generate default metrics dashboard")
			} else {
				mod.server.Config.ClientParams.GridParams.MetricsDashboard = dash
				log.Info("postgresmetrics module: generated default metrics dashboard on the server")
			}
		}
	}

	host := module.GetStringDefault(cfg, "host", "")
	if host == "" {
		log.Info("No host configured for postgresmetrics module; skipping database initialization")
		return nil
	}

	dbCfg := postgres.Config{
		Host:     host,
		Port:     module.GetIntDefault(cfg, "port", 5432),
		Database: module.GetStringDefault(cfg, "database", ""),
		Username: module.GetStringDefault(cfg, "user", ""),
		Password: module.GetStringDefault(cfg, "password", ""),
		SSLMode:  module.GetStringDefault(cfg, "sslMode", "allow"),
	}

	dbConn, err := postgres.Open(context.Background(), dbCfg)
	if err != nil {
		return fmt.Errorf("postgresmetrics module: failed to connect to metrics database: %w", err)
	}

	mod.dbConn = dbConn
	dbStore := database.New(dbConn)
	mod.metrics.SetStore(dbStore)

	mod.metrics.Init(cacheExpirationMs, maxMetricAgeSeconds)

	if mod.server != nil {
		mod.server.Metrics = mod.metrics
		log.Info("Postgres metrics module initialized and registered as server metrics provider")
	}

	return nil
}

func (mod *PostgresMetricsModule) Start() error {
	return nil
}

func (mod *PostgresMetricsModule) Stop() error {
	if mod.dbConn != nil {
		mod.dbConn.Close()
	}
	return nil
}

func (mod *PostgresMetricsModule) IsRunning() bool {
	return mod.server.Metrics == mod.metrics
}
