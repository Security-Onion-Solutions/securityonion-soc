// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgres"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics/database"
)

const DEFAULT_CACHE_EXPIRATION_MS = 30000
const DEFAULT_MAX_METRIC_AGE_SECONDS = 1200
const DEFAULT_ALARM_EVALUATION_INTERVAL = 30 * time.Second

type PostgresMetricsModule struct {
	config             module.ModuleConfig
	server             *server.Server
	metrics            *PostgresMetrics
	telegrafDBConn     *postgres.DB
	metricsStore       *database.Store
	alarmStore         *AlarmstoreImpl
	stopChan           chan struct{}
	evaluationInterval time.Duration
	isRunning          bool
	mu                 sync.RWMutex
}

func NewPostgresMetricsModule(srv *server.Server) *PostgresMetricsModule {
	return &PostgresMetricsModule{
		server:             srv,
		metrics:            NewPostgresMetrics(srv),
		evaluationInterval: DEFAULT_ALARM_EVALUATION_INTERVAL,
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

	// Metrics data store (telegraf/postgres metrics time series)
	host := module.GetStringDefault(cfg, "host", "")
	if host != "" {
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

		mod.telegrafDBConn = dbConn
		mod.metricsStore = database.New(dbConn)
	} else if mod.server != nil && mod.server.DB != nil {
		mod.metricsStore = database.New(mod.server.DB)
	}

	if mod.metricsStore != nil {
		mod.metrics.SetStore(mod.metricsStore)
	}

	mod.metrics.Init(cacheExpirationMs, maxMetricAgeSeconds)

	// Alarm states store (uses default SOC postgres DB connection)
	var alarmDBStore *database.Store
	if mod.server != nil && mod.server.DB != nil {
		alarmDBStore = database.New(mod.server.DB)
		ctx := context.Background()
		if mod.server.Context != nil {
			ctx = mod.server.Context
		}
		if err := alarmDBStore.Migrate(ctx); err != nil {
			log.WithError(err).Warn("postgresmetrics module: alarm database migration warning")
		}
	}

	if mod.server != nil {
		mod.server.Metrics = mod.metrics
		mod.alarmStore = NewAlarmstore(mod.server, alarmDBStore)
		mod.server.Alarmstore = mod.alarmStore
		log.Info("Postgres metrics module initialized and registered as server metrics and alarm provider")
	}

	return nil
}

func (mod *PostgresMetricsModule) Start() error {
	mod.mu.Lock()
	if mod.isRunning {
		mod.mu.Unlock()
		return nil
	}

	mod.stopChan = make(chan struct{})
	mod.isRunning = true
	mod.mu.Unlock()

	go mod.evaluationLoop()

	return nil
}

func (mod *PostgresMetricsModule) Stop() error {
	mod.mu.Lock()
	if mod.isRunning {
		mod.isRunning = false
		if mod.stopChan != nil {
			close(mod.stopChan)
		}
	}
	mod.mu.Unlock()

	if mod.telegrafDBConn != nil {
		mod.telegrafDBConn.Close()
	}
	return nil
}

func (mod *PostgresMetricsModule) IsRunning() bool {
	mod.mu.RLock()
	defer mod.mu.RUnlock()
	return mod.isRunning
}

func (mod *PostgresMetricsModule) evaluationLoop() {
	interval := mod.evaluationInterval
	if interval <= 0 {
		interval = DEFAULT_ALARM_EVALUATION_INTERVAL
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	ctx := context.Background()
	if mod.server != nil && mod.server.Context != nil {
		ctx = mod.server.Context
	}

	for {
		select {
		case <-mod.stopChan:
			log.Debug("Postgresmetrics alarm evaluation loop exiting")
			return
		case <-ticker.C:
			if mod.alarmStore != nil {
				if err := mod.alarmStore.EvaluateAlarms(ctx); err != nil {
					log.WithError(err).Warn("Failed to evaluate alarms in background loop")
				}
			}
		}
	}
}
