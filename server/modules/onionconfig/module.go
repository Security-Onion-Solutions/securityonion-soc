// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"fmt"

	"github.com/apex/log"
	pgcommon "github.com/security-onion-solutions/securityonion-soc/db/postgres"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
)

const DEFAULT_SALTSTACK_DIR = "/opt/so/saltstack"
const DEFAULT_BYPASS_ENABLED = false

type OnionConfigModule struct {
	config module.ModuleConfig
	server *server.Server
	impl   *OnionConfig
	store  *database.Store
}

func NewOnionConfigModule(srv *server.Server) *OnionConfigModule {
	return &OnionConfigModule{
		server: srv,
		impl:   NewOnionConfig(srv),
	}
}

func (mod *OnionConfigModule) PrerequisiteModules() []string {
	return nil
}

func (mod *OnionConfigModule) Init(cfg module.ModuleConfig) error {
	mod.config = cfg
	saltstackDir := module.GetStringDefault(cfg, "saltstackDir", DEFAULT_SALTSTACK_DIR)
	bypassEnabled := module.GetBoolDefault(cfg, "bypassEnabled", DEFAULT_BYPASS_ENABLED)

	store, err := mod.initDatabase(cfg)
	if err != nil {
		return fmt.Errorf("onionconfig: database init failed: %w", err)
	}
	mod.store = store

	err = mod.impl.Init(saltstackDir, bypassEnabled, store)
	if err == nil {
		mod.server.Configstore = mod.impl
	}
	return err
}

// initDatabase reads DB connection parameters from the module config and
// opens a connection + runs migrations. Returns nil store (and no error) when
// no DB host is configured, making the DB optional during development/testing.
func (mod *OnionConfigModule) initDatabase(cfg module.ModuleConfig) (*database.Store, error) {
	host := module.GetStringDefault(cfg, "dbHost", "")
	if host == "" {
		log.Info("No dbHost configured for onionconfig; running without database")
		return nil, nil
	}

	dbCfg := pgcommon.Config{
		Host:     host,
		Port:     module.GetIntDefault(cfg, "dbPort", 5432),
		Database: module.GetStringDefault(cfg, "dbName", "soc"),
		Username: module.GetStringDefault(cfg, "dbUser", ""),
		Password: module.GetStringDefault(cfg, "dbPassword", ""),
		SSLMode:  module.GetStringDefault(cfg, "dbSSLMode", "disable"),
	}

	store, err := database.New(context.Background(), dbCfg)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (mod *OnionConfigModule) Start() error {
	return nil
}

func (mod *OnionConfigModule) Stop() error {
	if mod.store != nil {
		mod.store.Close()
	}
	return nil
}

func (mod *OnionConfigModule) IsRunning() bool {
	return false
}
