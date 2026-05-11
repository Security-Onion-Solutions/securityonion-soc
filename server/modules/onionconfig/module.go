// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_SALTSTACK_DIR = "/opt/so/saltstack"
const DEFAULT_BYPASS_ENABLED = false

type OnionConfigModule struct {
	config module.ModuleConfig
	server *server.Server
	impl   *OnionConfig
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
	err := mod.impl.Init(saltstackDir, bypassEnabled)
	if err == nil {
		mod.server.Configstore = mod.impl
	}
	return err
}

func (mod *OnionConfigModule) Start() error {
	return nil
}

func (mod *OnionConfigModule) Stop() error {
	return nil
}

func (mod *OnionConfigModule) IsRunning() bool {
	return false
}
