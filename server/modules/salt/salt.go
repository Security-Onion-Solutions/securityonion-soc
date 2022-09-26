// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_TIMEOUT_MS = 30000
const DEFAULT_SALTSTACK_DIR = "/opt/so/saltstack"
const DEFAULT_SALT_PIPE = "/opt/so/conf/soc/salt.pipe"
const DEFAULT_BYPASS_ERRORS = false

type Salt struct {
  config module.ModuleConfig
  server *server.Server
  impl   *Saltstore
}

func NewSalt(srv *server.Server) *Salt {
  return &Salt{
    server: srv,
    impl:   NewSaltstore(srv),
  }
}

func (mod *Salt) PrerequisiteModules() []string {
  return nil
}

func (mod *Salt) Init(cfg module.ModuleConfig) error {
  mod.config = cfg
  timeoutMs := module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
  saltstackDir := module.GetStringDefault(cfg, "saltstackDir", DEFAULT_SALTSTACK_DIR)
  saltPipe := module.GetStringDefault(cfg, "saltPipe", DEFAULT_SALT_PIPE)
  bypassErrors := module.GetBoolDefault(cfg, "bypassErrors", DEFAULT_BYPASS_ERRORS)
  err := mod.impl.Init(timeoutMs, saltstackDir, saltPipe, saltPipe, bypassErrors)
  if err == nil {
    mod.server.Configstore = mod.impl
    mod.server.GridMembersstore = mod.impl
    mod.server.AdminUserstore = mod.impl
  }
  return err
}

func (mod *Salt) Start() error {
  return nil
}

func (mod *Salt) Stop() error {
  return nil
}

func (mod *Salt) IsRunning() bool {
  return false
}
