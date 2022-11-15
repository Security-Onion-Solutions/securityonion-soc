// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package staticrbac

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_SCAN_INTERVAL_MS = 60000

type StaticRbac struct {
  config module.ModuleConfig
  server *server.Server
  impl   *StaticRbacAuthorizer
}

func NewStaticRbac(srv *server.Server) *StaticRbac {
  return &StaticRbac{
    server: srv,
    impl:   NewStaticRbacAuthorizer(srv),
  }
}

func (auth *StaticRbac) PrerequisiteModules() []string {
  return nil
}

func (auth *StaticRbac) Init(cfg module.ModuleConfig) error {
  var err error
  auth.config = cfg
  var rolePaths []string
  rolePaths, err = module.GetStringArray(cfg, "roleFiles")
  if err == nil {
    var userPaths []string
    userPaths, err = module.GetStringArray(cfg, "userFiles")
    if err == nil {
      scanIntervalMs := module.GetIntDefault(cfg, "scanIntervalMs", DEFAULT_SCAN_INTERVAL_MS)
      err = auth.impl.Init(userPaths, rolePaths, scanIntervalMs)
      if err == nil {
        auth.server.Rolestore = auth.impl
        auth.server.Authorizer = auth.impl
        auth.server.Host.Authorizer = auth.impl
      }
    }
  }
  return err
}

func (auth *StaticRbac) Start() error {
  auth.impl.StartScanningFiles()
  return nil
}

func (auth *StaticRbac) Stop() error {
  auth.impl.StopScanningFiles()
  return nil
}

func (auth *StaticRbac) IsRunning() bool {
  return auth.impl.running
}
