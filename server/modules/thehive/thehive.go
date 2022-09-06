// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package thehive

import (
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type TheHive struct {
  config module.ModuleConfig
  server *server.Server
  store  *TheHiveCasestore
}

func NewTheHive(srv *server.Server) *TheHive {
  return &TheHive{
    server: srv,
    store:  NewTheHiveCasestore(srv),
  }
}

func (thehive *TheHive) PrerequisiteModules() []string {
  return nil
}

func (thehive *TheHive) Init(cfg module.ModuleConfig) error {
  thehive.config = cfg
  host, _ := module.GetString(cfg, "hostUrl")
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  key, _ := module.GetString(cfg, "key")
  err := thehive.store.Init(host, key, verifyCert)
  if err == nil && thehive.server != nil {
    if thehive.server.Casestore != nil {
      err = errors.New("Multiple case modules cannot be enabled concurrently")
    }
    thehive.server.Casestore = thehive.store
  }
  return err
}

func (thehive *TheHive) Start() error {
  return nil
}

func (thehive *TheHive) Stop() error {
  return nil
}

func (somodule *TheHive) IsRunning() bool {
  return false
}
