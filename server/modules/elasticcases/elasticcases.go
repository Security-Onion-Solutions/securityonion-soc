// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elasticcases

import (
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type ElasticCases struct {
  config module.ModuleConfig
  server *server.Server
  store  *ElasticCasestore
}

func NewElasticCases(srv *server.Server) *ElasticCases {
  return &ElasticCases{
    server: srv,
    store:  NewElasticCasestore(srv),
  }
}

func (somodule *ElasticCases) PrerequisiteModules() []string {
  return nil
}

func (somodule *ElasticCases) Init(cfg module.ModuleConfig) error {
  somodule.config = cfg
  host := module.GetStringDefault(cfg, "hostUrl", "kibana")
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  username := module.GetStringDefault(cfg, "username", "")
  password := module.GetStringDefault(cfg, "password", "")
  err := somodule.store.Init(host, username, password, verifyCert)
  if err == nil && somodule.server != nil {
    if somodule.server.Casestore != nil {
      err = errors.New("Multiple case modules cannot be enabled concurrently")
    }
    somodule.server.Casestore = somodule.store
  }
  return err
}

func (somodule *ElasticCases) Start() error {
  return nil
}

func (somodule *ElasticCases) Stop() error {
  return nil
}

func (somodule *ElasticCases) IsRunning() bool {
  return false
}
