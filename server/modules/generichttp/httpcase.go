// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package generichttp

import (
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type HttpCase struct {
  config module.ModuleConfig
  server *server.Server
  store  *HttpCasestore
}

func NewHttpCase(srv *server.Server) *HttpCase {
  return &HttpCase{
    server: srv,
    store:  NewHttpCasestore(srv),
  }
}

func (somodule *HttpCase) PrerequisiteModules() []string {
  return nil
}

func (somodule *HttpCase) Init(cfg module.ModuleConfig) error {
  somodule.config = cfg
  host, _ := module.GetString(cfg, "hostUrl")
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  headers := module.GetStringArrayDefault(cfg, "headers", nil)
  createParams := NewGenericHttpParams(cfg, "create")
  err := somodule.store.Init(host, verifyCert, headers, createParams)
  if err == nil && somodule.server != nil {
    if somodule.server.Casestore != nil {
      err = errors.New("Multiple case modules cannot be enabled concurrently")
    }
    somodule.server.Casestore = somodule.store
  }
  return err
}

func (somodule *HttpCase) Start() error {
  return nil
}

func (somodule *HttpCase) Stop() error {
  return nil
}

func (somodule *HttpCase) IsRunning() bool {
  return false
}
