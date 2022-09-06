// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package kratos

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type Kratos struct {
  config module.ModuleConfig
  server *server.Server
  impl   *KratosUserstore
}

func NewKratos(srv *server.Server) *Kratos {
  return &Kratos{
    server: srv,
    impl:   NewKratosUserstore(srv),
  }
}

func (kratos *Kratos) PrerequisiteModules() []string {
  return nil
}

func (kratos *Kratos) Init(cfg module.ModuleConfig) error {
  kratos.config = cfg
  url, err := module.GetString(cfg, "hostUrl")
  if err == nil {
    err = kratos.impl.Init(url)
    if err == nil {
      kratos.server.Userstore = kratos.impl
      err = kratos.server.Host.AddPreprocessor(NewKratosPreprocessor(kratos.impl))
    }
  }
  return err
}

func (kratos *Kratos) Start() error {
  return nil
}

func (kratos *Kratos) Stop() error {
  return nil
}

func (kratos *Kratos) IsRunning() bool {
  return false
}
