// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package staticrbac

import (
  "github.com/security-onion-solutions/securityonion-soc/config"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/stretchr/testify/assert"
  "testing"
)

func TestInit(tester *testing.T) {
  scfg := &config.ServerConfig{}
  srv := server.NewServer(scfg, "")
  auth := NewStaticRbac(srv)
  cfg := make(module.ModuleConfig)
  err := auth.Init(cfg)
  assert.Error(tester, err)

  array := make([]interface{}, 1, 1)
  array[0] = "MyValue1"
  cfg["roleFiles"] = array

  array = make([]interface{}, 1, 1)
  array[0] = "MyValue2"
  cfg["userFiles"] = array
  err = auth.Init(cfg)
  assert.NoError(tester, err)
  assert.NotNil(tester, auth.server.Authorizer)
}
