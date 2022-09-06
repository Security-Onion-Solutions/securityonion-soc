// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package generichttp

import (
  "testing"

  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/stretchr/testify/assert"
)

func TestHttpCase(tester *testing.T) {
  httpCase := NewHttpCase(server.NewFakeUnauthorizedServer())
  cfg := make(module.ModuleConfig)
  err := httpCase.Init(cfg)
  assert.Nil(tester, err)

  // Fail if casestore already initialized
  err = httpCase.Init(cfg)
  assert.Error(tester, err)
}
