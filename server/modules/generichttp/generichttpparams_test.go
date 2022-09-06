// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package generichttp

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/stretchr/testify/assert"
  "testing"
)

func TestNewHttpParams(tester *testing.T) {
  cfg := make(module.ModuleConfig)
  params := NewGenericHttpParams(cfg, "create")
  assert.Equal(tester, "POST", params.Method)
  assert.Equal(tester, "", params.Path)
  assert.Equal(tester, "application/json", params.ContentType)
  assert.Equal(tester, "", params.Body)
  assert.Equal(tester, 200, params.SuccessStatusCode)
}
