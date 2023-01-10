// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
