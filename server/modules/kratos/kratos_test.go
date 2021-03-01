// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package kratos

import (
  "testing"
  "github.com/security-onion-solutions/securityonion-soc/config"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

func TestInit(tester *testing.T) {
  scfg := &config.ServerConfig{}
  srv := server.NewServer(scfg, "")
  kratos := NewKratos(srv)
  cfg := make(module.ModuleConfig)
  err := kratos.Init(cfg)
  if err == nil {
    tester.Errorf("expected Init error")
  }

  cfg["hostUrl"] = "abc"
  err = kratos.Init(cfg)
  if err != nil {
    tester.Errorf("unexpected Init error")
  }
  if kratos.server.Userstore == nil {
    tester.Errorf("expected non-nil Userstore")
  }
}
