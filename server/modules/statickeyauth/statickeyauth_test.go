// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package statickeyauth

import (
  "testing"
  "github.com/sensoroni/sensoroni/config"
  "github.com/sensoroni/sensoroni/module"
  "github.com/sensoroni/sensoroni/server"
)

func TestAuthInit(tester *testing.T) {
  scfg := &config.ServerConfig{}
  srv := server.NewServer(scfg, "")
  auth := NewStaticKeyAuth(srv)
  cfg := make(module.ModuleConfig)
  err := auth.Init(cfg)
  if err == nil {
    tester.Errorf("expected Init error")
  }

  cfg["apiKey"] = "abc"
  err = auth.Init(cfg)
  if err != nil {
    tester.Errorf("unexpected Init error")
  }
  if auth.impl.anonymousNetwork.String() != "0.0.0.0/0" {
    tester.Errorf("expected anonymousNetwork %s but got %s", "0.0.0.0/0", auth.impl.anonymousNetwork.String())
  }
  if auth.server.Host.Auth == nil {
    tester.Errorf("expected non-nil Hot.Auth")
  }
}
