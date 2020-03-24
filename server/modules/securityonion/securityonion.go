// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package securityonion

import (
  "github.com/sensoroni/sensoroni/module"
  "github.com/sensoroni/sensoroni/server"
)

const DEFAULT_TIME_SHIFT_MS = 120000

type SecurityOnion struct {
  config			module.ModuleConfig
  server			*server.Server
  elastic			*SoElastic
}

func NewSecurityOnion(srv *server.Server) *SecurityOnion {
  return &SecurityOnion {
    server: srv,
    elastic: NewSoElastic(),
  }
}

func (somodule *SecurityOnion) PrerequisiteModules() []string {
  return nil
}

func (somodule *SecurityOnion) Init(cfg module.ModuleConfig) error {
  somodule.config = cfg
  host := module.GetStringDefault(cfg, "elasticsearchHost", "elasticsearch")
  verifyCert := module.GetBoolDefault(cfg, "elasticsearchVerifyCert", true)
  username := module.GetStringDefault(cfg, "elasticsearchUsername", "")
  password := module.GetStringDefault(cfg, "elasticsearchPassword", "")
  timeShiftMs := module.GetIntDefault(cfg, "timeShiftMs", DEFAULT_TIME_SHIFT_MS)
  return somodule.elastic.Init(host, username, password, verifyCert, timeShiftMs)
}

func (somodule *SecurityOnion) Start() error {
  somodule.server.Host.Register("/securityonion/joblookup", NewSoJobLookupHandler(somodule.server, somodule.elastic))
  return nil
}

func (somodule *SecurityOnion) Stop() error {
  return nil
}

func (somodule *SecurityOnion) IsRunning() bool {
  return false
}