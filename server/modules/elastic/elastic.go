// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_TIME_SHIFT_MS = 120000
const DEFAULT_TIMEOUT_MS = 120000
const DEFAULT_INDEX = "*:so-*"

type Elastic struct {
  config			module.ModuleConfig
  server			*server.Server
  store			  *ElasticEventstore
}

func NewElastic(srv *server.Server) *Elastic {
  return &Elastic {
    server: srv,
    store: NewElasticEventstore(),
  }
}

func (elastic *Elastic) PrerequisiteModules() []string {
  return nil
}

func (elastic *Elastic) Init(cfg module.ModuleConfig) error {
  elastic.config = cfg
  host := module.GetStringDefault(cfg, "hostUrl", "elasticsearch")
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  username := module.GetStringDefault(cfg, "username", "")
  password := module.GetStringDefault(cfg, "password", "")
  timeShiftMs := module.GetIntDefault(cfg, "timeShiftMs", DEFAULT_TIME_SHIFT_MS)
  timeoutMs := module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
  index := module.GetStringDefault(cfg, "index", DEFAULT_INDEX)
  err := elastic.store.Init(host, username, password, verifyCert, timeShiftMs, timeoutMs, index)
  if err == nil && elastic.server != nil {
    elastic.server.Eventstore = elastic.store
  }
  return err
}

func (elastic *Elastic) Start() error {
  handler := NewJobLookupHandler(elastic.server, elastic.store)
  elastic.server.Host.Register("/joblookup", handler)
  elastic.server.Host.Register("/securityonion/joblookup", handler) // deprecated
  return nil
}

func (elastic *Elastic) Stop() error {
  return nil
}

func (somodule *Elastic) IsRunning() bool {
  return false
}