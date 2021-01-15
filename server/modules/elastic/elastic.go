// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
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
const DEFAULT_DURATION_MS = 1800000
const DEFAULT_ES_SEARCH_OFFSET_MS = 1800000
const DEFAULT_TIMEOUT_MS = 120000
const DEFAULT_CACHE_MS = 86400000
const DEFAULT_INDEX = "*:so-*"
const DEFAULT_ASYNC_THRESHOLD = 10

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
  remoteHosts := module.GetStringArrayDefault(cfg, "remoteHostUrls", make([]string, 0, 0))
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  username := module.GetStringDefault(cfg, "username", "")
  password := module.GetStringDefault(cfg, "password", "")
  timeShiftMs := module.GetIntDefault(cfg, "timeShiftMs", DEFAULT_TIME_SHIFT_MS)
  defaultDurationMs := module.GetIntDefault(cfg, "defaultDurationMs", DEFAULT_DURATION_MS)
  esSearchOffsetMs := module.GetIntDefault(cfg, "esSearchOffsetMs", DEFAULT_ES_SEARCH_OFFSET_MS)
  timeoutMs := module.GetIntDefault(cfg, "timeoutMs", DEFAULT_TIMEOUT_MS)
  cacheMs := module.GetIntDefault(cfg, "cacheMs", DEFAULT_CACHE_MS)
  index := module.GetStringDefault(cfg, "index", DEFAULT_INDEX)
  asyncThreshold := module.GetIntDefault(cfg, "asyncThreshold", DEFAULT_ASYNC_THRESHOLD)
  err := elastic.store.Init(host, remoteHosts, username, password, verifyCert, timeShiftMs, defaultDurationMs, esSearchOffsetMs, timeoutMs, cacheMs, index, asyncThreshold)
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