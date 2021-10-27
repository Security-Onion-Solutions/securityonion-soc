// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elasticcases

import (
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type ElasticCases struct {
  config module.ModuleConfig
  server *server.Server
  store  *ElasticCasestore
}

func NewElasticCases(srv *server.Server) *ElasticCases {
  return &ElasticCases{
    server: srv,
    store:  NewElasticCasestore(srv),
  }
}

func (somodule *ElasticCases) PrerequisiteModules() []string {
  return nil
}

func (somodule *ElasticCases) Init(cfg module.ModuleConfig) error {
  somodule.config = cfg
  host := module.GetStringDefault(cfg, "hostUrl", "kibana")
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  username := module.GetStringDefault(cfg, "username", "")
  password := module.GetStringDefault(cfg, "password", "")
  err := somodule.store.Init(host, username, password, verifyCert)
  if err == nil && somodule.server != nil {
    if somodule.server.Casestore != nil {
      err = errors.New("Multiple case modules cannot be enabled concurrently")
    }
    somodule.server.Casestore = somodule.store
  }
  return err
}

func (somodule *ElasticCases) Start() error {
  return nil
}

func (somodule *ElasticCases) Stop() error {
  return nil
}

func (somodule *ElasticCases) IsRunning() bool {
  return false
}
