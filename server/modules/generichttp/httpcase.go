// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package generichttp

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type HttpCase struct {
  config module.ModuleConfig
  server *server.Server
  store  *HttpCasestore
}

func NewHttpCase(srv *server.Server) *HttpCase {
  return &HttpCase{
    server: srv,
    store:  NewHttpCasestore(srv),
  }
}

func (somodule *HttpCase) PrerequisiteModules() []string {
  return nil
}

func (somodule *HttpCase) Init(cfg module.ModuleConfig) error {
  somodule.config = cfg
  host, _ := module.GetString(cfg, "hostUrl")
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  headers := module.GetStringArrayDefault(cfg, "headers", nil)
  createParams := NewGenericHttpParams(cfg, "create")
  err := somodule.store.Init(host, verifyCert, headers, createParams)
  if err == nil && somodule.server != nil {
    somodule.server.Casestore = somodule.store
  }
  return err
}

func (somodule *HttpCase) Start() error {
  return nil
}

func (somodule *HttpCase) Stop() error {
  return nil
}

func (somodule *HttpCase) IsRunning() bool {
  return false
}
