// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package thehive

import (
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type TheHive struct {
  config module.ModuleConfig
  server *server.Server
  store  *TheHiveCasestore
}

func NewTheHive(srv *server.Server) *TheHive {
  return &TheHive{
    server: srv,
    store:  NewTheHiveCasestore(srv),
  }
}

func (thehive *TheHive) PrerequisiteModules() []string {
  return nil
}

func (thehive *TheHive) Init(cfg module.ModuleConfig) error {
  thehive.config = cfg
  host, _ := module.GetString(cfg, "hostUrl")
  verifyCert := module.GetBoolDefault(cfg, "verifyCert", true)
  key, _ := module.GetString(cfg, "key")
  err := thehive.store.Init(host, key, verifyCert)
  if err == nil && thehive.server != nil {
    if thehive.server.Casestore != nil {
      err = errors.New("Multiple case modules cannot be enabled concurrently")
    }
    thehive.server.Casestore = thehive.store
  }
  return err
}

func (thehive *TheHive) Start() error {
  return nil
}

func (thehive *TheHive) Stop() error {
  return nil
}

func (somodule *TheHive) IsRunning() bool {
  return false
}
