// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package staticrbac

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_SCAN_INTERVAL_MS = 60000

type StaticRbac struct {
  config module.ModuleConfig
  server *server.Server
  impl   *StaticRbacAuthorizer
}

func NewStaticRbac(srv *server.Server) *StaticRbac {
  return &StaticRbac{
    server: srv,
    impl:   NewStaticRbacAuthorizer(),
  }
}

func (auth *StaticRbac) PrerequisiteModules() []string {
  return nil
}

func (auth *StaticRbac) Init(cfg module.ModuleConfig) error {
  auth.config = cfg

  paths, err := module.GetStringArray(cfg, "roleFiles")
  if err == nil {
    scanIntervalMs := module.GetIntDefault(cfg, "scanIntervalMs", DEFAULT_SCAN_INTERVAL_MS)
    err = auth.impl.Init(paths, scanIntervalMs)
    if err == nil {
      auth.server.Rolestore = auth.impl
      auth.server.Authorizer = auth.impl
    }
  }
  return err
}

func (auth *StaticRbac) Start() error {
  auth.impl.StartScanningFiles()
  return nil
}

func (auth *StaticRbac) Stop() error {
  auth.impl.StopScanningFiles()
  return nil
}

func (auth *StaticRbac) IsRunning() bool {
  return auth.impl.running
}
