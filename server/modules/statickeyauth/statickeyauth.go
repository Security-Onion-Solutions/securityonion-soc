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
  "github.com/sensoroni/sensoroni/module"
  "github.com/sensoroni/sensoroni/server"
)

type StaticKeyAuth struct {
  config			module.ModuleConfig
  server			*server.Server
  impl				*StaticKeyAuthImpl
}

func NewStaticKeyAuth(srv *server.Server) *StaticKeyAuth {
  return &StaticKeyAuth {
    server: srv,
    impl: NewStaticKeyAuthImpl(),
  }
}

func (skmodule *StaticKeyAuth) PrerequisiteModules() []string {
  return nil
}

func (skmodule *StaticKeyAuth) Init(cfg module.ModuleConfig) error {
  skmodule.config = cfg
  key, err := module.GetString(cfg, "apiKey")
  if err == nil {
    anonymousCidr := module.GetStringDefault(cfg, "anonymousCidr", "0.0.0.0/0")
    err := skmodule.impl.Init(key, anonymousCidr)
    if err == nil {
      skmodule.server.Host.Auth = skmodule.impl
    }
  }
  return err
}

func (skmodule *StaticKeyAuth) Start() error {
  return nil
}

func (skmodule *StaticKeyAuth) Stop() error {
  return nil
}

func (skmodule *StaticKeyAuth) IsRunning() bool {
  return false
}
