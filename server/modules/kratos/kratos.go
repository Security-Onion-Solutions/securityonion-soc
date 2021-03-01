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
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type Kratos struct {
  config			module.ModuleConfig
  server			*server.Server
  impl				*KratosUserstore
}

func NewKratos(srv *server.Server) *Kratos {
  return &Kratos {
    server: srv,
    impl: NewKratosUserstore(),
  }
}

func (kratos *Kratos) PrerequisiteModules() []string {
  return nil
}

func (kratos *Kratos) Init(cfg module.ModuleConfig) error {
  kratos.config = cfg
  url, err := module.GetString(cfg, "hostUrl")
  if err == nil {
    err := kratos.impl.Init(url)
    if err == nil {
      kratos.server.Userstore = kratos.impl
    }
  }
  return err
}

func (kratos *Kratos) Start() error {
  return nil
}

func (kratos *Kratos) Stop() error {
  return nil
}

func (kratos *Kratos) IsRunning() bool {
  return false
}
