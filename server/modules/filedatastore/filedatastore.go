// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package filedatastore

import (
  "github.com/sensoroni/sensoroni/module"
  "github.com/sensoroni/sensoroni/server"
)

type FileDatastore struct {
  config			module.ModuleConfig
  server			*server.Server
  impl				*FileDatastoreImpl
}

func NewFileDatastore(srv *server.Server) *FileDatastore {
  return &FileDatastore {
    server: srv,
    impl: NewFileDatastoreImpl(),
  }
}

func (fdmodule *FileDatastore) PrerequisiteModules() []string {
  return nil
}

func (fdmodule *FileDatastore) Init(cfg module.ModuleConfig) error {
  fdmodule.config = cfg
  err := fdmodule.impl.Init(cfg)
  if err == nil {
    fdmodule.server.Datastore = fdmodule.impl
  }
  return err
}

func (fdmodule *FileDatastore) Start() error {
  return nil
}

func (fdmodule *FileDatastore) Stop() error {
  return nil
}

func (fdmodule *FileDatastore) IsRunning() bool {
  return false
}
