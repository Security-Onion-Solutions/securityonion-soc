// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package filedatastore

import (
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

type FileDatastore struct {
  config module.ModuleConfig
  server *server.Server
  impl   *FileDatastoreImpl
}

func NewFileDatastore(srv *server.Server) *FileDatastore {
  return &FileDatastore{
    server: srv,
    impl:   NewFileDatastoreImpl(srv),
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
