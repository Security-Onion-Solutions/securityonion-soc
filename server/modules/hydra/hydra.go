// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package hydra

import (
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type Hydra struct {
	config module.ModuleConfig
	server *server.Server
	impl   *HydraClientstore
}

func NewHydra(srv *server.Server) *Hydra {
	return &Hydra{
		server: srv,
		impl:   NewHydraClientstore(srv),
	}
}

func (hydra *Hydra) PrerequisiteModules() []string {
	return nil
}

func (hydra *Hydra) Init(cfg module.ModuleConfig) error {
	hydra.config = cfg
	url, err := module.GetString(cfg, "hostUrl")
	if err == nil {
		err = hydra.impl.Init(url)
		if err == nil {
			hydra.server.Clientstore = hydra.impl
			err = hydra.server.Host.AddPreprocessor(NewHydraPreprocessor(hydra.impl))
		}
	}
	return err
}

func (hydra *Hydra) Start() error {
	return nil
}

func (hydra *Hydra) Stop() error {
	return nil
}

func (hydra *Hydra) IsRunning() bool {
	return false
}
