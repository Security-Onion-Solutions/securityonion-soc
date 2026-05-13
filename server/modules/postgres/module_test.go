// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestPostgresModule_InitNoHost(t *testing.T) {
	srv := &server.Server{}
	mod := NewPostgresModule(srv)
	cfg := module.ModuleConfig{}
	err := mod.Init(cfg)
	assert.NoError(t, err)
	assert.Nil(t, srv.DB)
}

func TestPostgresModule_PrerequisiteModules(t *testing.T) {
	mod := NewPostgresModule(nil)
	assert.Nil(t, mod.PrerequisiteModules())
}

func TestPostgresModule_IsRunning(t *testing.T) {
	mod := NewPostgresModule(nil)
	assert.False(t, mod.IsRunning())
}
