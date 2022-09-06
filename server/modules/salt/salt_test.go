// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestInit(tester *testing.T) {
	scfg := &config.ServerConfig{}
	srv := server.NewServer(scfg, "")
	salt := NewSalt(srv)
	cfg := make(module.ModuleConfig)
	err := salt.Init(cfg)
	if assert.Nil(tester, err) {
		assert.NotNil(tester, salt.server.Configstore)
	}
}
