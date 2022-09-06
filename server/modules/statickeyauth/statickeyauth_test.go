// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package statickeyauth

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestAuthInit(tester *testing.T) {
	scfg := &config.ServerConfig{}
	srv := server.NewServer(scfg, "")
	auth := NewStaticKeyAuth(srv)
	cfg := make(module.ModuleConfig)

	authInit(tester, auth, cfg, true, "")

	cfg["apiKey"] = "abc"
	authInit(tester, auth, cfg, true, "")

	expectedCidr := "172.17.0.0/24"
	cfg["anonymousCidr"] = expectedCidr
	authInit(tester, auth, cfg, false, expectedCidr)
}

func authInit(tester *testing.T, auth *StaticKeyAuth, cfg module.ModuleConfig, failure bool, expectedCidr string) {
	assert.Len(tester, auth.server.Host.Preprocessors(), 1)
	err := auth.Init(cfg)
	if failure {
		assert.Error(tester, err, "Expected Init error")
	} else {
		if assert.Nil(tester, err) {
			assert.Equal(tester, expectedCidr, auth.impl.anonymousNetwork.String())
			assert.Len(tester, auth.server.Host.Preprocessors(), 2)
		}
	}
}
