// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
