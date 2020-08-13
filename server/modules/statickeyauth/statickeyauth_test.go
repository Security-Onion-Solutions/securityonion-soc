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
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
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
	err := auth.Init(cfg)
	if failure {
		if err == nil {
			tester.Errorf("expected Init error")
		}
	} else if err != nil {
		tester.Errorf("Unexpacted error: %v", err)
	} else {
		if auth.impl.anonymousNetwork.String() != expectedCidr {
			tester.Errorf("expected anonymousNetwork %s but got %s", expectedCidr, auth.impl.anonymousNetwork.String())
		}
		if auth.server.Host.Auth == nil {
			tester.Errorf("expected non-nil Host.Auth")
		}
	}
}
