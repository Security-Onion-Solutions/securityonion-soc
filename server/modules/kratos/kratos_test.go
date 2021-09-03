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
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestInit(tester *testing.T) {
	scfg := &config.ServerConfig{}
	srv := server.NewServer(scfg, "")
	kratos := NewKratos(srv)
	cfg := make(module.ModuleConfig)
	err := kratos.Init(cfg)
	assert.Error(tester, err)

	cfg["hostUrl"] = "abc"
	err = kratos.Init(cfg)
	if assert.Nil(tester, err) {
		assert.NotNil(tester, kratos.server.Userstore)
	}
}
