// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2022 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package thehive

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestTheHiveInit(tester *testing.T) {
	thehive := NewTheHive(server.NewFakeUnauthorizedServer())
	cfg := make(module.ModuleConfig)
	err := thehive.Init(cfg)
	assert.Nil(tester, err)

	// Fail if casestore already initialized
	err = thehive.Init(cfg)
	assert.Error(tester, err)
}
