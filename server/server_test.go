// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewServer(tester *testing.T) {
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")
	assert.NotNil(tester, srv.Host)
	assert.NotNil(tester, srv.stoppedChan)
}

func TestDeveloperAuthorization(tester *testing.T) {
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")
	cfg.DeveloperEnabled = true

	authErr := srv.CheckAuthorized(nil, "read", "users")
	assert.NoError(tester, authErr)
}

func TestMissingAuthorization(tester *testing.T) {
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")

	authErr := srv.CheckAuthorized(nil, "read", "users")
	assert.Error(tester, authErr)
	assert.Equal(tester, "Missing Authorizer module", authErr.Error())
}

func TestFailedAuthorization(tester *testing.T) {
	srv := NewFakeUnauthorizedServer()

	authErr := srv.CheckAuthorized(nil, "read", "users")
	assert.Error(tester, authErr)
	assert.Contains(tester, authErr.Error(), "not authorized to perform operation 'read' on target 'users'")
}
