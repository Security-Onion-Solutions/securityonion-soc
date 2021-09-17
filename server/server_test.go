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
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/stretchr/testify/assert"
)

func TestNewServer(tester *testing.T) {
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")
	assert.NotNil(tester, srv.Host)
	assert.NotNil(tester, srv.stoppedChan)
}
