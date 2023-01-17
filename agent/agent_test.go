// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package agent

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/stretchr/testify/assert"
)

func TestNewAgent(tester *testing.T) {
	cfg := &config.AgentConfig{}
	cfg.ServerUrl = "http://some.where"
	agent := NewAgent(cfg, "")
	assert.NotNil(tester, agent.Client)
	assert.NotNil(tester, agent.JobMgr)
	assert.NotNil(tester, agent.stoppedChan)
}
