// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyAgent(tester *testing.T) {
	cfg := &AgentConfig{}
	err := cfg.Verify()
	assert.Equal(tester, DEFAULT_POLL_INTERVAL_MS, cfg.PollIntervalMs)
	assert.NotEmpty(tester, cfg.NodeId)
	assert.Empty(tester, cfg.Model)
	assert.False(tester, cfg.VerifyCert)
	assert.Error(tester, err)

	cfg.PollIntervalMs = 123
	cfg.ServerUrl = "http://some.where"
	err = cfg.Verify()

	if assert.Nil(tester, err) {
		assert.Equal(tester, 123, cfg.PollIntervalMs)
	}
}
