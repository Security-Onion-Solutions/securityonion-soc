// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
