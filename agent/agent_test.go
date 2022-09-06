// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
