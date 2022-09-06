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

func TestVerifyServer(tester *testing.T) {
	cfg := &ServerConfig{}
	err := cfg.Verify()
	if assert.Error(tester, err) {
		assert.Equal(tester, DEFAULT_MAX_PACKET_COUNT, cfg.MaxPacketCount)
		assert.Equal(tester, DEFAULT_IDLE_CONNECTION_TIMEOUT_MS, cfg.IdleConnectionTimeoutMs)
		assert.Equal(tester, DEFAULT_MAX_UPLOAD_SIZE_BYTES, cfg.MaxUploadSizeBytes)
		assert.Equal(tester, DEFAULT_SRV_EXP_SECONDS, cfg.SrvExpSeconds)
		assert.False(tester, cfg.DeveloperEnabled)
		assert.Equal(tester, REQUIRED_SRV_KEY_LENGTH, len(cfg.SrvKeyBytes))
	}

	cfg.BindAddress = "http://some.where"
	cfg.MaxPacketCount = 123
	cfg.SrvKey = "xyz"
	err = cfg.Verify()
	if assert.Nil(tester, err) {
		assert.Equal(tester, 123, cfg.MaxPacketCount)
		assert.Equal(tester, "/opt/sensoroni/scripts/timezones.sh", cfg.TimezoneScript)
		assert.False(tester, cfg.DeveloperEnabled)
		assert.Equal(tester, "xyz", cfg.SrvKey)
		assert.Equal(tester, REQUIRED_SRV_KEY_LENGTH, len(cfg.SrvKeyBytes))
	}

	cfg.SrvKey = "0123456789012345678901234567890123456789012345678901234567890123"
	err = cfg.Verify()
	if assert.Nil(tester, err) {
		assert.Equal(tester, []byte(cfg.SrvKey), cfg.SrvKeyBytes)
		assert.Equal(tester, REQUIRED_SRV_KEY_LENGTH, len(cfg.SrvKeyBytes))
	}
}
