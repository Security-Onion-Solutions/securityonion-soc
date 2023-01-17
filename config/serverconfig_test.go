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

func TestVerifyServer(tester *testing.T) {
	cfg := &ServerConfig{}
	err := cfg.Verify()
	if assert.Error(tester, err) {
		assert.Equal(tester, DEFAULT_MAX_PACKET_COUNT, cfg.MaxPacketCount)
		assert.Equal(tester, DEFAULT_IDLE_CONNECTION_TIMEOUT_MS, cfg.IdleConnectionTimeoutMs)
		assert.Equal(tester, DEFAULT_MAX_UPLOAD_SIZE_BYTES, cfg.MaxUploadSizeBytes)
		assert.False(tester, cfg.DeveloperEnabled)
	}

	cfg.BindAddress = "http://some.where"
	cfg.MaxPacketCount = 123
	err = cfg.Verify()
	if assert.Nil(tester, err) {
		assert.Equal(tester, 123, cfg.MaxPacketCount)
		assert.Equal(tester, "/opt/sensoroni/scripts/timezones.sh", cfg.TimezoneScript)
		assert.False(tester, cfg.DeveloperEnabled)
	}
}
