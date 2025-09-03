// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
	"reflect"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
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
		assert.Equal(tester, DEFAULT_CUSTOM_REPORTS_PATH, cfg.CustomReportsPath)
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

func TestServerConfig_verifySubgrids(t *testing.T) {
	type fields struct {
		Subgrids []*model.Subgrid
	}
	tests := []struct {
		name   string
		fields fields
		want   []*model.Subgrid
	}{
		{
			name: "Empty subgrids",
			fields: fields{
				Subgrids: []*model.Subgrid{},
			},
			want: []*model.Subgrid{},
		},
		{
			name: "Single valid subgrid",
			fields: fields{
				Subgrids: []*model.Subgrid{
					{
						Id:           "grid1",
						ManagerUrl:   "https://example.com",
						ClientId:     "socl_client1",
						ClientSecret: "secret",
						Enabled:      true,
					},
				},
			},
			want: []*model.Subgrid{
				{
					Id:           "grid1",
					ManagerUrl:   "https://example.com",
					ClientId:     "socl_client1",
					ClientSecret: "secret",
					Enabled:      true,
				},
			},
		},
		{
			name: "Single disabled subgrid",
			fields: fields{
				Subgrids: []*model.Subgrid{
					{
						Id:           "grid1",
						ManagerUrl:   "https://example.com",
						ClientId:     "socl_client1",
						ClientSecret: "secret",
						Enabled:      false,
					},
				},
			},
			want: []*model.Subgrid{},
		},
		{
			name: "Duplicate subgrid IDs",
			fields: fields{
				Subgrids: []*model.Subgrid{
					{
						Id:           "grid1",
						ManagerUrl:   "https://example.com",
						ClientId:     "socl_client1",
						ClientSecret: "secret",
						Enabled:      true,
					},
					{
						Id:           "grid1",
						ManagerUrl:   "https://example.com",
						ClientId:     "socl_client1b",
						ClientSecret: "secret",
						Enabled:      true,
					},
				},
			},
			want: []*model.Subgrid{
				{
					Id:           "grid1",
					ManagerUrl:   "https://example.com",
					ClientId:     "socl_client1",
					ClientSecret: "secret",
					Enabled:      true,
				},
			},
		},
		{
			name: "Mixed valid, disabled, and duplicate subgrids",
			fields: fields{
				Subgrids: []*model.Subgrid{
					{
						Id:           "grid1",
						ManagerUrl:   "https://example.com",
						ClientId:     "socl_client1",
						ClientSecret: "secret",
						Enabled:      true,
					},
					{
						Id:           "grid2",
						ManagerUrl:   "https://example.com",
						ClientId:     "socl_client2",
						ClientSecret: "secret",
						Enabled:      false,
					},
					{
						Id:           "grid1",
						ManagerUrl:   "https://example.com",
						ClientId:     "socl_client1b",
						ClientSecret: "secret",
						Enabled:      true,
					},
					{
						Id:           "grid3",
						ManagerUrl:   "https://example.com",
						ClientId:     "socl_client3",
						ClientSecret: "secret",
						Enabled:      true,
					},
				},
			},
			want: []*model.Subgrid{
				{
					Id:           "grid1",
					ManagerUrl:   "https://example.com",
					ClientId:     "socl_client1",
					ClientSecret: "secret",
					Enabled:      true,
				},
				{
					Id:           "grid3",
					ManagerUrl:   "https://example.com",
					ClientId:     "socl_client3",
					ClientSecret: "secret",
					Enabled:      true,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ServerConfig{
				Subgrids: tt.fields.Subgrids,
			}
			config.verifySubgrids()
			if !reflect.DeepEqual(config.Subgrids, tt.want) {
				t.Errorf("ServerConfig.verifySubgrids() = %v, want %v", config.Subgrids, tt.want)
			}
		})
	}
}
