// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"encoding/json"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg := module.ModuleConfig{}
	parsed, err := ParseConfig(cfg)
	assert.NoError(t, err)
	assert.True(t, parsed.Enabled)
	assert.Equal(t, 0, parsed.GlobalSilenceWindowSeconds)
	assert.Equal(t, DEFAULT_DISMISSED_PRUNE_DAYS, parsed.DismissedPruneDays)

	// Check default soc-bell destination
	dest, exists := parsed.Destinations[model.DefaultDestinationSOCBell]
	assert.True(t, exists)
	assert.Equal(t, "", dest.Name)
	assert.Equal(t, "soc", dest.Type)
	assert.True(t, dest.Enabled)
}

func TestParseConfigCustom(t *testing.T) {
	cfg := module.ModuleConfig{
		"enabled":                    false,
		"globalSilenceWindowSeconds": float64(600),
		"dismissedPruneDays":         float64(45),
		"destinations": map[string]interface{}{
			"email-alerts": map[string]interface{}{
				"name":       "SOC Email",
				"type":       "smtp",
				"enabled":    true,
				"scheduleIds": []interface{}{"work-hours"},
				"severities": []interface{}{"high", "critical"},
				"params": map[string]interface{}{
					"host": "mail.example.com",
					"port": float64(587),
				},
			},
			"slack-alerts": map[string]interface{}{
				"name":    "Slack Alerts",
				"type":    "slack",
				"enabled": false,
				"params": map[string]interface{}{
					"webhookUrl": "https://hooks.slack.com/services/xxx",
				},
			},
		},
	}

	parsed, err := ParseConfig(cfg)
	assert.NoError(t, err)
	assert.False(t, parsed.Enabled)
	assert.Equal(t, 600, parsed.GlobalSilenceWindowSeconds)
	assert.Equal(t, 45, parsed.DismissedPruneDays)
	assert.Len(t, parsed.Destinations, 2)

	emailDest, ok := parsed.Destinations["email-alerts"]
	assert.True(t, ok)
	assert.Equal(t, "email-alerts", emailDest.ID)
	assert.Equal(t, "SOC Email", emailDest.Name)
	assert.Equal(t, "smtp", emailDest.Type)
	assert.True(t, emailDest.Enabled)
	assert.Equal(t, []string{"work-hours"}, emailDest.ScheduleIDs)
	assert.Equal(t, []string{"high", "critical"}, emailDest.Severities)
	assert.Equal(t, "mail.example.com", emailDest.Params["host"])

	slackDest, ok := parsed.Destinations["slack-alerts"]
	assert.True(t, ok)
	assert.Equal(t, "Slack Alerts", slackDest.Name)
	assert.Equal(t, "slack", slackDest.Type)
	assert.False(t, slackDest.Enabled)
}

func TestLoadConfigFromStore(t *testing.T) {
	// Nil store -> false
	dests, ok := LoadConfigFromStore(nil, nil)
	assert.False(t, ok)
	assert.Nil(t, dests)

	// Store with custom settings
	customDests := map[string]model.DestinationConfig{
		"my-bell": {
			ID:      "my-bell",
			Name:    "My Bell",
			Type:    "soc",
			Enabled: true,
		},
	}
	destsJSON, _ := json.Marshal(customDests)

	store := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingNotificationDestinations,
			Value: string(destsJSON),
		},
	})

	dests, ok = LoadConfigFromStore(nil, store)
	assert.True(t, ok)
	assert.Len(t, dests, 1)
	assert.Contains(t, dests, "my-bell")
	assert.Equal(t, "My Bell", dests["my-bell"].Name)
}
