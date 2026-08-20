// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/stretchr/testify/assert"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg := module.ModuleConfig{}
	parsed, err := ParseConfig(cfg)
	assert.NoError(t, err)
	assert.True(t, parsed.Enabled)
	assert.Equal(t, []string{model.DefaultDestinationSOCBell}, parsed.DefaultDestinations)
	assert.Equal(t, DEFAULT_GLOBAL_SILENCE_WINDOW_SECONDS, parsed.GlobalSilenceWindowSeconds)

	// Check default soc-bell destination
	dest, exists := parsed.Destinations[model.DefaultDestinationSOCBell]
	assert.True(t, exists)
	assert.Equal(t, "SOC Notification Bell", dest.Name)
	assert.Equal(t, model.ChannelTypeSOC, dest.Type)
	assert.True(t, dest.Enabled)
	assert.Equal(t, true, dest.Params["storeInPostgres"])
	assert.Equal(t, model.AttachmentModeLink, dest.Params["attachmentMode"])
}

func TestParseConfigCustom(t *testing.T) {
	cfg := module.ModuleConfig{
		"enabled":                    false,
		"defaultDestinations":        []interface{}{"email-alerts", "slack-alerts"},
		"globalSilenceWindowSeconds": float64(600),
		"destinations": map[string]interface{}{
			"email-alerts": map[string]interface{}{
				"name":    "SOC Email",
				"type":    "smtp",
				"enabled": true,
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
	assert.Equal(t, []string{"email-alerts", "slack-alerts"}, parsed.DefaultDestinations)
	assert.Equal(t, 600, parsed.GlobalSilenceWindowSeconds)
	assert.Len(t, parsed.Destinations, 2)

	emailDest, ok := parsed.Destinations["email-alerts"]
	assert.True(t, ok)
	assert.Equal(t, "SOC Email", emailDest.Name)
	assert.Equal(t, "smtp", emailDest.Type)
	assert.True(t, emailDest.Enabled)
	assert.Equal(t, "mail.example.com", emailDest.Params["host"])

	slackDest, ok := parsed.Destinations["slack-alerts"]
	assert.True(t, ok)
	assert.Equal(t, "Slack Alerts", slackDest.Name)
	assert.Equal(t, "slack", slackDest.Type)
	assert.False(t, slackDest.Enabled)
}
