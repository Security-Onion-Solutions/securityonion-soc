// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestNotificationModuleLifecycle_Licensed(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := &server.Server{}
	mod := NewNotificationModule(srv)

	assert.Nil(t, mod.PrerequisiteModules())
	assert.False(t, mod.IsRunning())

	// Init with empty config (should set default soc-bell)
	err := mod.Init(module.ModuleConfig{})
	assert.NoError(t, err)
	assert.NotNil(t, srv.Notifier)

	// Verify soc channel registered
	ch, found := srv.Notifier.GetChannel("soc")
	assert.True(t, found)
	assert.Equal(t, "soc", ch.Type())

	// Verify destinations contain default soc-bell
	dests := srv.Notifier.GetDestinations()
	assert.Contains(t, dests, model.DefaultDestinationSOCBell)
	assert.Equal(t, model.ChannelTypeSOC, dests[model.DefaultDestinationSOCBell].Type)

	// Start
	err = mod.Start()
	assert.NoError(t, err)
	assert.True(t, mod.IsRunning())

	// Send a test notification
	payload := &model.NotificationPayload{
		Title:    "Test Notification",
		Summary:  "Lifecycle test summary",
		Severity: model.NotificationSeverityInfo,
	}
	err = srv.Notifier.Send(context.Background(), payload)
	assert.NoError(t, err)

	// Stop
	err = mod.Stop()
	assert.NoError(t, err)
	assert.False(t, mod.IsRunning())
}

func TestNotificationModuleLifecycle_Unlicensed(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_API, 0, 0, "", "")

	srv := &server.Server{}
	mod := NewNotificationModule(srv)

	// Init without NTF license should skip initialization
	err := mod.Init(module.ModuleConfig{})
	assert.NoError(t, err)
	assert.Nil(t, srv.Notifier)

	// Start without NTF license should skip start
	err = mod.Start()
	assert.NoError(t, err)
	assert.False(t, mod.IsRunning())
}

func TestNotificationModuleInitWithCustomDestinations_Licensed(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := &server.Server{}
	mod := NewNotificationModule(srv)

	cfg := module.ModuleConfig{
		"defaultDestinations": []interface{}{"custom-soc"},
		"destinations": map[string]interface{}{
			"custom-soc": map[string]interface{}{
				"name":    "Custom Bell",
				"type":    "soc",
				"enabled": true,
				"params": map[string]interface{}{
					"storeInPostgres": false,
				},
			},
		},
	}

	err := mod.Init(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, srv.Notifier)

	dests := srv.Notifier.GetDestinations()
	assert.Contains(t, dests, "custom-soc")
	assert.Equal(t, "Custom Bell", dests["custom-soc"].Name)
	assert.Equal(t, []string{"custom-soc"}, srv.Notifier.GetDefaultDestinations())
}
