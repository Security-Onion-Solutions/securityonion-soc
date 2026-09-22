// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"encoding/json"
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

	assert.Equal(t, []string{"onionconfig", "postgres"}, mod.PrerequisiteModules())
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
	assert.Equal(t, "soc", dests[model.DefaultDestinationSOCBell].Type)

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

	dests := map[string]model.DestinationConfig{
		"custom-soc": {
			ID:      "custom-soc",
			Name:    "Custom Bell",
			Type:    "soc",
			Enabled: true,
		},
	}
	destsJSON, _ := json.Marshal(dests)

	srv := &server.Server{
		Configstore: server.NewMemConfigStore([]*model.Setting{
			{
				Id:    ConfigSettingNotificationDestinations,
				Value: string(destsJSON),
			},
		}),
	}
	mod := NewNotificationModule(srv)

	err := mod.Init(module.ModuleConfig{})
	assert.NoError(t, err)
	assert.NotNil(t, srv.Notifier)

	err = mod.Start()
	assert.NoError(t, err)

	notifierDests := srv.Notifier.GetDestinations()
	assert.Contains(t, notifierDests, "custom-soc")
	assert.Equal(t, "Custom Bell", notifierDests["custom-soc"].Name)
}

func TestNotificationModuleOnConfigSettingUpdated(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := &server.Server{}
	mod := NewNotificationModule(srv)

	err := mod.Init(module.ModuleConfig{})
	assert.NoError(t, err)

	// Update destinations via callback
	destJSON := `{"updated-bell": {"name": "Updated Bell", "type": "soc", "enabled": true, "severities": ["critical"]}}`
	mod.OnConfigSettingUpdated(context.Background(), &model.Setting{
		Id:    ConfigSettingNotificationDestinations,
		Value: destJSON,
	}, false)

	dests := srv.Notifier.GetDestinations()
	assert.Len(t, dests, 1)
	assert.Contains(t, dests, "updated-bell")
	assert.Equal(t, "Updated Bell", dests["updated-bell"].Name)
	assert.Equal(t, []string{"critical"}, dests["updated-bell"].Severities)

	// Update enabled via callback
	mod.OnConfigSettingUpdated(context.Background(), &model.Setting{
		Id:    ConfigSettingNotificationEnabled,
		Value: "false",
	}, false)
	assert.False(t, mod.notifier.config.Enabled)

	// Setting removed -> reverts to defaults
	mod.OnConfigSettingUpdated(context.Background(), &model.Setting{
		Id: ConfigSettingNotificationDestinations,
	}, true)
	dests = srv.Notifier.GetDestinations()
	assert.Contains(t, dests, model.DefaultDestinationSOCBell)

	// Update dismissedPruneDays via callback
	mod.OnConfigSettingUpdated(context.Background(), &model.Setting{
		Id:    ConfigSettingNotificationDismissedPruneDays,
		Value: "60",
	}, false)
	assert.Equal(t, 60, mod.notifier.config.DismissedPruneDays)

	// DismissedPruneDays removed -> reverts to default 30
	mod.OnConfigSettingUpdated(context.Background(), &model.Setting{
		Id: ConfigSettingNotificationDismissedPruneDays,
	}, true)
	assert.Equal(t, DEFAULT_DISMISSED_PRUNE_DAYS, mod.notifier.config.DismissedPruneDays)
}

func TestNotificationModule_PruneDismissed_NilStore(t *testing.T) {
	srv := &server.Server{}
	mod := NewNotificationModule(srv)
	err := mod.PruneDismissed(context.Background())
	assert.NoError(t, err)
}
