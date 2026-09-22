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
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestNotifierImpl_ListDestinations(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	dests := map[string]model.DestinationConfig{
		"dest-b": {
			ID:      "dest-b",
			Name:    "B Channel",
			Type:    "soc",
			Enabled: true,
		},
		"dest-a": {
			ID:      "dest-a",
			Name:    "A Channel",
			Type:    "soc",
			Enabled: true,
		},
	}
	destsJSON, _ := json.Marshal(dests)

	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingNotificationDestinations,
			Value: string(destsJSON),
		},
	})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	registry := NewChannelRegistry()
	_ = registry.Register(&mockChannel{channelType: "soc", supportsRecipients: true, supportsAttachments: true, supportsLinks: true})

	notifier := NewNotifier(srv, registry, model.NotificationConfig{})

	ctx := context.Background()
	result, err := notifier.ListDestinations(ctx)
	assert.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "dest-a", result[0].ID)
	assert.Equal(t, "A Channel", result[0].Name)
	assert.True(t, result[0].RecipientsSupported)
	assert.True(t, result[0].AttachmentsSupported)
	assert.True(t, result[0].LinksSupported)
	assert.Equal(t, "dest-b", result[1].ID)
	assert.Equal(t, "B Channel", result[1].Name)
}

func TestNotifierImpl_ListDestinations_DefaultFallback(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	cfgStore := server.NewMemConfigStore([]*model.Setting{})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	registry := NewChannelRegistry()
	notifier := NewNotifier(srv, registry, model.NotificationConfig{})

	ctx := context.Background()
	result, err := notifier.ListDestinations(ctx)
	assert.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, model.DefaultDestinationSOCBell, result[0].ID)
}

func TestNotifierImpl_GetDestination(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	dests := map[string]model.DestinationConfig{
		"my-dest": {
			ID:      "my-dest",
			Name:    "My Dest",
			Type:    "soc",
			Enabled: true,
		},
	}
	destsJSON, _ := json.Marshal(dests)

	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingNotificationDestinations,
			Value: string(destsJSON),
		},
	})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	registry := NewChannelRegistry()
	notifier := NewNotifier(srv, registry, model.NotificationConfig{})

	ctx := context.Background()

	// Invalid ID
	_, err := notifier.GetDestination(ctx, "invalid id!")
	assert.ErrorIs(t, err, server.ErrInvalidDestinationID)

	// Not Found
	_, err = notifier.GetDestination(ctx, "not-found")
	assert.ErrorIs(t, err, server.ErrDestinationNotFound)

	// Success
	dest, err := notifier.GetDestination(ctx, "my-dest")
	assert.NoError(t, err)
	assert.NotNil(t, dest)
	assert.Equal(t, "my-dest", dest.ID)
	assert.Equal(t, "My Dest", dest.Name)
}

func TestNotifierImpl_CreateDestination(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	cfgStore := server.NewMemConfigStore([]*model.Setting{})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	registry := NewChannelRegistry()
	notifier := NewNotifier(srv, registry, model.NotificationConfig{})

	ctx := context.Background()

	// Nil destination
	_, err := notifier.CreateDestination(ctx, nil)
	assert.Error(t, err)

	// Invalid name
	_, err = notifier.CreateDestination(ctx, &model.DestinationConfig{
		Name: string(make([]byte, 300)),
	})
	assert.Error(t, err)

	// Invalid ID
	_, err = notifier.CreateDestination(ctx, &model.DestinationConfig{
		ID:   "invalid dest id!",
		Name: "Valid Name",
	})
	assert.ErrorIs(t, err, server.ErrInvalidDestinationID)

	// Success creation with auto UUID
	created, err := notifier.CreateDestination(ctx, &model.DestinationConfig{
		Name: "Auto UUID Dest",
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, "soc", created.Type)

	// Duplicate ID
	_, err = notifier.CreateDestination(ctx, &model.DestinationConfig{
		ID:   created.ID,
		Name: "Duplicate",
	})
	assert.ErrorIs(t, err, server.ErrDuplicateDestinationID)

	// Verify saved to configstore
	setting, err := cfgStore.GetSetting(ctx, ConfigSettingNotificationDestinations)
	assert.NoError(t, err)
	assert.Contains(t, setting.Value, created.ID)
}

func TestNotifierImpl_UpdateDestination(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	dests := map[string]model.DestinationConfig{
		"dest-1": {
			ID:   "dest-1",
			Name: "Initial Name",
			Type: "soc",
		},
	}
	destsJSON, _ := json.Marshal(dests)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingNotificationDestinations,
			Value: string(destsJSON),
		},
	})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	registry := NewChannelRegistry()
	notifier := NewNotifier(srv, registry, model.NotificationConfig{})

	ctx := context.Background()

	// Invalid ID
	_, err := notifier.UpdateDestination(ctx, "invalid!id", &model.DestinationConfig{Name: "Name"})
	assert.ErrorIs(t, err, server.ErrInvalidDestinationID)

	// Not found
	_, err = notifier.UpdateDestination(ctx, "nonexistent", &model.DestinationConfig{Name: "Name"})
	assert.ErrorIs(t, err, server.ErrDestinationNotFound)

	// Success
	updated, err := notifier.UpdateDestination(ctx, "dest-1", &model.DestinationConfig{
		Name:    "Updated Name",
		Enabled: true,
	})
	assert.NoError(t, err)
	assert.Equal(t, "dest-1", updated.ID)
	assert.Equal(t, "Updated Name", updated.Name)

	// Verify saved in configstore
	setting, err := cfgStore.GetSetting(ctx, ConfigSettingNotificationDestinations)
	assert.NoError(t, err)
	assert.Contains(t, setting.Value, "Updated Name")
}

func TestNotifierImpl_DeleteDestination(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	dests := map[string]model.DestinationConfig{
		"dest-1": {
			ID:   "dest-1",
			Name: "Dest 1",
			Type: "soc",
		},
	}
	destsJSON, _ := json.Marshal(dests)
	cfgStore := server.NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingNotificationDestinations,
			Value: string(destsJSON),
		},
	})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	registry := NewChannelRegistry()
	notifier := NewNotifier(srv, registry, model.NotificationConfig{})

	ctx := context.Background()

	// Delete default destination blocked
	err := notifier.DeleteDestination(ctx, model.DefaultDestinationSOCBell)
	assert.ErrorIs(t, err, server.ErrCannotDeleteDefaultDestination)

	// Invalid ID
	err = notifier.DeleteDestination(ctx, "invalid id!")
	assert.ErrorIs(t, err, server.ErrInvalidDestinationID)

	// Not found
	err = notifier.DeleteDestination(ctx, "nonexistent")
	assert.ErrorIs(t, err, server.ErrDestinationNotFound)

	// Success
	err = notifier.DeleteDestination(ctx, "dest-1")
	assert.NoError(t, err)

	// Verify removed in configstore
	setting, err := cfgStore.GetSetting(ctx, ConfigSettingNotificationDestinations)
	assert.NoError(t, err)
	assert.NotContains(t, setting.Value, "dest-1")
}

func TestNotifierImpl_Unauthorized(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	cfgStore := server.NewMemConfigStore([]*model.Setting{})
	srv := &server.Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: false},
	}
	registry := NewChannelRegistry()
	notifier := NewNotifier(srv, registry, model.NotificationConfig{})

	ctx := context.Background()

	_, err := notifier.ListDestinations(ctx)
	assert.Error(t, err)

	_, err = notifier.GetDestination(ctx, "dest-1")
	assert.Error(t, err)

	_, err = notifier.CreateDestination(ctx, &model.DestinationConfig{Name: "New"})
	assert.Error(t, err)

	_, err = notifier.UpdateDestination(ctx, "dest-1", &model.DestinationConfig{Name: "Update"})
	assert.Error(t, err)

	err = notifier.DeleteDestination(ctx, "dest-1")
	assert.Error(t, err)
}

func TestNotifierImpl_UnmarshalDestinations_Formats(t *testing.T) {
	// Array format
	arrayJSON := `[{"id":"arr-1","name":"Arr 1","type":"soc"}]`
	res, err := unmarshalDestinations(arrayJSON)
	assert.NoError(t, err)
	assert.Contains(t, res, "arr-1")

	// NDJSON format
	ndjson := "{\"id\":\"nd-1\",\"name\":\"ND 1\",\"type\":\"soc\"}\n{\"id\":\"nd-2\",\"name\":\"ND 2\",\"type\":\"soc\"}\n"
	res, err = unmarshalDestinations(ndjson)
	assert.NoError(t, err)
	assert.Contains(t, res, "nd-1")
	assert.Contains(t, res, "nd-2")

	// Empty
	res, err = unmarshalDestinations("")
	assert.NoError(t, err)
	assert.Empty(t, res)

	// Invalid
	_, err = unmarshalDestinations("invalid not json")
	assert.Error(t, err)
}
