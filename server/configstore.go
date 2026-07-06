// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type ConfigHistory struct {
	History []model.AuditHistory `json:"history"`
	Total   int                  `json:"total"`
}

type Configstore interface {
	GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error)
	UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error
	GetAuditHistory(ctx context.Context, settingID, nodeID string, limit, offset int, sort, order string) (*ConfigHistory, error)
	GetAllAuditHistory(ctx context.Context, limit, offset int, sort, order string) (*ConfigHistory, error)
	RevertSetting(ctx context.Context, settingID, nodeID string, timestamp time.Time, note string) error
	RevertAllSettings(ctx context.Context, timestamp time.Time, note string) (int, error)
	GetRevertCount(ctx context.Context, timestamp time.Time) (int, error)
}

// ConfigSettingCallbackHandler is implemented by components that want to be
// notified when a specific configuration setting has been successfully updated.
// The handler is invoked after the change has been persisted. Implementations
// must be safe to call from a goroutine other than the one serving the config
// request, and must not block for long (the notifier recovers from panics but
// invokes handlers inline with the update).
type ConfigSettingCallbackHandler interface {
	// OnConfigSettingUpdated is called after the setting identified by
	// setting.Id has been persisted. removed is true when the setting was
	// deleted/reverted rather than assigned a new value.
	OnConfigSettingUpdated(ctx context.Context, setting *model.Setting, removed bool)
}

// ConfigSettingCallbackRegistrar is implemented by a Configstore that supports
// registering callbacks for setting changes. Callers should type-assert their
// Configstore to this interface, since not every store implementation supports
// notifications.
type ConfigSettingCallbackRegistrar interface {
	// RegisterConfigSettingCallback registers handler to be notified whenever
	// the setting with the given settingID is updated. Multiple handlers may be
	// registered for the same settingID.
	RegisterConfigSettingCallback(settingID string, handler ConfigSettingCallbackHandler)
}

type AdminConfigstore interface {
	SyncSettings(ctx context.Context) error
	SyncModule(ctx context.Context, module string, force bool) error
}
