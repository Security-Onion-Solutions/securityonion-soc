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

type AdminConfigstore interface {
	SyncSettings(ctx context.Context) error
	SyncModule(ctx context.Context, module string, force bool) error
}
