// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
)

// dbSettingsMutator abstracts the DB write operations so they can be mocked.
type dbSettingsMutator interface {
	UpdateSettingWithAudit(ctx context.Context, row database.SettingRow, audit database.AuditEntry, remove bool) error
	RecordAudit(ctx context.Context, audit database.AuditEntry) error
}

// updateSettingInDB writes (or removes) a setting in the DB and records an audit entry,
// wrapping both operations in a single transaction.
func updateSettingInDB(ctx context.Context, store dbSettingsMutator, setting *model.Setting, oldValue string, remove bool, userID string) error {
	var newVal *string
	if !remove {
		v := encodeSettingValue(setting)
		newVal = &v
	}

	entry := database.AuditEntry{
		SettingID:        setting.Id,
		NodeID:           setting.NodeId,
		Timestamp:        time.Now().UTC(),
		UserID:           userID,
		OldValue:         encodeOldValue(oldValue),
		NewValue:         newVal,
		Note:             setting.Note,
		DuplicatedFromID: setting.DuplicatedFromID,
	}

	return store.UpdateSettingWithAudit(ctx, settingToDBRow(setting), entry, remove)
}

// auditSettingOnly records an audit entry in the DB for a setting that was modified elsewhere (e.g. YAML).
func auditSettingOnly(ctx context.Context, store dbSettingsMutator, setting *model.Setting, oldValue string, remove bool, userID string) error {
	var newVal *string
	if !remove {
		v := encodeSettingValue(setting)
		newVal = &v
	}

	entry := database.AuditEntry{
		SettingID:        setting.Id,
		NodeID:           setting.NodeId,
		Timestamp:        time.Now().UTC(),
		UserID:           userID,
		OldValue:         encodeOldValue(oldValue),
		NewValue:         newVal,
		Note:             setting.Note,
		DuplicatedFromID: setting.DuplicatedFromID,
	}

	return store.RecordAudit(ctx, entry)
}

func encodeOldValue(v string) *string {
	if v == "" {
		return nil
	}
	encoded := encodeSettingValue(&model.Setting{Value: v})
	return &encoded
}
