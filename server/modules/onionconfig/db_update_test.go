// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
	"github.com/stretchr/testify/assert"
)

type fakeMutator struct {
	updated []struct {
		row    database.SettingRow
		audit  database.AuditEntry
		remove bool
	}
	audited []database.AuditEntry
	err     error
}

func (f *fakeMutator) UpdateSettingWithAudit(_ context.Context, row database.SettingRow, audit database.AuditEntry, remove bool) error {
	if f.err != nil {
		return f.err
	}
	f.updated = append(f.updated, struct {
		row    database.SettingRow
		audit  database.AuditEntry
		remove bool
	}{row, audit, remove})
	return nil
}

func (f *fakeMutator) RecordAudit(_ context.Context, audit database.AuditEntry) error {
	if f.err != nil {
		return f.err
	}
	f.audited = append(f.audited, audit)
	return nil
}

func TestUpdateSettingInDB_Upsert(t *testing.T) {
	mutator := &fakeMutator{}
	s := model.NewSetting("soc.key")
	s.Value = "newval"
	s.NodeId = ""

	err := updateSettingInDB(context.Background(), mutator, s, "oldval", false, "user1")
	assert.NoError(t, err)
	assert.Len(t, mutator.updated, 1)
	assert.Equal(t, "soc.key", mutator.updated[0].row.SettingID)
	assert.Equal(t, false, mutator.updated[0].remove)
	assert.Equal(t, "user1", mutator.updated[0].audit.UserID)
}

func TestUpdateSettingInDB_Delete(t *testing.T) {
	mutator := &fakeMutator{}
	s := model.NewSetting("soc.key")
	s.NodeId = "node1"

	err := updateSettingInDB(context.Background(), mutator, s, "old", true, "user2")
	assert.NoError(t, err)
	assert.Len(t, mutator.updated, 1)
	assert.Equal(t, true, mutator.updated[0].remove)
	assert.Equal(t, "node1", mutator.updated[0].row.NodeID)
	assert.Equal(t, "", mutator.updated[0].audit.NewValue)
}

func TestUpdateSettingInDB_Error(t *testing.T) {
	mutator := &fakeMutator{err: errors.New("db error")}
	s := model.NewSetting("soc.key")

	err := updateSettingInDB(context.Background(), mutator, s, "", false, "user")
	assert.EqualError(t, err, "db error")
}

func TestEncodeOldValue_Empty(t *testing.T) {
	assert.Equal(t, "null", encodeOldValue(""))
}

func TestEncodeOldValue_String(t *testing.T) {
	assert.Equal(t, `"foo"`, encodeOldValue("foo"))
}

func TestAuditSettingOnly(t *testing.T) {
	mutator := &fakeMutator{}
	s := model.NewSetting("yaml.key")
	s.Value = "yamlval"

	err := auditSettingOnly(context.Background(), mutator, s, "oldyaml", false, "user3")
	assert.NoError(t, err)
	assert.Len(t, mutator.audited, 1)
	assert.Equal(t, "yaml.key", mutator.audited[0].SettingID)
	assert.Equal(t, "user3", mutator.audited[0].UserID)
}
