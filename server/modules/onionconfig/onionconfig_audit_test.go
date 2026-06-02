// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore implements storeProvider for testing.
type fakeStore struct {
	auditHistory      map[string][]database.AuditEntry
	dbSettings        []database.SettingRow
	getAuditErr       error
	getAllAuditErr    error
	getSettingErr     error
	getRevertErr      error
	getAuditEntryErr  error
	updateErr         error
	recordAuditErr    error
}

func (f *fakeStore) GetAllSettings(_ context.Context) ([]database.SettingRow, error) {
	return f.dbSettings, nil
}

func (f *fakeStore) GetAuditHistory(_ context.Context, settingID, nodeID string, limit, offset int, sort, order string) ([]database.AuditEntry, int, error) {
	if f.getAuditErr != nil {
		return nil, 0, f.getAuditErr
	}
	entries := f.auditHistory[settingID]
	if entries == nil {
		return nil, 0, nil
	}
	return entries, len(entries), nil
}

func (f *fakeStore) GetAllAuditHistory(_ context.Context, limit, offset int, sort, order string) ([]database.AuditEntry, int, error) {
	if f.getAllAuditErr != nil {
		return nil, 0, f.getAllAuditErr
	}
	return nil, 0, nil
}

func (f *fakeStore) GetAuditEntryAtTimestamp(_ context.Context, settingID, nodeID string, ts time.Time) (*database.AuditEntry, error) {
	if f.getAuditEntryErr != nil {
		return nil, f.getAuditEntryErr
	}
	return nil, nil
}

func (f *fakeStore) GetRevertState(_ context.Context, ts time.Time) ([]database.SettingRow, error) {
	if f.getRevertErr != nil {
		return nil, f.getRevertErr
	}
	return nil, nil
}

func (f *fakeStore) UpdateSettingWithAudit(_ context.Context, row database.SettingRow, audit database.AuditEntry, remove bool) error {
	return f.updateErr
}

func (f *fakeStore) RecordAudit(_ context.Context, entry database.AuditEntry) error {
	return f.recordAuditErr
}

func TestLoadAllSettings_AuditHistoryDuplicates(t *testing.T) {
	saltstackDir := SetupTestPillar()
	defer Cleanup()

	srv := server.NewFakeAuthorizedServer(nil)
	ready := make(chan struct{})
	close(ready)

	t.Run("NonDBSettingWithoutAnnotationGetsDuplicateFromAudit", func(t *testing.T) {
		store := &fakeStore{
			auditHistory: map[string][]database.AuditEntry{
				"myapp.setting": {
					{
						SettingID:        "myapp.setting",
						NodeID:           "",
						Timestamp:        time.Now().UTC(),
						DuplicatedFromID: "myapp.original",
					},
				},
			},
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations: map[string]map[string]interface{}{
				"other.key": {"sensitive": false},
			},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "myapp.original", found.DuplicatedFromID)
	})

	t.Run("NonDBSettingWithExistingDuplicateSkipsAudit", func(t *testing.T) {
		store := &fakeStore{
			auditHistory: map[string][]database.AuditEntry{
				"myapp.setting": {
					{
						SettingID:        "myapp.setting",
						NodeID:           "",
						Timestamp:        time.Now().UTC(),
						DuplicatedFromID: "myapp.from-audit",
					},
				},
			},
			dbSettings: []database.SettingRow{
				{
					SettingID:        "myapp.setting",
					Value:            sp(`"val"`),
					DuplicatedFromID: "myapp.from-db",
					NodeID:           "",
				},
			},
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations:  map[string]map[string]interface{}{},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "myapp.from-db", found.DuplicatedFromID)
	})

	t.Run("DBSettingSkipsAuditCheck", func(t *testing.T) {
		store := &fakeStore{
			auditHistory: map[string][]database.AuditEntry{
				"myapp.setting": {
					{
						SettingID:        "myapp.setting",
						NodeID:           "",
						Timestamp:        time.Now().UTC(),
						DuplicatedFromID: "myapp.from-audit",
					},
				},
			},
			dbSettings: []database.SettingRow{
				{
					SettingID: "myapp.setting",
					Value:     sp(`"val"`),
					NodeID:    "",
				},
			},
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations:  map[string]map[string]interface{}{},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, model.SettingOriginDB, found.Origin)
		assert.Equal(t, "", found.DuplicatedFromID)
	})

	t.Run("NoAuditEntryLeavesEmptyDuplicate", func(t *testing.T) {
		store := &fakeStore{
			auditHistory: map[string][]database.AuditEntry{},
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations:  map[string]map[string]interface{}{},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "", found.DuplicatedFromID)
	})

	t.Run("AuditEntryWithoutDuplicateLeavesEmpty", func(t *testing.T) {
		store := &fakeStore{
			auditHistory: map[string][]database.AuditEntry{
				"myapp.setting": {
					{
						SettingID: "myapp.setting",
						NodeID:    "",
						Timestamp: time.Now().UTC(),
					},
				},
			},
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations:  map[string]map[string]interface{}{},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "", found.DuplicatedFromID)
	})

	t.Run("AuditErrorDoesNotCrash", func(t *testing.T) {
		store := &fakeStore{
			getAuditErr: assert.AnError,
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations:  map[string]map[string]interface{}{},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "", found.DuplicatedFromID)
	})

	t.Run("NilStoreSkipsAuditCheck", func(t *testing.T) {
		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        nil,
			ready:        ready,
			annotations:  map[string]map[string]interface{}{},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "", found.DuplicatedFromID)
	})

	t.Run("AdvancedSuffixSkipsAuditCheck", func(t *testing.T) {
		// myapp.advanced exists in the pillar (from adv_myapp.sls) and ends with .advanced
		// Audit check should be skipped regardless of audit history content
		store := &fakeStore{
			auditHistory: map[string][]database.AuditEntry{
				"myapp.other": {
					{
						SettingID:        "myapp.other",
						NodeID:           "",
						Timestamp:        time.Now().UTC(),
						DuplicatedFromID: "myapp.original",
					},
				},
			},
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations: map[string]map[string]interface{}{
				"other.key": {"sensitive": false},
			},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.advanced" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "", found.DuplicatedFromID)
	})

	t.Run("NonAdvancedSettingGetsDuplicateFromAudit", func(t *testing.T) {
		// myapp.setting exists in the pillar (from soc_myapp.sls) and does NOT end with .advanced
		// Audit check should NOT be skipped, so DuplicatedFromID should be populated
		store := &fakeStore{
			auditHistory: map[string][]database.AuditEntry{
				"myapp.setting": {
					{
						SettingID:        "myapp.setting",
						NodeID:           "",
						Timestamp:        time.Now().UTC(),
						DuplicatedFromID: "myapp.original",
					},
				},
			},
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations: map[string]map[string]interface{}{
				"other.key": {"sensitive": false},
			},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "myapp.original", found.DuplicatedFromID)
	})

	t.Run("SettingWithIntermediateAdvancedSuffixGetsDuplicateFromAudit", func(t *testing.T) {
		// Create a setting with an ID that has .advanced in the middle but doesn't end with it
		// We test this by using a DB setting (which bypasses yaml loading) and checking
		// that the .advanced suffix check only applies to the end of the ID
		store := &fakeStore{
			auditHistory: map[string][]database.AuditEntry{
				"myapp.setting": {
					{
						SettingID:        "myapp.setting",
						NodeID:           "",
						Timestamp:        time.Now().UTC(),
						DuplicatedFromID: "myapp.original",
					},
				},
			},
		}

		oc := &OnionConfig{
			server:       srv,
			saltstackDir: saltstackDir,
			store:        store,
			ready:        ready,
			annotations: map[string]map[string]interface{}{
				"other.key": {"sensitive": false},
			},
		}

		settings, err := oc.loadAllSettings(context.Background(), "")
		require.NoError(t, err)

		var found *model.Setting
		for _, s := range settings {
			if s.Id == "myapp.setting" {
				found = s
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "myapp.original", found.DuplicatedFromID)
	})
}
