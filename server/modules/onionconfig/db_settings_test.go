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
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
	"github.com/stretchr/testify/assert"
)

// fakeLoader implements dbSettingsLoader for tests.
type fakeLoader struct {
	rows  []database.SettingRow
	err   error
}

func (f *fakeLoader) GetAllSettings(_ context.Context) ([]database.SettingRow, error) {
	return f.rows, f.err
}

func testTime(year, month, day, hour, min int) time.Time {
	return time.Date(year, time.Month(month), day, hour, min, 0, 0, time.UTC)
}

func TestLoadDBSettings_Empty(t *testing.T) {
	loader := &fakeLoader{}
	settings, err := loadDBSettings(context.Background(), loader)
	assert.NoError(t, err)
	assert.Empty(t, settings)
}

func TestLoadDBSettings_Single(t *testing.T) {
	loader := &fakeLoader{rows: []database.SettingRow{
		{SettingID: "soc.key", Value: sp(`"val"`), NodeID: ""},
	}}
	settings, err := loadDBSettings(context.Background(), loader)
	assert.NoError(t, err)
	assert.Len(t, settings, 1)
	assert.Equal(t, "soc.key", settings[0].Id)
	assert.Equal(t, "val", settings[0].Value)
	assert.Equal(t, model.SettingOriginDB, settings[0].Origin)
}

func TestMergeDBIntoYaml_DBOverridesYaml(t *testing.T) {
	yaml := []*model.Setting{
		{Id: "a.b", NodeId: "", Value: "yaml-val", Origin: model.SettingOriginYaml},
	}
	db := []*model.Setting{
		{Id: "a.b", NodeId: "", Value: "db-val", Origin: model.SettingOriginDB},
	}
	result := mergeDBIntoYaml(db, yaml)
	assert.Len(t, result, 1)
	assert.Equal(t, "db-val", result[0].Value)
	assert.Equal(t, model.SettingOriginDB, result[0].Origin)
}

func TestMergeDBIntoYaml_DBAddsNew(t *testing.T) {
	yaml := []*model.Setting{
		{Id: "a.b", NodeId: "", Value: "yaml-val", Origin: model.SettingOriginYaml},
	}
	db := []*model.Setting{
		{Id: "c.d", NodeId: "", Value: "db-only", Origin: model.SettingOriginDB},
	}
	result := mergeDBIntoYaml(db, yaml)
	assert.Len(t, result, 2)
}

func TestMergeDBIntoYaml_NodeSpecificDistinct(t *testing.T) {
	yaml := []*model.Setting{
		{Id: "a.b", NodeId: "", Value: "global-yaml", Origin: model.SettingOriginYaml},
	}
	db := []*model.Setting{
		{Id: "a.b", NodeId: "node1", Value: "node-db", Origin: model.SettingOriginDB},
	}
	result := mergeDBIntoYaml(db, yaml)
	// Both should be present: one global yaml, one node-specific DB.
	assert.Len(t, result, 2)
}
