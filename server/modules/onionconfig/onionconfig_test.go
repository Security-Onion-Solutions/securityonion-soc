// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouteUpdate(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	oc := &OnionConfig{
		server:       srv,
		saltstackDir: "/tmp",
	}

	ctx := context.Background()
	logger := log.Log

	t.Run("OriginDB_StoreMissing", func(t *testing.T) {
		setting := &model.Setting{Id: "test.db", Origin: model.SettingOriginDB}
		oc.store = nil
		err := oc.routeUpdate(ctx, setting, "", false, logger)
		assert.EqualError(t, err, "database not configured; cannot update DB setting")
	})
}

func TestPostProcess_OriginMapping(t *testing.T) {
	t.Run("StorageDB_NoOrigin_SetsDB", func(t *testing.T) {
		setting := &model.Setting{Id: "test", Storage: "db", Origin: model.SettingOriginDefault}
		PostProcess([]*model.Setting{setting})
		assert.Equal(t, model.SettingOriginDB, setting.Origin)
	})

	t.Run("StorageDB_EmptyOrigin_SetsDB", func(t *testing.T) {
		setting := &model.Setting{Id: "test", Storage: "db", Origin: ""}
		PostProcess([]*model.Setting{setting})
		assert.Equal(t, model.SettingOriginDB, setting.Origin)
	})

	t.Run("StorageDB_ExistingYamlOrigin_StaysYaml", func(t *testing.T) {
		setting := &model.Setting{Id: "test", Storage: "db", Origin: model.SettingOriginYaml}
		PostProcess([]*model.Setting{setting})
		assert.Equal(t, model.SettingOriginYaml, setting.Origin)
	})

	t.Run("NoStorageDB_NoOrigin_SetsYaml", func(t *testing.T) {
		setting := &model.Setting{Id: "test", Origin: model.SettingOriginDefault}
		PostProcess([]*model.Setting{setting})
		assert.Equal(t, model.SettingOriginYaml, setting.Origin)
	})

	t.Run("NoStorageDB_ExistingYamlOrigin_StaysYaml", func(t *testing.T) {
		setting := &model.Setting{Id: "test", Origin: model.SettingOriginYaml}
		PostProcess([]*model.Setting{setting})
		assert.Equal(t, model.SettingOriginYaml, setting.Origin)
	})

	t.Run("NoStorageDB_ExistingDBOrigin_StaysDB", func(t *testing.T) {
		setting := &model.Setting{Id: "test", Origin: model.SettingOriginDB}
		PostProcess([]*model.Setting{setting})
		assert.Equal(t, model.SettingOriginDB, setting.Origin)
	})
}

func newTestOnionConfig(srv *server.Server) *OnionConfig {
	ready := make(chan struct{})
	close(ready)
	return &OnionConfig{
		server:       srv,
		saltstackDir: "/tmp",
		ready:        ready,
	}
}

func TestDecodeAndMaskAuditValues(t *testing.T) {
	t.Run("BothNil", func(t *testing.T) {
		o, n := decodeAndMaskAuditValues(false, nil, nil)
		assert.Equal(t, "", o)
		assert.Equal(t, "", n)
	})

	t.Run("BothValuesNotSensitive", func(t *testing.T) {
		o, n := decodeAndMaskAuditValues(false, sp(`"old"`), sp(`"new"`))
		assert.Equal(t, "old", o)
		assert.Equal(t, "new", n)
	})

	t.Run("BothValuesSensitive", func(t *testing.T) {
		o, n := decodeAndMaskAuditValues(true, sp(`"secret"`), sp(`"newsecret"`))
		assert.Equal(t, "******", o)
		assert.Equal(t, "******", n)
	})

	t.Run("OldNilNewSensitive", func(t *testing.T) {
		o, n := decodeAndMaskAuditValues(true, nil, sp(`"secret"`))
		assert.Equal(t, "", o)
		assert.Equal(t, "******", n)
	})

	t.Run("OldValueNewNilSensitive", func(t *testing.T) {
		o, n := decodeAndMaskAuditValues(true, sp(`"old"`), nil)
		assert.Equal(t, "******", o)
		assert.Equal(t, "", n)
	})

	t.Run("JSONNumberNotSensitive", func(t *testing.T) {
		o, n := decodeAndMaskAuditValues(false, sp("42"), sp("99"))
		assert.Equal(t, "42", o)
		assert.Equal(t, "99", n)
	})

	t.Run("JSONObjectNotSensitive", func(t *testing.T) {
		o, n := decodeAndMaskAuditValues(false, sp(`{"a":1}`), sp(`{"b":2}`))
		assert.Equal(t, `{"a":1}`, o)
		assert.Equal(t, `{"b":2}`, n)
	})

	t.Run("NullValuesNotSensitive", func(t *testing.T) {
		o, n := decodeAndMaskAuditValues(false, sp("null"), sp("null"))
		assert.Equal(t, "", o)
		assert.Equal(t, "", n)
	})
}

func TestIsSensitive(t *testing.T) {
	oc := &OnionConfig{
		annotations: map[string]map[string]interface{}{
			"secret.key": {"sensitive": true},
			"normal.key": {"sensitive": false},
			"other.key":  {"otherField": true},
		},
	}

	t.Run("SensitiveTrue", func(t *testing.T) {
		assert.True(t, oc.isSensitive("secret.key"))
	})

	t.Run("SensitiveFalse", func(t *testing.T) {
		assert.False(t, oc.isSensitive("normal.key"))
	})

	t.Run("NoSensitiveField", func(t *testing.T) {
		assert.False(t, oc.isSensitive("other.key"))
	})

	t.Run("UnknownID", func(t *testing.T) {
		assert.False(t, oc.isSensitive("unknown.key"))
	})

	t.Run("EmptyAnnotations", func(t *testing.T) {
		oc2 := &OnionConfig{annotations: map[string]map[string]interface{}{}}
		assert.False(t, oc2.isSensitive("any.key"))
	})

	t.Run("NilAnnotations", func(t *testing.T) {
		oc2 := &OnionConfig{annotations: nil}
		assert.False(t, oc2.isSensitive("any.key"))
	})

	t.Run("SensitiveNonBool", func(t *testing.T) {
		oc2 := &OnionConfig{
			annotations: map[string]map[string]interface{}{
				"bad.key": {"sensitive": "yes"},
			},
		}
		assert.False(t, oc2.isSensitive("bad.key"))
	})
}

func TestGetAuditHistory_Unauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	oc := newTestOnionConfig(srv)
	_, err := oc.GetAuditHistory(context.Background(), "test.key", "", 10, 0, "ts", "desc")
	assert.Error(t, err)
}

func TestGetAuditHistory_NoStore(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	oc := newTestOnionConfig(srv)
	_, err := oc.GetAuditHistory(context.Background(), "test.key", "", 10, 0, "ts", "desc")
	assert.EqualError(t, err, "database not configured")
}

func TestGetAllAuditHistory_Unauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	oc := newTestOnionConfig(srv)
	_, err := oc.GetAllAuditHistory(context.Background(), 10, 0, "ts", "desc")
	assert.Error(t, err)
}

func TestGetAllAuditHistory_NoStore(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	oc := newTestOnionConfig(srv)
	_, err := oc.GetAllAuditHistory(context.Background(), 10, 0, "ts", "desc")
	assert.EqualError(t, err, "database not configured")
}

func TestRevertSetting_Unauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	oc := newTestOnionConfig(srv)
	err := oc.RevertSetting(context.Background(), "test.key", "", time.Now(), "note")
	assert.Error(t, err)
}

func TestRevertSetting_NoStore(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	oc := newTestOnionConfig(srv)
	err := oc.RevertSetting(context.Background(), "test.key", "", time.Now(), "note")
	assert.EqualError(t, err, "database not configured")
}

func TestRevertAllSettings_Unauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	oc := newTestOnionConfig(srv)
	_, err := oc.RevertAllSettings(context.Background(), time.Now(), "note")
	assert.Error(t, err)
}

func TestRevertAllSettings_NoStore(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	oc := newTestOnionConfig(srv)
	_, err := oc.RevertAllSettings(context.Background(), time.Now(), "note")
	assert.EqualError(t, err, "database not configured")
}

func TestGetRevertCount_Unauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	oc := newTestOnionConfig(srv)
	_, err := oc.GetRevertCount(context.Background(), time.Now())
	assert.Error(t, err)
}

func TestGetRevertCount_NoStore(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	oc := newTestOnionConfig(srv)
	_, err := oc.GetRevertCount(context.Background(), time.Now())
	assert.EqualError(t, err, "database not configured")
}

func TestResolveExistingSetting(t *testing.T) {
	t.Run("GlobalOnly_GlobalUpdate", func(t *testing.T) {
		settings := []*model.Setting{
			{Id: "myapp.str", NodeId: "", Value: "global_val"},
		}
		settingDef, oldValue := resolveExistingSetting(settings, "myapp.str", "")
		assert.NotNil(t, settingDef)
		assert.Equal(t, "global_val", oldValue)
	})

	t.Run("GlobalAndNode_NodeUpdate_ExistingNode", func(t *testing.T) {
		settings := []*model.Setting{
			{Id: "myapp.str", NodeId: "", Value: "global_val"},
			{Id: "myapp.str", NodeId: "node1", Value: "node_val"},
		}
		settingDef, oldValue := resolveExistingSetting(settings, "myapp.str", "node1")
		assert.NotNil(t, settingDef)
		assert.Equal(t, "node_val", oldValue)
	})

	t.Run("GlobalAndNode_NewNodeUpdate_OldValueEmpty", func(t *testing.T) {
		settings := []*model.Setting{
			{Id: "myapp.str", NodeId: "", Value: "global_val"},
			{Id: "myapp.str", NodeId: "node1", Value: "node_val"},
		}
		settingDef, oldValue := resolveExistingSetting(settings, "myapp.str", "node2")
		assert.NotNil(t, settingDef)
		assert.Equal(t, "", oldValue)
	})

	t.Run("GlobalOnly_NewNodeUpdate_OldValueEmpty", func(t *testing.T) {
		settings := []*model.Setting{
			{Id: "myapp.str", NodeId: "", Value: "global_val"},
		}
		settingDef, oldValue := resolveExistingSetting(settings, "myapp.str", "node1")
		assert.NotNil(t, settingDef)
		assert.Equal(t, "", oldValue)
	})

	t.Run("NoMatchingSettings", func(t *testing.T) {
		settings := []*model.Setting{
			{Id: "other.key", NodeId: "", Value: "other"},
		}
		settingDef, oldValue := resolveExistingSetting(settings, "myapp.str", "")
		assert.Nil(t, settingDef)
		assert.Equal(t, "", oldValue)
	})
}

func TestFilterUnchangedReverts(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir+"/local/pillar", 0755))

	srv := server.NewFakeAuthorizedServer(nil)
	ready := make(chan struct{})
	close(ready)
	oc := &OnionConfig{
		server:       srv,
		saltstackDir: dir,
		ready:        ready,
	}

	t.Run("FiltersWhenBothEmpty", func(t *testing.T) {
		rows := []database.SettingRow{
			{SettingID: "s1", NodeID: "", Value: nil},
		}
		filtered, err := oc.filterUnchangedReverts(context.Background(), rows)
		assert.NoError(t, err)
		assert.Empty(t, filtered)
	})

	t.Run("KeepsChangedValues", func(t *testing.T) {
		val := `"val1"`
		rows := []database.SettingRow{
			{SettingID: "s1", NodeID: "", Value: &val},
		}
		filtered, err := oc.filterUnchangedReverts(context.Background(), rows)
		assert.NoError(t, err)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "s1", filtered[0].SettingID)
	})

	t.Run("MixedRows", func(t *testing.T) {
		val := `"val1"`
		rows := []database.SettingRow{
			{SettingID: "s1", NodeID: "", Value: &val},
			{SettingID: "s2", NodeID: "", Value: nil},
		}
		filtered, err := oc.filterUnchangedReverts(context.Background(), rows)
		assert.NoError(t, err)
		assert.Len(t, filtered, 1)
		assert.Equal(t, "s1", filtered[0].SettingID)
	})

	t.Run("EmptyInput", func(t *testing.T) {
		filtered, err := oc.filterUnchangedReverts(context.Background(), nil)
		assert.NoError(t, err)
		assert.Empty(t, filtered)
	})
}
