// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"
	"testing"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
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
