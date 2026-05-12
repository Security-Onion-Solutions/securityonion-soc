// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
)

// dbSettingsLoader abstracts DB access for settings loading so it can be mocked in tests.
type dbSettingsLoader interface {
	GetAllSettings(ctx context.Context) ([]database.SettingRow, error)
}

// loadDBSettings fetches all settings from the DB and returns them as model.Setting slice.
func loadDBSettings(ctx context.Context, loader dbSettingsLoader) ([]*model.Setting, error) {
	rows, err := loader.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}
	settings := make([]*model.Setting, 0, len(rows))
	for _, row := range rows {
		settings = append(settings, dbRowToSetting(row))
	}
	return settings, nil
}

// mergeDBIntoYaml overlays DB settings on top of yaml settings.
// DB settings take precedence: if the same (id, nodeId) exists in both,
// the DB version replaces the yaml version. Settings only in DB or only in yaml
// are included as-is, with appropriate origins set.
//
// The yaml settings passed in should already have Origin = SettingOriginYaml set
// before calling this function.
func mergeDBIntoYaml(dbSettings, yamlSettings []*model.Setting) []*model.Setting {
	// Index yaml settings by (id, nodeId) for O(1) lookup.
	type key struct{ id, nodeId string }
	yamlIdx := make(map[key]int, len(yamlSettings))
	for i, s := range yamlSettings {
		yamlIdx[key{s.Id, s.NodeId}] = i
	}

	result := make([]*model.Setting, len(yamlSettings))
	copy(result, yamlSettings)

	for _, dbS := range dbSettings {
		k := key{dbS.Id, dbS.NodeId}
		if idx, found := yamlIdx[k]; found {
			// DB overrides yaml: update the existing entry to preserve metadata/annotations.
			result[idx].Value = dbS.Value
			result[idx].Origin = dbS.Origin
			result[idx].DuplicatedFromID = dbS.DuplicatedFromID
		} else {
			result = append(result, dbS)
		}
	}
	return result
}
