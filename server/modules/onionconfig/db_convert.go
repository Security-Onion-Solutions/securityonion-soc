// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
)

// dbRowToSetting converts a raw DB row into a model.Setting.
// The JSONB value column is decoded back into a flat string representation
// matching what the rest of the system expects.
func dbRowToSetting(row database.SettingRow) *model.Setting {
	s := model.NewSetting(row.SettingID)
	s.NodeId = row.NodeID
	s.Origin = model.SettingOriginDB
	s.DuplicatedFromID = row.DuplicatedFromID
	s.Value = decodeJSONBValue(row.Value)
	return s
}

// settingToDBRow converts a model.Setting into the SettingRow format for DB storage.
func settingToDBRow(setting *model.Setting) database.SettingRow {
	var val *string
	if setting.Value != "" {
		v := encodeSettingValue(setting)
		val = &v
	}
	return database.SettingRow{
		SettingID:        setting.Id,
		Value:            val,
		DuplicatedFromID: setting.DuplicatedFromID,
		NodeID:           setting.NodeId,
	}
}

// decodeJSONBValue turns a JSONB-encoded string back into the flat string
// representation used by the rest of the onionconfig system.
func decodeJSONBValue(jsonVal *string) string {
	if jsonVal == nil {
		return ""
	}
	val := *jsonVal
	if val == "null" {
		return ""
	}
	// If it's a JSON string, unwrap the quotes.
	var s string
	if err := json.Unmarshal([]byte(val), &s); err == nil {
		return s
	}
	// For other JSON types (number, bool, object, array) return as-is.
	return val
}

// encodeSettingValue converts a setting's Value into a JSON representation
// suitable for storage as JSONB.
func encodeSettingValue(setting *model.Setting) string {
	trimmed := strings.TrimSpace(setting.Value)
	// If the value is a JSON object or array, pass it through directly.
	if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
		if json.Valid([]byte(setting.Value)) {
			return setting.Value
		}
	}
	// Otherwise treat as a plain string and marshal it.
	b, err := json.Marshal(setting.Value)
	if err != nil {
		return fmt.Sprintf("%q", setting.Value)
	}
	return string(b)
}
