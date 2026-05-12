// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/onionconfig/database"
	"github.com/stretchr/testify/assert"
)

func TestDecodeJSONBValue_Empty(t *testing.T) {
	assert.Equal(t, "", decodeJSONBValue(""))
}

func TestDecodeJSONBValue_Null(t *testing.T) {
	assert.Equal(t, "", decodeJSONBValue("null"))
}

func TestDecodeJSONBValue_StringJSON(t *testing.T) {
	assert.Equal(t, "hello", decodeJSONBValue(`"hello"`))
}

func TestDecodeJSONBValue_NumberJSON(t *testing.T) {
	assert.Equal(t, "42", decodeJSONBValue("42"))
}

func TestDecodeJSONBValue_BoolJSON(t *testing.T) {
	assert.Equal(t, "true", decodeJSONBValue("true"))
}

func TestDecodeJSONBValue_ObjectJSON(t *testing.T) {
	assert.Equal(t, `{"a":1}`, decodeJSONBValue(`{"a":1}`))
}

func TestEncodeSettingValue_Empty(t *testing.T) {
	s := model.NewSetting("test")
	s.Value = ""
	assert.Equal(t, "null", encodeSettingValue(s))
}

func TestEncodeSettingValue_PlainString(t *testing.T) {
	s := model.NewSetting("test")
	s.Value = "some value"
	assert.Equal(t, `"some value"`, encodeSettingValue(s))
}

func TestEncodeSettingValue_ValidJSON(t *testing.T) {
	s := model.NewSetting("test")
	s.Value = `{"key":"val"}`
	assert.Equal(t, `{"key":"val"}`, encodeSettingValue(s))
}

func TestEncodeSettingValue_BoolJSON(t *testing.T) {
	s := model.NewSetting("test")
	s.Value = "true"
	assert.Equal(t, "true", encodeSettingValue(s))
}

func TestDbRowToSetting(t *testing.T) {
	row := database.SettingRow{
		SettingID:        "soc.config.key",
		Value:            `"myvalue"`,
		DuplicatedFromID: "soc.config.orig",
		NodeID:           "node1",
	}
	s := dbRowToSetting(row)
	assert.Equal(t, "soc.config.key", s.Id)
	assert.Equal(t, "myvalue", s.Value)
	assert.Equal(t, "soc.config.orig", s.DuplicatedFromID)
	assert.Equal(t, "node1", s.NodeId)
	assert.Equal(t, model.SettingOriginDB, s.Origin)
}

func TestSettingToDBRow(t *testing.T) {
	s := model.NewSetting("soc.config.key")
	s.Value = "hello"
	s.NodeId = "node2"
	s.DuplicatedFromID = "soc.config.orig"

	row := settingToDBRow(s)
	assert.Equal(t, "soc.config.key", row.SettingID)
	assert.Equal(t, `"hello"`, row.Value)
	assert.Equal(t, "node2", row.NodeID)
	assert.Equal(t, "soc.config.orig", row.DuplicatedFromID)
}
