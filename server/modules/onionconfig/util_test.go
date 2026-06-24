// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlattenInterfaceSliceToString_Simple(t *testing.T) {
	input := []interface{}{"item1", 123, true, 45.67}
	expected := "item1\n123\ntrue\n45.67\n"
	result := FlattenInterfaceSliceToString(input)
	assert.Equal(t, expected, result)
}

func TestFlattenInterfaceSliceToString_Nested(t *testing.T) {
	input := []interface{}{
		map[string]interface{}{"key": "value"},
		[]interface{}{"nested1", "nested2"},
	}
	expected := "{\"key\":\"value\"}\n[\"nested1\",\"nested2\"]\n"
	result := FlattenInterfaceSliceToString(input)
	assert.Equal(t, expected, result)
}

func TestFlattenInterfaceSliceToString_Empty(t *testing.T) {
	input := []interface{}{}
	expected := ""
	result := FlattenInterfaceSliceToString(input)
	assert.Equal(t, expected, result)
}

func TestRelPathFromId(t *testing.T) {
	assert.Equal(t, "soc/files/soc/banner.md", RelPathFromId("soc.files.soc.banner__md"))
}

func TestCastToStringArray(t *testing.T) {
	input := []interface{}{"foo", "bar"}
	expected := []string{"foo", "bar"}
	result := CastToStringArray(input)
	assert.Equal(t, expected, result)
}
