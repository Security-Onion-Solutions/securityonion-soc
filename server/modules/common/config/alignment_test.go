// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestAlignInt64List(t *testing.T) {
	// Success
	val, err := AlignInt64List("44\n55")
	assert.NoError(t, err)
	assert.Equal(t, []int64{44, 55}, val)

	// Empty
	val, err = AlignInt64List("")
	assert.NoError(t, err)
	assert.Nil(t, val)

	// Failure
	val, err = AlignInt64List("44\nnot-an-int")
	assert.Error(t, err)
	assert.Nil(t, val)
}

func TestAlignBoolList(t *testing.T) {
	// Success
	val, err := AlignBoolList("true\nfalse")
	assert.NoError(t, err)
	assert.Equal(t, []bool{true, false}, val)

	// Empty
	val, err = AlignBoolList("")
	assert.NoError(t, err)
	assert.Nil(t, val)

	// Failure
	val, err = AlignBoolList("true\nnot-a-bool")
	assert.Error(t, err)
	assert.Nil(t, val)
}

func TestAlignFloat64List(t *testing.T) {
	// Success
	val, err := AlignFloat64List("44.2\n55.5")
	assert.NoError(t, err)
	assert.Equal(t, []float64{44.2, 55.5}, val)

	// Empty
	val, err = AlignFloat64List("")
	assert.NoError(t, err)
	assert.Nil(t, val)

	// Failure
	val, err = AlignFloat64List("44.2\nnot-a-float")
	assert.Error(t, err)
	assert.Nil(t, val)
}

func TestAlignListList(t *testing.T) {
	// Success
	val, err := AlignListList("[\"item1\",\"item2\"]\n[\"item3\",\"item4\"]")
	assert.NoError(t, err)
	assert.Equal(t, [][]interface{}{{"item1", "item2"}, {"item3", "item4"}}, val)

	// Failure
	val, err = AlignListList("not-a-list")
	assert.Error(t, err)
	assert.Nil(t, val)
}

func TestAlignMapList(t *testing.T) {
	// Success
	val, err := AlignMapList("{\"key1\":\"value1\"}\n{\"key2\":\"value2\"}")
	assert.NoError(t, err)
	assert.Equal(t, []map[string]interface{}{{"key1": "value1"}, {"key2": "value2"}}, val)

	// Failure
	val, err = AlignMapList("not-a-map")
	assert.Error(t, err)
	assert.Nil(t, val)
}

func TestInterfaceToString(t *testing.T) {
	assert.Equal(t, "hello", InterfaceToString("hello"))
	assert.Equal(t, "44", InterfaceToString(float64(44)))
	assert.Equal(t, "44.5", InterfaceToString(float64(44.5)))
	assert.Equal(t, "true", InterfaceToString(true))
	assert.Equal(t, "item1\nitem2", InterfaceToString([]any{"item1", "item2"}))
	assert.Equal(t, "123", InterfaceToString(123))
}

func TestForceType(t *testing.T) {
	testCases := []struct {
		value       string
		forcedType  string
		expected    interface{}
		errorString string
	}{
		{value: "44", forcedType: "int", expected: int64(44), errorString: ""},
		{value: "44", forcedType: "[]int", expected: []int64{44}, errorString: ""},
		{value: "44\n55", forcedType: "[]int", expected: []int64{44, 55}, errorString: ""},
		{value: "blah", forcedType: "[]int", expected: []int64{}, errorString: "invalid syntax"},
		{value: "44.4", forcedType: "float", expected: float64(44.4), errorString: ""},
		{value: "44.3", forcedType: "[]float", expected: []float64{44.3}, errorString: ""},
		{value: "44.2\n55", forcedType: "[]float", expected: []float64{44.2, 55}, errorString: ""},
		{value: "blah", forcedType: "[]float", expected: []float64{}, errorString: "invalid syntax"},
		{value: "true", forcedType: "bool", expected: true, errorString: ""},
		{value: "true", forcedType: "[]bool", expected: []bool{true}, errorString: ""},
		{value: "true\nfalse", forcedType: "[]bool", expected: []bool{true, false}, errorString: ""},
		{value: "blah", forcedType: "[]bool", expected: []bool{}, errorString: "invalid syntax"},
		{value: "hello", forcedType: "string", expected: "hello", errorString: ""},
		{value: "", forcedType: "[]string", expected: []string{}, errorString: ""},
		{value: "hello\nthere", forcedType: "[]string", expected: []string{"hello", "there"}, errorString: ""},
		{value: "blah", forcedType: "[]string", expected: []string{"blah"}, errorString: ""},
		{value: "[\"hello\"]", forcedType: "[][]", expected: [][]interface{}([][]interface{}{[]interface{}{"hello"}}), errorString: ""},
		{value: "[\"hello\"]\n[\"there\"]", forcedType: "[][]", expected: [][]interface{}([][]interface{}{[]interface{}{"hello"}, []interface{}{"there"}}), errorString: ""},
		{value: "{\"name\":\"hello\"}", forcedType: "[]{}", expected: []map[string]interface{}([]map[string]interface{}{map[string]interface{}{"name": "hello"}}), errorString: ""},
		{value: "{\"name\":\"hello\"}\n{\"name\":\"there\"}", forcedType: "[]{}", expected: []map[string]interface{}([]map[string]interface{}{map[string]interface{}{"name": "hello"}, map[string]interface{}{"name": "there"}}), errorString: ""},
	}

	for _, testCase := range testCases {
		actual, err := ForceType(testCase.value, testCase.forcedType)
		if testCase.errorString != "" {
			assert.ErrorContains(t, err, testCase.errorString)
		} else {
			assert.Equal(t, testCase.expected, actual)
		}
	}
}

func TestCoerceMapListFieldTypes(t *testing.T) {
	testCases := []struct {
		name             string
		list             []map[string]any
		uiElements       []model.UiElement
		errContains      string
		checkField       string
		expected         any
		wantEmptyResult  bool
	}{
		{
			name: "valid int and bool strings coerced correctly",
			list: []map[string]any{{"port": "8080", "enabled": "true", "name": "alpha"}},
			uiElements: []model.UiElement{
				{Field: "port", ForcedType: "int", Required: true},
				{Field: "enabled", ForcedType: "bool"},
			},
			checkField: "port",
			expected:   int64(8080),
		},
		{
			name:        "invalid bool required returns error",
			list:        []map[string]any{{"enabled": "maybe"}},
			uiElements:  []model.UiElement{{Field: "enabled", ForcedType: "bool", Required: true}},
			errContains: "enabled",
		},
		{
			name:        "required empty value returns error",
			list:        []map[string]any{{"port": ""}},
			uiElements:  []model.UiElement{{Field: "port", ForcedType: "int", Required: true}},
			errContains: "port",
		},
		{
			name:       "unsupported type not required uses zero value",
			list:       []map[string]any{{"id": "some-uuid"}},
			uiElements: []model.UiElement{{Field: "id", ForcedType: "uuid", Required: false}},
			checkField: "id",
			expected:   nil,
		},
		{
			name:        "unsupported type required returns error",
			list:        []map[string]any{{"id": "some-uuid"}},
			uiElements:  []model.UiElement{{Field: "id", ForcedType: "uuid", Required: true}},
			errContains: "id",
		},
		{
			name:        "error in second object",
			list:        []map[string]any{{"port": "8080"}, {"port": "abc"}},
			uiElements:  []model.UiElement{{Field: "port", ForcedType: "int", Required: true}},
			errContains: "port",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := CoerceMapListFieldTypes(tc.list, tc.uiElements)
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
			} else {
				assert.NoError(t, err)
				if tc.wantEmptyResult {
					assert.Empty(t, result)
				} else if tc.checkField != "" {
					assert.Equal(t, tc.expected, result[0][tc.checkField])
				}
			}
		})
	}
}

func TestCoerceMapListFieldTypes_MultipleFields_AllStrings(t *testing.T) {
	list := []map[string]any{
		{"port": "8080", "enabled": "true", "name": "alpha"},
	}
	uiElements := []model.UiElement{
		{Field: "port", ForcedType: "int"},
		{Field: "enabled", ForcedType: "bool"},
		{Field: "name"}, // no ForcedType — should remain a string
	}
	result, err := CoerceMapListFieldTypes(list, uiElements)
	assert.NoError(t, err)
	assert.Equal(t, int64(8080), result[0]["port"])
	assert.Equal(t, true, result[0]["enabled"])
	assert.Equal(t, "alpha", result[0]["name"])
}

func TestCoerceMapListFieldTypes_MultipleObjects_AllStrings(t *testing.T) {
	list := []map[string]any{
		{"port": "8080", "enabled": "true", "name": "alpha"},
		{"port": "9090", "enabled": "false", "name": "beta"},
		{"port": "443", "enabled": "true", "name": "gamma"},
	}
	uiElements := []model.UiElement{
		{Field: "port", ForcedType: "int"},
		{Field: "enabled", ForcedType: "bool"},
	}
	result, err := CoerceMapListFieldTypes(list, uiElements)
	assert.NoError(t, err)

	assert.Equal(t, int64(8080), result[0]["port"])
	assert.Equal(t, true, result[0]["enabled"])
	assert.Equal(t, "alpha", result[0]["name"])

	assert.Equal(t, int64(9090), result[1]["port"])
	assert.Equal(t, false, result[1]["enabled"])
	assert.Equal(t, "beta", result[1]["name"])

	assert.Equal(t, int64(443), result[2]["port"])
	assert.Equal(t, true, result[2]["enabled"])
	assert.Equal(t, "gamma", result[2]["name"])
}

func TestCoerceMapListFieldTypes_AllScalarStringTypes(t *testing.T) {
	list := []map[string]any{
		{
			"port":    "8080",
			"enabled": "true",
			"ratio":   "2.718",
			"name":    "delta",
		},
	}
	uiElements := []model.UiElement{
		{Field: "port", ForcedType: "int"},
		{Field: "enabled", ForcedType: "bool"},
		{Field: "ratio", ForcedType: "float"},
		{Field: "name", ForcedType: "string"},
	}
	result, err := CoerceMapListFieldTypes(list, uiElements)
	assert.NoError(t, err)
	assert.Equal(t, int64(8080), result[0]["port"])
	assert.Equal(t, true, result[0]["enabled"])
	assert.Equal(t, float64(2.718), result[0]["ratio"])
	assert.Equal(t, "delta", result[0]["name"])
}

func TestZeroForType(t *testing.T) {
	testCases := []struct {
		typ      string
		expected any
	}{
		{typ: "float", expected: float64(0)},
		{typ: "int", expected: int64(0)},
		{typ: "bool", expected: false},
		{typ: "string", expected: ""},
		{typ: "[]int", expected: []int64{}},
		{typ: "[]bool", expected: []bool{}},
		{typ: "[]float", expected: []float64{}},
		{typ: "[]string", expected: []string{}},
		{typ: "[][]", expected: [][]interface{}{}},
		{typ: "[]{}", expected: []map[string]interface{}{}},
		{typ: "unknown", expected: nil},
		{typ: "", expected: nil},
	}

	for _, tc := range testCases {
		t.Run(tc.typ, func(t *testing.T) {
			assert.Equal(t, tc.expected, ZeroForType(tc.typ))
		})
	}
}

func TestAlignBestGuess(t *testing.T) {
	assert.Equal(t, int64(123), AlignBestGuess("123"))
	assert.Equal(t, 1.23, AlignBestGuess("1.23"))
	assert.Equal(t, true, AlignBestGuess("true"))
	assert.Equal(t, []int64{1, 2}, AlignBestGuess("1\n2"))
	assert.Equal(t, map[string]interface{}{"a": float64(1)}, AlignBestGuess("{\"a\":1}"))
	assert.Equal(t, []interface{}{float64(1)}, AlignBestGuess("[1]"))
	assert.Equal(t, "not-special", AlignBestGuess("not-special"))
}
