// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetString(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetString(options, "MyKey")
	assert.Error(tester, err)

	options["MyKey"] = "MyValue"
	actual, err := GetString(options, "MyKey")
	if assert.Nil(tester, err) {
		assert.Equal(tester, "MyValue", actual)
	}

}

func TestGetStringDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetStringDefault(options, "MyKey", "MyValue")
	assert.Equal(tester, "MyValue", actual)
	options["MyKey"] = "YourValue"
	actual = GetStringDefault(options, "MyKey", "MyValue")
	assert.Equal(tester, "YourValue", actual)
}

func TestGetInt(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetInt(options, "MyKey")
	assert.Error(tester, err)
	options["MyKey"] = float64(123)
	actual, err := GetInt(options, "MyKey")
	if assert.Nil(tester, err) {
		assert.Equal(tester, 123, actual)
	}

}

func TestGetIntDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetIntDefault(options, "MyKey", 123)
	assert.Equal(tester, 123, actual)
	options["MyKey"] = float64(1234)
	actual = GetIntDefault(options, "MyKey", 123)
	assert.Equal(tester, 1234, actual)
}

func TestGetBool(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetBool(options, "MyKey")
	assert.Error(tester, err)
	options["MyKey"] = true
	actual, err := GetBool(options, "MyKey")
	if assert.Nil(tester, err) {
		assert.True(tester, actual)
	}
}

func TestGetBoolDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetBoolDefault(options, "MyKey", true)
	assert.True(tester, actual)
	options["MyKey"] = false
	actual = GetBoolDefault(options, "MyKey", true)
	assert.False(tester, actual)
}

func TestGetStringArray(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetStringArray(options, "MyKey")
	assert.Error(tester, err)
	array := make([]interface{}, 2, 2)
	array[0] = "MyValue1"
	array[1] = "MyValue2"
	options["MyKey"] = array
	actual, err := GetStringArray(options, "MyKey")
	if assert.Nil(tester, err) {
		assert.Equal(tester, "MyValue1", actual[0])
		assert.Equal(tester, "MyValue2", actual[1])
	}
}

func TestGetStringArrayDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetStringArrayDefault(options, "MyKey", make([]string, 0, 0))
	assert.Len(tester, actual, 0)

	array := make([]interface{}, 2, 2)
	array[0] = "MyValue1"
	array[1] = "MyValue2"
	options["MyKey"] = array
	actual = GetStringArrayDefault(options, "MyKey", make([]string, 0, 0))
	assert.Equal(tester, "MyValue1", actual[0])
	assert.Equal(tester, "MyValue2", actual[1])
}
