// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package json

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJson(tester *testing.T) {
	testFile := "/tmp/sensoroni_test.json"
	defer os.Remove(testFile)
	obj := make(map[string]string)
	obj["MyKey"] = "MyValue"
	err := WriteJsonFile(testFile, obj)
	assert.Nil(tester, err)
	obj = make(map[string]string)
	err = LoadJsonFile(testFile, &obj)
	if assert.Nil(tester, err) {
		assert.Equal(tester, "MyValue", obj["MyKey"])
	}
}
