// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitLogging(tester *testing.T) {
	testFile := "/tmp/sensoroni_test.log"
	defer os.Remove(testFile)
	file, err := InitLogging(testFile, "debug")
	if assert.Nil(tester, err) {
		assert.NotNil(tester, file)
	}
}
