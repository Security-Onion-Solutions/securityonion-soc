// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
