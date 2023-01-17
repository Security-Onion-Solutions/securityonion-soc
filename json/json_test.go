// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
