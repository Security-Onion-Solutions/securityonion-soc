// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package module

import (
	"testing"
)

func TestGetString(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetString(options, "MyKey")
	if err == nil {
		tester.Errorf("expected GetString error")
	}
	options["MyKey"] = "MyValue"
	actual, err := GetString(options, "MyKey")
	if err != nil {
		tester.Errorf("unexpected GetString error")
	}
	if actual != "MyValue" {
		tester.Errorf("expected GetString to return %s but got %s", "MyValue", actual)
	}
}

func TestGetStringDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetStringDefault(options, "MyKey", "MyValue")
	if actual != "MyValue" {
		tester.Errorf("expected GetStringDefault to return %s but got %s", "MyValue", actual)
	}
	options["MyKey"] = "YourValue"
	actual = GetStringDefault(options, "MyKey", "MyValue")
	if actual != "YourValue" {
		tester.Errorf("expected GetStringDefault to return %s but got %s", "YourValue", actual)
	}
}

func TestGetInt(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetInt(options, "MyKey")
	if err == nil {
		tester.Errorf("expected GetInt error")
	}
	options["MyKey"] = float64(123)
	actual, err := GetInt(options, "MyKey")
	if err != nil {
		tester.Errorf("unexpected GetInt error")
	}
	if actual != 123 {
		tester.Errorf("expected GetInt to return %d but got %d", 123, actual)
	}
}

func TestGetIntDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetIntDefault(options, "MyKey", 123)
	if actual != 123 {
		tester.Errorf("expected GetIntDefault to return %d but got %d", 123, actual)
	}
	options["MyKey"] = float64(1234)
	actual = GetIntDefault(options, "MyKey", 123)
	if actual != 1234 {
		tester.Errorf("expected GetIntDefault to return %d but got %d", 1234, actual)
	}
}

func TestGetBool(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetBool(options, "MyKey")
	if err == nil {
		tester.Errorf("expected GetBool error")
	}
	options["MyKey"] = true
	actual, err := GetBool(options, "MyKey")
	if err != nil {
		tester.Errorf("unexpected GetBool error")
	}
	if actual != true {
		tester.Errorf("expected GetBool to return %t but got %t", true, actual)
	}
}

func TestGetBoolDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetBoolDefault(options, "MyKey", true)
	if actual != true {
		tester.Errorf("expected GetBoolDefault to return %t but got %t", true, actual)
	}
	options["MyKey"] = false
	actual = GetBoolDefault(options, "MyKey", true)
	if actual != false {
		tester.Errorf("expected GetBoolDefault to return %t but got %t", false, actual)
	}
}

func TestGetStringArray(tester *testing.T) {
	options := make(map[string]interface{})
	_, err := GetStringArray(options, "MyKey")
	if err == nil {
		tester.Errorf("expected GetStringArray error")
	}
	array := make([]interface{}, 2, 2)
	array[0] = "MyValue1"
	array[1] = "MyValue2"
	options["MyKey"] = array
	actual, err := GetStringArray(options, "MyKey")
	if err != nil {
		tester.Errorf("unexpected GetString error")
	}
	if actual[0] != "MyValue1" {
		tester.Errorf("expected GetString to return %s but got %s", "MyValue1", actual[0])
	}
	if actual[1] != "MyValue2" {
		tester.Errorf("expected GetString to return %s but got %s", "MyValue2", actual[1])
	}
}

func TestGetStringArrayDefault(tester *testing.T) {
	options := make(map[string]interface{})
	actual := GetStringArrayDefault(options, "MyKey", make([]string, 0, 0))
	if len(actual) != 0 {
		tester.Errorf("expected empty default string array but got %v", actual)
	}

	array := make([]interface{}, 2, 2)
	array[0] = "MyValue1"
	array[1] = "MyValue2"
	options["MyKey"] = array
	actual = GetStringArrayDefault(options, "MyKey", make([]string, 0, 0))
	if actual[0] != "MyValue1" {
		tester.Errorf("expected GetString to return %s but got %s", "MyValue1", actual[0])
	}
	if actual[1] != "MyValue2" {
		tester.Errorf("expected GetString to return %s but got %s", "MyValue2", actual[1])
	}
}
