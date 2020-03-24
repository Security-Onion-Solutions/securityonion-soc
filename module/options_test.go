// Copyright 2019 Jason Ertel (jertel). All rights reserved.
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
  options["MyKey"] = 123
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
  options["MyKey"] = 1234
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
