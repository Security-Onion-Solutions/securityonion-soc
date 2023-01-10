// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package module

import (
  "errors"
)

func GetString(options map[string]interface{}, key string) (string, error) {
  var err error
  var value string
  if gen, ok := options[key]; ok {
    value = gen.(string)
  } else {
    err = errors.New("Required option is missing: " + key + " (string)")
  }
  return value, err
}

func GetStringDefault(options map[string]interface{}, key string, dflt string) string {
  var value string
  if gen, ok := options[key]; ok {
    value = gen.(string)
  } else {
    value = dflt
  }
  return value
}

func GetInt(options map[string]interface{}, key string) (int, error) {
  var err error
  var value int
  if gen, ok := options[key]; ok {
    value = int(gen.(float64))
  } else {
    err = errors.New("Required option is missing: " + key + " (int)")
  }
  return value, err
}

func GetIntDefault(options map[string]interface{}, key string, dflt int) int {
  var value int
  if gen, ok := options[key]; ok {
    value = int(gen.(float64))
  } else {
    value = dflt
  }
  return value
}

func GetBool(options map[string]interface{}, key string) (bool, error) {
  var err error
  var value bool
  if gen, ok := options[key]; ok {
    value = gen.(bool)
  } else {
    err = errors.New("Required option is missing: " + key + " (bool)")
  }
  return value, err
}

func GetBoolDefault(options map[string]interface{}, key string, dflt bool) bool {
  var value bool
  if gen, ok := options[key]; ok {
    value = gen.(bool)
  } else {
    value = dflt
  }
  return value
}

func GetStringArray(options map[string]interface{}, key string) ([]string, error) {
  var err error
  var value []string
  if gen, ok := options[key]; ok {
    value = make([]string, 0)
    for _, iface := range gen.([]interface{}) {
      value = append(value, iface.(string))
    }
  } else {
    err = errors.New("Required option is missing: " + key + " ([]string)")
  }
  return value, err
}

func GetStringArrayDefault(options map[string]interface{}, key string, dflt []string) []string {
  value, err := GetStringArray(options, key)
  if err != nil {
    value = dflt
  }
  return value
}
