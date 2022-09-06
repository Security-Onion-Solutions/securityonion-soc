// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
