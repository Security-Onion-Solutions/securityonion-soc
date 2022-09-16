// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
  "regexp"
)

type Setting struct {
  Id                  string `json:"id"`
  Title               string `json:"title"`
  Description         string `json:"description"`
  Global              bool   `json:"global"` // If Global == Node then the setting applies to both
  Node                bool   `json:"node"`
  NodeId              string `json:"nodeId"`
  Default             string `json:"default"`
  DefaultAvailable    bool   `json:"defaultAvailable"`
  Value               string `json:"value"`
  Multiline           bool   `json:"multiline"`
  Readonly            bool   `json:"readonly"`
  Sensitive           bool   `json:"sensitive"`
  Regex               string `json:"regex"`
  RegexFailureMessage string `json:"regexFailureMessage"`
  File                bool   `json:"file"`
  Advanced            bool   `json:"advanced"`
  HelpLink            string `json:"helpLink"`
  Syntax              string `json:"syntax"`
}

func NewSetting(Id string) *Setting {
  return &Setting{
    Id: Id,
  }
}

func IsValidMinionId(id string) bool {
  return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(id)
}

func IsValidSettingId(id string) bool {
  return regexp.MustCompile(`^[a-zA-Z0-9:_.-]+$`).MatchString(id)
}
