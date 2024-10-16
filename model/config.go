// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	ReadonlyUi          bool   `json:"readonlyUi"`
	Sensitive           bool   `json:"sensitive"`
	Regex               string `json:"regex"`
	RegexFailureMessage string `json:"regexFailureMessage"`
	File                bool   `json:"file"`
	Advanced            bool   `json:"advanced"`
	HelpLink            string `json:"helpLink"`
	Syntax              string `json:"syntax"`
	ForcedType          string `json:"forcedType"`
	Duplicates          bool   `json:"duplicates"`
	JinjaEscaped        bool   `json:"jinjaEscaped"`
}

func NewSetting(id string) *Setting {
	setting := &Setting{}
	setting.SetId(id)
	return setting
}

func (setting *Setting) SetId(id string) {
	setting.Id = id
}

func (setting *Setting) SupportsJinja() bool {
	// Assume duplicated settings should support Jinja, since those lose their annotations.
	return setting.JinjaEscaped || setting.IsDuplicatedSetting()
}

func (setting *Setting) IsDuplicatedSetting() bool {
	// Assume descriptionless settings are duplicated, since annotations are lost for duplicated settings
	return len(setting.Description) == 0
}

func IsValidMinionId(id string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(id)
}

func IsValidSettingId(id string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9\*\/:_.-]+$`).MatchString(id)
}
