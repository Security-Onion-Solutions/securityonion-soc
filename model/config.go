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
	// The ID of the configuration setting. Each period represents a nested level.
	Id string `json:"id" example:"elastalert.alerter_parameters"`
	// (metadata) The configuration setting more human-friendly title, if one is available.
	Title string `json:"title" example:"Custom Configuration Parameters"`
	// (metadata) A description explaining the purpose of the configuration setting, if one is available.
	Description string `json:"description" example:"Optional configuration parameters made available as defaults for all rules and alerters"`
	// (metadata) Indicates whether this setting only applies to the grid as a whole
	Global bool `json:"global" example:"true"` // If Global == Node then the setting applies to both
	// (metadata) Indicates whether this setting can be applied differently per each node in the grid
	Node bool `json:"node" example:"false"`
	// The node ID to which this setting's value applies
	NodeId string `json:"nodeId" example:"chi-so-001_standalone"`
	// (metadata) The default value for this configuration setting, if available
	Default string `json:"default" example:"some default value"`
	// (metadata) Indicates whether there is a default value available for this configuration setting
	DefaultAvailable bool `json:"defaultAvailable" example:"true"`
	// The value of this specific configuration setting. Note that a setting exist multiple times if different values are applied to specific nodes
	Value string `json:"value" example:"some custom value"`
	// (metadata) Indicates whether this setting's user interface display should allow the user to enter values onto multiple lines
	Multiline bool `json:"multiline" example:"true"`
	// (metadata) Indicates whether this setting is read-only. Read-only settings should not be modified.
	Readonly bool `json:"readonly" example:"false"`
	// (metadata) Indicates whether this setting is read-only in the user interface only, but may be adjusted by the system itself.
	ReadonlyUi bool `json:"readonlyUi" example:"false"`
	// (metadata) Indicates whether this setting's value should be masked in the user interface to prevent obtaining the existing value, while still permitting new values to be applied.
	Sensitive bool `json:"sensitive" example:"true"`
	// (metadata) An optional regular expression pattern that the value of this setting must match
	Regex string `json:"regex" example:"^(true|false)$"`
	// (metadata) The failure message to show on the user interface when the user enters a value that fails to match the regex.
	RegexFailureMessage string `json:"regexFailureMessage" example:"Only true or false values are accepted"`
	// (metadata) Indicates whether the ID of this setting refers to a file on disk, in which case the changing the setting's value will replace the contents of the file on disk.
	File bool `json:"file" example:"false"`
	// (metadata) Indicates whether this setting should only be shown when the 'Show advanced settings' option is enabled in the user interface.
	Advanced bool `json:"advanced" example:"false"`
	// (metadata) An HTML page, relative to the doc URL, that may assist the user in understanding the purpose of this setting.
	HelpLink string `json:"helpLink" example:"elastalert.html"`
	// (metadata) An optional syntax designator for validating the given setting value.
	Syntax string `json:"syntax" example:"yaml"`
	// (metadata) The type that the value will be converted to internally before applied to the component that uses it.
	ForcedType string `json:"forcedType" example:"[]string"`
	// (metadata) Indicates whether this setting can be duplicated. Duplicating settings is a complex area that can lead to system or upgrade failures so this is used sparingly.
	Duplicates bool `json:"duplicates" example:"false"`
	// (metadata) Indicates whether the setting value allows Jinja2 escape characters. By default these are prohibited as a security precaution.
	JinjaEscaped bool `json:"jinjaEscaped" example:"false"`
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
