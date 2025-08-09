// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRule(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    *Rule
		wantErr bool
	}{
		{
			name: "basic rule",
			yaml: `
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: stable
description: Test rule for parsing
author: Test Author
date: 2024-01-01
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    CommandLine|contains: 'powershell'
  condition: selection
`,
			want: &Rule{
				Title:       "Test Rule",
				ID:          "12345678-1234-1234-1234-123456789012",
				Status:      "stable",
				Description: "Test rule for parsing",
				Author:      "Test Author",
				Level:       "high",
				LogSource: LogSource{
					Category: "process_creation",
					Product:  "windows",
				},
				Detection: Detection{
					Condition: "selection",
					Selections: map[string]interface{}{
						"selection": map[string]interface{}{
							"EventID":              1,
							"CommandLine|contains": "powershell",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "rule with multiple selections",
			yaml: `
title: Multi Selection Rule
id: 87654321-4321-4321-4321-210987654321
status: test
logsource:
  product: linux
  service: syslog
detection:
  selection1:
    User: root
  selection2:
    Command:
      - sudo
      - su
  filter:
    SourceIP: 127.0.0.1
  condition: (selection1 or selection2) and not filter
`,
			want: &Rule{
				Title:  "Multi Selection Rule",
				ID:     "87654321-4321-4321-4321-210987654321",
				Status: "test",
				LogSource: LogSource{
					Product: "linux",
					Service: "syslog",
				},
				Detection: Detection{
					Condition: "(selection1 or selection2) and not filter",
					Selections: map[string]interface{}{
						"selection1": map[string]interface{}{
							"User": "root",
						},
						"selection2": map[string]interface{}{
							"Command": []interface{}{"sudo", "su"},
						},
						"filter": map[string]interface{}{
							"SourceIP": "127.0.0.1",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing required fields",
			yaml: `
description: Invalid rule without title and id
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule([]byte(tt.yaml))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)

			// Compare basic fields
			assert.Equal(t, tt.want.Title, got.Title)
			assert.Equal(t, tt.want.ID, got.ID)
			assert.Equal(t, tt.want.Status, got.Status)
			assert.Equal(t, tt.want.Description, got.Description)
			assert.Equal(t, tt.want.Author, got.Author)
			assert.Equal(t, tt.want.Level, got.Level)

			// Compare logsource
			assert.Equal(t, tt.want.LogSource.Category, got.LogSource.Category)
			assert.Equal(t, tt.want.LogSource.Product, got.LogSource.Product)
			assert.Equal(t, tt.want.LogSource.Service, got.LogSource.Service)

			// Compare detection
			assert.Equal(t, tt.want.Detection.Condition, got.Detection.Condition)
			assert.Equal(t, len(tt.want.Detection.Selections), len(got.Detection.Selections))
		})
	}
}

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    *Rule
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid rule",
			rule: &Rule{
				Title:  "Valid Rule",
				ID:     "12345678-1234-1234-1234-123456789012",
				Status: StatusStable,
				Level:  LevelHigh,
				Detection: Detection{
					Condition: "selection",
					Selections: map[string]interface{}{
						"selection": map[string]interface{}{
							"EventID": 1,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing title",
			rule: &Rule{
				ID: "12345678-1234-1234-1234-123456789012",
				Detection: Detection{
					Condition: "selection",
					Selections: map[string]interface{}{
						"selection": map[string]interface{}{
							"EventID": 1,
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "rule missing required field: title",
		},
		{
			name: "invalid level",
			rule: &Rule{
				Title: "Test Rule",
				ID:    "12345678-1234-1234-1234-123456789012",
				Level: "invalid",
				Detection: Detection{
					Condition: "selection",
					Selections: map[string]interface{}{
						"selection": map[string]interface{}{
							"EventID": 1,
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid rule level: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRule(tt.rule)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseModifier(t *testing.T) {
	tests := []struct {
		field        string
		wantField    string
		wantModifier ModifierType
	}{
		{"CommandLine", "CommandLine", ModifierNone},
		{"CommandLine|contains", "CommandLine", ModifierContains},
		{"FilePath|endswith", "FilePath", ModifierEndsWith},
		{"Registry|startswith", "Registry", ModifierStartsWith},
		{"Data|base64", "Data", ModifierBase64},
		{"Field|unknown", "Field|unknown", ModifierNone},
		{"Field|re", "Field", ModifierRe},
		{"SourceIP|cidr", "SourceIP", ModifierCIDR},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			gotField, gotModifier := ParseModifier(tt.field)
			assert.Equal(t, tt.wantField, gotField)
			assert.Equal(t, tt.wantModifier, gotModifier)
		})
	}
}

func TestParseDate(t *testing.T) {
	tests := []struct {
		dateStr string
		valid   bool
	}{
		{"2024-01-01", true},
		{"2024/01/01", true},
		{"2024-01-01T15:04:05Z", true},
		{"invalid date", false},
	}

	for _, tt := range tests {
		t.Run(tt.dateStr, func(t *testing.T) {
			date, err := parseDate(tt.dateStr)
			if tt.valid {
				assert.NoError(t, err)
				assert.False(t, date.IsZero())
			} else {
				assert.Error(t, err)
			}
		})
	}
}