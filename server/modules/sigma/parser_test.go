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
		input   string
		wantErr bool
		check   func(t *testing.T, rule *Rule)
	}{
		{
			name: "valid sigma rule",
			input: `
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Test description
author: Test Author
date: 2023-01-01
modified: 2023-01-02
tags:
  - attack.execution
  - attack.t1059
level: high
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
    CommandLine|contains: 'powershell'
  condition: selection
fields:
  - CommandLine
  - Image
falsepositives:
  - Legitimate PowerShell usage
`,
			wantErr: false,
			check: func(t *testing.T, rule *Rule) {
				assert.Equal(t, "Test Rule", rule.Title)
				assert.Equal(t, "12345678-1234-1234-1234-123456789012", rule.ID)
				assert.Equal(t, "experimental", rule.Status)
				assert.Equal(t, "Test description", rule.Description)
				assert.Equal(t, "Test Author", rule.Author)
				assert.Equal(t, "high", rule.Level)
				
				assert.Equal(t, "windows", rule.LogSource.Product)
				assert.Equal(t, "sysmon", rule.LogSource.Service)
				assert.Equal(t, "process_creation", rule.LogSource.Category)
				
				assert.Equal(t, "selection", rule.Detection.Condition)
				assert.Contains(t, rule.Detection.Selections, "selection")
				
				assert.Len(t, rule.Tags, 2)
				assert.Contains(t, rule.Tags, "attack.execution")
				assert.Contains(t, rule.Tags, "attack.t1059")
				
				assert.Len(t, rule.Fields, 2)
				assert.Contains(t, rule.Fields, "CommandLine")
				assert.Contains(t, rule.Fields, "Image")
				
				assert.Len(t, rule.FalsePositives, 1)
				assert.Contains(t, rule.FalsePositives[0], "Legitimate PowerShell usage")
			},
		},
		{
			name: "rule without title",
			input: `
id: 12345678-1234-1234-1234-123456789012
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
`,
			wantErr: true,
		},
		{
			name: "rule without logsource",
			input: `
title: Test Rule
detection:
  selection:
    EventID: 1
  condition: selection
`,
			wantErr: true,
		},
		{
			name: "rule without detection",
			input: `
title: Test Rule
logsource:
  product: windows
`,
			wantErr: true,
		},
		{
			name: "rule with multiple selections",
			input: `
title: Multi Selection Rule
logsource:
  product: windows
detection:
  selection1:
    EventID: 1
  selection2:
    EventID: 4688
  filter:
    CommandLine|contains: 'legitimate.exe'
  condition: (selection1 or selection2) and not filter
`,
			wantErr: false,
			check: func(t *testing.T, rule *Rule) {
				assert.Equal(t, "Multi Selection Rule", rule.Title)
				assert.Equal(t, "(selection1 or selection2) and not filter", rule.Detection.Condition)
				assert.Len(t, rule.Detection.Selections, 3) // doesn't include condition
				assert.Contains(t, rule.Detection.Selections, "selection1")
				assert.Contains(t, rule.Detection.Selections, "selection2")
				assert.Contains(t, rule.Detection.Selections, "filter")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := ParseRule([]byte(tt.input))
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, rule)
				if tt.check != nil {
					tt.check(t, rule)
				}
			}
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
				Title: "Test Rule",
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
			name: "rule without title",
			rule: &Rule{
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
			errMsg:  "rule must have a title",
		},
		{
			name: "rule without condition",
			rule: &Rule{
				Title: "Test Rule",
				Detection: Detection{
					Selections: map[string]interface{}{
						"selection": map[string]interface{}{
							"EventID": 1,
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "rule must have a detection condition",
		},
		{
			name: "rule with non-existent selection reference",
			rule: &Rule{
				Title: "Test Rule",
				Detection: Detection{
					Condition: "selection and nonexistent",
					Selections: map[string]interface{}{
						"selection": map[string]interface{}{
							"EventID": 1,
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "condition references non-existent selection: nonexistent",
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