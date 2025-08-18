// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConvertToEQL(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	config := Config{
		UseNativeConverter: true,
	}
	converter := NewSigmaConverter(config, iom)

	tests := []struct {
		name      string
		rule      string
		overrides []*model.Override
		expected  string
		wantErr   bool
	}{
		{
			name: "simple process creation rule",
			rule: `
title: Test Process Creation
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    CommandLine|contains: 'powershell'
  condition: selection
`,
			expected: `process where wildcard(process.command_line, "*powershell*") and event.code == 1`,
			wantErr:  false,
		},
		{
			name: "rule with multiple selections",
			rule: `
title: Multiple Selections
logsource:
  product: windows
  category: process_creation
detection:
  selection1:
    EventID: 1
  selection2:
    CommandLine|contains: 'cmd.exe'
  condition: selection1 and selection2
`,
			expected: `process where (event.code == 1) and (wildcard(process.command_line, "*cmd.exe*"))`,
			wantErr:  false,
		},
		{
			name: "rule with OR condition",
			rule: `
title: OR Condition
logsource:
  product: windows
detection:
  sel1:
    EventID: 1
  sel2:
    EventID: 4688
  condition: sel1 or sel2
`,
			expected: `where (event.code == 1) or (event.code == 4688)`,
			wantErr:  false,
		},
		{
			name: "rule with NOT condition",
			rule: `
title: NOT Condition
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  filter:
    User: 'SYSTEM'
  condition: selection and not filter
`,
			expected: `where (event.code == 1) and not (user.name == "SYSTEM")`,
			wantErr:  false,
		},
		{
			name: "rule with 1 of pattern",
			rule: `
title: 1 of Pattern
logsource:
  product: windows
detection:
  selection1:
    EventID: 1
  selection2:
    EventID: 4688
  condition: 1 of selection*
`,
			expected: `where ((event.code == 1) or (event.code == 4688))`,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := converter.ConvertToEQL(context.Background(), tt.rule, tt.overrides)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestConvertToSecurityOnion(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	config := Config{
		UseNativeConverter: true,
	}
	converter := NewSigmaConverter(config, iom)

	tests := []struct {
		name     string
		queries  []string
		expected []*model.ConvertedQuery
		wantErr  bool
	}{
		{
			name: "simple query conversion",
			queries: []string{`
title: Test Query
logsource:
  product: windows
detection:
  selection:
    EventID: 1
    CommandLine|contains: 'powershell'
  condition: selection
fields:
  - CommandLine
  - User
`},
			expected: []*model.ConvertedQuery{
				{
					Query:  `(process.command_line:*powershell* AND event.code:1)`,
					Fields: []string{"CommandLine", "User"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := converter.ConvertToSecurityOnion(context.Background(), tt.queries)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Len(t, result, len(tt.expected))
				
				for i, expected := range tt.expected {
					assert.Equal(t, expected.Query, result[i].Query)
					assert.ElementsMatch(t, expected.Fields, result[i].Fields)
				}
			}
		})
	}
}