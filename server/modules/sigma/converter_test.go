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

func TestConvertRule(t *testing.T) {
	// Sample Sigma rule
	sigmaRule := `
title: Suspicious PowerShell Download
id: 3b6ab547-8ec2-4991-a2dc-0b34e419e3aa
status: experimental
description: Detects suspicious PowerShell download command
author: Test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    CommandLine|contains:
      - 'Invoke-WebRequest'
      - 'iwr'
      - 'wget'
      - 'curl'
      - 'DownloadFile'
      - 'DownloadString'
  condition: selection
level: medium
`

	// Parse the rule
	rule, err := ParseRule([]byte(sigmaRule))
	require.NoError(t, err)
	require.NotNil(t, rule)

	// Convert to EQL
	query, err := ConvertRule(rule, "eql", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, query)

	// Check that the query contains expected elements
	assert.Contains(t, query, "process where")
	assert.Contains(t, query, "EventID == 1")
	assert.Contains(t, query, "CommandLine like")
	assert.Contains(t, query, "Invoke-WebRequest")
}

func TestConvertRuleWithMultipleSelections(t *testing.T) {
	sigmaRule := `
title: Suspicious Process Creation
id: test-rule-001
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection1:
    EventID: 1
    Image|endswith: '\cmd.exe'
  selection2:
    EventID: 1
    CommandLine|contains: 'powershell'
  filter:
    ParentImage|endswith: '\explorer.exe'
  condition: (selection1 or selection2) and not filter
`

	rule, err := ParseRule([]byte(sigmaRule))
	require.NoError(t, err)

	query, err := ConvertRule(rule, "eql", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, query)

	// Verify the query structure
	assert.Contains(t, query, "process where")
	assert.Contains(t, query, "EventID == 1")
	assert.Contains(t, query, "Image like")
	assert.Contains(t, query, "cmd.exe")
	assert.Contains(t, query, "CommandLine like")
	assert.Contains(t, query, "powershell")
	assert.Contains(t, query, "not")
	assert.Contains(t, query, "ParentImage")
}

func TestConvertRuleWithWildcards(t *testing.T) {
	sigmaRule := `
title: Test Wildcards
id: test-wildcards
logsource:
  product: windows
detection:
  selection:
    CommandLine: 
      - '*test*'
      - 'start*end'
      - '?single'
  condition: selection
`

	rule, err := ParseRule([]byte(sigmaRule))
	require.NoError(t, err)

	query, err := ConvertRule(rule, "eql", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, query)

	// EQL should convert wildcards to proper patterns
	assert.Contains(t, query, "CommandLine")
}

func TestConverterRegistry(t *testing.T) {
	// Test listing converters
	converters := ListConverters()
	assert.Contains(t, converters, "eql")
	assert.Contains(t, converters, "elasticsearch")

	// Test getting converter
	eqlConverter, err := GetConverter("eql")
	require.NoError(t, err)
	assert.NotNil(t, eqlConverter)
	assert.Equal(t, "eql", eqlConverter.GetTargetFormat())

	// Test unknown converter
	_, err = GetConverter("unknown")
	assert.Error(t, err)
}

func TestConvertRuleWithFieldMapping(t *testing.T) {
	sigmaRule := `
title: Test Field Mapping
id: test-field-mapping
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    CommandLine|contains: 'test'
    Image|endswith: '.exe'
  condition: selection
`

	rule, err := ParseRule([]byte(sigmaRule))
	require.NoError(t, err)

	// Create converter with field mappings
	converter, err := GetConverter("eql")
	require.NoError(t, err)

	// Set field mappings
	mappings := []FieldMapping{
		{Source: "EventID", Target: "event.code"},
		{Source: "CommandLine", Target: "process.command_line"},
		{Source: "Image", Target: "process.executable"},
	}
	converter.SetFieldMappings(mappings)

	// Convert with mappings
	query, err := converter.Convert(rule, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, query)

	// Check mapped fields
	assert.Contains(t, query, "event.code == 1")
	assert.Contains(t, query, "process.command_line like")
	assert.Contains(t, query, "process.executable like")
}

func TestConvertRuleWithOneOfPattern(t *testing.T) {
	sigmaRule := `
title: Test One Of Pattern
id: test-one-of
logsource:
  product: windows
detection:
  selection_cmd:
    CommandLine|contains: 'cmd'
  selection_ps:
    CommandLine|contains: 'powershell'
  selection_wmi:
    CommandLine|contains: 'wmic'
  condition: 1 of selection_*
`

	rule, err := ParseRule([]byte(sigmaRule))
	require.NoError(t, err)

	query, err := ConvertRule(rule, "eql", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, query)

	// Should create OR condition with all selections
	assert.Contains(t, query, "cmd")
	assert.Contains(t, query, "powershell")
	assert.Contains(t, query, "wmic")
	assert.Contains(t, query, " or ")
}

func TestConvertRuleWithAllOfThem(t *testing.T) {
	sigmaRule := `
title: Test All Of Them
id: test-all-of-them
logsource:
  product: windows
detection:
  selection1:
    EventID: 1
  selection2:
    User: 'Administrator'
  selection3:
    IntegrityLevel: 'High'
  condition: all of them
`

	rule, err := ParseRule([]byte(sigmaRule))
	require.NoError(t, err)

	query, err := ConvertRule(rule, "eql", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, query)

	// Should create AND condition with all selections
	assert.Contains(t, query, "EventID == 1")
	assert.Contains(t, query, "User == \"Administrator\"")
	assert.Contains(t, query, "IntegrityLevel == \"High\"")
	assert.Contains(t, query, " and ")
}