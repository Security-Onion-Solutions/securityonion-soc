// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma_test

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
	_ "github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/backends" // Register backends
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrationConvertRule(t *testing.T) {
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
	rule, err := sigma.ParseRule([]byte(sigmaRule))
	require.NoError(t, err)
	require.NotNil(t, rule)

	// Convert to EQL
	query, err := sigma.ConvertRule(rule, "eql", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, query)

	// Check that the query contains expected elements
	assert.Contains(t, query, "process where")
	assert.Contains(t, query, "EventID == 1")
	assert.Contains(t, query, "CommandLine like")
	assert.Contains(t, query, "Invoke-WebRequest")
}

func TestIntegrationConverterRegistry(t *testing.T) {
	// Test listing converters
	converters := sigma.ListConverters()
	assert.Contains(t, converters, "eql")
	assert.Contains(t, converters, "elasticsearch")
	assert.Contains(t, converters, "security_onion")

	// Test getting converter
	eqlConverter, err := sigma.GetConverter("eql")
	require.NoError(t, err)
	assert.NotNil(t, eqlConverter)
	assert.Equal(t, "eql", eqlConverter.GetTargetFormat())

	// Test unknown converter
	_, err = sigma.GetConverter("unknown")
	assert.Error(t, err)
}