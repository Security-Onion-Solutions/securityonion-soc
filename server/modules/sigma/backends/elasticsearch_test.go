// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package backends

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestElasticsearchBackend(t *testing.T) {
	backend := NewElasticsearchBackend()
	
	tests := []struct {
		name     string
		rule     *sigma.Rule
		expected string
		contains []string
	}{
		{
			name: "simple process creation",
			rule: &sigma.Rule{
				Title: "Test Process Creation",
				ID:    "test-001",
				LogSource: sigma.LogSource{
					Product:  "windows",
					Category: "process_creation",
				},
				Detection: sigma.Detection{
					Condition: "selection",
					Selections: map[string]interface{}{
						"selection": map[string]interface{}{
							"EventID":     1,
							"CommandLine": "test.exe",
						},
					},
				},
			},
			contains: []string{
				"process where",
				"EventID == 1",
				"CommandLine == \"test.exe\"",
			},
		},
		{
			name: "contains modifier",
			rule: &sigma.Rule{
				Title: "Test Contains",
				ID:    "test-002",
				LogSource: sigma.LogSource{
					Product:  "windows",
					Category: "process_creation",
				},
				Detection: sigma.Detection{
					Condition: "selection",
					Selections: map[string]interface{}{
						"selection": map[string]interface{}{
							"CommandLine|contains": []interface{}{"powershell", "cmd"},
						},
					},
				},
			},
			contains: []string{
				"process where",
				"CommandLine like \"*powershell*\"",
				"CommandLine like \"*cmd*\"",
				" or ",
			},
		},
		{
			name: "complex condition",
			rule: &sigma.Rule{
				Title: "Test Complex Condition",
				ID:    "test-003",
				LogSource: sigma.LogSource{
					Product:  "windows",
					Category: "process_creation",
				},
				Detection: sigma.Detection{
					Condition: "(selection1 or selection2) and not filter",
					Selections: map[string]interface{}{
						"selection1": map[string]interface{}{
							"Image|endswith": "\\cmd.exe",
						},
						"selection2": map[string]interface{}{
							"Image|endswith": "\\powershell.exe",
						},
						"filter": map[string]interface{}{
							"User": "SYSTEM",
						},
					},
				},
			},
			contains: []string{
				"process where",
				"Image like \"*\\\\cmd.exe\"",
				"Image like \"*\\\\powershell.exe\"",
				" or ",
				"not",
				"User == \"SYSTEM\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := backend.Convert(tt.rule, nil)
			require.NoError(t, err)
			assert.NotEmpty(t, query)
			
			for _, expected := range tt.contains {
				assert.Contains(t, query, expected)
			}
		})
	}
}

func TestElasticsearchBackendFieldMapping(t *testing.T) {
	backend := NewElasticsearchBackend()
	
	// Set field mappings
	mappings := []sigma.FieldMapping{
		{Source: "EventID", Target: "event.code"},
		{Source: "CommandLine", Target: "process.command_line"},
		{Source: "Image", Target: "process.executable"},
	}
	backend.SetFieldMappings(mappings)
	
	rule := &sigma.Rule{
		Title: "Test Field Mapping",
		ID:    "test-mapping",
		LogSource: sigma.LogSource{
			Product:  "windows",
			Category: "process_creation",
		},
		Detection: sigma.Detection{
			Condition: "selection",
			Selections: map[string]interface{}{
				"selection": map[string]interface{}{
					"EventID":               1,
					"CommandLine|contains": "test",
					"Image|endswith":       ".exe",
				},
			},
		},
	}
	
	query, err := backend.Convert(rule, nil)
	require.NoError(t, err)
	assert.Contains(t, query, "event.code == 1")
	assert.Contains(t, query, "process.command_line like")
	assert.Contains(t, query, "process.executable like")
}