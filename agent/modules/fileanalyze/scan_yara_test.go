// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestYaraScannerInit(t *testing.T) {
	s := NewYaraScanner()
	assert.Equal(t, "ScanYara", s.Name())
	assert.Equal(t, []string{"*"}, s.Flavors())
	assert.Equal(t, 5, s.Priority())
	assert.Equal(t, DEFAULT_YARA_RULES_PATH, s.rulesPath)
}

func TestYaraScannerMissingRules(t *testing.T) {
	s := &YaraScanner{
		rulesPath: "/nonexistent/path/rules.compiled",
		compiled:  true,
		timeout:   10,
	}

	// Should return nil result when rules don't exist (not an error)
	result, err := s.Scan([]byte("test data"), FileMetadata{Name: "test.bin"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestParseYaraOutput(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected []interface{}
	}{
		{
			name:     "no matches",
			output:   "",
			expected: []interface{}{},
		},
		{
			name:     "single match",
			output:   "malware_rule /tmp/test.bin\n",
			expected: []interface{}{"malware_rule"},
		},
		{
			name:     "multiple matches",
			output:   "rule_one /tmp/test.bin\nrule_two /tmp/test.bin\n",
			expected: []interface{}{"rule_one", "rule_two"},
		},
		{
			name:     "with string match details",
			output:   "malware_rule /tmp/test.bin\n0x0:$s1: test_string\n0x10:$s2: other_string\n",
			expected: []interface{}{"malware_rule"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseYaraOutput(tt.output)
			assert.Equal(t, tt.expected, result)
		})
	}
}
