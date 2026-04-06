// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntropyScanner(t *testing.T) {
	s := NewEntropyScanner()

	assert.Equal(t, "ScanEntropy", s.Name())

	tests := []struct {
		name     string
		input    []byte
		expected float64
	}{
		{
			name:     "empty file",
			input:    []byte{},
			expected: 0.0,
		},
		{
			name:     "single byte repeated",
			input:    []byte("aaaaaaaaaa"),
			expected: 0.0,
		},
		{
			name:     "two bytes equally distributed",
			input:    []byte("ababababab"),
			expected: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.Scan(tt.input, FileMetadata{Name: "test"})
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result.Data["entropy"])
		})
	}
}

func TestEntropyHighEntropy(t *testing.T) {
	s := NewEntropyScanner()

	// All 256 byte values — maximum entropy (8.0)
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}

	result, err := s.Scan(data, FileMetadata{Name: "test"})
	require.NoError(t, err)

	entropy := result.Data["entropy"].(float64)
	assert.Equal(t, 8.0, entropy)
}
