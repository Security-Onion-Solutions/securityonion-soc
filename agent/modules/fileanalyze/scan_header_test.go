// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderScanner(t *testing.T) {
	s := NewHeaderScanner()

	assert.Equal(t, "ScanHeader", s.Name())

	tests := []struct {
		name           string
		input          []byte
		expectedHeader string
		expectedFooter string
	}{
		{
			name:           "file smaller than header size",
			input:          []byte("hello"),
			expectedHeader: hex.EncodeToString([]byte("hello")),
			expectedFooter: hex.EncodeToString([]byte("hello")),
		},
		{
			name:           "file exactly header size",
			input:          make([]byte, 50),
			expectedHeader: hex.EncodeToString(make([]byte, 50)),
			expectedFooter: hex.EncodeToString(make([]byte, 50)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.Scan(tt.input, FileMetadata{Name: "test"})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedHeader, result.Data["header"])
			assert.Equal(t, tt.expectedFooter, result.Data["footer"])
		})
	}
}

func TestHeaderScannerLargeFile(t *testing.T) {
	s := NewHeaderScanner()

	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}

	result, err := s.Scan(data, FileMetadata{Name: "test"})
	require.NoError(t, err)

	header := result.Data["header"].(string)
	footer := result.Data["footer"].(string)

	// Header should be first 50 bytes
	expectedHeader := hex.EncodeToString(data[:50])
	assert.Equal(t, expectedHeader, header)

	// Footer should be last 50 bytes
	expectedFooter := hex.EncodeToString(data[150:])
	assert.Equal(t, expectedFooter, footer)
}
