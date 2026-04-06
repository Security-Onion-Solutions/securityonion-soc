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

func TestHashScanner(t *testing.T) {
	s := NewHashScanner()

	assert.Equal(t, "ScanHash", s.Name())
	assert.Equal(t, []string{"*"}, s.Flavors())
	assert.Equal(t, 5, s.Priority())

	tests := []struct {
		name   string
		input  []byte
		md5    string
		sha1   string
		sha256 string
	}{
		{
			name:   "empty file",
			input:  []byte{},
			md5:    "d41d8cd98f00b204e9800998ecf8427e",
			sha1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:   "hello world",
			input:  []byte("hello world"),
			md5:    "5eb63bbbe01eeed093cb22bb8f5acdc3",
			sha1:   "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
			sha256: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.Scan(tt.input, FileMetadata{Name: "test"})
			require.NoError(t, err)
			assert.Equal(t, tt.md5, result.Data["md5"])
			assert.Equal(t, tt.sha1, result.Data["sha1"])
			assert.Equal(t, tt.sha256, result.Data["sha256"])
		})
	}
}
