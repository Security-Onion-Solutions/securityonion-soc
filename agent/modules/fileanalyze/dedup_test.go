// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupInMemory(t *testing.T) {
	dedup := NewDedup(100, 3600, "")

	// Create temp file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("test content"), 0644))

	// First check — not a duplicate
	isDup, hash, err := dedup.IsDuplicate(filePath)
	require.NoError(t, err)
	assert.False(t, isDup)
	assert.NotEmpty(t, hash)

	// Mark as seen
	require.NoError(t, dedup.MarkSeen(hash))

	// Second check — is a duplicate
	isDup, _, err = dedup.IsDuplicate(filePath)
	require.NoError(t, err)
	assert.True(t, isDup)
}

func TestDedupOnDisk(t *testing.T) {
	historyDir := t.TempDir()
	dedup := NewDedup(100, 3600, historyDir)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("test content"), 0644))

	_, hash, err := dedup.IsDuplicate(filePath)
	require.NoError(t, err)
	require.NoError(t, dedup.MarkSeen(hash))

	// Verify history file was created on disk
	histFile := filepath.Join(historyDir, hash)
	_, err = os.Stat(histFile)
	assert.NoError(t, err)

	// New dedup instance (simulating restart) should find the file on disk
	dedup2 := NewDedup(100, 3600, historyDir)
	isDup, _, err := dedup2.IsDuplicate(filePath)
	require.NoError(t, err)
	assert.True(t, isDup)
}

func TestDedupEviction(t *testing.T) {
	dedup := NewDedup(2, 3600, "")

	tmpDir := t.TempDir()

	// Create 3 different files
	for i, content := range []string{"file1", "file2", "file3"} {
		path := filepath.Join(tmpDir, content)
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))

		_, hash, err := dedup.IsDuplicate(path)
		require.NoError(t, err)
		require.NoError(t, dedup.MarkSeen(hash))

		_ = i
	}

	// Cache should have at most 2 entries
	assert.LessOrEqual(t, len(dedup.cache), 2)
}
