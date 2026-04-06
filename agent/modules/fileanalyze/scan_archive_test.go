// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZipScanner(t *testing.T) {
	s := NewZipScanner()
	assert.Equal(t, "ScanZip", s.Name())

	// Create a zip in memory
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f, err := w.Create("test.txt")
	require.NoError(t, err)
	_, err = f.Write([]byte("hello from zip"))
	require.NoError(t, err)

	f2, err := w.Create("subdir/other.txt")
	require.NoError(t, err)
	_, err = f2.Write([]byte("another file"))
	require.NoError(t, err)

	require.NoError(t, w.Close())

	result, err := s.Scan(buf.Bytes(), FileMetadata{Name: "test.zip"})
	require.NoError(t, err)
	assert.Equal(t, "ScanZip", result.Scanner)
	assert.Equal(t, 2, result.Data["total"])
	assert.Equal(t, 2, result.Data["extracted"])
	assert.Len(t, result.Files, 2)
	assert.Equal(t, "test.txt", result.Files[0].Name)
	assert.Equal(t, []byte("hello from zip"), result.Files[0].Content)
}

func TestZipScannerLimit(t *testing.T) {
	s := &ZipScanner{limit: 1, maxFileSize: DEFAULT_MAX_FILE_SIZE}

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		f, err := w.Create(name)
		require.NoError(t, err)
		_, err = f.Write([]byte("data"))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	result, err := s.Scan(buf.Bytes(), FileMetadata{Name: "test.zip"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Data["extracted"])
	assert.Len(t, result.Files, 1)
}

func TestGzipScanner(t *testing.T) {
	s := NewGzipScanner()
	assert.Equal(t, "ScanGzip", s.Name())

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write([]byte("hello from gzip"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	result, err := s.Scan(buf.Bytes(), FileMetadata{Name: "test.gz"})
	require.NoError(t, err)
	assert.Equal(t, "ScanGzip", result.Scanner)
	assert.Equal(t, 15, result.Data["decompressedSize"])
	assert.Len(t, result.Files, 1)
	assert.Equal(t, []byte("hello from gzip"), result.Files[0].Content)
	assert.Equal(t, "test", result.Files[0].Name) // .gz stripped
}

func TestBzip2Scanner(t *testing.T) {
	s := NewBzip2Scanner()
	assert.Equal(t, "ScanBzip2", s.Name())
	assert.Contains(t, s.Flavors(), "application/x-bzip2")
}

func TestTarScanner(t *testing.T) {
	s := NewTarScanner()
	assert.Equal(t, "ScanTar", s.Name())

	var buf bytes.Buffer
	w := tar.NewWriter(&buf)

	content := []byte("hello from tar")
	hdr := &tar.Header{
		Name: "test.txt",
		Mode: 0600,
		Size: int64(len(content)),
	}
	require.NoError(t, w.WriteHeader(hdr))
	_, err := w.Write(content)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	result, err := s.Scan(buf.Bytes(), FileMetadata{Name: "test.tar"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Data["extracted"])
	assert.Len(t, result.Files, 1)
	assert.Equal(t, "test.txt", result.Files[0].Name)
	assert.Equal(t, content, result.Files[0].Content)
}

func TestZlibScanner(t *testing.T) {
	s := NewZlibScanner()
	assert.Equal(t, "ScanZlib", s.Name())
	assert.Contains(t, s.Flavors(), "application/zlib")
}
