// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLnkScanner(t *testing.T) {
	s := NewLnkScanner()
	assert.Equal(t, "ScanLNK", s.Name())

	// Create minimal LNK header (76 bytes minimum)
	lnk := make([]byte, 100)
	copy(lnk[:4], lnkMagic)
	// Set flags at offset 20: HasName (0x04) + HasArguments (0x20)
	binary.LittleEndian.PutUint32(lnk[20:24], 0x24)
	// Set attributes at offset 24: Hidden (0x02)
	binary.LittleEndian.PutUint32(lnk[24:28], 0x02)

	result, err := s.Scan(lnk, FileMetadata{Name: "test.lnk"})
	require.NoError(t, err)

	flags := result.Data["flags"].([]interface{})
	assert.Contains(t, flags, "HasName")
	assert.Contains(t, flags, "HasArguments")
	assert.True(t, result.Data["isHidden"].(bool))
}

func TestLnkScannerNotLnk(t *testing.T) {
	s := NewLnkScanner()
	result, err := s.Scan([]byte("not a lnk"), FileMetadata{Name: "test.bin"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestLnkScannerSuspicious(t *testing.T) {
	s := NewLnkScanner()

	lnk := make([]byte, 200)
	copy(lnk[:4], lnkMagic)
	binary.LittleEndian.PutUint32(lnk[20:24], 0x01)
	binary.LittleEndian.PutUint32(lnk[24:28], 0x00)
	// Put "powershell.exe" in the data area
	copy(lnk[80:], []byte("powershell.exe -enc AAAA"))

	result, err := s.Scan(lnk, FileMetadata{Name: "evil.lnk"})
	require.NoError(t, err)

	suspicious := result.Data["suspicious"].([]interface{})
	assert.NotEmpty(t, suspicious)
}

func TestUrlScanner(t *testing.T) {
	s := NewUrlScanner()

	url := []byte("[InternetShortcut]\nURL=https://example.com\nIconFile=icon.ico\nIconIndex=1\n")
	result, err := s.Scan(url, FileMetadata{Name: "test.url"})
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", result.Data["url"])
	assert.Equal(t, "icon.ico", result.Data["iconFile"])
}

func TestIqyScanner(t *testing.T) {
	s := NewIqyScanner()

	iqy := []byte("WEB\n1\nhttps://evil.com/payload\n\n")
	result, err := s.Scan(iqy, FileMetadata{Name: "test.iqy"})
	require.NoError(t, err)

	urls := result.Data["urls"].([]interface{})
	assert.Contains(t, urls, "https://evil.com/payload")
	assert.True(t, result.Data["suspicious"].(bool))
}

func TestJarManifestScanner(t *testing.T) {
	s := NewJarManifestScanner()

	manifest := []byte("Manifest-Version: 1.0\nMain-Class: com.example.Main\nCreated-By: 11.0.2 (Oracle)\n")
	result, err := s.Scan(manifest, FileMetadata{Name: "MANIFEST.MF"})
	require.NoError(t, err)
	assert.Equal(t, "com.example.Main", result.Data["mainClass"])
	assert.Equal(t, "1.0", result.Data["manifestVersion"])
}

func TestManifestScannerInit(t *testing.T) {
	s := NewManifestScanner()
	assert.Equal(t, "ScanManifest", s.Name())
}

func TestVstoScannerInit(t *testing.T) {
	s := NewVstoScanner()
	assert.Equal(t, "ScanVsto", s.Name())
}

func TestExiftoolScannerInit(t *testing.T) {
	s := NewExiftoolScanner()
	assert.Equal(t, "ScanExiftool", s.Name())
	assert.Equal(t, 9, s.Priority()) // Late runner
}
