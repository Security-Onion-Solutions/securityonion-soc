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

func TestBmpEofScanner(t *testing.T) {
	s := NewBmpEofScanner()
	assert.Equal(t, "ScanBmpEof", s.Name())

	// Create minimal BMP header: BM + size(4) + reserved(4) + offset(4)
	bmp := make([]byte, 100)
	bmp[0], bmp[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(bmp[2:6], 80) // Declared size 80

	result, err := s.Scan(bmp, FileMetadata{Name: "test.bmp"})
	require.NoError(t, err)
	assert.True(t, result.Data["hasTrailingData"].(bool))
	assert.Equal(t, uint32(20), result.Data["trailingDataSize"].(uint32))
	assert.Len(t, result.Files, 1) // Extracted trailing data
}

func TestBmpEofScannerNoTrailing(t *testing.T) {
	s := NewBmpEofScanner()

	bmp := make([]byte, 80)
	bmp[0], bmp[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(bmp[2:6], 80)

	result, err := s.Scan(bmp, FileMetadata{Name: "clean.bmp"})
	require.NoError(t, err)
	assert.False(t, result.Data["hasTrailingData"].(bool))
}

func TestBmpEofScannerNotBmp(t *testing.T) {
	s := NewBmpEofScanner()
	result, err := s.Scan([]byte("not a bmp"), FileMetadata{Name: "test.bin"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestPngEofScannerInit(t *testing.T) {
	s := NewPngEofScanner()
	assert.Equal(t, "ScanPngEof", s.Name())
	assert.Contains(t, s.Flavors(), "image/png")
}

func TestGifScannerInit(t *testing.T) {
	s := NewGifScanner()
	assert.Equal(t, "ScanGif", s.Name())
	assert.Contains(t, s.Flavors(), "image/gif")
}

func TestJpegScannerInit(t *testing.T) {
	s := NewJpegScanner()
	assert.Equal(t, "ScanJpeg", s.Name())
	assert.Contains(t, s.Flavors(), "image/jpeg")
}

func TestLsbScannerInit(t *testing.T) {
	s := NewLsbScanner()
	assert.Equal(t, "ScanLsb", s.Name())
	assert.Equal(t, 7, s.Priority())
}

func TestOcrScannerInit(t *testing.T) {
	s := NewOcrScanner()
	assert.Equal(t, "ScanOcr", s.Name())
	assert.Equal(t, 8, s.Priority())
}

func TestQrScannerInit(t *testing.T) {
	s := NewQrScanner()
	assert.Equal(t, "ScanQr", s.Name())
	assert.Equal(t, 8, s.Priority())
}

func TestTranscodeScannerInit(t *testing.T) {
	s := NewTranscodeScanner()
	assert.Equal(t, "ScanTranscode", s.Name())
	assert.Equal(t, 4, s.Priority()) // Before other image scanners
}

func TestTruncateString(t *testing.T) {
	assert.Equal(t, "hello", truncateString("hello", 10))
	assert.Equal(t, "hel...", truncateString("hello world", 3))
}

func TestMathRound(t *testing.T) {
	assert.Equal(t, 3.142, math_round(3.14159, 3))
	assert.Equal(t, 3.14, math_round(3.14159, 2))
	assert.Equal(t, 0.0, math_round(0, 3))
}

func TestExtractPrintable(t *testing.T) {
	data := []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x01, 0x57, 0x6F, 0x72, 0x6C, 0x64}
	assert.Equal(t, "HelloWorld", extractPrintable(data, 100))
	assert.Equal(t, "Hel", extractPrintable(data, 3))
}
