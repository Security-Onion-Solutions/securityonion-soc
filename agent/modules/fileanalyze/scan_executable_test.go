// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPeScannerInit(t *testing.T) {
	s := NewPeScanner()
	assert.Equal(t, "ScanPe", s.Name())
	assert.Contains(t, s.Flavors(), "application/x-dosexec")
	assert.Equal(t, 5, s.Priority())
}

func TestPeScannerInvalidFile(t *testing.T) {
	s := NewPeScanner()
	// Not a valid PE
	_, err := s.Scan([]byte("not a PE file"), FileMetadata{Name: "test.exe"})
	assert.Error(t, err)
}

func TestElfScannerInit(t *testing.T) {
	s := NewElfScanner()
	assert.Equal(t, "ScanElf", s.Name())
	assert.Contains(t, s.Flavors(), "application/x-elf")
	assert.Equal(t, 5, s.Priority())
}

func TestElfScannerInvalidFile(t *testing.T) {
	s := NewElfScanner()
	_, err := s.Scan([]byte("not an ELF file"), FileMetadata{Name: "test"})
	assert.Error(t, err)
}

func TestMachoScannerInit(t *testing.T) {
	s := NewMachoScanner()
	assert.Equal(t, "ScanMacho", s.Name())
	assert.Contains(t, s.Flavors(), "application/x-mach-binary")
}

func TestMachoScannerInvalidFile(t *testing.T) {
	s := NewMachoScanner()
	_, err := s.Scan([]byte("not a mach-o file"), FileMetadata{Name: "test"})
	assert.Error(t, err)
}

func TestSubsystemName(t *testing.T) {
	assert.Equal(t, "NATIVE", subsystemName(1))
	assert.Equal(t, "WINDOWS_GUI", subsystemName(2))
	assert.Equal(t, "WINDOWS_CUI", subsystemName(3))
	assert.Equal(t, "UNKNOWN", subsystemName(99))
}

func TestShannonEntropy(t *testing.T) {
	// All same bytes = 0 entropy
	data := make([]byte, 100)
	assert.Equal(t, 0.0, shannonEntropy(data))

	// All different bytes = max entropy
	data = make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	assert.InDelta(t, 8.0, shannonEntropy(data), 0.001)

	// Empty = 0
	assert.Equal(t, 0.0, shannonEntropy(nil))
}

func TestSplitImport(t *testing.T) {
	parts := splitImport("kernel32.dll:CreateFileA")
	assert.Equal(t, []string{"kernel32.dll", "CreateFileA"}, parts)

	parts = splitImport("nocolon")
	assert.Equal(t, []string{"nocolon"}, parts)
}

func TestParseDllCharacteristics(t *testing.T) {
	chars := parseDllCharacteristics(0x0040 | 0x0100) // DYNAMIC_BASE + NX_COMPAT
	assert.Contains(t, chars, "DYNAMIC_BASE")
	assert.Contains(t, chars, "NX_COMPAT")
}
