// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentifyTypeZip(t *testing.T) {
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00}
	types := IdentifyType(data)
	assert.Contains(t, types, "application/zip")
	assert.Contains(t, types, "*")
}

func TestIdentifyTypeGzip(t *testing.T) {
	data := []byte{0x1F, 0x8B, 0x08, 0x00}
	types := IdentifyType(data)
	assert.Contains(t, types, "application/gzip")
}

func TestIdentifyTypePE(t *testing.T) {
	data := []byte{0x4D, 0x5A, 0x90, 0x00}
	types := IdentifyType(data)
	assert.Contains(t, types, "application/x-dosexec")
}

func TestIdentifyTypeELF(t *testing.T) {
	data := []byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01}
	types := IdentifyType(data)
	assert.Contains(t, types, "application/x-elf")
}

func TestIdentifyTypePDF(t *testing.T) {
	data := []byte("%PDF-1.4 test content")
	types := IdentifyType(data)
	assert.Contains(t, types, "application/pdf")
}

func TestIdentifyTypeHTML(t *testing.T) {
	data := []byte("<!DOCTYPE html><html><body>test</body></html>")
	types := IdentifyType(data)
	assert.Contains(t, types, "text/html")
}

func TestIdentifyTypeJSON(t *testing.T) {
	data := []byte(`{"key": "value"}`)
	types := IdentifyType(data)
	assert.Contains(t, types, "application/json")
}

func TestIdentifyTypeUnknown(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	types := IdentifyType(data)
	// Should still include wildcard
	assert.Contains(t, types, "*")
}

func TestIdentifyType7z(t *testing.T) {
	data := []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}
	types := IdentifyType(data)
	assert.Contains(t, types, "application/x-7z-compressed")
}

func TestIdentifyTypeRAR(t *testing.T) {
	data := []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}
	types := IdentifyType(data)
	assert.Contains(t, types, "application/x-rar")
}

func TestIdentifyTypeOLE(t *testing.T) {
	data := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	types := IdentifyType(data)
	assert.Contains(t, types, "application/x-ole")
}

func TestIdentifyTypeEmail(t *testing.T) {
	data := []byte("Received: from mail.example.com")
	types := IdentifyType(data)
	assert.Contains(t, types, "message/rfc822")
}
