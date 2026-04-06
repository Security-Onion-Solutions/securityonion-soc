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

func TestHtmlScanner(t *testing.T) {
	s := NewHtmlScanner()
	assert.Equal(t, "ScanHtml", s.Name())

	html := []byte(`<!DOCTYPE html><html><head><title>Test Page</title></head>
<body>
<script>alert(1)</script>
<script src="evil.js"></script>
<iframe src="http://evil.com"></iframe>
<form action="/login" method="post"><input type="text"></form>
</body></html>`)

	result, err := s.Scan(html, FileMetadata{Name: "test.html"})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Data["scripts"])
	assert.Equal(t, 1, result.Data["iframes"])
	assert.Equal(t, 1, result.Data["forms"])
	assert.Equal(t, "Test Page", result.Data["title"])
}

func TestHtmlScannerSuspicious(t *testing.T) {
	s := NewHtmlScanner()

	html := []byte(`<html><body>
<object data="malware.swf"></object>
<meta http-equiv="refresh" content="0;url=http://evil.com">
<img src="x" onerror="alert(1)">
<a href="data:text/html;base64,PHNjcmlwdD4=">click</a>
</body></html>`)

	result, err := s.Scan(html, FileMetadata{Name: "phish.html"})
	require.NoError(t, err)

	suspicious := result.Data["suspicious"].([]interface{})
	assert.Contains(t, suspicious, "object_tag")
	assert.Contains(t, suspicious, "meta_refresh")
	assert.Contains(t, suspicious, "event_handlers")
	assert.Contains(t, suspicious, "base64_data_uri")
}

func TestXmlScanner(t *testing.T) {
	s := NewXmlScanner()

	xml := []byte(`<?xml version="1.0"?>
<root xmlns:ns="http://example.com">
  <child>data</child>
  <child>more</child>
</root>`)

	result, err := s.Scan(xml, FileMetadata{Name: "test.xml"})
	require.NoError(t, err)
	assert.Equal(t, "root", result.Data["rootElement"])
	assert.Equal(t, 3, result.Data["elementCount"]) // root + 2 children
}

func TestXmlScannerXXE(t *testing.T) {
	s := NewXmlScanner()

	xml := []byte(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>`)

	result, err := s.Scan(xml, FileMetadata{Name: "xxe.xml"})
	require.NoError(t, err)

	suspicious := result.Data["suspicious"].([]interface{})
	assert.Contains(t, suspicious, "XXE_entity_declaration")
	assert.Contains(t, suspicious, "external_entity")
}

func TestJsonScanner(t *testing.T) {
	s := NewJsonScanner()

	result, err := s.Scan([]byte(`{"key": "value", "num": 42}`), FileMetadata{Name: "test.json"})
	require.NoError(t, err)
	assert.True(t, result.Data["valid"].(bool))
	assert.Equal(t, "object", result.Data["type"])
	assert.Equal(t, 2, result.Data["keys"])
}

func TestJsonScannerArray(t *testing.T) {
	s := NewJsonScanner()

	result, err := s.Scan([]byte(`[1, 2, 3]`), FileMetadata{Name: "test.json"})
	require.NoError(t, err)
	assert.Equal(t, "array", result.Data["type"])
	assert.Equal(t, 3, result.Data["length"])
}

func TestJsonScannerInvalid(t *testing.T) {
	s := NewJsonScanner()

	result, err := s.Scan([]byte(`{invalid json`), FileMetadata{Name: "bad.json"})
	require.NoError(t, err)
	assert.False(t, result.Data["valid"].(bool))
}

func TestIniScanner(t *testing.T) {
	s := NewIniScanner()

	ini := []byte(`; comment
[section1]
key1=value1
key2=value2

[section2]
key3=value3`)

	result, err := s.Scan(ini, FileMetadata{Name: "test.ini"})
	require.NoError(t, err)
	sections := result.Data["sections"].([]interface{})
	assert.Len(t, sections, 2)
	assert.Contains(t, sections, "section1")
	assert.Equal(t, 3, result.Data["keys"])
}
