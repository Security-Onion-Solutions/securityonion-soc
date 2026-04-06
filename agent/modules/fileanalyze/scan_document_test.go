// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDocxScanner(t *testing.T) {
	s := NewDocxScanner()
	assert.Equal(t, "ScanDocx", s.Name())
	assert.Contains(t, s.Flavors(), "application/vnd.openxmlformats-officedocument")

	// Create a minimal docx-like zip
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add content types
	ct, _ := w.Create("[Content_Types].xml")
	ct.Write([]byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`))

	// Add core properties
	core, _ := w.Create("docProps/core.xml")
	core.Write([]byte(`<?xml version="1.0"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:title>Test Document</dc:title>
  <dc:creator>Test Author</dc:creator>
</cp:coreProperties>`))

	// Add a relationships file
	rels, _ := w.Create("_rels/.rels")
	rels.Write([]byte(`<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`))

	doc, _ := w.Create("word/document.xml")
	doc.Write([]byte(`<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>`))

	require.NoError(t, w.Close())

	result, err := s.Scan(buf.Bytes(), FileMetadata{Name: "test.docx"})
	require.NoError(t, err)
	assert.Equal(t, "ScanDocx", result.Scanner)
	assert.False(t, result.Data["hasMacro"].(bool))

	parts := result.Data["parts"].([]interface{})
	assert.Contains(t, parts, "[Content_Types].xml")
	assert.Contains(t, parts, "docProps/core.xml")

	// Check properties were extracted
	props := result.Data["properties"].(map[string]interface{})
	assert.Equal(t, "Test Document", props["title"])
	assert.Equal(t, "Test Author", props["creator"])
}

func TestDocxScannerWithVBA(t *testing.T) {
	s := NewDocxScanner()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	ct, _ := w.Create("[Content_Types].xml")
	ct.Write([]byte(`<?xml version="1.0"?><Types></Types>`))

	// Add a vbaProject.bin to simulate macros
	vba, _ := w.Create("word/vbaProject.bin")
	vba.Write([]byte{0xD0, 0xCF, 0x11, 0xE0}) // OLE header

	require.NoError(t, w.Close())

	result, err := s.Scan(buf.Bytes(), FileMetadata{Name: "macro.docm"})
	require.NoError(t, err)
	assert.True(t, result.Data["hasMacro"].(bool))
	assert.Len(t, result.Files, 1)
	assert.Equal(t, "vbaProject.bin", result.Files[0].Name)
}

func TestRtfScanner(t *testing.T) {
	s := NewRtfScanner()
	assert.Equal(t, "ScanRtf", s.Name())

	// Basic RTF
	rtf := []byte(`{\rtf1\ansi Hello World}`)
	result, err := s.Scan(rtf, FileMetadata{Name: "test.rtf"})
	require.NoError(t, err)
	assert.Equal(t, 0, result.Data["objects"])
	assert.False(t, result.Data["hasOLE"].(bool))
	assert.False(t, result.Data["hasEquation"].(bool))
}

func TestRtfScannerWithObjects(t *testing.T) {
	s := NewRtfScanner()

	rtf := []byte(`{\rtf1\ansi\object\objemb some content \objdata 48656C6C6F }`)
	result, err := s.Scan(rtf, FileMetadata{Name: "malicious.rtf"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Data["objects"])
	assert.True(t, result.Data["hasOLE"].(bool))

	suspicious := result.Data["suspicious"].([]interface{})
	assert.Contains(t, suspicious, `\objdata`)
	assert.Contains(t, suspicious, `\objemb`)
}

func TestRtfScannerNotRtf(t *testing.T) {
	s := NewRtfScanner()

	result, err := s.Scan([]byte("not an rtf file"), FileMetadata{Name: "test.txt"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestPdfScanner(t *testing.T) {
	s := NewPdfScanner()
	assert.Equal(t, "ScanPdf", s.Name())

	pdf := []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
2 0 obj
<< /Type /Page >>
endobj
`)
	result, err := s.Scan(pdf, FileMetadata{Name: "test.pdf"})
	require.NoError(t, err)
	assert.Equal(t, "1.4", result.Data["version"])
	assert.Equal(t, 2, result.Data["objects"])
	assert.False(t, result.Data["hasJavaScript"].(bool))
	assert.False(t, result.Data["isEncrypted"].(bool))
}

func TestPdfScannerSuspicious(t *testing.T) {
	s := NewPdfScanner()

	pdf := []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert("test")) >>
endobj
/URI (https://evil.example.com/payload)
`)
	result, err := s.Scan(pdf, FileMetadata{Name: "malicious.pdf"})
	require.NoError(t, err)
	assert.True(t, result.Data["hasJavaScript"].(bool))
	assert.True(t, result.Data["hasAutoAction"].(bool))

	uris := result.Data["uris"].([]interface{})
	assert.Contains(t, uris, "https://evil.example.com/payload")

	suspicious := result.Data["suspicious"].([]interface{})
	assert.Contains(t, suspicious, "/JavaScript")
}

func TestEmailScanner(t *testing.T) {
	s := NewEmailScanner()
	assert.Equal(t, "ScanEmail", s.Name())

	email := []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <test@example.com>\r\n\r\nHello World\r\n")

	result, err := s.Scan(email, FileMetadata{Name: "test.eml"})
	require.NoError(t, err)
	assert.Equal(t, "ScanEmail", result.Scanner)

	headers := result.Data["headers"].(map[string]interface{})
	assert.Equal(t, "sender@example.com", headers["From"])
	assert.Equal(t, "recipient@example.com", headers["To"])
	assert.Equal(t, "Test", headers["Subject"])
}

func TestOleScannerInit(t *testing.T) {
	s := NewOleScanner()
	assert.Equal(t, "ScanOle", s.Name())
	assert.Contains(t, s.Flavors(), "application/x-ole")
}

func TestVbaScannerInit(t *testing.T) {
	s := NewVbaScanner()
	assert.Equal(t, "ScanVba", s.Name())
	assert.Equal(t, 6, s.Priority()) // After OLE
}

func TestTnefScannerInit(t *testing.T) {
	s := NewTnefScanner()
	assert.Equal(t, "ScanTnef", s.Name())
	assert.Contains(t, s.Flavors(), "application/ms-tnef")
}

func TestTnefScannerNotTnef(t *testing.T) {
	s := NewTnefScanner()
	result, err := s.Scan([]byte("not a tnef file"), FileMetadata{Name: "test.bin"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestOnenoteScannerInit(t *testing.T) {
	s := NewOnenoteScanner()
	assert.Equal(t, "ScanOnenote", s.Name())
	assert.Contains(t, s.Flavors(), "application/onenote")
}

func TestOnenoteScannerNotOnenote(t *testing.T) {
	s := NewOnenoteScanner()
	result, err := s.Scan([]byte("not a onenote file"), FileMetadata{Name: "test.bin"})
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestEncryptedZipScannerMissingPasswords(t *testing.T) {
	s := &EncryptedZipScanner{
		passwordsPath: "/nonexistent/passwords.dat",
		timeout:       10,
	}

	result, err := s.Scan([]byte("test"), FileMetadata{Name: "test.zip"})
	assert.NoError(t, err)
	assert.False(t, result.Data["cracked"].(bool))
	assert.Equal(t, "password list not found", result.Data["error"])
}

func TestEncryptedDocScannerMissingPasswords(t *testing.T) {
	s := &EncryptedDocScanner{
		passwordsPath: "/nonexistent/passwords.dat",
		timeout:       10,
	}

	result, err := s.Scan([]byte("test"), FileMetadata{Name: "test.doc"})
	assert.NoError(t, err)
	assert.False(t, result.Data["cracked"].(bool))
}

func TestLoadPasswords(t *testing.T) {
	tmpFile := t.TempDir() + "/passwords.dat"
	content := []byte("password1\npassword2\n# comment\n\npassword3\n")
	require.NoError(t, os.WriteFile(tmpFile, content, 0644))

	passwords, err := loadPasswords(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, []string{"password1", "password2", "password3"}, passwords)
}

func TestLoadPasswordsFileNotFound(t *testing.T) {
	_, err := loadPasswords("/nonexistent/file")
	assert.Error(t, err)
}
