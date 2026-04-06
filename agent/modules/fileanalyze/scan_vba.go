// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"io"
	"strings"

	"github.com/richardlehane/mscfb"
)

// Suspicious VBA keywords that may indicate malicious macros
var suspiciousVBAKeywords = []string{
	"AutoOpen", "AutoClose", "AutoExec", "Auto_Open", "Auto_Close",
	"Document_Open", "Document_Close", "Workbook_Open",
	"Shell", "WScript", "CreateObject", "GetObject",
	"PowerShell", "cmd.exe", "cmd /c",
	"URLDownloadToFile", "XMLHTTP", "WinHttp",
	"Environ", "CallByName",
	"Chr(", "ChrW(", "Asc(",
	"Base64", "FromBase64",
	"RegWrite", "RegRead", "RegDelete",
	"Kill ", "FileCopy", "MkDir",
}

type VbaScanner struct{}

func NewVbaScanner() *VbaScanner {
	return &VbaScanner{}
}

func (s *VbaScanner) Name() string { return "ScanVba" }

func (s *VbaScanner) Init(config map[string]interface{}) error { return nil }

func (s *VbaScanner) Flavors() []string {
	return []string{"application/x-ole", "application/vnd.ms-excel", "application/msword"}
}

func (s *VbaScanner) Priority() int { return 6 } // After OLE scanner

func (s *VbaScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	doc, err := mscfb.New(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	var macroStreams []interface{}
	var macroCode []string
	var suspicious []interface{}
	hasMacros := false

	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		name := strings.ToLower(entry.Name)

		// VBA macro streams are typically in "VBA" directory or have specific names
		isVBA := strings.Contains(name, "vba") ||
			strings.Contains(name, "macro") ||
			strings.Contains(name, "module") ||
			name == "thisworkbook" ||
			name == "thisdocument" ||
			name == "sheet1" ||
			name == "sheet2" ||
			name == "sheet3"

		if !isVBA || entry.Size == 0 {
			continue
		}

		hasMacros = true
		macroStreams = append(macroStreams, entry.Name)

		if entry.Size < DEFAULT_MAX_FILE_SIZE {
			data, readErr := io.ReadAll(entry)
			if readErr != nil {
				continue
			}

			// Look for readable VBA code in the stream
			code := extractReadableStrings(data, 6)
			if len(code) > 0 {
				macroCode = append(macroCode, code...)
			}

			// Check for suspicious keywords
			content := string(data)
			for _, keyword := range suspiciousVBAKeywords {
				if strings.Contains(content, keyword) {
					suspicious = append(suspicious, keyword)
				}
			}
		}
	}

	if !hasMacros {
		return &ScanResult{
			Scanner: s.Name(),
			Data: map[string]interface{}{
				"hasMacros": false,
			},
		}, nil
	}

	// Deduplicate suspicious keywords
	suspicious = deduplicateSlice(suspicious)

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"hasMacros":    true,
			"macroStreams": macroStreams,
			"suspicious":  suspicious,
		},
	}, nil
}

// extractReadableStrings pulls printable ASCII strings of minLen or longer from binary data
func extractReadableStrings(data []byte, minLen int) []string {
	var result []string
	var current []byte

	for _, b := range data {
		if b >= 0x20 && b <= 0x7E {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				result = append(result, string(current))
			}
			current = current[:0]
		}
	}
	if len(current) >= minLen {
		result = append(result, string(current))
	}
	return result
}

func deduplicateSlice(input []interface{}) []interface{} {
	seen := make(map[interface{}]bool)
	var result []interface{}
	for _, v := range input {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
