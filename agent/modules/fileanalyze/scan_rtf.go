// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	rtfObjectPattern  = regexp.MustCompile(`(?i)\\object`)
	rtfObjDataPattern = regexp.MustCompile(`(?i)\\objdata\s+([0-9a-fA-F\s]+)`)
	rtfOLEPattern     = regexp.MustCompile(`(?i)\\objemb|\\objlink|\\objautlnk`)
	rtfEquationPattern = regexp.MustCompile(`(?i)equation\.3|equation native`)
)

type RtfScanner struct{}

func NewRtfScanner() *RtfScanner {
	return &RtfScanner{}
}

func (s *RtfScanner) Name() string { return "ScanRtf" }

func (s *RtfScanner) Init(config map[string]interface{}) error { return nil }

func (s *RtfScanner) Flavors() []string {
	return []string{"application/rtf", "text/rtf"}
}

func (s *RtfScanner) Priority() int { return 5 }

func (s *RtfScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	if !bytes.HasPrefix(file, []byte(`{\rtf`)) {
		return nil, nil
	}

	content := string(file)
	var extracted []ExtractedFile

	// Count embedded objects
	objectCount := len(rtfObjectPattern.FindAllStringIndex(content, -1))

	// Check for OLE objects
	hasOLE := rtfOLEPattern.MatchString(content)

	// Check for equation editor (CVE-2017-11882 and similar)
	hasEquation := rtfEquationPattern.MatchString(content)

	// Extract embedded object data
	objDataMatches := rtfObjDataPattern.FindAllStringSubmatch(content, 10)
	for i, match := range objDataMatches {
		if len(match) > 1 {
			hexData := strings.ReplaceAll(match[1], " ", "")
			hexData = strings.ReplaceAll(hexData, "\r", "")
			hexData = strings.ReplaceAll(hexData, "\n", "")
			if len(hexData) > 0 && len(hexData)%2 == 0 {
				decoded, err := hex.DecodeString(hexData)
				if err == nil && len(decoded) > 0 {
					extracted = append(extracted, ExtractedFile{
						Name:    metadata.Name + ".objdata." + string(rune('0'+i)),
						Content: decoded,
					})
				}
			}
		}
	}

	// Look for suspicious control words
	var suspicious []interface{}
	suspiciousWords := []string{
		`\objupdate`, `\objdata`, `\objemb`, `\objlink`,
		`\ddeauto`, `\dde`,
	}
	for _, word := range suspiciousWords {
		if strings.Contains(content, word) {
			suspicious = append(suspicious, word)
		}
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"objects":     objectCount,
			"hasOLE":      hasOLE,
			"hasEquation": hasEquation,
			"suspicious":  suspicious,
		},
		Files: extracted,
	}, nil
}
