// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"regexp"
	"strings"
)

var (
	pdfObjPattern       = regexp.MustCompile(`\d+ \d+ obj`)
	pdfStreamPattern    = regexp.MustCompile(`(?s)stream\r?\n`)
	pdfEndStreamPattern = regexp.MustCompile(`endstream`)
	pdfJSPattern        = regexp.MustCompile(`(?i)/JavaScript|/JS\s`)
	pdfActionPattern    = regexp.MustCompile(`(?i)/OpenAction|/AA\s|/Launch`)
	pdfURIPattern       = regexp.MustCompile(`(?i)/URI\s*\((https?://[^)]+)\)`)
	pdfEmbeddedPattern  = regexp.MustCompile(`(?i)/EmbeddedFile`)
	pdfEncryptPattern   = regexp.MustCompile(`(?i)/Encrypt`)
	pdfXFAPattern       = regexp.MustCompile(`(?i)/XFA`)
	pdfObjStmPattern    = regexp.MustCompile(`(?i)/ObjStm`)
)

type PdfScanner struct {
	limit int
}

func NewPdfScanner() *PdfScanner {
	return &PdfScanner{limit: 2000}
}

func (s *PdfScanner) Name() string { return "ScanPdf" }

func (s *PdfScanner) Init(config map[string]interface{}) error {
	if config != nil {
		if v, ok := config["limit"]; ok {
			s.limit = int(v.(float64))
		}
	}
	return nil
}

func (s *PdfScanner) Flavors() []string {
	return []string{"application/pdf"}
}

func (s *PdfScanner) Priority() int { return 5 }

func (s *PdfScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)

	// Extract PDF version
	version := ""
	if strings.HasPrefix(content, "%PDF-") {
		endLine := strings.IndexByte(content, '\n')
		if endLine > 0 && endLine < 20 {
			version = strings.TrimSpace(content[5:endLine])
		}
	}

	// Count objects and streams
	objects := len(pdfObjPattern.FindAllStringIndex(content, s.limit))
	streams := len(pdfStreamPattern.FindAllStringIndex(content, s.limit))

	// Detect suspicious features
	hasJavaScript := pdfJSPattern.MatchString(content)
	hasAutoAction := pdfActionPattern.MatchString(content)
	hasEmbedded := pdfEmbeddedPattern.MatchString(content)
	isEncrypted := pdfEncryptPattern.MatchString(content)
	hasXFA := pdfXFAPattern.MatchString(content)
	hasObjStm := pdfObjStmPattern.MatchString(content)

	// Extract URIs
	var uris []interface{}
	uriMatches := pdfURIPattern.FindAllStringSubmatch(content, 50)
	for _, m := range uriMatches {
		if len(m) > 1 {
			uris = append(uris, m[1])
		}
	}

	// Build suspicious indicators
	var suspicious []interface{}
	if hasJavaScript {
		suspicious = append(suspicious, "/JavaScript")
	}
	if hasAutoAction {
		suspicious = append(suspicious, "/OpenAction or /AA or /Launch")
	}
	if hasXFA {
		suspicious = append(suspicious, "/XFA (XML Forms)")
	}

	result := map[string]interface{}{
		"version":       version,
		"objects":       objects,
		"streams":       streams,
		"hasJavaScript": hasJavaScript,
		"hasAutoAction": hasAutoAction,
		"hasEmbedded":   hasEmbedded,
		"isEncrypted":   isEncrypted,
		"hasObjStm":     hasObjStm,
	}

	if len(uris) > 0 {
		result["uris"] = uris
	}
	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
	}, nil
}
