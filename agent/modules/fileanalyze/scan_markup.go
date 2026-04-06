// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
)

// HtmlScanner analyzes HTML files for suspicious content
type HtmlScanner struct{}

func NewHtmlScanner() *HtmlScanner { return &HtmlScanner{} }

func (s *HtmlScanner) Name() string                                  { return "ScanHtml" }
func (s *HtmlScanner) Init(config map[string]interface{}) error       { return nil }
func (s *HtmlScanner) Flavors() []string                              { return []string{"text/html"} }
func (s *HtmlScanner) Priority() int                                  { return 5 }

var (
	htmlScriptPattern  = regexp.MustCompile(`(?i)<script[^>]*>`)
	htmlIframePattern  = regexp.MustCompile(`(?i)<iframe[^>]*>`)
	htmlObjectPattern  = regexp.MustCompile(`(?i)<object[^>]*>`)
	htmlEmbedPattern   = regexp.MustCompile(`(?i)<embed[^>]*>`)
	htmlFormPattern    = regexp.MustCompile(`(?i)<form[^>]*action\s*=`)
	htmlMetaRefresh    = regexp.MustCompile(`(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh`)
	htmlBase64Data     = regexp.MustCompile(`(?i)data:[^;]+;base64,`)
	htmlEventHandlers  = regexp.MustCompile(`(?i)\bon(load|error|click|mouseover|focus|blur)\s*=`)
)

func (s *HtmlScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)

	result := map[string]interface{}{
		"scripts": len(htmlScriptPattern.FindAllStringIndex(content, -1)),
		"iframes": len(htmlIframePattern.FindAllStringIndex(content, -1)),
		"forms":   len(htmlFormPattern.FindAllStringIndex(content, -1)),
	}

	var suspicious []interface{}
	if htmlObjectPattern.MatchString(content) {
		suspicious = append(suspicious, "object_tag")
	}
	if htmlEmbedPattern.MatchString(content) {
		suspicious = append(suspicious, "embed_tag")
	}
	if htmlMetaRefresh.MatchString(content) {
		suspicious = append(suspicious, "meta_refresh")
	}
	if htmlBase64Data.MatchString(content) {
		suspicious = append(suspicious, "base64_data_uri")
	}
	if htmlEventHandlers.MatchString(content) {
		suspicious = append(suspicious, "event_handlers")
	}

	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	// Extract title
	titleStart := strings.Index(strings.ToLower(content), "<title>")
	titleEnd := strings.Index(strings.ToLower(content), "</title>")
	if titleStart >= 0 && titleEnd > titleStart {
		result["title"] = strings.TrimSpace(content[titleStart+7 : titleEnd])
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// XmlScanner parses XML files
type XmlScanner struct{}

func NewXmlScanner() *XmlScanner { return &XmlScanner{} }

func (s *XmlScanner) Name() string                                  { return "ScanXml" }
func (s *XmlScanner) Init(config map[string]interface{}) error       { return nil }
func (s *XmlScanner) Flavors() []string                              { return []string{"text/xml", "application/xml"} }
func (s *XmlScanner) Priority() int                                  { return 5 }

func (s *XmlScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	result := make(map[string]interface{})

	// Try to parse and count elements
	decoder := xml.NewDecoder(strings.NewReader(string(file)))
	elementCount := 0
	var rootElement string
	var namespaces []interface{}
	seenNS := make(map[string]bool)

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			elementCount++
			if rootElement == "" {
				rootElement = t.Name.Local
				if t.Name.Space != "" {
					rootElement = t.Name.Space + ":" + t.Name.Local
				}
			}
			for _, attr := range t.Attr {
				if attr.Name.Space == "xmlns" || attr.Name.Local == "xmlns" {
					if !seenNS[attr.Value] {
						seenNS[attr.Value] = true
						namespaces = append(namespaces, attr.Value)
					}
				}
			}
		}
	}

	result["rootElement"] = rootElement
	result["elementCount"] = elementCount

	if len(namespaces) > 0 {
		result["namespaces"] = namespaces
	}

	// Check for suspicious XML patterns (XXE, DTD)
	content := string(file)
	var suspicious []interface{}
	if strings.Contains(content, "<!DOCTYPE") && strings.Contains(content, "<!ENTITY") {
		suspicious = append(suspicious, "XXE_entity_declaration")
	}
	if strings.Contains(content, "SYSTEM") && strings.Contains(content, "<!ENTITY") {
		suspicious = append(suspicious, "external_entity")
	}
	if len(suspicious) > 0 {
		result["suspicious"] = suspicious
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// JsonScanner validates and analyzes JSON files
type JsonScanner struct{}

func NewJsonScanner() *JsonScanner { return &JsonScanner{} }

func (s *JsonScanner) Name() string                                  { return "ScanJson" }
func (s *JsonScanner) Init(config map[string]interface{}) error       { return nil }
func (s *JsonScanner) Flavors() []string                              { return []string{"application/json"} }
func (s *JsonScanner) Priority() int                                  { return 5 }

func (s *JsonScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	result := make(map[string]interface{})

	var parsed interface{}
	err := json.Unmarshal(file, &parsed)
	if err != nil {
		result["valid"] = false
		result["error"] = err.Error()
		return &ScanResult{Scanner: s.Name(), Data: result}, nil
	}

	result["valid"] = true

	switch v := parsed.(type) {
	case map[string]interface{}:
		result["type"] = "object"
		result["keys"] = len(v)
		if len(v) <= 20 {
			var keys []interface{}
			for k := range v {
				keys = append(keys, k)
			}
			result["topLevelKeys"] = keys
		}
	case []interface{}:
		result["type"] = "array"
		result["length"] = len(v)
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// IniScanner parses INI/config files
type IniScanner struct{}

func NewIniScanner() *IniScanner { return &IniScanner{} }

func (s *IniScanner) Name() string                                  { return "ScanIni" }
func (s *IniScanner) Init(config map[string]interface{}) error       { return nil }
func (s *IniScanner) Flavors() []string                              { return []string{"text/x-ini"} }
func (s *IniScanner) Priority() int                                  { return 5 }

func (s *IniScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	var sections []interface{}
	var keyCount int

	for _, line := range strings.Split(string(file), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sections = append(sections, line[1:len(line)-1])
		} else if strings.Contains(line, "=") {
			keyCount++
		}
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"sections": sections,
			"keys":     keyCount,
		},
	}, nil
}
