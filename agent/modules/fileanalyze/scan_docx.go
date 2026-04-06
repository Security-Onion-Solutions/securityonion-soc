// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

type DocxScanner struct{}

func NewDocxScanner() *DocxScanner {
	return &DocxScanner{}
}

func (s *DocxScanner) Name() string { return "ScanDocx" }

func (s *DocxScanner) Init(config map[string]interface{}) error { return nil }

func (s *DocxScanner) Flavors() []string {
	return []string{
		"application/vnd.openxmlformats-officedocument",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	}
}

func (s *DocxScanner) Priority() int { return 5 }

func (s *DocxScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	reader, err := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		return nil, err
	}

	var parts []interface{}
	var extracted []ExtractedFile
	properties := make(map[string]interface{})
	var relationships []interface{}
	hasVBA := false

	for _, f := range reader.File {
		parts = append(parts, f.Name)

		// Check for VBA project (indicates macros)
		if strings.Contains(strings.ToLower(f.Name), "vbaproject") {
			hasVBA = true
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, DEFAULT_MAX_FILE_SIZE))
		rc.Close()
		if err != nil {
			continue
		}

		switch {
		case f.Name == "docProps/core.xml":
			props := parseCoreProperties(data)
			for k, v := range props {
				properties[k] = v
			}

		case f.Name == "docProps/app.xml":
			props := parseAppProperties(data)
			for k, v := range props {
				properties[k] = v
			}

		case strings.HasSuffix(f.Name, ".rels"):
			rels := parseRelationships(data)
			relationships = append(relationships, rels...)

		case strings.Contains(f.Name, "vbaProject"):
			// Extract VBA project for further analysis
			extracted = append(extracted, ExtractedFile{
				Name:    "vbaProject.bin",
				Content: data,
			})

		case strings.Contains(f.Name, "oleObject") || strings.Contains(f.Name, "embeddings/"):
			// Extract embedded objects
			extracted = append(extracted, ExtractedFile{
				Name:    f.Name,
				Content: data,
			})
		}
	}

	// Check relationships for external targets
	var externalLinks []interface{}
	for _, rel := range relationships {
		if r, ok := rel.(map[string]string); ok {
			if target, exists := r["Target"]; exists {
				if strings.HasPrefix(target, "http") || strings.HasPrefix(target, "ftp") {
					externalLinks = append(externalLinks, target)
				}
			}
		}
	}

	result := map[string]interface{}{
		"parts":    parts,
		"hasMacro": hasVBA,
	}

	if len(properties) > 0 {
		result["properties"] = properties
	}
	if len(externalLinks) > 0 {
		result["externalLinks"] = externalLinks
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
		Files:   extracted,
	}, nil
}

func parseCoreProperties(data []byte) map[string]interface{} {
	props := make(map[string]interface{})
	decoder := xml.NewDecoder(bytes.NewReader(data))

	var currentElement string
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			currentElement = t.Name.Local
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && currentElement != "" {
				switch currentElement {
				case "title", "subject", "creator", "keywords",
					"description", "lastModifiedBy", "created", "modified":
					props[currentElement] = text
				}
			}
		case xml.EndElement:
			currentElement = ""
		}
	}
	return props
}

func parseAppProperties(data []byte) map[string]interface{} {
	props := make(map[string]interface{})
	decoder := xml.NewDecoder(bytes.NewReader(data))

	var currentElement string
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			currentElement = t.Name.Local
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && currentElement != "" {
				switch currentElement {
				case "Application", "AppVersion", "Company", "Template",
					"Pages", "Words", "Characters", "Lines", "Paragraphs":
					props[currentElement] = text
				}
			}
		case xml.EndElement:
			currentElement = ""
		}
	}
	return props
}

func parseRelationships(data []byte) []interface{} {
	type Relationship struct {
		ID     string `xml:"Id,attr"`
		Type   string `xml:"Type,attr"`
		Target string `xml:"Target,attr"`
		Mode   string `xml:"TargetMode,attr"`
	}
	type Relationships struct {
		Rels []Relationship `xml:"Relationship"`
	}

	var rels Relationships
	if err := xml.Unmarshal(data, &rels); err != nil {
		return nil
	}

	var result []interface{}
	for _, r := range rels.Rels {
		result = append(result, map[string]string{
			"Id":     r.ID,
			"Type":   r.Type,
			"Target": r.Target,
			"Mode":   r.Mode,
		})
	}
	return result
}
