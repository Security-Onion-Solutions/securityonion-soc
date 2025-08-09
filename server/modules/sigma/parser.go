// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ParseRule parses a Sigma rule from YAML content
func ParseRule(content []byte) (*Rule, error) {
	var rawRule map[string]interface{}
	if err := yaml.Unmarshal(content, &rawRule); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	rule := &Rule{
		Custom: make(map[string]interface{}),
	}

	// Parse metadata fields
	if err := parseMetadata(rawRule, rule); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	// Parse logsource
	if logsource, ok := rawRule["logsource"].(map[string]interface{}); ok {
		rule.LogSource = parseLogSource(logsource)
	} else {
		return nil, fmt.Errorf("missing required field: logsource")
	}

	// Parse detection
	if detection, ok := rawRule["detection"].(map[string]interface{}); ok {
		rule.Detection = parseDetection(detection)
	} else {
		return nil, fmt.Errorf("missing required field: detection")
	}

	// Store any unknown fields in Custom
	for key, value := range rawRule {
		if !isKnownField(key) {
			rule.Custom[key] = value
		}
	}

	return rule, nil
}

// parseMetadata extracts metadata fields from the raw rule
func parseMetadata(raw map[string]interface{}, rule *Rule) error {
	// Required fields
	if title, ok := raw["title"].(string); ok {
		rule.Title = title
	} else {
		return fmt.Errorf("missing required field: title")
	}

	if id, ok := raw["id"].(string); ok {
		rule.ID = id
	} else {
		return fmt.Errorf("missing required field: id")
	}

	// Optional fields
	if status, ok := raw["status"].(string); ok {
		rule.Status = status
	}

	if description, ok := raw["description"].(string); ok {
		rule.Description = description
	}

	if author, ok := raw["author"].(string); ok {
		rule.Author = author
	}

	if license, ok := raw["license"].(string); ok {
		rule.License = license
	}

	if level, ok := raw["level"].(string); ok {
		rule.Level = level
	}

	// Parse arrays
	if refs, ok := raw["references"].([]interface{}); ok {
		rule.References = make([]string, len(refs))
		for i, ref := range refs {
			if s, ok := ref.(string); ok {
				rule.References[i] = s
			}
		}
	}

	if tags, ok := raw["tags"].([]interface{}); ok {
		rule.Tags = make([]string, len(tags))
		for i, tag := range tags {
			if s, ok := tag.(string); ok {
				rule.Tags[i] = s
			}
		}
	}

	if fps, ok := raw["falsepositives"].([]interface{}); ok {
		rule.FalsePositives = make([]string, len(fps))
		for i, fp := range fps {
			if s, ok := fp.(string); ok {
				rule.FalsePositives[i] = s
			}
		}
	}

	if fields, ok := raw["fields"].([]interface{}); ok {
		rule.Fields = make([]string, len(fields))
		for i, field := range fields {
			if s, ok := field.(string); ok {
				rule.Fields[i] = s
			}
		}
	}

	// Parse dates
	if dateStr, ok := raw["date"].(string); ok {
		if date, err := parseDate(dateStr); err == nil {
			rule.Date = &date
		}
	}

	if modifiedStr, ok := raw["modified"].(string); ok {
		if modified, err := parseDate(modifiedStr); err == nil {
			rule.Modified = &modified
		}
	}

	// Parse related rules
	if related, ok := raw["related"].([]interface{}); ok {
		rule.Related = make([]RelatedRule, 0, len(related))
		for _, rel := range related {
			if relMap, ok := rel.(map[string]interface{}); ok {
				relRule := RelatedRule{}
				if id, ok := relMap["id"].(string); ok {
					relRule.ID = id
				}
				if typ, ok := relMap["type"].(string); ok {
					relRule.Type = typ
				}
				rule.Related = append(rule.Related, relRule)
			}
		}
	}

	return nil
}

// parseLogSource parses the logsource section
func parseLogSource(raw map[string]interface{}) LogSource {
	ls := LogSource{
		Custom: make(map[string]interface{}),
	}

	if category, ok := raw["category"].(string); ok {
		ls.Category = category
	}

	if product, ok := raw["product"].(string); ok {
		ls.Product = product
	}

	if service, ok := raw["service"].(string); ok {
		ls.Service = service
	}

	if definition, ok := raw["definition"].(string); ok {
		ls.Definition = definition
	}

	// Store unknown fields
	for key, value := range raw {
		if !isKnownLogSourceField(key) {
			ls.Custom[key] = value
		}
	}

	return ls
}

// parseDetection parses the detection section
func parseDetection(raw map[string]interface{}) Detection {
	detection := Detection{
		Selections: make(map[string]interface{}),
	}

	// Extract condition
	if condition, ok := raw["condition"].(string); ok {
		detection.Condition = condition
	}

	// Extract timeframe
	if timeframe, ok := raw["timeframe"].(string); ok {
		detection.Timeframe = timeframe
	}

	// All other fields are selections
	for key, value := range raw {
		if key != "condition" && key != "timeframe" {
			detection.Selections[key] = value
		}
	}

	return detection
}

// parseDate parses a date string in various formats
func parseDate(dateStr string) (time.Time, error) {
	// Try common date formats
	formats := []string{
		"2006-01-02",
		"2006/01/02",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// isKnownField checks if a field is a known Sigma rule field
func isKnownField(field string) bool {
	knownFields := map[string]bool{
		"title":          true,
		"id":             true,
		"related":        true,
		"status":         true,
		"description":    true,
		"references":     true,
		"author":         true,
		"date":           true,
		"modified":       true,
		"tags":           true,
		"license":        true,
		"level":          true,
		"falsepositives": true,
		"fields":         true,
		"logsource":      true,
		"detection":      true,
	}
	return knownFields[strings.ToLower(field)]
}

// isKnownLogSourceField checks if a field is a known logsource field
func isKnownLogSourceField(field string) bool {
	knownFields := map[string]bool{
		"category":   true,
		"product":    true,
		"service":    true,
		"definition": true,
	}
	return knownFields[strings.ToLower(field)]
}

// ValidateRule performs basic validation on a parsed rule
func ValidateRule(rule *Rule) error {
	if rule.Title == "" {
		return fmt.Errorf("rule missing required field: title")
	}

	if rule.ID == "" {
		return fmt.Errorf("rule missing required field: id")
	}

	if rule.Detection.Condition == "" {
		return fmt.Errorf("rule missing detection condition")
	}

	if len(rule.Detection.Selections) == 0 {
		return fmt.Errorf("rule has no detection selections")
	}

	// Validate level if present
	if rule.Level != "" {
		validLevels := map[string]bool{
			LevelInformational: true,
			LevelLow:           true,
			LevelMedium:        true,
			LevelHigh:          true,
			LevelCritical:      true,
		}
		if !validLevels[rule.Level] {
			return fmt.Errorf("invalid rule level: %s", rule.Level)
		}
	}

	// Validate status if present
	if rule.Status != "" {
		validStatuses := map[string]bool{
			StatusStable:       true,
			StatusTest:         true,
			StatusExperimental: true,
			StatusDeprecated:   true,
			StatusUnsupported:  true,
		}
		if !validStatuses[rule.Status] {
			return fmt.Errorf("invalid rule status: %s", rule.Status)
		}
	}

	return nil
}