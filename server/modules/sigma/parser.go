// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"fmt"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/base"
	"gopkg.in/yaml.v3"
)

// ParseRule parses a YAML Sigma rule into a Rule struct
func ParseRule(content []byte) (*base.Rule, error) {
	var rawRule map[string]interface{}
	if err := yaml.Unmarshal(content, &rawRule); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	rule := &base.Rule{
		CustomAttributes: make(map[string]interface{}),
	}

	// Parse basic fields
	if title, ok := getString(rawRule, "title"); ok {
		rule.Title = title
	} else {
		return nil, fmt.Errorf("sigma rule must have a title")
	}

	if id, ok := getString(rawRule, "id"); ok {
		rule.ID = id
	}

	if status, ok := getString(rawRule, "status"); ok {
		rule.Status = status
	}

	if desc, ok := getString(rawRule, "description"); ok {
		rule.Description = desc
	}

	if author, ok := getString(rawRule, "author"); ok {
		rule.Author = author
	}

	if level, ok := getString(rawRule, "level"); ok {
		rule.Level = level
	}

	// Parse arrays
	if refs, ok := getStringArray(rawRule, "references"); ok {
		rule.References = refs
	}

	if tags, ok := getStringArray(rawRule, "tags"); ok {
		rule.Tags = tags
	}

	if fields, ok := getStringArray(rawRule, "fields"); ok {
		rule.Fields = fields
	}

	if fps, ok := getStringArray(rawRule, "falsepositives"); ok {
		rule.FalsePositives = fps
	}

	// Parse dates
	if dateStr, ok := getString(rawRule, "date"); ok {
		if date, err := parseDate(dateStr); err == nil {
			rule.Date = &date
		}
	}

	if modifiedStr, ok := getString(rawRule, "modified"); ok {
		if modified, err := parseDate(modifiedStr); err == nil {
			rule.Modified = &modified
		}
	}

	// Parse logsource
	if logsourceRaw, ok := rawRule["logsource"].(map[string]interface{}); ok {
		rule.LogSource = parseLogSource(logsourceRaw)
	} else {
		return nil, fmt.Errorf("sigma rule must have a logsource")
	}

	// Parse detection
	if detectionRaw, ok := rawRule["detection"].(map[string]interface{}); ok {
		rule.Detection = parseDetection(detectionRaw)
	} else {
		return nil, fmt.Errorf("sigma rule must have a detection section")
	}

	// Store any additional fields
	for k, v := range rawRule {
		switch k {
		case "title", "id", "status", "description", "author", "date", "modified",
			"tags", "logsource", "detection", "fields", "falsepositives", "level", "references":
			// Already processed
		default:
			rule.CustomAttributes[k] = v
		}
	}

	return rule, nil
}

// parseLogSource parses the logsource section
func parseLogSource(raw map[string]interface{}) base.LogSource {
	ls := base.LogSource{}

	if product, ok := getString(raw, "product"); ok {
		ls.Product = product
	}

	if service, ok := getString(raw, "service"); ok {
		ls.Service = service
	}

	if category, ok := getString(raw, "category"); ok {
		ls.Category = category
	}

	if definition, ok := getString(raw, "definition"); ok {
		ls.Definition = definition
	}

	return ls
}

// parseDetection parses the detection section
func parseDetection(raw map[string]interface{}) base.Detection {
	det := base.Detection{
		Selections: make(map[string]interface{}),
	}

	if condition, ok := getString(raw, "condition"); ok {
		det.Condition = condition
	}

	if timeframe, ok := getString(raw, "timeframe"); ok {
		det.Timeframe = timeframe
	}

	// All other fields are selections
	for k, v := range raw {
		switch k {
		case "condition", "timeframe":
			// Already processed
		default:
			det.Selections[k] = v
		}
	}

	return det
}

// Helper functions
func getString(m map[string]interface{}, key string) (string, bool) {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

func getStringArray(m map[string]interface{}, key string) ([]string, bool) {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case []interface{}:
			result := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result, true
		case []string:
			return v, true
		}
	}
	return nil, false
}

func parseDate(dateStr string) (time.Time, error) {
	// Try common date formats
	formats := []string{
		"2006-01-02",
		"2006/01/02",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// ValidateRule performs basic validation on a Sigma rule
func ValidateRule(rule *base.Rule) error {
	if rule.Title == "" {
		return fmt.Errorf("rule must have a title")
	}

	if rule.Detection.Condition == "" {
		return fmt.Errorf("rule must have a detection condition")
	}

	// Validate that condition references exist in selections
	conditionTokens := strings.Fields(rule.Detection.Condition)
	for _, token := range conditionTokens {
		// Skip operators and keywords
		if isOperator(token) || isKeyword(token) {
			continue
		}

		// Check if it's a selection reference
		if !strings.HasPrefix(token, "1") && !strings.HasPrefix(token, "all") && !strings.Contains(token, "*") {
			if _, exists := rule.Detection.Selections[token]; !exists {
				return fmt.Errorf("condition references non-existent selection: %s", token)
			}
		}
	}

	return nil
}

func isOperator(token string) bool {
	operators := []string{"and", "or", "not", "(", ")"}
	for _, op := range operators {
		if strings.EqualFold(token, op) {
			return true
		}
	}
	return false
}

func isKeyword(token string) bool {
	keywords := []string{"of", "them", "1", "all"}
	for _, kw := range keywords {
		if strings.EqualFold(token, kw) {
			return true
		}
	}
	return false
}