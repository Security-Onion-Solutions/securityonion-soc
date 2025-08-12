// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"gopkg.in/yaml.v3"
)

// ConvertDetectionToEQL converts a SecurityOnion detection with Sigma content to EQL
func ConvertDetectionToEQL(ctx context.Context, det *model.Detection, pipelineFiles []string) (string, error) {
	// Validate input
	if det == nil {
		return "", fmt.Errorf("detection is nil")
	}
	if det.Content == "" {
		return "", fmt.Errorf("detection content is empty")
	}

	// Parse the Sigma rule
	rule, err := ParseRule([]byte(det.Content))
	if err != nil {
		return "", fmt.Errorf("failed to parse sigma rule: %w", err)
	}

	// Apply overrides if present
	if len(det.Overrides) > 0 {
		rule, err = applyDetectionOverrides(rule, det.Overrides)
		if err != nil {
			return "", fmt.Errorf("failed to apply overrides: %w", err)
		}
	}

	// Load pipelines
	pipelines := make([]Pipeline, 0)
	// TODO: Implement pipeline loading from files
	// For now, we'll skip pipeline loading

	// Get the EQL converter
	converter, err := GetConverter("eql")
	if err != nil {
		return "", fmt.Errorf("failed to get EQL converter: %w", err)
	}

	// Convert to EQL
	query, err := converter.Convert(rule, pipelines)
	if err != nil {
		return "", fmt.Errorf("failed to convert rule: %w", err)
	}

	// Clean up the query (remove first line if it's a comment)
	lines := strings.Split(query, "\n")
	if len(lines) > 1 && strings.HasPrefix(lines[0], "#") {
		query = strings.Join(lines[1:], "\n")
	}

	return strings.TrimSpace(query), nil
}

// applyDetectionOverrides applies SecurityOnion detection overrides to a Sigma rule
func applyDetectionOverrides(rule *Rule, overrides []*model.Override) (*Rule, error) {
	// Filter for enabled custom filters
	filters := make([]*model.Override, 0)
	for _, override := range overrides {
		if override.Type == model.OverrideTypeCustomFilter && override.IsEnabled {
			filters = append(filters, override)
		}
	}

	if len(filters) == 0 {
		return rule, nil
	}

	// Create a copy of the rule
	ruleCopy := *rule
	
	// Marshal rule to map for manipulation
	var ruleMap map[string]interface{}
	ruleBytes, err := yaml.Marshal(rule)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rule: %w", err)
	}
	
	if err := yaml.Unmarshal(ruleBytes, &ruleMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule: %w", err)
	}

	// Get detection section
	detection, ok := ruleMap["detection"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("rule does not contain a detection section")
	}

	// Apply each filter
	for i, filter := range filters {
		filterMap, err := prepareOverrideForSigma(filter)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare filter %d: %w", i, err)
		}

		// Add filter to detection
		filterName := fmt.Sprintf("sofilter%d", i+1)
		detection[filterName] = filterMap
	}

	// Update condition to exclude filters
	originalCondition, ok := detection["condition"].(string)
	if !ok {
		return nil, fmt.Errorf("detection does not have a condition")
	}

	// Build filter exclusion
	filterNames := make([]string, len(filters))
	for i := range filters {
		filterNames[i] = fmt.Sprintf("sofilter%d", i+1)
	}
	
	detection["condition"] = fmt.Sprintf("(%s) and not 1 of sofilter*", originalCondition)

	// Update the rule's detection
	ruleCopy.Detection.Selections = make(map[string]interface{})
	for k, v := range detection {
		if k != "condition" && k != "timeframe" {
			ruleCopy.Detection.Selections[k] = v
		}
	}
	ruleCopy.Detection.Condition = detection["condition"].(string)

	return &ruleCopy, nil
}

// prepareOverrideForSigma converts a SecurityOnion override to Sigma format
func prepareOverrideForSigma(override *model.Override) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Parse the override value as YAML
	var overrideData map[string]interface{}
	if err := yaml.Unmarshal([]byte(*override.Value), &overrideData); err != nil {
		// If it's not YAML, treat it as a simple key-value
		parts := strings.SplitN(*override.Value, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		} else {
			return nil, fmt.Errorf("invalid override format")
		}
	} else {
		result = overrideData
	}

	return result, nil
}

// ConvertPlaybookQueries converts multiple Sigma queries to SecurityOnion format (OQL)
func ConvertPlaybookQueries(ctx context.Context, queries []string, pipelineFiles []string) ([]*model.ConvertedQuery, error) {
	// For playbooks, OQL is the original Sigma query itself, not converted to EQL
	// The Python backend with "-t security_onion" was returning the Sigma query as-is
	
	results := make([]*model.ConvertedQuery, 0, len(queries))
	
	for i, query := range queries {
		// Playbook queries are often partial Sigma rules without metadata
		// We need to parse them to extract fields if specified
		var rule *Rule
		var fields []string
		
		// First try parsing as-is
		rule, err := ParseRule([]byte(query))
		if err != nil {
			// If parsing fails due to missing metadata, wrap the query
			if strings.Contains(err.Error(), "missing required field: title") {
				// Create a minimal wrapper with required metadata
				wrappedQuery := fmt.Sprintf(`title: Playbook Query %d
id: %s
description: Auto-generated wrapper for playbook query
%s`, i+1, generateTempID(), query)
				
				rule, err = ParseRule([]byte(wrappedQuery))
				if err != nil {
					// If still fails, just use the original query
					// Some playbook queries might not be full Sigma rules
					fields = extractFieldsFromQuery(query)
				} else {
					fields = rule.Fields
				}
			} else {
				// Other parsing error - still try to extract fields
				fields = extractFieldsFromQuery(query)
			}
		} else {
			// Successfully parsed - get fields from rule
			fields = rule.Fields
		}

		// For OQL, return the original Sigma query
		result := &model.ConvertedQuery{
			Query: strings.TrimSpace(query),
		}

		// Add fields if found
		if len(fields) > 0 {
			result.Fields = fields
		}

		results = append(results, result)
	}

	return results, nil
}

// extractFieldsFromQuery attempts to extract fields from a Sigma query string
func extractFieldsFromQuery(query string) []string {
	fields := []string{}
	lines := strings.Split(query, "\n")
	inFields := false
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "fields:" {
			inFields = true
			continue
		}
		if inFields {
			if strings.HasPrefix(trimmed, "-") {
				field := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
				if field != "" {
					fields = append(fields, field)
				}
			} else if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				// End of fields section
				break
			}
		}
	}
	
	return fields
}

// generateTempID generates a temporary ID for wrapped queries
func generateTempID() string {
	return fmt.Sprintf("temp-%d", time.Now().UnixNano())
}