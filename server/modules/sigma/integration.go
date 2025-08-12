// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"context"
	"fmt"
	"strings"

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

// ConvertPlaybookQueries converts multiple Sigma queries to SecurityOnion format
func ConvertPlaybookQueries(ctx context.Context, queries []string, pipelineFiles []string) ([]*model.ConvertedQuery, error) {
	// Load pipelines
	pipelines := make([]Pipeline, 0)
	// TODO: Implement pipeline loading from files

	// Get the Security Onion converter
	converter, err := GetConverter("security_onion")
	if err != nil {
		// Fall back to EQL if SO converter not available
		converter, err = GetConverter("eql")
		if err != nil {
			return nil, err
		}
	}

	results := make([]*model.ConvertedQuery, 0, len(queries))
	
	for i, query := range queries {
		// Parse the query as a Sigma rule
		rule, err := ParseRule([]byte(query))
		if err != nil {
			// If parsing fails, add error result
			// Note: ConvertedQuery doesn't have Error field, so we encode it in the query
			results = append(results, &model.ConvertedQuery{
				Query: fmt.Sprintf("ERROR: %s", err.Error()),
			})
			continue
		}

		// Convert the rule
		converted, err := converter.Convert(rule, pipelines)
		if err != nil {
			results = append(results, &model.ConvertedQuery{
				Query: fmt.Sprintf("ERROR: %s", err.Error()),
			})
			continue
		}

		// Create result
		// Note: ConvertedQuery only has Query field in the model
		result := &model.ConvertedQuery{
			Query: converted,
		}

		// Since ConvertedQuery doesn't have Title/ID fields, we'll encode them in the query
		// as a comment if they exist
		if rule.Title != "" || rule.ID != "" {
			commentPrefix := fmt.Sprintf("# Rule: %s", rule.Title)
			if rule.ID != "" {
				commentPrefix += fmt.Sprintf(" (ID: %s)", rule.ID)
			}
			result.Query = commentPrefix + "\n" + result.Query
		}

		results = append(results, result)
		_ = i // Use the index to avoid unused variable warning
	}

	return results, nil
}