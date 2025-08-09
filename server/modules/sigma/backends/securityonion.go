// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package backends

import (
	"fmt"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
)

// SecurityOnionBackend converts Sigma rules to Security Onion format
type SecurityOnionBackend struct {
	*ElasticsearchBackend
}

// NewSecurityOnionBackend creates a new Security Onion backend
func NewSecurityOnionBackend() *SecurityOnionBackend {
	backend := &SecurityOnionBackend{
		ElasticsearchBackend: NewElasticsearchBackend(),
	}
	// Use EQL as the base format
	backend.SetOutputFormat("security_onion")
	return backend
}

// GetTargetFormat returns the target format name
func (s *SecurityOnionBackend) GetTargetFormat() string {
	return "security_onion"
}

// Convert converts a Sigma rule to Security Onion format
func (s *SecurityOnionBackend) Convert(rule *sigma.Rule, pipelines []sigma.Pipeline) (string, error) {
	// First convert to EQL using the parent implementation
	eqlQuery, err := s.ElasticsearchBackend.Convert(rule, pipelines)
	if err != nil {
		return "", err
	}

	// Create Security Onion specific output
	output := &model.ConvertedQuery{
		Query: eqlQuery,
	}

	// Extract fields from the rule if specified
	if len(rule.Fields) > 0 {
		output.Fields = rule.Fields
	}

	// Since ConvertedQuery has limited fields, we'll encode metadata as a comment
	metadata := ""
	if rule.ID != "" || rule.Title != "" {
		metadata = fmt.Sprintf("# Sigma Rule: %s", rule.Title)
		if rule.ID != "" {
			metadata += fmt.Sprintf(" (ID: %s)", rule.ID)
		}
		if rule.Level != "" {
			metadata += fmt.Sprintf(" [%s]", rule.Level)
		}
		metadata += "\n"
	}

	// Return the query with metadata comment
	if metadata != "" {
		return metadata + output.Query, nil
	}
	
	return output.Query, nil
}

// mapSigmaLevelToSeverity maps Sigma levels to Security Onion severity
func mapSigmaLevelToSeverity(level string) string {
	switch level {
	case sigma.LevelCritical:
		return "critical"
	case sigma.LevelHigh:
		return "high"
	case sigma.LevelMedium:
		return "medium"
	case sigma.LevelLow:
		return "low"
	case sigma.LevelInformational:
		return "informational"
	default:
		return "medium"
	}
}

// ConvertForElastAlert converts specifically for ElastAlert integration
func (s *SecurityOnionBackend) ConvertForElastAlert(rule *sigma.Rule, pipelines []sigma.Pipeline) (map[string]interface{}, error) {
	// Apply pipelines
	processedRule, err := s.ApplyPipelines(rule, pipelines)
	if err != nil {
		return nil, err
	}

	// Get EQL query
	eqlQuery, err := s.ElasticsearchBackend.Convert(processedRule, nil)
	if err != nil {
		return nil, err
	}

	// Build ElastAlert rule structure
	elastAlertRule := map[string]interface{}{
		"name":        processedRule.Title,
		"type":        "any",
		"index":       "logs-*",
		"filter":      []map[string]interface{}{},
		"alert":       []string{"modules.so"},
		"realert":     map[string]interface{}{"minutes": 5},
		"include":     []string{"*"},
		"sigma_query": eqlQuery,
	}

	// Add metadata
	if processedRule.Description != "" {
		elastAlertRule["description"] = processedRule.Description
	}

	if processedRule.ID != "" {
		elastAlertRule["sigma_id"] = processedRule.ID
	}

	if processedRule.Level != "" {
		elastAlertRule["severity"] = mapSigmaLevelToSeverity(processedRule.Level)
	}

	if len(processedRule.Tags) > 0 {
		elastAlertRule["tags"] = processedRule.Tags
	}

	if processedRule.Author != "" {
		elastAlertRule["author"] = processedRule.Author
	}

	// Add logsource info
	if processedRule.LogSource.Product != "" {
		elastAlertRule["sigma_product"] = processedRule.LogSource.Product
	}
	if processedRule.LogSource.Category != "" {
		elastAlertRule["sigma_category"] = processedRule.LogSource.Category
	}
	if processedRule.LogSource.Service != "" {
		elastAlertRule["sigma_service"] = processedRule.LogSource.Service
	}

	return elastAlertRule, nil
}

// Register the backend
func init() {
	sigma.RegisterConverter("security_onion", func() sigma.Converter {
		return NewSecurityOnionBackend()
	})
}