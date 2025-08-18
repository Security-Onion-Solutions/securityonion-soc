// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package common

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/samber/lo"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"gopkg.in/yaml.v3"
)

// ApplyOverridesToRule applies custom filters to a Sigma rule
func ApplyOverridesToRule(rule string, overrides []*model.Override) (string, error) {
	if len(overrides) == 0 {
		return rule, nil
	}

	// Filter for enabled custom filters
	filters := lo.Filter(overrides, func(item *model.Override, _ int) bool {
		return item.Type == model.OverrideTypeCustomFilter && item.IsEnabled
	})

	if len(filters) == 0 {
		return rule, nil
	}

	// Parse the rule
	doc := map[string]interface{}{}
	if err := yaml.Unmarshal([]byte(rule), &doc); err != nil {
		return "", fmt.Errorf("unable to unmarshal sigma rule: %w", err)
	}

	detection, ok := doc["detection"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("sigma rule does not contain a detection section")
	}

	// Apply overrides
	for _, f := range filters {
		prepared, err := f.PrepareForSigma()
		if err != nil {
			return "", fmt.Errorf("unable to prepare filter: %w", err)
		}
		for k, v := range prepared {
			detection[k] = v
		}
	}

	// Update condition
	if condition, ok := detection["condition"].(string); ok {
		detection["condition"] = fmt.Sprintf("(%s) and not 1 of sofilter*", condition)
	}

	// Marshal back to YAML
	result, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("unable to marshal sigma rule with overrides: %w", err)
	}

	return string(result), nil
}

// ParseSigmaOutput parses the output from sigma converter
func ParseSigmaOutput(output []byte) (string, error) {
	query := string(output)
	// Skip the first line if it exists (usually contains "Converted queries:" or similar)
	if firstLine := strings.Index(query, "\n"); firstLine != -1 {
		query = query[firstLine+1:]
	}
	return strings.TrimSpace(query), nil
}

// ParseConvertedQueries parses JSON lines output into ConvertedQuery structs
func ParseConvertedQueries(output string) ([]*model.ConvertedQuery, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	lines = lo.Filter(lines, func(line string, _ int) bool {
		return len(strings.TrimSpace(line)) > 0
	})

	queries := make([]*model.ConvertedQuery, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cq := &model.ConvertedQuery{}
		if err := json.Unmarshal([]byte(line), &cq); err != nil {
			return nil, fmt.Errorf("problem unmarshalling sigma cli output: %w", err)
		}
		queries = append(queries, cq)
	}
	return queries, nil
}

// EscapeSpecialCharacters escapes special characters for the target query language
func EscapeSpecialCharacters(value string, targetFormat string) string {
	switch targetFormat {
	case "eql":
		// EQL specific escaping
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `"`, `\"`)
		return value
	case "security_onion":
		// Security Onion specific escaping
		value = strings.ReplaceAll(value, `\`, `\\`)
		value = strings.ReplaceAll(value, `"`, `\"`)
		return value
	default:
		return value
	}
}

// ConvertWildcards converts Sigma wildcards to target format
func ConvertWildcards(value string, targetFormat string) string {
	switch targetFormat {
	case "eql":
		// Convert * to EQL wildcard format
		// EQL uses * for wildcards as well
		return value
	case "security_onion":
		// Convert to Security Onion format
		// Assuming Lucene-style wildcards
		return value
	default:
		return value
	}
}

// NormalizeFieldName normalizes field names for the target backend
func NormalizeFieldName(field string, targetFormat string) string {
	switch targetFormat {
	case "eql":
		// EQL field normalization
		// Replace common Windows field names with ECS equivalents
		fieldMappings := map[string]string{
			"EventID":           "event.code",
			"CommandLine":       "process.command_line",
			"Image":             "process.executable",
			"ParentImage":       "process.parent.executable",
			"TargetFilename":    "file.path",
			"User":              "user.name",
			"ComputerName":      "host.name",
			"ProcessId":         "process.pid",
			"ParentProcessId":   "process.parent.pid",
		}
		
		if mapped, ok := fieldMappings[field]; ok {
			return mapped
		}
		return field
		
	case "security_onion":
		// Security Onion specific field mappings
		fieldMappings := map[string]string{
			// Network fields
			"community_id": "network.community_id",
			"src_ip":       "source.ip",
			"dst_ip":       "destination.ip",
			"src_port":     "source.port",
			"dst_port":     "destination.port",
			"protocol":     "network.protocol",
			
			// Process fields
			"EventID":           "event.code",
			"CommandLine":       "process.command_line",
			"Image":             "process.executable",
			"ParentImage":       "process.parent.executable",
			"ProcessId":         "process.pid",
			"ParentProcessId":   "process.parent.pid",
			"ProcessGuid":       "process.entity_id",
			"ParentProcessGuid": "process.parent.entity_id",
			"CurrentDirectory":  "process.working_directory",
			
			// File fields
			"TargetFilename": "file.path",
			"FileName":       "file.name",
			"FilePath":       "file.path",
			
			// User/Host fields
			"User":         "user.name",
			"ComputerName": "host.name",
			"HostName":     "host.name",
			"hostname":     "host.name",
			
			// Alert/Detection fields
			"tags":                 "tags",
			"rule_name":            "rule.name",
			"alert_signature":      "alert.signature",
			"alert_signature_id":   "alert.signature_id",
			"alert_category":       "alert.category",
			"event_module":         "event.module",
			"event_dataset":        "event.dataset",
			"event_category":       "event.category",
			"event_type":           "event.type",
			"severity":             "event.severity",
			"sid":                  "rule.id",
			
			// HTTP fields
			"http_method":          "http.request.method",
			"http_uri":             "url.path",
			"http_user_agent":      "user_agent.original",
			"http_status":          "http.response.status_code",
			"http_host":            "url.domain",
			
			// DNS fields
			"dns_query":            "dns.question.name",
			"dns_type":             "dns.question.type",
			"dns_rcode":            "dns.response_code",
			
			// TLS fields
			"tls_sni":              "tls.client.server_name",
			"tls_version":          "tls.version",
			"tls_cipher":           "tls.cipher",
			
			// Generic fields
			"EventTime": "@timestamp",
		}
		
		if mapped, ok := fieldMappings[field]; ok {
			return mapped
		}
		return field
		
	default:
		return field
	}
}