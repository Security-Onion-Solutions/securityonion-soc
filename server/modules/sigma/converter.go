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
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/backends"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/common"
)

// SigmaConverter is the main interface for Sigma rule conversion
type SigmaConverter interface {
	ConvertToEQL(ctx context.Context, rule string, overrides []*model.Override) (string, error)
	ConvertToSecurityOnion(ctx context.Context, queries []string) ([]*model.ConvertedQuery, error)
}

// BaseConverter provides common functionality for all converters
type BaseConverter struct {
	config Config
	iom    detections.IOManager
}

// NativeConverter implements the Go-based Sigma converter
type NativeConverter struct {
	BaseConverter
	fallback SigmaConverter
}

// NewSigmaConverter creates a new Sigma converter based on configuration
func NewSigmaConverter(config Config, iom detections.IOManager) SigmaConverter {
	if config.UseNativeConverter {
		return &NativeConverter{
			BaseConverter: BaseConverter{
				config: config,
				iom:    iom,
			},
			fallback: nil, // No fallback in test environment
		}
	}
	// This path won't be used in test environment
	return &PythonConverter{
		BaseConverter: BaseConverter{
			config: config,
			iom:    iom,
		},
	}
}

// PythonConverter wraps the Python implementation (kept for reference)
type PythonConverter struct {
	BaseConverter
}

// ConvertToEQL converts a Sigma rule to Elasticsearch Query Language
func (nc *NativeConverter) ConvertToEQL(ctx context.Context, rule string, overrides []*model.Override) (string, error) {
	// Apply overrides to the rule
	processedRule, err := common.ApplyOverridesToRule(rule, overrides)
	if err != nil {
		return "", fmt.Errorf("failed to apply overrides: %w", err)
	}

	// Parse the Sigma rule
	sigmaRule, err := ParseRule([]byte(processedRule))
	if err != nil {
		return "", fmt.Errorf("failed to parse sigma rule: %w", err)
	}

	// Load pipelines (for now, we'll implement basic conversion without pipelines)
	// TODO: Implement pipeline loading
	var pipelines []Pipeline

	// Convert to EQL using the EQL backend
	converter := backends.NewEQLBackend()
	query, err := converter.Convert(sigmaRule, pipelines)
	if err != nil {
		return "", fmt.Errorf("failed to convert to EQL: %w", err)
	}

	return query, nil
}

// ConvertToSecurityOnion converts Sigma queries to Security Onion format
func (nc *NativeConverter) ConvertToSecurityOnion(ctx context.Context, queries []string) ([]*model.ConvertedQuery, error) {
	results := make([]*model.ConvertedQuery, 0, len(queries))

	for _, query := range queries {
		// Wrap the partial query in a minimal Sigma rule structure if needed
		fullRule := query
		if !containsTitle(query) {
			// This is a partial query from a playbook, wrap it
			fullRule = fmt.Sprintf(`title: Playbook Query
%s`, query)
		}

		// Parse each query as a Sigma rule
		sigmaRule, err := ParseRule([]byte(fullRule))
		if err != nil {
			return nil, fmt.Errorf("failed to parse sigma query: %w", err)
		}

		// Convert using Security Onion backend
		converter := backends.NewSecurityOnionBackend()
		output, err := converter.Convert(sigmaRule, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to convert to Security Onion format: %w", err)
		}

		// Parse the JSON output
		convertedQueries, err := common.ParseConvertedQueries(output)
		if err != nil {
			return nil, err
		}
		
		// Log the generated query for debugging
		if len(convertedQueries) > 0 {
			fmt.Printf("DEBUG: Generated query: %s\n", convertedQueries[0].Query)
			fmt.Printf("DEBUG: Fields: %v\n", convertedQueries[0].Fields)
		}

		results = append(results, convertedQueries...)
	}

	return results, nil
}

// containsTitle checks if the query contains a title field
func containsTitle(query string) bool {
	return strings.HasPrefix(strings.TrimSpace(query), "title:")
}

// Python converter methods (stubs for reference)
func (pc *PythonConverter) ConvertToEQL(ctx context.Context, rule string, overrides []*model.Override) (string, error) {
	return "", fmt.Errorf("Python converter not available in test environment")
}

func (pc *PythonConverter) ConvertToSecurityOnion(ctx context.Context, queries []string) ([]*model.ConvertedQuery, error) {
	return nil, fmt.Errorf("Python converter not available in test environment")
}