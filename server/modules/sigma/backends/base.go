// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package backends

import (
	"fmt"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/conditions"
)

// BaseBackend provides common functionality for all backends
type BaseBackend struct {
	fieldMappings map[string]string
	pipelines     []sigma.Pipeline
}

// NewBaseBackend creates a new base backend
func NewBaseBackend() *BaseBackend {
	return &BaseBackend{
		fieldMappings: make(map[string]string),
		pipelines:     make([]sigma.Pipeline, 0),
	}
}

// SetFieldMappings sets custom field mappings
func (b *BaseBackend) SetFieldMappings(mappings []sigma.FieldMapping) {
	b.fieldMappings = make(map[string]string)
	for _, mapping := range mappings {
		b.fieldMappings[mapping.Source] = mapping.Target
	}
}

// MapField maps a Sigma field name to the target field name
func (b *BaseBackend) MapField(field string) string {
	if mapped, ok := b.fieldMappings[field]; ok {
		return mapped
	}
	return field
}

// ApplyPipelines applies all pipelines to a rule
func (b *BaseBackend) ApplyPipelines(rule *sigma.Rule, pipelines []sigma.Pipeline) (*sigma.Rule, error) {
	result := rule
	var err error

	// Apply pipelines in order of priority
	for _, pipeline := range pipelines {
		result, err = pipeline.Process(result)
		if err != nil {
			return nil, fmt.Errorf("pipeline %s failed: %w", pipeline.GetName(), err)
		}
	}

	return result, nil
}

// ParseCondition parses a condition string into an AST
func (b *BaseBackend) ParseCondition(condition string) (sigma.ConditionNode, error) {
	parser := conditions.NewParser(condition)
	return parser.Parse()
}

// ParseSelection parses a selection into structured format
func (b *BaseBackend) ParseSelection(name string, selection interface{}) (*sigma.ParsedSelection, error) {
	parsed := &sigma.ParsedSelection{
		Name:  name,
		Items: make([]sigma.SelectionItem, 0),
	}

	switch sel := selection.(type) {
	case map[string]interface{}:
		// Simple field-value mapping
		for field, value := range sel {
			item := sigma.SelectionItem{
				Field: field,
			}

			// Check for negation
			if strings.HasPrefix(field, "-") {
				item.Negated = true
				item.Field = strings.TrimPrefix(field, "-")
			}

			// Parse modifiers
			var modifierType sigma.ModifierType
			item.Field, modifierType = sigma.ParseModifier(item.Field)
			item.Modifier = string(modifierType)

			// Parse values
			switch v := value.(type) {
			case []interface{}:
				item.Values = v
			case interface{}:
				item.Values = []interface{}{v}
			}

			parsed.Items = append(parsed.Items, item)
		}

	case []interface{}:
		// List of conditions (OR)
		parsed.IsOr = true
		for _, cond := range sel {
			if condMap, ok := cond.(map[string]interface{}); ok {
				subParsed, err := b.ParseSelection(name+"_sub", condMap)
				if err != nil {
					return nil, err
				}
				parsed.Items = append(parsed.Items, subParsed.Items...)
			}
		}

	default:
		return nil, fmt.Errorf("unsupported selection type: %T", selection)
	}

	return parsed, nil
}

// EscapeString escapes special characters in a string for the target query language
// This should be overridden by specific backends
func (b *BaseBackend) EscapeString(value string) string {
	// Default implementation - backends should override
	return value
}

// ConvertValue converts a Sigma value to the target format
// This should be overridden by specific backends
func (b *BaseBackend) ConvertValue(value interface{}, modifier string) (string, error) {
	// Default implementation - backends should override
	return fmt.Sprintf("%v", value), nil
}

// GenerateFieldComparison generates a field comparison expression
// This should be overridden by specific backends
func (b *BaseBackend) GenerateFieldComparison(field string, values []interface{}, modifier string, negated bool) (string, error) {
	return "", fmt.Errorf("GenerateFieldComparison not implemented")
}

// CombineConditions combines multiple conditions with an operator
// This should be overridden by specific backends
func (b *BaseBackend) CombineConditions(conditions []string, operator string) string {
	return ""
}

// SupportsCorrelation indicates if the backend supports correlation rules
func (b *BaseBackend) SupportsCorrelation() bool {
	return false
}

// ConvertCorrelation converts a correlation rule to the target format
func (b *BaseBackend) ConvertCorrelation(rules []*sigma.Rule, correlation sigma.CorrelationRule) (string, error) {
	return "", fmt.Errorf("correlation rules not supported by this backend")
}