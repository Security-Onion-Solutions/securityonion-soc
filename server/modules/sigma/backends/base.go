// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package backends

import (
	"fmt"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/base"
)

// Backend is the base interface for all Sigma backends
type Backend interface {
	Convert(rule *base.Rule, pipelines []base.Pipeline) (string, error)
	GetTargetFormat() string
	SupportsCorrelation() bool
}

// BaseBackend provides common functionality for backends
type BaseBackend struct {
	targetFormat string
}

// ProcessSelection processes a selection into query conditions
func (b *BaseBackend) ProcessSelection(processor ValueProcessor, name string, selection interface{}) ([]string, error) {
	conditions := []string{}
	
	switch sel := selection.(type) {
	case map[string]interface{}:
		for field, value := range sel {
			cond, err := ProcessFieldValue(processor, field, value)
			if err != nil {
				return nil, err
			}
			conditions = append(conditions, cond...)
		}
	case []interface{}:
		// List of conditions (OR between them)
		for _, item := range sel {
			if itemMap, ok := item.(map[string]interface{}); ok {
				itemConds := []string{}
				for field, value := range itemMap {
					cond, err := ProcessFieldValue(processor, field, value)
					if err != nil {
						return nil, err
					}
					itemConds = append(itemConds, cond...)
				}
				if len(itemConds) > 0 {
					conditions = append(conditions, "("+strings.Join(itemConds, " AND ")+")")
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported selection type: %T", selection)
	}
	
	return conditions, nil
}

// ValueProcessor is an interface for processing field values
type ValueProcessor interface {
	ProcessStringValue(field, value string, modifiers []string) string
	ProcessNumericValue(field string, value interface{}, modifiers []string) string
	ProcessBoolValue(field string, value bool, modifiers []string) string
	ProcessNullValue(field string, modifiers []string) string
}

// ProcessFieldValue processes a field-value pair
func ProcessFieldValue(processor ValueProcessor, field string, value interface{}) ([]string, error) {
	conditions := []string{}
	
	// Handle modifiers in field name
	fieldParts := strings.Split(field, "|")
	baseField := fieldParts[0]
	modifiers := fieldParts[1:]
	
	switch val := value.(type) {
	case string:
		cond := processor.ProcessStringValue(baseField, val, modifiers)
		conditions = append(conditions, cond)
	case []interface{}:
		// Multiple values (OR between them)
		valueConds := []string{}
		for _, v := range val {
			if strVal, ok := v.(string); ok {
				cond := processor.ProcessStringValue(baseField, strVal, modifiers)
				valueConds = append(valueConds, cond)
			}
		}
		if len(valueConds) > 0 {
			conditions = append(conditions, "("+strings.Join(valueConds, " OR ")+")")
		}
	case int, int64, float64:
		cond := processor.ProcessNumericValue(baseField, val, modifiers)
		conditions = append(conditions, cond)
	case bool:
		cond := processor.ProcessBoolValue(baseField, val, modifiers)
		conditions = append(conditions, cond)
	case nil:
		cond := processor.ProcessNullValue(baseField, modifiers)
		conditions = append(conditions, cond)
	default:
		return nil, fmt.Errorf("unsupported value type for field %s: %T", field, value)
	}
	
	return conditions, nil
}

// ProcessStringValue processes string values with modifiers
func (b *BaseBackend) ProcessStringValue(field, value string, modifiers []string) string {
	// This should be overridden by specific backends
	return field + ":" + value
}

// ProcessNumericValue processes numeric values
func (b *BaseBackend) ProcessNumericValue(field string, value interface{}, modifiers []string) string {
	// This should be overridden by specific backends
	return fmt.Sprintf("%s:%v", field, value)
}

// ProcessBoolValue processes boolean values
func (b *BaseBackend) ProcessBoolValue(field string, value bool, modifiers []string) string {
	// This should be overridden by specific backends
	return fmt.Sprintf("%s:%v", field, value)
}

// ProcessNullValue processes null values
func (b *BaseBackend) ProcessNullValue(field string, modifiers []string) string {
	// This should be overridden by specific backends
	return fmt.Sprintf("NOT %s:*", field)
}

// HasModifier checks if a modifier exists in the list
func HasModifier(modifiers []string, modifier string) bool {
	for _, m := range modifiers {
		if strings.EqualFold(m, modifier) {
			return true
		}
	}
	return false
}

// ApplyModifiers applies modifiers to a value
func ApplyModifiers(value string, modifiers []string) string {
	result := value
	
	for _, mod := range modifiers {
		switch strings.ToLower(mod) {
		case "contains":
			if !strings.HasPrefix(result, "*") {
				result = "*" + result
			}
			if !strings.HasSuffix(result, "*") {
				result = result + "*"
			}
		case "startswith":
			if !strings.HasSuffix(result, "*") {
				result = result + "*"
			}
		case "endswith":
			if !strings.HasPrefix(result, "*") {
				result = "*" + result
			}
		case "all":
			// This requires special handling at the field level
		case "base64":
			// TODO: Implement base64 encoding
		case "utf16", "utf16le", "utf16be", "wide":
			// TODO: Implement UTF16 encoding
		}
	}
	
	return result
}