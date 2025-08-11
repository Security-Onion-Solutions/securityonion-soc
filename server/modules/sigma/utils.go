// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"fmt"
	"strconv"
	"strings"
)

// StringUtils provides common string manipulation utilities for Sigma processing
type StringUtils struct{}

// EscapeString escapes special characters in strings for safe query usage
func (s *StringUtils) EscapeString(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "\\r")
	value = strings.ReplaceAll(value, "\t", "\\t")
	return value
}

// EscapeWildcard escapes wildcards for LIKE queries while preserving * and ?
func (s *StringUtils) EscapeWildcard(value string) string {
	return s.EscapeString(value) // Don't escape * and ? as they are wildcards
}

// FormatValue formats a value for query output with proper escaping
func (s *StringUtils) FormatValue(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		// Handle wildcards
		if strings.Contains(v, "*") || strings.Contains(v, "?") {
			escaped := s.EscapeWildcard(v)
			return fmt.Sprintf("\"%s\"", escaped), nil
		}
		// Regular string
		return fmt.Sprintf("\"%s\"", s.EscapeString(v)), nil
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprintf("%d", v), nil
	case float32, float64:
		return fmt.Sprintf("%f", v), nil
	case bool:
		return strconv.FormatBool(v), nil
	case nil:
		return "null", nil
	default:
		// Try to convert to string
		return fmt.Sprintf("\"%v\"", v), nil
	}
}

// ValidationUtils provides validation utilities for Sigma rules
type ValidationUtils struct{}

// IsValidFieldName checks if a field name is valid
func (v *ValidationUtils) IsValidFieldName(field string) bool {
	if field == "" {
		return false
	}
	
	// Field names should not start with special characters (except -)
	if strings.HasPrefix(field, ".") || strings.HasPrefix(field, "*") {
		return false
	}
	
	return true
}

// IsValidLevel checks if a rule level is valid
func (v *ValidationUtils) IsValidLevel(level string) bool {
	validLevels := map[string]bool{
		LevelInformational: true,
		LevelLow:           true,
		LevelMedium:        true,
		LevelHigh:          true,
		LevelCritical:      true,
	}
	return level == "" || validLevels[level]
}

// IsValidStatus checks if a rule status is valid
func (v *ValidationUtils) IsValidStatus(status string) bool {
	validStatuses := map[string]bool{
		StatusStable:       true,
		StatusTest:         true,
		StatusExperimental: true,
		StatusDeprecated:   true,
		StatusUnsupported:  true,
	}
	return status == "" || validStatuses[status]
}

// QueryUtils provides utilities for query building
type QueryUtils struct {
	stringUtils *StringUtils
}

// NewQueryUtils creates a new QueryUtils instance
func NewQueryUtils() *QueryUtils {
	return &QueryUtils{
		stringUtils: &StringUtils{},
	}
}

// BuildValueComparison builds a comparison expression for a field and values
func (q *QueryUtils) BuildValueComparison(field string, values []interface{}, operator, negationPrefix string) ([]string, error) {
	parts := make([]string, 0, len(values))
	
	for _, value := range values {
		formattedValue, err := q.stringUtils.FormatValue(value)
		if err != nil {
			return nil, fmt.Errorf("failed to format value %v: %w", value, err)
		}
		
		expr := fmt.Sprintf("%s %s %s", field, operator, formattedValue)
		if negationPrefix != "" {
			expr = negationPrefix + " " + expr
		}
		
		parts = append(parts, expr)
	}
	
	return parts, nil
}

// BuildLikeComparison builds LIKE comparisons for pattern matching
func (q *QueryUtils) BuildLikeComparison(field string, values []interface{}, pattern, negationPrefix string) ([]string, error) {
	parts := make([]string, 0, len(values))
	
	for _, value := range values {
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("pattern matching requires string value, got %T", value)
		}
		
		escaped := q.stringUtils.EscapeWildcard(str)
		likeValue := fmt.Sprintf(pattern, escaped)
		
		expr := fmt.Sprintf("%s like \"%s\"", field, likeValue)
		if negationPrefix != "" {
			expr = fmt.Sprintf("%s %s like \"%s\"", field, negationPrefix, likeValue)
		}
		
		parts = append(parts, expr)
	}
	
	return parts, nil
}

// CombineExpressions combines multiple expressions with an operator
func (q *QueryUtils) CombineExpressions(expressions []string, operator string) string {
	if len(expressions) == 0 {
		return ""
	}
	if len(expressions) == 1 {
		return expressions[0]
	}
	
	return "(" + strings.Join(expressions, " "+operator+" ") + ")"
}

// ErrorUtils provides utilities for creating consistent error messages
type ErrorUtils struct{}

// NewParseError creates a new parsing error with context
func (e *ErrorUtils) NewParseError(context, field string, err error) error {
	return fmt.Errorf("failed to parse %s for field '%s': %w", context, field, err)
}

// NewValidationError creates a new validation error
func (e *ErrorUtils) NewValidationError(field, message string) error {
	return fmt.Errorf("validation error for field '%s': %s", field, message)
}

// NewConversionError creates a new conversion error
func (e *ErrorUtils) NewConversionError(backend, operation string, err error) error {
	return fmt.Errorf("conversion error in %s backend during %s: %w", backend, operation, err)
}

// Global utility instances for convenience
var (
	StringUtil     = &StringUtils{}
	ValidationUtil = &ValidationUtils{}
	QueryUtil      = NewQueryUtils()
	ErrorUtil      = &ErrorUtils{}
)