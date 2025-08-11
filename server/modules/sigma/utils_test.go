// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringUtils(t *testing.T) {
	utils := &StringUtils{}

	t.Run("EscapeString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"simple", "simple"},
			{"with\"quotes", "with\\\"quotes"},
			{"with\\backslash", "with\\\\backslash"},
			{"with\nnewline", "with\\nnewline"},
			{"with\ttab", "with\\ttab"},
		}

		for _, test := range tests {
			result := utils.EscapeString(test.input)
			assert.Equal(t, test.expected, result, "Failed for input: %s", test.input)
		}
	})

	t.Run("FormatValue", func(t *testing.T) {
		tests := []struct {
			input    interface{}
			expected string
		}{
			{"simple", "\"simple\""},
			{"with*wildcard", "\"with*wildcard\""},
			{42, "42"},
			{3.14, "3.140000"},
			{true, "true"},
			{false, "false"},
			{nil, "null"},
		}

		for _, test := range tests {
			result, err := utils.FormatValue(test.input)
			require.NoError(t, err, "Failed to format value: %v", test.input)
			assert.Equal(t, test.expected, result, "Failed for input: %v", test.input)
		}
	})
}

func TestValidationUtils(t *testing.T) {
	utils := &ValidationUtils{}

	t.Run("IsValidLevel", func(t *testing.T) {
		validLevels := []string{"", "informational", "low", "medium", "high", "critical"}
		for _, level := range validLevels {
			assert.True(t, utils.IsValidLevel(level), "Expected %s to be valid", level)
		}

		invalidLevels := []string{"invalid", "HIGH", "Critical"}
		for _, level := range invalidLevels {
			assert.False(t, utils.IsValidLevel(level), "Expected %s to be invalid", level)
		}
	})

	t.Run("IsValidStatus", func(t *testing.T) {
		validStatuses := []string{"", "stable", "test", "experimental", "deprecated", "unsupported"}
		for _, status := range validStatuses {
			assert.True(t, utils.IsValidStatus(status), "Expected %s to be valid", status)
		}

		invalidStatuses := []string{"invalid", "STABLE", "Testing"}
		for _, status := range invalidStatuses {
			assert.False(t, utils.IsValidStatus(status), "Expected %s to be invalid", status)
		}
	})

	t.Run("IsValidFieldName", func(t *testing.T) {
		validFields := []string{"field", "field.subfield", "-negated", "field_name"}
		for _, field := range validFields {
			assert.True(t, utils.IsValidFieldName(field), "Expected %s to be valid", field)
		}

		invalidFields := []string{"", ".field", "*field"}
		for _, field := range invalidFields {
			assert.False(t, utils.IsValidFieldName(field), "Expected %s to be invalid", field)
		}
	})
}

func TestQueryUtils(t *testing.T) {
	utils := NewQueryUtils()

	t.Run("BuildValueComparison", func(t *testing.T) {
		values := []interface{}{"value1", "value2"}
		result, err := utils.BuildValueComparison("field", values, "==", "")
		require.NoError(t, err)
		
		assert.Len(t, result, 2)
		assert.Equal(t, "field == \"value1\"", result[0])
		assert.Equal(t, "field == \"value2\"", result[1])
	})

	t.Run("BuildLikeComparison", func(t *testing.T) {
		values := []interface{}{"test"}
		result, err := utils.BuildLikeComparison("field", values, "*%s*", "not")
		require.NoError(t, err)
		
		assert.Len(t, result, 1)
		assert.Equal(t, "field not like \"*test*\"", result[0])
	})

	t.Run("CombineExpressions", func(t *testing.T) {
		tests := []struct {
			expressions []string
			operator    string
			expected    string
		}{
			{[]string{}, "and", ""},
			{[]string{"expr1"}, "and", "expr1"},
			{[]string{"expr1", "expr2"}, "and", "(expr1 and expr2)"},
			{[]string{"expr1", "expr2", "expr3"}, "or", "(expr1 or expr2 or expr3)"},
		}

		for _, test := range tests {
			result := utils.CombineExpressions(test.expressions, test.operator)
			assert.Equal(t, test.expected, result)
		}
	})
}

func TestErrorUtils(t *testing.T) {
	utils := &ErrorUtils{}

	t.Run("NewParseError", func(t *testing.T) {
		err := utils.NewParseError("value", "field", assert.AnError)
		assert.Contains(t, err.Error(), "failed to parse value for field 'field'")
		assert.Contains(t, err.Error(), "assert.AnError")
	})

	t.Run("NewValidationError", func(t *testing.T) {
		err := utils.NewValidationError("field", "invalid value")
		assert.Equal(t, "validation error for field 'field': invalid value", err.Error())
	})

	t.Run("NewConversionError", func(t *testing.T) {
		err := utils.NewConversionError("elasticsearch", "convert", assert.AnError)
		assert.Contains(t, err.Error(), "conversion error in elasticsearch backend during convert")
		assert.Contains(t, err.Error(), "assert.AnError")
	})
}

func TestGlobalUtilInstances(t *testing.T) {
	// Test that global instances are properly initialized
	assert.NotNil(t, StringUtil)
	assert.NotNil(t, ValidationUtil)
	assert.NotNil(t, QueryUtil)
	assert.NotNil(t, ErrorUtil)

	// Test basic functionality through global instances
	result := StringUtil.EscapeString("test\"string")
	assert.Equal(t, "test\\\"string", result)

	valid := ValidationUtil.IsValidLevel("high")
	assert.True(t, valid)

	err := ErrorUtil.NewValidationError("test", "message")
	assert.Contains(t, err.Error(), "validation error")
}

func TestUtilsIntegration(t *testing.T) {
	// Test how utilities work together in a realistic scenario
	t.Run("Complex query building", func(t *testing.T) {
		field := "process.command_line"
		values := []interface{}{"powershell.exe", "cmd.exe"}
		
		// Build value comparisons
		comparisons, err := QueryUtil.BuildValueComparison(field, values, "==", "")
		require.NoError(t, err)
		
		// Combine with OR
		result := QueryUtil.CombineExpressions(comparisons, "or")
		expected := "(process.command_line == \"powershell.exe\" or process.command_line == \"cmd.exe\")"
		assert.Equal(t, expected, result)
	})

	t.Run("Error propagation", func(t *testing.T) {
		// Test error propagation through utility chain
		field := "test.field"
		
		// Test BuildLikeComparison with non-string values (should fail)
		_, err := QueryUtil.BuildLikeComparison(field, []interface{}{123}, "*%s*", "")
		assert.Error(t, err)
		assert.Contains(t, strings.ToLower(err.Error()), "pattern matching requires string")
	})
}