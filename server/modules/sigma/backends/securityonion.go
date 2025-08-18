// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package backends

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/base"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/common"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/conditions"
)

// SecurityOnionBackend converts Sigma rules to Security Onion format
type SecurityOnionBackend struct {
	BaseBackend
}

// NewSecurityOnionBackend creates a new Security Onion backend
func NewSecurityOnionBackend() *SecurityOnionBackend {
	return &SecurityOnionBackend{
		BaseBackend: BaseBackend{
			targetFormat: "security_onion",
		},
	}
}

// Convert converts a Sigma rule to Security Onion format
func (s *SecurityOnionBackend) Convert(rule *base.Rule, pipelines []base.Pipeline) (string, error) {
	// Apply pipelines
	processedRule := rule
	for _, pipeline := range pipelines {
		var err error
		processedRule, err = pipeline.Process(processedRule)
		if err != nil {
			return "", fmt.Errorf("pipeline processing failed: %w", err)
		}
	}

	// Process condition to get query
	query, err := s.processCondition(processedRule)
	if err != nil {
		return "", fmt.Errorf("failed to process condition: %w", err)
	}

	// Extract fields from the rule
	fields := s.extractFields(processedRule)

	// Check if this is an aggregation query
	isAggregation := false
	if agg, ok := processedRule.CustomAttributes["aggregation"].(bool); ok && agg {
		isAggregation = true
	}

	// For aggregation queries, append groupby clause
	if isAggregation && len(fields) > 0 {
		// Normalize field names for groupby clause to match the query
		normalizedFields := make([]string, len(fields))
		for i, field := range fields {
			normalizedFields[i] = common.NormalizeFieldName(field, "security_onion")
		}
		query = fmt.Sprintf("%s | groupby %s", query, strings.Join(normalizedFields, " "))
	}

	// Create the output structure
	output := map[string]interface{}{
		"query":  query,
		"fields": fields,
	}

	// Convert to JSON
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return "", fmt.Errorf("failed to marshal output: %w", err)
	}

	return string(jsonBytes), nil
}

// GetTargetFormat returns the target format name
func (s *SecurityOnionBackend) GetTargetFormat() string {
	return s.targetFormat
}

// SupportsCorrelation indicates if the backend supports correlation rules
func (s *SecurityOnionBackend) SupportsCorrelation() bool {
	return false
}

// processCondition processes the detection condition
func (s *SecurityOnionBackend) processCondition(rule *base.Rule) (string, error) {
	// Parse condition
	ast, err := conditions.Parse(rule.Detection.Condition)
	if err != nil {
		return "", fmt.Errorf("failed to parse condition: %w", err)
	}

	// Convert AST to query
	return s.astToQuery(ast, rule)
}

// astToQuery converts an AST node to Security Onion query format
func (s *SecurityOnionBackend) astToQuery(node base.ConditionNode, rule *base.Rule) (string, error) {
	switch n := node.(type) {
	case *base.OperatorNode:
		return s.operatorToQuery(n, rule)
	case *base.SelectionNode:
		return s.selectionToQuery(n, rule)
	case *base.PatternNode:
		return s.patternToQuery(n, rule)
	default:
		return "", fmt.Errorf("unsupported node type: %T", node)
	}
}

// operatorToQuery converts an operator node to query
func (s *SecurityOnionBackend) operatorToQuery(node *base.OperatorNode, rule *base.Rule) (string, error) {
	childQueries := []string{}
	
	for _, child := range node.Children {
		query, err := s.astToQuery(child, rule)
		if err != nil {
			return "", err
		}
		childQueries = append(childQueries, query)
	}
	
	switch node.Operator {
	case "AND":
		return "(" + strings.Join(childQueries, " AND ") + ")", nil
	case "OR":
		return "(" + strings.Join(childQueries, " OR ") + ")", nil
	case "NOT":
		if len(childQueries) != 1 {
			return "", fmt.Errorf("NOT operator requires exactly one child")
		}
		return "NOT " + childQueries[0], nil
	default:
		return "", fmt.Errorf("unsupported operator: %s", node.Operator)
	}
}

// selectionToQuery converts a selection reference to query
func (s *SecurityOnionBackend) selectionToQuery(node *base.SelectionNode, rule *base.Rule) (string, error) {
	selection, exists := rule.Detection.Selections[node.Name]
	if !exists {
		return "", fmt.Errorf("selection not found: %s", node.Name)
	}
	
	conditions := []string{}
	
	switch sel := selection.(type) {
	case map[string]interface{}:
		// Sort fields for deterministic output
		fields := make([]string, 0, len(sel))
		for field := range sel {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		
		for _, field := range fields {
			value := sel[field]
			cond, err := ProcessFieldValue(s, field, value)
			if err != nil {
				return "", err
			}
			conditions = append(conditions, cond...)
		}
	case []interface{}:
		// List of conditions (OR between them)
		for _, item := range sel {
			if itemMap, ok := item.(map[string]interface{}); ok {
				itemConds := []string{}
				// Sort fields for deterministic output
				fields := make([]string, 0, len(itemMap))
				for field := range itemMap {
					fields = append(fields, field)
				}
				sort.Strings(fields)
				
				for _, field := range fields {
					value := itemMap[field]
					cond, err := ProcessFieldValue(s, field, value)
					if err != nil {
						return "", err
					}
					itemConds = append(itemConds, cond...)
				}
				if len(itemConds) > 0 {
					conditions = append(conditions, "("+strings.Join(itemConds, " AND ")+")")
				}
			}
		}
	}
	
	if len(conditions) == 0 {
		return "*", nil
	}
	
	if len(conditions) == 1 {
		return conditions[0], nil
	}
	
	return "(" + strings.Join(conditions, " AND ") + ")", nil
}

// patternToQuery converts a pattern node to query
func (s *SecurityOnionBackend) patternToQuery(node *base.PatternNode, rule *base.Rule) (string, error) {
	// Handle "1 of" and "all of" patterns
	var selectionNames []string
	
	if node.Target == "them" {
		// All selections
		for name := range rule.Detection.Selections {
			if name != "condition" && name != "timeframe" {
				selectionNames = append(selectionNames, name)
			}
		}
	} else if strings.Contains(node.Target, "*") {
		// Wildcard pattern
		pattern := strings.ReplaceAll(node.Target, "*", "")
		for name := range rule.Detection.Selections {
			if strings.Contains(name, pattern) {
				selectionNames = append(selectionNames, name)
			}
		}
	} else {
		// Specific selection
		selectionNames = []string{node.Target}
	}
	
	if len(selectionNames) == 0 {
		return "", fmt.Errorf("no selections match pattern: %s", node.Target)
	}
	
	// Sort selection names for deterministic output
	sort.Strings(selectionNames)
	
	// Convert selections to queries
	selectionQueries := []string{}
	for _, name := range selectionNames {
		selNode := &base.SelectionNode{Name: name}
		query, err := s.selectionToQuery(selNode, rule)
		if err != nil {
			return "", err
		}
		selectionQueries = append(selectionQueries, query)
	}
	
	switch node.Pattern {
	case "1 of":
		return "(" + strings.Join(selectionQueries, " OR ") + ")", nil
	case "all of":
		return "(" + strings.Join(selectionQueries, " AND ") + ")", nil
	default:
		return "", fmt.Errorf("unsupported pattern: %s", node.Pattern)
	}
}

// ProcessStringValue processes string values for Security Onion
func (s *SecurityOnionBackend) ProcessStringValue(field, value string, modifiers []string) string {
	// Normalize field name
	field = common.NormalizeFieldName(field, "security_onion")
	
	// Check if CIDR modifier is present
	hasCIDR := false
	for _, mod := range modifiers {
		if strings.ToLower(mod) == "cidr" {
			hasCIDR = true
			break
		}
	}
	
	// Apply modifiers (except CIDR which we handle specially)
	value = ApplyModifiers(value, modifiers)
	
	// For CIDR notation, don't quote or escape
	if hasCIDR {
		return fmt.Sprintf("%s:%s", field, value)
	}
	
	// Escape special characters
	value = common.EscapeSpecialCharacters(value, "security_onion")
	
	// Handle wildcards (Lucene style)
	if strings.Contains(value, "*") || strings.Contains(value, "?") {
		return fmt.Sprintf("%s:%s", field, value)
	}
	
	// Regular equality
	return fmt.Sprintf("%s:\"%s\"", field, value)
}

// ProcessNumericValue processes numeric values
func (s *SecurityOnionBackend) ProcessNumericValue(field string, value interface{}, modifiers []string) string {
	field = common.NormalizeFieldName(field, "security_onion")
	return fmt.Sprintf("%s:%v", field, value)
}

// ProcessBoolValue processes boolean values
func (s *SecurityOnionBackend) ProcessBoolValue(field string, value bool, modifiers []string) string {
	field = common.NormalizeFieldName(field, "security_onion")
	return fmt.Sprintf("%s:%v", field, value)
}

// ProcessNullValue processes null values
func (s *SecurityOnionBackend) ProcessNullValue(field string, modifiers []string) string {
	field = common.NormalizeFieldName(field, "security_onion")
	return fmt.Sprintf("NOT %s:*", field)
}

// extractFields extracts field names from the rule
func (s *SecurityOnionBackend) extractFields(rule *base.Rule) []string {
	// If explicit fields are defined, return them as-is for UI display
	// The normalization happens in the query generation, not in the field list
	if len(rule.Fields) > 0 {
		return rule.Fields
	}
	
	// Otherwise, extract from selections
	fieldMap := make(map[string]bool)
	
	for _, selection := range rule.Detection.Selections {
		fields := s.extractFieldsFromSelection(selection)
		for _, field := range fields {
			// Keep original field names for UI display
			fieldMap[field] = true
		}
	}
	
	// Convert map to slice
	fields := []string{}
	for field := range fieldMap {
		fields = append(fields, field)
	}
	
	return fields
}

// extractFieldsFromSelection extracts field names from a selection
func (s *SecurityOnionBackend) extractFieldsFromSelection(selection interface{}) []string {
	fields := []string{}
	
	switch sel := selection.(type) {
	case map[string]interface{}:
		for field := range sel {
			// Remove modifiers
			baseField := strings.Split(field, "|")[0]
			fields = append(fields, baseField)
		}
	case []interface{}:
		for _, item := range sel {
			if itemMap, ok := item.(map[string]interface{}); ok {
				for field := range itemMap {
					baseField := strings.Split(field, "|")[0]
					fields = append(fields, baseField)
				}
			}
		}
	}
	
	return fields
}