// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package backends

import (
	"fmt"
	"sort"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/base"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/common"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/conditions"
)

// EQLBackend converts Sigma rules to Elasticsearch Query Language
type EQLBackend struct {
	BaseBackend
}

// NewEQLBackend creates a new EQL backend
func NewEQLBackend() *EQLBackend {
	return &EQLBackend{
		BaseBackend: BaseBackend{
			targetFormat: "eql",
		},
	}
}

// Convert converts a Sigma rule to EQL
func (e *EQLBackend) Convert(rule *base.Rule, pipelines []base.Pipeline) (string, error) {
	// Apply pipelines
	processedRule := rule
	for _, pipeline := range pipelines {
		var err error
		processedRule, err = pipeline.Process(processedRule)
		if err != nil {
			return "", fmt.Errorf("pipeline processing failed: %w", err)
		}
	}

	// Build the query
	queryParts := []string{}

	// Add event category if specified
	if processedRule.LogSource.Category != "" {
		category := e.mapLogSourceCategory(processedRule.LogSource.Category)
		if category != "" {
			queryParts = append(queryParts, category)
		}
	}

	// Process condition
	conditionQuery, err := e.processCondition(processedRule)
	if err != nil {
		return "", fmt.Errorf("failed to process condition: %w", err)
	}

	// Add where clause
	whereClause := "where " + conditionQuery
	queryParts = append(queryParts, whereClause)

	return strings.Join(queryParts, " "), nil
}

// GetTargetFormat returns the target format name
func (e *EQLBackend) GetTargetFormat() string {
	return e.targetFormat
}

// SupportsCorrelation indicates if the backend supports correlation rules
func (e *EQLBackend) SupportsCorrelation() bool {
	return true
}

// processCondition processes the detection condition
func (e *EQLBackend) processCondition(rule *base.Rule) (string, error) {
	// Parse condition
	ast, err := conditions.Parse(rule.Detection.Condition)
	if err != nil {
		return "", fmt.Errorf("failed to parse condition: %w", err)
	}

	// Convert AST to EQL
	return e.astToEQL(ast, rule)
}

// astToEQL converts an AST node to EQL
func (e *EQLBackend) astToEQL(node base.ConditionNode, rule *base.Rule) (string, error) {
	switch n := node.(type) {
	case *base.OperatorNode:
		return e.operatorToEQL(n, rule)
	case *base.SelectionNode:
		return e.selectionToEQL(n, rule)
	case *base.PatternNode:
		return e.patternToEQL(n, rule)
	default:
		return "", fmt.Errorf("unsupported node type: %T", node)
	}
}

// operatorToEQL converts an operator node to EQL
func (e *EQLBackend) operatorToEQL(node *base.OperatorNode, rule *base.Rule) (string, error) {
	childQueries := []string{}
	
	for _, child := range node.Children {
		query, err := e.astToEQL(child, rule)
		if err != nil {
			return "", err
		}
		// Wrap child queries in parentheses if they're selections
		if _, ok := child.(*base.SelectionNode); ok {
			query = "(" + query + ")"
		}
		childQueries = append(childQueries, query)
	}
	
	switch node.Operator {
	case "AND":
		return strings.Join(childQueries, " and "), nil
	case "OR":
		return strings.Join(childQueries, " or "), nil
	case "NOT":
		if len(childQueries) != 1 {
			return "", fmt.Errorf("NOT operator requires exactly one child")
		}
		return "not " + childQueries[0], nil
	default:
		return "", fmt.Errorf("unsupported operator: %s", node.Operator)
	}
}

// selectionToEQL converts a selection reference to EQL
func (e *EQLBackend) selectionToEQL(node *base.SelectionNode, rule *base.Rule) (string, error) {
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
			cond, err := ProcessFieldValue(e, field, value)
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
					cond, err := ProcessFieldValue(e, field, value)
					if err != nil {
						return "", err
					}
					itemConds = append(itemConds, cond...)
				}
				if len(itemConds) > 0 {
					conditions = append(conditions, "("+strings.Join(itemConds, " and ")+")")
				}
			}
		}
	}
	
	if len(conditions) == 0 {
		return "true", nil
	}
	
	// Return conditions joined with "and"
	return strings.Join(conditions, " and "), nil
}

// patternToEQL converts a pattern node to EQL
func (e *EQLBackend) patternToEQL(node *base.PatternNode, rule *base.Rule) (string, error) {
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
		prefix := strings.TrimSuffix(node.Target, "*")
		for name := range rule.Detection.Selections {
			if strings.HasPrefix(name, prefix) {
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
		query, err := e.selectionToEQL(selNode, rule)
		if err != nil {
			return "", err
		}
		selectionQueries = append(selectionQueries, query)
	}
	
	switch node.Pattern {
	case "1 of":
		// Wrap each selection query in parentheses
		wrappedQueries := []string{}
		for _, q := range selectionQueries {
			wrappedQueries = append(wrappedQueries, "("+q+")")
		}
		return "(" + strings.Join(wrappedQueries, " or ") + ")", nil
	case "all of":
		// Wrap each selection query in parentheses
		wrappedQueries := []string{}
		for _, q := range selectionQueries {
			wrappedQueries = append(wrappedQueries, "("+q+")")
		}
		return "(" + strings.Join(wrappedQueries, " and ") + ")", nil
	default:
		return "", fmt.Errorf("unsupported pattern: %s", node.Pattern)
	}
}

// ProcessStringValue processes string values for EQL
func (e *EQLBackend) ProcessStringValue(field, value string, modifiers []string) string {
	// Normalize field name
	field = common.NormalizeFieldName(field, "eql")
	
	// Apply modifiers
	value = ApplyModifiers(value, modifiers)
	
	// Escape special characters
	value = common.EscapeSpecialCharacters(value, "eql")
	
	// Handle wildcards
	if strings.Contains(value, "*") {
		// EQL uses wildcard function
		return fmt.Sprintf("wildcard(%s, \"%s\")", field, value)
	}
	
	// Handle contains modifier
	if HasModifier(modifiers, "contains") {
		return fmt.Sprintf("wildcard(%s, \"%s\")", field, value)
	}
	
	// Regular equality
	return fmt.Sprintf("%s == \"%s\"", field, value)
}

// ProcessNumericValue processes numeric values for EQL
func (e *EQLBackend) ProcessNumericValue(field string, value interface{}, modifiers []string) string {
	field = common.NormalizeFieldName(field, "eql")
	return fmt.Sprintf("%s == %v", field, value)
}

// ProcessBoolValue processes boolean values for EQL
func (e *EQLBackend) ProcessBoolValue(field string, value bool, modifiers []string) string {
	field = common.NormalizeFieldName(field, "eql")
	return fmt.Sprintf("%s == %v", field, value)
}

// ProcessNullValue processes null values for EQL
func (e *EQLBackend) ProcessNullValue(field string, modifiers []string) string {
	field = common.NormalizeFieldName(field, "eql")
	return fmt.Sprintf("%s == null", field)
}

// mapLogSourceCategory maps Sigma log source categories to EQL event categories
func (e *EQLBackend) mapLogSourceCategory(category string) string {
	categoryMap := map[string]string{
		"process_creation": "process",
		"file_event":       "file",
		"network_connection": "network",
		"registry_event":   "registry",
		"dns_query":        "dns",
	}
	
	if mapped, ok := categoryMap[category]; ok {
		return mapped
	}
	
	return ""
}

