// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package backends

import (
	"fmt"
	"strings"

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

// Convert converts a Sigma rule to Security Onion format (OQL)
func (s *SecurityOnionBackend) Convert(rule *sigma.Rule, pipelines []sigma.Pipeline) (string, error) {
	// Apply pipelines
	processedRule, err := s.ApplyPipelines(rule, pipelines)
	if err != nil {
		return "", err
	}

	// Parse condition
	conditionAST, err := s.ParseCondition(processedRule.Detection.Condition)
	if err != nil {
		return "", fmt.Errorf("failed to parse condition: %w", err)
	}

	// Parse selections
	selections := make(map[string]*sigma.ParsedSelection)
	for name, selection := range processedRule.Detection.Selections {
		parsed, err := s.ParseSelection(name, selection)
		if err != nil {
			return "", fmt.Errorf("failed to parse selection %s: %w", name, err)
		}
		selections[name] = parsed
	}

	// Create visitor to convert AST to OQL
	visitor := &oqlVisitor{
		backend:    s,
		selections: selections,
		rule:       processedRule,
	}

	// Convert condition to query
	err = conditionAST.Accept(visitor)
	if err != nil {
		return "", err
	}

	return visitor.result, nil
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

// oqlVisitor implements the visitor pattern for converting AST to OQL
type oqlVisitor struct {
	backend    *SecurityOnionBackend
	selections map[string]*sigma.ParsedSelection
	rule       *sigma.Rule
	result     string
	errors     []error
}

func (v *oqlVisitor) VisitAnd(node *sigma.AndNode) error {
	parts := make([]string, 0, len(node.Children))
	for _, child := range node.Children {
		childVisitor := &oqlVisitor{
			backend:    v.backend,
			selections: v.selections,
			rule:       v.rule,
		}
		if err := child.Accept(childVisitor); err != nil {
			return err
		}
		if childVisitor.result != "" {
			parts = append(parts, childVisitor.result)
		}
	}
	v.result = "(" + strings.Join(parts, " AND ") + ")"
	return nil
}

func (v *oqlVisitor) VisitOr(node *sigma.OrNode) error {
	parts := make([]string, 0, len(node.Children))
	for _, child := range node.Children {
		childVisitor := &oqlVisitor{
			backend:    v.backend,
			selections: v.selections,
			rule:       v.rule,
		}
		if err := child.Accept(childVisitor); err != nil {
			return err
		}
		if childVisitor.result != "" {
			parts = append(parts, childVisitor.result)
		}
	}
	v.result = "(" + strings.Join(parts, " OR ") + ")"
	return nil
}

func (v *oqlVisitor) VisitNot(node *sigma.NotNode) error {
	childVisitor := &oqlVisitor{
		backend:    v.backend,
		selections: v.selections,
		rule:       v.rule,
	}
	if err := node.Child.Accept(childVisitor); err != nil {
		return err
	}
	v.result = "NOT " + childVisitor.result
	return nil
}

func (v *oqlVisitor) VisitSelection(node *sigma.SelectionNode) error {
	selection, ok := v.selections[node.Name]
	if !ok {
		return fmt.Errorf("unknown selection: %s", node.Name)
	}

	parts := make([]string, 0, len(selection.Items))
	for _, item := range selection.Items {
		expr, err := convertSelectionItemToOQL(v.backend, item)
		if err != nil {
			return err
		}
		parts = append(parts, expr)
	}

	if len(parts) == 1 {
		v.result = parts[0]
	} else if selection.IsOr {
		v.result = "(" + strings.Join(parts, " OR ") + ")"
	} else {
		v.result = "(" + strings.Join(parts, " AND ") + ")"
	}

	return nil
}

func (v *oqlVisitor) VisitOneOf(node *sigma.OneOfNode) error {
	// Find all selections matching the pattern
	matchingSelections := make([]string, 0)
	
	// Special case: "them" means all selections
	if node.Pattern == "them" {
		for name := range v.selections {
			matchingSelections = append(matchingSelections, name)
		}
	} else {
		// Regular pattern matching
		for name := range v.selections {
			if sigma.MatchesPattern(name, node.Pattern) {
				matchingSelections = append(matchingSelections, name)
			}
		}
	}

	if len(matchingSelections) == 0 {
		return fmt.Errorf("no selections match pattern: %s", node.Pattern)
	}

	// Convert to OR of all matching selections
	parts := make([]string, 0, len(matchingSelections))
	for _, name := range matchingSelections {
		selNode := &sigma.SelectionNode{Name: name}
		selVisitor := &oqlVisitor{
			backend:    v.backend,
			selections: v.selections,
			rule:       v.rule,
		}
		if err := selNode.Accept(selVisitor); err != nil {
			return err
		}
		parts = append(parts, selVisitor.result)
	}

	v.result = "(" + strings.Join(parts, " OR ") + ")"
	return nil
}

func (v *oqlVisitor) VisitAllOf(node *sigma.AllOfNode) error {
	// Find all selections matching the pattern
	matchingSelections := make([]string, 0)
	
	// Special case: "them" means all selections
	if node.Pattern == "them" {
		for name := range v.selections {
			matchingSelections = append(matchingSelections, name)
		}
	} else {
		// Regular pattern matching
		for name := range v.selections {
			if sigma.MatchesPattern(name, node.Pattern) {
				matchingSelections = append(matchingSelections, name)
			}
		}
	}

	if len(matchingSelections) == 0 {
		return fmt.Errorf("no selections match pattern: %s", node.Pattern)
	}

	// Convert to AND of all matching selections
	parts := make([]string, 0, len(matchingSelections))
	for _, name := range matchingSelections {
		selNode := &sigma.SelectionNode{Name: name}
		selVisitor := &oqlVisitor{
			backend:    v.backend,
			selections: v.selections,
			rule:       v.rule,
		}
		if err := selNode.Accept(selVisitor); err != nil {
			return err
		}
		parts = append(parts, selVisitor.result)
	}

	v.result = "(" + strings.Join(parts, " AND ") + ")"
	return nil
}

func (v *oqlVisitor) VisitThem(node *sigma.ThemNode) error {
	// "them" means all selections
	allSelections := make([]string, 0, len(v.selections))
	for name := range v.selections {
		allSelections = append(allSelections, name)
	}

	if len(allSelections) == 0 {
		return fmt.Errorf("no selections available for 'them'")
	}

	// Convert to AND of all selections
	parts := make([]string, 0, len(allSelections))
	for _, name := range allSelections {
		selNode := &sigma.SelectionNode{Name: name}
		selVisitor := &oqlVisitor{
			backend:    v.backend,
			selections: v.selections,
			rule:       v.rule,
		}
		if err := selNode.Accept(selVisitor); err != nil {
			return err
		}
		parts = append(parts, selVisitor.result)
	}

	v.result = "(" + strings.Join(parts, " AND ") + ")"
	return nil
}

// convertSelectionItemToOQL converts a single selection item to OQL
func convertSelectionItemToOQL(backend *SecurityOnionBackend, item sigma.SelectionItem) (string, error) {
	field := backend.MapField(item.Field)
	
	// Handle null/exists checks
	if len(item.Values) == 1 && item.Values[0] == nil {
		if item.Negated {
			// In OQL, checking for existence is done with a wildcard
			return fmt.Sprintf("%s:*", field), nil
		}
		return fmt.Sprintf("NOT %s:*", field), nil
	}

	// Handle different modifiers
	switch item.Modifier {
	case string(sigma.ModifierContains):
		return convertContainsToOQL(field, item.Values, item.Negated)
	case string(sigma.ModifierStartsWith):
		return convertStartsWithToOQL(field, item.Values, item.Negated)
	case string(sigma.ModifierEndsWith):
		return convertEndsWithToOQL(field, item.Values, item.Negated)
	case "expand":
		// Expand modifier is for variable substitution in playbooks
		return convertExpandToOQL(field, item.Values, item.Negated)
	default:
		return convertEqualsToOQL(field, item.Values, item.Negated)
	}
}

// convertEqualsToOQL converts equality comparisons to OQL
func convertEqualsToOQL(field string, values []interface{}, negated bool) (string, error) {
	parts := make([]string, 0, len(values))
	
	for _, v := range values {
		valueStr, err := sigma.StringUtil.FormatValue(v)
		if err != nil {
			return "", err
		}
		
		// In OQL, field:value is the basic syntax
		if negated {
			parts = append(parts, fmt.Sprintf("NOT %s:%s", field, valueStr))
		} else {
			parts = append(parts, fmt.Sprintf("%s:%s", field, valueStr))
		}
	}
	
	if len(parts) == 1 {
		return parts[0], nil
	}
	
	// Multiple values are OR'd together
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

// convertContainsToOQL converts contains comparisons
func convertContainsToOQL(field string, values []interface{}, negated bool) (string, error) {
	parts := make([]string, 0, len(values))
	
	for _, v := range values {
		str, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("contains modifier requires string value")
		}
		
		// In OQL, *value* is wildcard syntax
		if negated {
			parts = append(parts, fmt.Sprintf("NOT %s:*%s*", field, str))
		} else {
			parts = append(parts, fmt.Sprintf("%s:*%s*", field, str))
		}
	}
	
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

// convertStartsWithToOQL converts startswith comparisons
func convertStartsWithToOQL(field string, values []interface{}, negated bool) (string, error) {
	parts := make([]string, 0, len(values))
	
	for _, v := range values {
		str, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("startswith modifier requires string value")
		}
		
		// In OQL, value* is prefix wildcard
		if negated {
			parts = append(parts, fmt.Sprintf("NOT %s:%s*", field, str))
		} else {
			parts = append(parts, fmt.Sprintf("%s:%s*", field, str))
		}
	}
	
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

// convertEndsWithToOQL converts endswith comparisons
func convertEndsWithToOQL(field string, values []interface{}, negated bool) (string, error) {
	parts := make([]string, 0, len(values))
	
	for _, v := range values {
		str, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("endswith modifier requires string value")
		}
		
		// In OQL, *value is suffix wildcard
		if negated {
			parts = append(parts, fmt.Sprintf("NOT %s:*%s", field, str))
		} else {
			parts = append(parts, fmt.Sprintf("%s:*%s", field, str))
		}
	}
	
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

// convertExpandToOQL handles variable expansion for playbooks
func convertExpandToOQL(field string, values []interface{}, negated bool) (string, error) {
	// For expand modifier, we just pass through the variable reference
	// The frontend will substitute the actual values
	parts := make([]string, 0, len(values))
	
	for _, v := range values {
		str, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("expand modifier requires string value")
		}
		
		// Keep the variable syntax as-is
		if negated {
			parts = append(parts, fmt.Sprintf("NOT %s:%s", field, str))
		} else {
			parts = append(parts, fmt.Sprintf("%s:%s", field, str))
		}
	}
	
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", nil
}

// Register the backend
func init() {
	sigma.RegisterConverter("security_onion", func() sigma.Converter {
		return NewSecurityOnionBackend()
	})
}