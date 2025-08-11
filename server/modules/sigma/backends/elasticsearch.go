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

// ElasticsearchBackend converts Sigma rules to Elasticsearch Query Language (EQL)
type ElasticsearchBackend struct {
	*BaseBackend
	outputFormat string // "eql" or "dsl"
}

// NewElasticsearchBackend creates a new Elasticsearch backend
func NewElasticsearchBackend() *ElasticsearchBackend {
	return &ElasticsearchBackend{
		BaseBackend:  NewBaseBackend(),
		outputFormat: "eql",
	}
}

// SetOutputFormat sets the output format (eql or dsl)
func (e *ElasticsearchBackend) SetOutputFormat(format string) {
	e.outputFormat = format
}

// GetTargetFormat returns the target format name
func (e *ElasticsearchBackend) GetTargetFormat() string {
	return e.outputFormat
}

// Convert converts a Sigma rule to EQL or DSL
func (e *ElasticsearchBackend) Convert(rule *sigma.Rule, pipelines []sigma.Pipeline) (string, error) {
	// Apply pipelines
	processedRule, err := e.ApplyPipelines(rule, pipelines)
	if err != nil {
		return "", err
	}

	// Parse condition
	conditionAST, err := e.ParseCondition(processedRule.Detection.Condition)
	if err != nil {
		return "", fmt.Errorf("failed to parse condition: %w", err)
	}

	// Parse selections
	selections := make(map[string]*sigma.ParsedSelection)
	for name, selection := range processedRule.Detection.Selections {
		parsed, err := e.ParseSelection(name, selection)
		if err != nil {
			return "", fmt.Errorf("failed to parse selection %s: %w", name, err)
		}
		selections[name] = parsed
	}

	// Create visitor to convert AST to query
	visitor := &eqlVisitor{
		backend:    e,
		selections: selections,
		rule:       processedRule,
	}

	// Convert condition to query
	err = conditionAST.Accept(visitor)
	if err != nil {
		return "", err
	}

	// Get the event type based on logsource
	eventType := e.getEventType(processedRule.LogSource)
	
	// Build final query
	query := visitor.result
	if eventType != "" && e.outputFormat == "eql" {
		query = fmt.Sprintf("%s where %s", eventType, query)
	}

	return query, nil
}

// eqlVisitor implements the visitor pattern for converting AST to EQL
type eqlVisitor struct {
	backend    *ElasticsearchBackend
	selections map[string]*sigma.ParsedSelection
	rule       *sigma.Rule
	result     string
	errors     []error
}

func (v *eqlVisitor) VisitAnd(node *sigma.AndNode) error {
	parts := make([]string, 0, len(node.Children))
	for _, child := range node.Children {
		childVisitor := &eqlVisitor{
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
	v.result = "(" + strings.Join(parts, " and ") + ")"
	return nil
}

func (v *eqlVisitor) VisitOr(node *sigma.OrNode) error {
	parts := make([]string, 0, len(node.Children))
	for _, child := range node.Children {
		childVisitor := &eqlVisitor{
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
	v.result = "(" + strings.Join(parts, " or ") + ")"
	return nil
}

func (v *eqlVisitor) VisitNot(node *sigma.NotNode) error {
	childVisitor := &eqlVisitor{
		backend:    v.backend,
		selections: v.selections,
		rule:       v.rule,
	}
	if err := node.Child.Accept(childVisitor); err != nil {
		return err
	}
	v.result = "not " + childVisitor.result
	return nil
}

func (v *eqlVisitor) VisitSelection(node *sigma.SelectionNode) error {
	selection, ok := v.selections[node.Name]
	if !ok {
		return fmt.Errorf("unknown selection: %s", node.Name)
	}

	parts := make([]string, 0, len(selection.Items))
	for _, item := range selection.Items {
		expr, err := v.backend.convertSelectionItem(item)
		if err != nil {
			return err
		}
		parts = append(parts, expr)
	}

	if len(parts) == 1 {
		v.result = parts[0]
	} else if selection.IsOr {
		v.result = "(" + strings.Join(parts, " or ") + ")"
	} else {
		v.result = "(" + strings.Join(parts, " and ") + ")"
	}

	return nil
}

func (v *eqlVisitor) VisitOneOf(node *sigma.OneOfNode) error {
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
		selVisitor := &eqlVisitor{
			backend:    v.backend,
			selections: v.selections,
			rule:       v.rule,
		}
		if err := selNode.Accept(selVisitor); err != nil {
			return err
		}
		parts = append(parts, selVisitor.result)
	}

	v.result = "(" + strings.Join(parts, " or ") + ")"
	return nil
}

func (v *eqlVisitor) VisitAllOf(node *sigma.AllOfNode) error {
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
		selVisitor := &eqlVisitor{
			backend:    v.backend,
			selections: v.selections,
			rule:       v.rule,
		}
		if err := selNode.Accept(selVisitor); err != nil {
			return err
		}
		parts = append(parts, selVisitor.result)
	}

	v.result = "(" + strings.Join(parts, " and ") + ")"
	return nil
}

func (v *eqlVisitor) VisitThem(node *sigma.ThemNode) error {
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
		selVisitor := &eqlVisitor{
			backend:    v.backend,
			selections: v.selections,
			rule:       v.rule,
		}
		if err := selNode.Accept(selVisitor); err != nil {
			return err
		}
		parts = append(parts, selVisitor.result)
	}

	v.result = "(" + strings.Join(parts, " and ") + ")"
	return nil
}

// convertSelectionItem converts a single selection item to EQL
func (e *ElasticsearchBackend) convertSelectionItem(item sigma.SelectionItem) (string, error) {
	field := e.MapField(item.Field)
	
	// Handle null/exists checks
	if len(item.Values) == 1 && item.Values[0] == nil {
		if item.Negated {
			return fmt.Sprintf("%s != null", field), nil
		}
		return fmt.Sprintf("%s == null", field), nil
	}

	// Convert based on modifier
	switch item.Modifier {
	case string(sigma.ModifierContains):
		return e.convertContains(field, item.Values, item.Negated)
	case string(sigma.ModifierStartsWith):
		return e.convertStartsWith(field, item.Values, item.Negated)
	case string(sigma.ModifierEndsWith):
		return e.convertEndsWith(field, item.Values, item.Negated)
	case string(sigma.ModifierRe):
		return e.convertRegex(field, item.Values, item.Negated)
	case string(sigma.ModifierCIDR):
		return e.convertCIDR(field, item.Values, item.Negated)
	default:
		return e.convertEquals(field, item.Values, item.Negated)
	}
}

// convertEquals converts equality comparisons
func (e *ElasticsearchBackend) convertEquals(field string, values []interface{}, negated bool) (string, error) {
	if len(values) == 1 {
		valueStr, err := sigma.StringUtil.FormatValue(values[0])
		if err != nil {
			return "", sigma.ErrorUtil.NewConversionError("elasticsearch", "format value", err)
		}
		op := "=="
		if negated {
			op = "!="
		}
		return fmt.Sprintf("%s %s %s", field, op, valueStr), nil
	}

	// Multiple values - use IN
	valueStrs := make([]string, 0, len(values))
	for _, v := range values {
		str, err := sigma.StringUtil.FormatValue(v)
		if err != nil {
			return "", sigma.ErrorUtil.NewConversionError("elasticsearch", "format value", err)
		}
		valueStrs = append(valueStrs, str)
	}

	if negated {
		return fmt.Sprintf("%s not in (%s)", field, strings.Join(valueStrs, ", ")), nil
	}
	return fmt.Sprintf("%s in (%s)", field, strings.Join(valueStrs, ", ")), nil
}

// convertContains converts contains comparisons
func (e *ElasticsearchBackend) convertContains(field string, values []interface{}, negated bool) (string, error) {
	negationPrefix := ""
	if negated {
		negationPrefix = "not"
	}
	
	parts, err := sigma.QueryUtil.BuildLikeComparison(field, values, "*%s*", negationPrefix)
	if err != nil {
		return "", sigma.ErrorUtil.NewConversionError("elasticsearch", "contains conversion", err)
	}
	
	return sigma.QueryUtil.CombineExpressions(parts, "or"), nil
}

// convertStartsWith converts startswith comparisons
func (e *ElasticsearchBackend) convertStartsWith(field string, values []interface{}, negated bool) (string, error) {
	negationPrefix := ""
	if negated {
		negationPrefix = "not"
	}
	
	parts, err := sigma.QueryUtil.BuildLikeComparison(field, values, "%s*", negationPrefix)
	if err != nil {
		return "", sigma.ErrorUtil.NewConversionError("elasticsearch", "startswith conversion", err)
	}
	
	return sigma.QueryUtil.CombineExpressions(parts, "or"), nil
}

// convertEndsWith converts endswith comparisons
func (e *ElasticsearchBackend) convertEndsWith(field string, values []interface{}, negated bool) (string, error) {
	negationPrefix := ""
	if negated {
		negationPrefix = "not"
	}
	
	parts, err := sigma.QueryUtil.BuildLikeComparison(field, values, "*%s", negationPrefix)
	if err != nil {
		return "", sigma.ErrorUtil.NewConversionError("elasticsearch", "endswith conversion", err)
	}
	
	return sigma.QueryUtil.CombineExpressions(parts, "or"), nil
}

// convertRegex converts regex comparisons
func (e *ElasticsearchBackend) convertRegex(field string, values []interface{}, negated bool) (string, error) {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		str, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("re modifier requires string value")
		}
		if negated {
			parts = append(parts, fmt.Sprintf("%s not regex \"%s\"", field, str))
		} else {
			parts = append(parts, fmt.Sprintf("%s regex \"%s\"", field, str))
		}
	}

	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " or ") + ")", nil
}

// convertCIDR converts CIDR comparisons
func (e *ElasticsearchBackend) convertCIDR(field string, values []interface{}, negated bool) (string, error) {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		str, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("cidr modifier requires string value")
		}
		if negated {
			parts = append(parts, fmt.Sprintf("not cidrMatch(%s, \"%s\")", field, str))
		} else {
			parts = append(parts, fmt.Sprintf("cidrMatch(%s, \"%s\")", field, str))
		}
	}

	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " or ") + ")", nil
}


// getEventType determines the EQL event type based on logsource
func (e *ElasticsearchBackend) getEventType(logsource sigma.LogSource) string {
	// Map common categories to EQL event types
	switch logsource.Category {
	case "process_creation":
		return "process"
	case "network_connection":
		return "network"
	case "file_event", "file_creation", "file_change", "file_delete":
		return "file"
	case "registry_event", "registry_add", "registry_delete", "registry_set":
		return "registry"
	case "dns_query":
		return "dns"
	default:
		// For Windows logs, use appropriate event type
		if logsource.Product == "windows" {
			switch logsource.Service {
			case "security":
				return "security"
			case "system":
				return "system"
			case "application":
				return "application"
			case "powershell":
				return "powershell"
			default:
				return "any"
			}
		}
		return "any"
	}
}

// Register the backend
func init() {
	sigma.RegisterConverter("eql", func() sigma.Converter {
		return NewElasticsearchBackend()
	})
	sigma.RegisterConverter("elasticsearch", func() sigma.Converter {
		backend := NewElasticsearchBackend()
		backend.SetOutputFormat("dsl")
		return backend
	})
}