// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"fmt"
	"strings"
)

// ConditionNode represents a node in the condition AST
type ConditionNode interface {
	// String returns a string representation of the node
	String() string
	// Accept implements the visitor pattern for traversing the AST
	Accept(visitor ConditionVisitor) error
}

// ConditionVisitor is the interface for visiting condition nodes
type ConditionVisitor interface {
	VisitAnd(node *AndNode) error
	VisitOr(node *OrNode) error
	VisitNot(node *NotNode) error
	VisitSelection(node *SelectionNode) error
	VisitOneOf(node *OneOfNode) error
	VisitAllOf(node *AllOfNode) error
	VisitThem(node *ThemNode) error
}

// AndNode represents an AND operation
type AndNode struct {
	Children []ConditionNode
}

func (n *AndNode) String() string {
	parts := make([]string, len(n.Children))
	for i, child := range n.Children {
		parts[i] = child.String()
	}
	return "(" + strings.Join(parts, " AND ") + ")"
}

func (n *AndNode) Accept(visitor ConditionVisitor) error {
	return visitor.VisitAnd(n)
}

// OrNode represents an OR operation
type OrNode struct {
	Children []ConditionNode
}

func (n *OrNode) String() string {
	parts := make([]string, len(n.Children))
	for i, child := range n.Children {
		parts[i] = child.String()
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func (n *OrNode) Accept(visitor ConditionVisitor) error {
	return visitor.VisitOr(n)
}

// NotNode represents a NOT operation
type NotNode struct {
	Child ConditionNode
}

func (n *NotNode) String() string {
	return "NOT " + n.Child.String()
}

func (n *NotNode) Accept(visitor ConditionVisitor) error {
	return visitor.VisitNot(n)
}

// SelectionNode represents a reference to a selection
type SelectionNode struct {
	Name string
}

func (n *SelectionNode) String() string {
	return n.Name
}

func (n *SelectionNode) Accept(visitor ConditionVisitor) error {
	return visitor.VisitSelection(n)
}

// OneOfNode represents a "1 of" operation
type OneOfNode struct {
	Pattern string
}

func (n *OneOfNode) String() string {
	return "1 of " + n.Pattern
}

func (n *OneOfNode) Accept(visitor ConditionVisitor) error {
	return visitor.VisitOneOf(n)
}

// AllOfNode represents an "all of" operation
type AllOfNode struct {
	Pattern string
}

func (n *AllOfNode) String() string {
	return "all of " + n.Pattern
}

func (n *AllOfNode) Accept(visitor ConditionVisitor) error {
	return visitor.VisitAllOf(n)
}

// ThemNode represents "them" keyword (all selections)
type ThemNode struct{}

func (n *ThemNode) String() string {
	return "them"
}

func (n *ThemNode) Accept(visitor ConditionVisitor) error {
	return visitor.VisitThem(n)
}

// SelectionItem represents a single field-value pair in a selection
type SelectionItem struct {
	Field    string
	Modifier string
	Values   []interface{}
	Negated  bool
}

// ParsedSelection represents a parsed selection with its items
type ParsedSelection struct {
	Name  string
	Items []SelectionItem
	// For complex selections that are ANDed or ORed
	IsAnd bool
	IsOr  bool
}

// ModifierType represents different value modifiers
type ModifierType string

const (
	ModifierNone       ModifierType = ""
	ModifierContains   ModifierType = "contains"
	ModifierAll        ModifierType = "all"
	ModifierBase64     ModifierType = "base64"
	ModifierBase64Wide ModifierType = "wide"
	ModifierEndsWith   ModifierType = "endswith"
	ModifierStartsWith ModifierType = "startswith"
	ModifierRe         ModifierType = "re"
	ModifierCIDR       ModifierType = "cidr"
)

// ParseModifier extracts modifier from field name
func ParseModifier(field string) (string, ModifierType) {
	parts := strings.Split(field, "|")
	if len(parts) == 1 {
		return field, ModifierNone
	}
	
	fieldName := parts[0]
	modifier := strings.ToLower(parts[1])
	
	switch modifier {
	case "contains":
		return fieldName, ModifierContains
	case "all":
		return fieldName, ModifierAll
	case "base64":
		return fieldName, ModifierBase64
	case "wide":
		return fieldName, ModifierBase64Wide
	case "endswith":
		return fieldName, ModifierEndsWith
	case "startswith":
		return fieldName, ModifierStartsWith
	case "re":
		return fieldName, ModifierRe
	case "cidr":
		return fieldName, ModifierCIDR
	default:
		// Unknown modifier, treat as part of field name
		return field, ModifierNone
	}
}

// ConditionError represents an error in condition parsing or evaluation
type ConditionError struct {
	Position int
	Message  string
}

func (e *ConditionError) Error() string {
	if e.Position >= 0 {
		return fmt.Sprintf("condition error at position %d: %s", e.Position, e.Message)
	}
	return fmt.Sprintf("condition error: %s", e.Message)
}

// MatchesPattern checks if a name matches a pattern with wildcards
func MatchesPattern(name, pattern string) bool {
	// Import from conditions package to avoid circular dependency
	return matchesPatternInternal(name, pattern)
}

// matchesPatternInternal is the internal implementation
func matchesPatternInternal(name, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}
	
	// Convert pattern to regex-like matching
	// Replace * with regex equivalent
	pattern = strings.ReplaceAll(pattern, "*", ".*")
	
	// Check if name matches pattern
	if strings.Contains(pattern, ".*") {
		// Pattern has wildcards
		prefix := strings.Split(pattern, ".*")[0]
		suffix := ""
		parts := strings.Split(pattern, ".*")
		if len(parts) > 1 {
			suffix = parts[len(parts)-1]
		}
		
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			return false
		}
		if suffix != "" && !strings.HasSuffix(name, suffix) {
			return false
		}
		return true
	}
	
	// Exact match
	return name == pattern
}