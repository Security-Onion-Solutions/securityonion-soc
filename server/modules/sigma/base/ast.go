// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package base

import "fmt"

// OperatorNode represents a boolean operator (AND, OR, NOT)
type OperatorNode struct {
	Operator string
	Children []ConditionNode
}

func (n *OperatorNode) Type() string {
	return "operator"
}

func (n *OperatorNode) String() string {
	return n.Operator
}

// SelectionNode represents a reference to a selection
type SelectionNode struct {
	Name string
}

func (n *SelectionNode) Type() string {
	return "selection"
}

func (n *SelectionNode) String() string {
	return n.Name
}

// PatternNode represents a pattern match (1 of, all of, etc.)
type PatternNode struct {
	Pattern string // "1 of", "all of", etc.
	Target  string // selection pattern or "them"
}

func (n *PatternNode) Type() string {
	return "pattern"
}

func (n *PatternNode) String() string {
	return n.Pattern + " " + n.Target
}

// ValueNode represents a value comparison
type ValueNode struct {
	Field    string
	Operator string // "=", "!=", ">", "<", etc.
	Value    interface{}
}

func (n *ValueNode) Type() string {
	return "value"
}

func (n *ValueNode) String() string {
	return n.Field + " " + n.Operator + " " + formatValue(n.Value)
}

func formatValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return "\"" + val + "\""
	default:
		return fmt.Sprintf("%v", val)
	}
}