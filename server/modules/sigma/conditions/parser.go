// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package conditions

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/server/modules/sigma/base"
)

// Parser parses Sigma condition strings into AST
type Parser struct {
	tokens  []string
	current int
}

// Parse parses a condition string into an AST
func Parse(condition string) (base.ConditionNode, error) {
	p := &Parser{
		tokens: tokenize(condition),
	}
	
	if len(p.tokens) == 0 {
		return nil, fmt.Errorf("empty condition")
	}
	
	return p.parseExpression()
}

// tokenize splits the condition string into tokens
func tokenize(condition string) []string {
	// Replace parentheses with spaces around them
	condition = strings.ReplaceAll(condition, "(", " ( ")
	condition = strings.ReplaceAll(condition, ")", " ) ")
	
	// Split by whitespace
	tokens := strings.Fields(condition)
	
	// Merge tokens that should be together (e.g., "1 of")
	var result []string
	i := 0
	for i < len(tokens) {
		if i < len(tokens)-1 {
			combined := tokens[i] + " " + tokens[i+1]
			if isPatternOperator(combined) {
				result = append(result, combined)
				i += 2
				continue
			}
		}
		result = append(result, tokens[i])
		i++
	}
	
	return result
}

func isPatternOperator(s string) bool {
	patterns := []string{"1 of", "all of"}
	for _, p := range patterns {
		if strings.EqualFold(s, p) {
			return true
		}
	}
	return false
}

// parseExpression parses a logical expression
func (p *Parser) parseExpression() (base.ConditionNode, error) {
	return p.parseOr()
}

// parseOr parses OR expressions
func (p *Parser) parseOr() (base.ConditionNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	
	for p.current < len(p.tokens) && strings.EqualFold(p.tokens[p.current], "or") {
		p.current++ // consume "or"
		
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		
		left = &base.OperatorNode{
			Operator: "OR",
			Children: []base.ConditionNode{left, right},
		}
	}
	
	return left, nil
}

// parseAnd parses AND expressions
func (p *Parser) parseAnd() (base.ConditionNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	
	for p.current < len(p.tokens) && strings.EqualFold(p.tokens[p.current], "and") {
		p.current++ // consume "and"
		
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		
		left = &base.OperatorNode{
			Operator: "AND",
			Children: []base.ConditionNode{left, right},
		}
	}
	
	return left, nil
}

// parseNot parses NOT expressions
func (p *Parser) parseNot() (base.ConditionNode, error) {
	if p.current < len(p.tokens) && strings.EqualFold(p.tokens[p.current], "not") {
		p.current++ // consume "not"
		
		expr, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		
		return &base.OperatorNode{
			Operator: "NOT",
			Children: []base.ConditionNode{expr},
		}, nil
	}
	
	return p.parsePrimary()
}

// parsePrimary parses primary expressions
func (p *Parser) parsePrimary() (base.ConditionNode, error) {
	if p.current >= len(p.tokens) {
		return nil, fmt.Errorf("unexpected end of condition")
	}
	
	token := p.tokens[p.current]
	
	// Handle parentheses
	if token == "(" {
		p.current++ // consume "("
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		
		if p.current >= len(p.tokens) || p.tokens[p.current] != ")" {
			return nil, fmt.Errorf("expected closing parenthesis")
		}
		p.current++ // consume ")"
		
		return expr, nil
	}
	
	// Handle pattern operators (1 of, all of)
	if isPatternOperator(token) {
		p.current++ // consume pattern operator
		
		if p.current >= len(p.tokens) {
			return nil, fmt.Errorf("expected target after '%s'", token)
		}
		
		target := p.tokens[p.current]
		p.current++
		
		return &base.PatternNode{
			Pattern: token,
			Target:  target,
		}, nil
	}
	
	// Handle selection references
	if isSelectionReference(token) {
		p.current++
		return &base.SelectionNode{
			Name: token,
		}, nil
	}
	
	return nil, fmt.Errorf("unexpected token: %s", token)
}

// isSelectionReference checks if a token is a selection reference
func isSelectionReference(token string) bool {
	// Selection references are identifiers that are not keywords
	keywords := []string{"and", "or", "not", "of", "them", "(", ")"}
	
	for _, kw := range keywords {
		if strings.EqualFold(token, kw) {
			return false
		}
	}
	
	// Check if it's a valid identifier (alphanumeric + underscore)
	match, _ := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_\*]*$`, token)
	return match
}