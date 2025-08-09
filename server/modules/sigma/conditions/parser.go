// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package conditions

import (
	"fmt"
	"regexp"
	"strings"

	sigma "github.com/security-onion-solutions/securityonion-soc/server/modules/sigma"
)

// Parser handles parsing of Sigma condition strings into AST
type Parser struct {
	input    string
	position int
	tokens   []token
	current  int
}

// token represents a lexical token
type token struct {
	typ   tokenType
	value string
	pos   int
}

// tokenType represents the type of a token
type tokenType int

const (
	tokenEOF tokenType = iota
	tokenIdentifier
	tokenAnd
	tokenOr
	tokenNot
	tokenOneOf
	tokenAllOf
	tokenThem
	tokenLParen
	tokenRParen
	tokenOf
	tokenNumber
)

// NewParser creates a new condition parser
func NewParser(condition string) *Parser {
	return &Parser{
		input: condition,
	}
}

// Parse parses the condition string into an AST
func (p *Parser) Parse() (sigma.ConditionNode, error) {
	// Tokenize the input
	if err := p.tokenize(); err != nil {
		return nil, err
	}

	// Parse the tokens into an AST
	node, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	// Ensure we've consumed all tokens
	if p.current < len(p.tokens)-1 {
		return nil, &sigma.ConditionError{
			Position: p.tokens[p.current].pos,
			Message:  fmt.Sprintf("unexpected token: %s", p.tokens[p.current].value),
		}
	}

	return node, nil
}

// tokenize breaks the input into tokens
func (p *Parser) tokenize() error {
	p.tokens = make([]token, 0)
	p.position = 0

	for p.position < len(p.input) {
		// Skip whitespace
		if p.skipWhitespace() {
			continue
		}

		pos := p.position
		ch := p.input[p.position]

		switch ch {
		case '(':
			p.tokens = append(p.tokens, token{typ: tokenLParen, value: "(", pos: pos})
			p.position++
		case ')':
			p.tokens = append(p.tokens, token{typ: tokenRParen, value: ")", pos: pos})
			p.position++
		default:
			// Try to match keywords or identifiers
			if word := p.readWord(); word != "" {
				tok := p.classifyWord(word, pos)
				p.tokens = append(p.tokens, tok)
			} else if num := p.readNumber(); num != "" {
				p.tokens = append(p.tokens, token{typ: tokenNumber, value: num, pos: pos})
			} else {
				return &sigma.ConditionError{
					Position: pos,
					Message:  fmt.Sprintf("unexpected character: %c", ch),
				}
			}
		}
	}

	// Add EOF token
	p.tokens = append(p.tokens, token{typ: tokenEOF, value: "", pos: p.position})
	return nil
}

// skipWhitespace skips whitespace characters
func (p *Parser) skipWhitespace() bool {
	start := p.position
	for p.position < len(p.input) && isWhitespace(p.input[p.position]) {
		p.position++
	}
	return p.position > start
}

// readWord reads a word (identifier or keyword)
func (p *Parser) readWord() string {
	start := p.position
	for p.position < len(p.input) && (isAlphaNumeric(p.input[p.position]) || p.input[p.position] == '_' || p.input[p.position] == '*') {
		p.position++
	}
	if p.position > start {
		return p.input[start:p.position]
	}
	return ""
}

// readNumber reads a number
func (p *Parser) readNumber() string {
	start := p.position
	for p.position < len(p.input) && isDigit(p.input[p.position]) {
		p.position++
	}
	if p.position > start {
		return p.input[start:p.position]
	}
	return ""
}

// classifyWord determines the token type for a word
func (p *Parser) classifyWord(word string, pos int) token {
	upperWord := strings.ToUpper(word)
	switch upperWord {
	case "AND":
		return token{typ: tokenAnd, value: word, pos: pos}
	case "OR":
		return token{typ: tokenOr, value: word, pos: pos}
	case "NOT":
		return token{typ: tokenNot, value: word, pos: pos}
	case "OF":
		return token{typ: tokenOf, value: word, pos: pos}
	case "THEM":
		return token{typ: tokenThem, value: word, pos: pos}
	case "ALL":
		return token{typ: tokenAllOf, value: word, pos: pos}
	default:
		// Check if it's a number followed by "of"
		if p.current+1 < len(p.input) && isDigit(word[0]) {
			// This might be "1 of" pattern
			return token{typ: tokenNumber, value: word, pos: pos}
		}
		return token{typ: tokenIdentifier, value: word, pos: pos}
	}
}

// parseExpression parses an expression (OR level)
func (p *Parser) parseExpression() (sigma.ConditionNode, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for p.current < len(p.tokens) && p.tokens[p.current].typ == tokenOr {
		p.current++ // consume OR
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}

		// Build OR node
		if orNode, ok := left.(*sigma.OrNode); ok {
			orNode.Children = append(orNode.Children, right)
		} else {
			left = &sigma.OrNode{Children: []sigma.ConditionNode{left, right}}
		}
	}

	return left, nil
}

// parseAndExpression parses an AND expression
func (p *Parser) parseAndExpression() (sigma.ConditionNode, error) {
	left, err := p.parseUnaryExpression()
	if err != nil {
		return nil, err
	}

	for p.current < len(p.tokens) && p.tokens[p.current].typ == tokenAnd {
		p.current++ // consume AND
		right, err := p.parseUnaryExpression()
		if err != nil {
			return nil, err
		}

		// Build AND node
		if andNode, ok := left.(*sigma.AndNode); ok {
			andNode.Children = append(andNode.Children, right)
		} else {
			left = &sigma.AndNode{Children: []sigma.ConditionNode{left, right}}
		}
	}

	return left, nil
}

// parseUnaryExpression parses a unary expression (NOT or primary)
func (p *Parser) parseUnaryExpression() (sigma.ConditionNode, error) {
	if p.current >= len(p.tokens) {
		return nil, &sigma.ConditionError{
			Position: p.position,
			Message:  "unexpected end of condition",
		}
	}

	// Handle NOT
	if p.tokens[p.current].typ == tokenNot {
		p.current++ // consume NOT
		expr, err := p.parseUnaryExpression()
		if err != nil {
			return nil, err
		}
		return &sigma.NotNode{Child: expr}, nil
	}

	return p.parsePrimaryExpression()
}

// parsePrimaryExpression parses a primary expression
func (p *Parser) parsePrimaryExpression() (sigma.ConditionNode, error) {
	if p.current >= len(p.tokens) {
		return nil, &sigma.ConditionError{
			Position: p.position,
			Message:  "unexpected end of condition",
		}
	}

	tok := p.tokens[p.current]

	// Handle parentheses
	if tok.typ == tokenLParen {
		p.current++ // consume (
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if p.current >= len(p.tokens) || p.tokens[p.current].typ != tokenRParen {
			return nil, &sigma.ConditionError{
				Position: tok.pos,
				Message:  "missing closing parenthesis",
			}
		}
		p.current++ // consume )
		return expr, nil
	}

	// Handle "1 of" pattern
	if tok.typ == tokenNumber && p.current+1 < len(p.tokens) && p.tokens[p.current+1].typ == tokenOf {
		num := tok.value
		p.current += 2 // consume number and "of"
		
		if p.current >= len(p.tokens) {
			return nil, &sigma.ConditionError{
				Position: tok.pos,
				Message:  "expected pattern after 'of'",
			}
		}
		
		pattern := p.tokens[p.current].value
		p.current++
		
		if num == "1" {
			return &sigma.OneOfNode{Pattern: pattern}, nil
		}
		// For now, treat other numbers as "all of"
		return &sigma.AllOfNode{Pattern: pattern}, nil
	}

	// Handle "all of" pattern
	if tok.typ == tokenAllOf && p.current+1 < len(p.tokens) && p.tokens[p.current+1].typ == tokenOf {
		p.current += 2 // consume "all" and "of"
		
		if p.current >= len(p.tokens) {
			return nil, &sigma.ConditionError{
				Position: tok.pos,
				Message:  "expected pattern after 'of'",
			}
		}
		
		pattern := p.tokens[p.current].value
		p.current++
		return &sigma.AllOfNode{Pattern: pattern}, nil
	}

	// Handle "them"
	if tok.typ == tokenThem {
		p.current++
		return &sigma.ThemNode{}, nil
	}

	// Handle selection reference
	if tok.typ == tokenIdentifier {
		p.current++
		return &sigma.SelectionNode{Name: tok.value}, nil
	}

	return nil, &sigma.ConditionError{
		Position: tok.pos,
		Message:  fmt.Sprintf("unexpected token: %s", tok.value),
	}
}

// Helper functions
func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func isAlphaNumeric(ch byte) bool {
	return isAlpha(ch) || isDigit(ch)
}

func isAlpha(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

// MatchesPattern checks if a selection name matches a pattern (with wildcards)
func MatchesPattern(name, pattern string) bool {
	// Convert pattern to regex
	regexPattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*") + "$"
	matched, _ := regexp.MatchString(regexPattern, name)
	return matched
}