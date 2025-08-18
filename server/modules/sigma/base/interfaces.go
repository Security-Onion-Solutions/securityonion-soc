// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package base

import "time"

// Rule represents a parsed Sigma rule with all its components
type Rule struct {
	Title            string                 `yaml:"title"`
	ID               string                 `yaml:"id"`
	Status           string                 `yaml:"status"`
	Description      string                 `yaml:"description"`
	References       []string               `yaml:"references,omitempty"`
	Author           string                 `yaml:"author,omitempty"`
	Date             *time.Time             `yaml:"date,omitempty"`
	Modified         *time.Time             `yaml:"modified,omitempty"`
	Tags             []string               `yaml:"tags,omitempty"`
	LogSource        LogSource              `yaml:"logsource"`
	Detection        Detection              `yaml:"detection"`
	Fields           []string               `yaml:"fields,omitempty"`
	FalsePositives   []string               `yaml:"falsepositives,omitempty"`
	Level            string                 `yaml:"level,omitempty"`
	CustomAttributes map[string]interface{} `yaml:",inline"`
}

// LogSource defines where the log data comes from
type LogSource struct {
	Product    string `yaml:"product,omitempty"`
	Service    string `yaml:"service,omitempty"`
	Category   string `yaml:"category,omitempty"`
	Definition string `yaml:"definition,omitempty"`
}

// Detection contains the detection logic and conditions
type Detection struct {
	Condition  string                            `yaml:"condition"`
	Selections map[string]interface{}            `yaml:",inline"`
	Timeframe  string                            `yaml:"timeframe,omitempty"`
}

// Pipeline interface for rule transformations
type Pipeline interface {
	Process(rule *Rule) (*Rule, error)
	GetName() string
	GetPriority() int
}

// Converter interface for different backend conversions
type Converter interface {
	Convert(rule *Rule, pipelines []Pipeline) (string, error)
	GetTargetFormat() string
	SupportsCorrelation() bool
}

// ConvertedQuery represents a converted Sigma query for Security Onion format
type ConvertedQuery struct {
	Query  string   `json:"query"`
	Fields []string `json:"fields"`
}

// Override represents a custom filter override
type Override struct {
	Type      string                 `json:"type"`
	IsEnabled bool                   `json:"isEnabled"`
	Value     map[string]interface{} `json:"value"`
}

// ConditionNode represents a node in the condition AST
type ConditionNode interface {
	Type() string
	String() string
}