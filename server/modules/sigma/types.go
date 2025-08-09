// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"time"
)

// Rule represents a parsed Sigma rule with all its components
type Rule struct {
	// Metadata fields
	Title          string                 `yaml:"title" json:"title"`
	ID             string                 `yaml:"id" json:"id"`
	Related        []RelatedRule          `yaml:"related,omitempty" json:"related,omitempty"`
	Status         string                 `yaml:"status" json:"status"`
	Description    string                 `yaml:"description,omitempty" json:"description,omitempty"`
	References     []string               `yaml:"references,omitempty" json:"references,omitempty"`
	Author         string                 `yaml:"author,omitempty" json:"author,omitempty"`
	Date           *time.Time             `yaml:"date,omitempty" json:"date,omitempty"`
	Modified       *time.Time             `yaml:"modified,omitempty" json:"modified,omitempty"`
	Tags           []string               `yaml:"tags,omitempty" json:"tags,omitempty"`
	License        string                 `yaml:"license,omitempty" json:"license,omitempty"`
	Level          string                 `yaml:"level,omitempty" json:"level,omitempty"`
	FalsePositives []string               `yaml:"falsepositives,omitempty" json:"falsepositives,omitempty"`
	Fields         []string               `yaml:"fields,omitempty" json:"fields,omitempty"`
	Custom         map[string]interface{} `yaml:",inline" json:"custom,omitempty"`

	// Core rule components
	LogSource LogSource           `yaml:"logsource" json:"logsource"`
	Detection Detection           `yaml:"detection" json:"detection"`
}

// RelatedRule represents a reference to a related Sigma rule
type RelatedRule struct {
	ID   string `yaml:"id" json:"id"`
	Type string `yaml:"type" json:"type"`
}

// LogSource defines the log source the rule applies to
type LogSource struct {
	Category   string `yaml:"category,omitempty" json:"category,omitempty"`
	Product    string `yaml:"product,omitempty" json:"product,omitempty"`
	Service    string `yaml:"service,omitempty" json:"service,omitempty"`
	Definition string `yaml:"definition,omitempty" json:"definition,omitempty"`
	// Custom fields for specific log sources
	Custom map[string]interface{} `yaml:",inline" json:"custom,omitempty"`
}

// Detection contains the detection logic and patterns
type Detection struct {
	// Selection patterns (named detection items)
	Selections map[string]interface{} `yaml:",inline" json:"selections"`
	// Condition that combines selections
	Condition string `yaml:"condition" json:"condition"`
	// Timeframe for the detection
	Timeframe string `yaml:"timeframe,omitempty" json:"timeframe,omitempty"`
}

// FieldMapping represents a mapping between Sigma field names and target field names
type FieldMapping struct {
	Source string
	Target string
}

// Pipeline represents a transformation pipeline that can be applied to rules
type Pipeline interface {
	// Process applies the pipeline transformations to a rule
	Process(rule *Rule) (*Rule, error)
	// GetName returns the name of the pipeline
	GetName() string
	// GetPriority returns the priority (lower numbers = higher priority)
	GetPriority() int
}

// Converter is the interface for backend converters
type Converter interface {
	// Convert converts a Sigma rule to the target query language
	Convert(rule *Rule, pipelines []Pipeline) (string, error)
	// ConvertCorrelation converts a correlation rule to the target format
	ConvertCorrelation(rules []*Rule, correlation CorrelationRule) (string, error)
	// GetTargetFormat returns the name of the target format (e.g., "eql", "spl", "kql")
	GetTargetFormat() string
	// SupportsCorrelation indicates if the backend supports correlation rules
	SupportsCorrelation() bool
	// SetFieldMappings sets custom field mappings for the converter
	SetFieldMappings(mappings []FieldMapping)
}

// CorrelationRule represents a Sigma correlation rule
type CorrelationRule struct {
	Name        string
	Description string
	Rules       []string // Rule IDs
	Timespan    string
	Condition   string
	GroupBy     []string
}

// ValueType represents different value types in Sigma
type ValueType int

const (
	ValueTypeString ValueType = iota
	ValueTypeNumber
	ValueTypeBoolean
	ValueTypeNull
	ValueTypeRegex
	ValueTypeCIDR
	ValueTypeList
)

// DetectionValue represents a value in a detection pattern
type DetectionValue struct {
	Type     ValueType
	Value    interface{}
	Modifier string // contains, all, base64, etc.
}

// Level constants for Sigma rule severity
const (
	LevelInformational = "informational"
	LevelLow           = "low"
	LevelMedium        = "medium"
	LevelHigh          = "high"
	LevelCritical      = "critical"
)

// Status constants for Sigma rule status
const (
	StatusStable       = "stable"
	StatusTest         = "test"
	StatusExperimental = "experimental"
	StatusDeprecated   = "deprecated"
	StatusUnsupported  = "unsupported"
)