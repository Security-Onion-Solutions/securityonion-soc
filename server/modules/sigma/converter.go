// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"fmt"
	"strings"
	"sync"
)

// converterRegistry holds registered converter backends
var (
	converterRegistry = make(map[string]ConverterFactory)
	registryMutex     sync.RWMutex
)

// ConverterFactory is a function that creates a new converter instance
type ConverterFactory func() Converter

// RegisterConverter registers a new converter backend
func RegisterConverter(name string, factory ConverterFactory) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	converterRegistry[strings.ToLower(name)] = factory
}

// GetConverter returns a converter for the specified backend
func GetConverter(name string) (Converter, error) {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	
	factory, ok := converterRegistry[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown converter backend: %s", name)
	}
	
	return factory(), nil
}

// ListConverters returns a list of registered converter names
func ListConverters() []string {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	
	names := make([]string, 0, len(converterRegistry))
	for name := range converterRegistry {
		names = append(names, name)
	}
	return names
}

// ConvertRule is a convenience function that converts a single rule using the specified backend
func ConvertRule(rule *Rule, backend string, pipelines []Pipeline) (string, error) {
	converter, err := GetConverter(backend)
	if err != nil {
		return "", err
	}
	
	return converter.Convert(rule, pipelines)
}

// ConversionOptions holds options for rule conversion
type ConversionOptions struct {
	// Backend is the target backend for conversion
	Backend string
	// Pipelines to apply during conversion
	Pipelines []Pipeline
	// FieldMappings for custom field name mappings
	FieldMappings []FieldMapping
	// DisablePipelineCheck skips pipeline validation
	DisablePipelineCheck bool
	// OutputFormat specifies the output format (if supported by backend)
	OutputFormat string
}