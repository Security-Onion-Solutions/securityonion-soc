// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sigma

import (
	"time"
)

// Config holds the configuration for the Sigma converter
type Config struct {
	UseNativeConverter bool          `json:"useNativeConverter"`
	FallbackOnError    bool          `json:"fallbackOnError"`
	ComparisonMode     bool          `json:"comparisonMode"`
	LogMismatches      bool          `json:"logMismatches"`
	PythonTimeout      time.Duration `json:"pythonTimeout"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		UseNativeConverter: true,  // Use Go implementation immediately in test env
		FallbackOnError:    false, // No Python fallback in test env
		ComparisonMode:     false, // No comparison needed
		LogMismatches:      false,
		PythonTimeout:      30 * time.Second,
	}
}

// ConverterMetrics tracks metrics during conversion
type ConverterMetrics struct {
	ConversionsTotal int64
	ConversionErrors int64
	FallbacksUsed    int64
	ConversionTimeMs []float64
	MismatchCount    int64
	PythonTimeouts   int64
}

// ConversionComparison logs comparison results between converters
type ConversionComparison struct {
	RuleID       string
	PythonOutput string
	GoOutput     string
	Match        bool
	TimeDiffMs   float64
}