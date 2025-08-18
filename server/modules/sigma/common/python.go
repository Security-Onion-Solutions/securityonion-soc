// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package common

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
)

// PythonConverter wraps the existing Python sigma CLI (kept for reference)
// Note: This won't work in the test environment but is kept as reference
type PythonConverter struct {
	Config Config
	IOM    detections.IOManager
}

// ConvertToEQL converts a Sigma rule to EQL using Python CLI
func (pc *PythonConverter) ConvertToEQL(ctx context.Context, rule string, overrides []*model.Override) (string, error) {
	// Apply overrides
	processedRule, err := ApplyOverridesToRule(rule, overrides)
	if err != nil {
		return "", err
	}

	// Prepare command
	args := []string{
		"convert", "-t", "eql",
		"-p", "/opt/sensoroni/sigma_final_pipeline.yaml",
		"-p", "/opt/sensoroni/sigma_so_pipeline.yaml",
		"-p", "windows-logsources",
		"-p", "ecs_windows",
		"/dev/stdin",
	}

	cmd := exec.CommandContext(ctx, "sigma", args...)
	cmd.Stdin = strings.NewReader(processedRule)

	// Execute command
	output, _, _, err := pc.IOM.ExecCommand(cmd)
	if err != nil {
		return "", fmt.Errorf("problem with sigma cli: %w", err)
	}

	// Parse output
	return ParseSigmaOutput(output)
}

// ConvertToSecurityOnion converts Sigma queries to Security Onion format using Python CLI
func (pc *PythonConverter) ConvertToSecurityOnion(ctx context.Context, queries []string) ([]*model.ConvertedQuery, error) {
	// Join queries with separator
	input := strings.Join(queries, "\n---\n")

	// Prepare command
	args := []string{
		"convert", "-t", "security_onion",
		"-p", "/opt/sensoroni/sigma_final_pipeline.yaml",
		"-p", "/opt/sensoroni/sigma_so_pipeline.yaml",
		"-p", "windows-logsources",
		"-p", "ecs_windows",
		"--disable-pipeline-check",
		"/dev/stdin",
	}

	// Create context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, pc.Config.PythonTimeout)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "sigma", args...)
	cmd.Stdin = strings.NewReader(input)

	// Execute command
	output, _, _, err := pc.IOM.ExecCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("problem with sigma cli: %w", err)
	}

	// Parse output
	query, err := ParseSigmaOutput(output)
	if err != nil {
		return nil, err
	}

	return ParseConvertedQueries(query)
}

// Config is re-exported from parent package to avoid circular import
type Config struct {
	UseNativeConverter bool          `json:"useNativeConverter"`
	FallbackOnError    bool          `json:"fallbackOnError"`
	ComparisonMode     bool          `json:"comparisonMode"`
	LogMismatches      bool          `json:"logMismatches"`
	PythonTimeout      time.Duration `json:"pythonTimeout"`
}