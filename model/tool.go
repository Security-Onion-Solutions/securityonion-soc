// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"time"
)

type ToolResult struct {
	ToolName       string
	Parameters     any
	Result         any
	TimeToExecute  time.Duration
	OnBehalfOfUser string
}

type ToolConfig struct {
	Tools      []*ToolSpec    `json:"tools"`
	ToolChoice map[string]any `json:"toolChoice"`
}

type ToolSpec struct {
	Spec ToolDefinition `json:"toolSpec"`
}

type ToolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

type JSONSchema struct {
	Json *ToolSchema `json:"json"`
}

type ToolSchema struct {
	Type       string                        `json:"type"`
	Properties map[string]ToolSchemaProperty `json:"properties"`
	Required   []string                      `json:"required,omitempty"`
}

type ToolSchemaProperty struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Default     any    `json:"default,omitempty"`
}

type ToolChoice struct {
	Type string
}

func (tc ToolChoice) MarshalJSON() ([]byte, error) {
	if tc.Type == "" {
		return []byte("null"), nil
	}
	
	result := map[string]any{
		tc.Type: map[string]any{},
	}
	
	return json.Marshal(result)
}
