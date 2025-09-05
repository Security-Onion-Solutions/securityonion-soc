// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"time"
)

type ToolRequest struct {
	SessionId string          `json:"sessionId" example:"chat_1757086398900_ykhmndscn"`
	ToolUseId string          `json:"toolUseId" example:"tooluse_mT45or7ISwSEUivo63nqow"`
	Params    json.RawMessage `json:"params" example:"{\"key\":\"value\"}"`
}

type ToolResponse struct {
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
