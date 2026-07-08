// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"time"
)

type ToolRequest struct {
	// The sessionId this chat message belongs to.
	SessionId string `json:"sessionId" example:"chat_1757086398900_ykhmndscn"`
	// The unique identifier for this tool use.
	ToolUseId string `json:"toolUseId" example:"tooluse_mT45or7ISwSEUivo63nqow"`
	// The parameters for this tool use.
	Params json.RawMessage `json:"params" example:"{\"key\":\"value\"}"`
	// The model to use for this tool execution.
	Model string `json:"model,omitempty" example:"claude-sonnet-4.5"`
	// Auxiliary data for certain tools.
	AuxData json.RawMessage `json:"auxData,omitempty" example:"{toolSpecificData: 'example'}"`
	// Rejected indicates the user declined this tool: it is not executed; an error
	// tool_result is recorded instead so the turn (and any parallel siblings) resolves.
	Rejected bool `json:"rejected,omitempty"`
}

type ToolResponse struct {
	ToolName       string
	Parameters     any
	Result         any
	TimeToExecute  time.Duration
	OnBehalfOfUser string
}

type ToolConfig struct {
	Tools      []*ToolSpec           `json:"tools"`
	ToolChoice map[string]JSONSchema `json:"toolChoice"`
}

type ToolSpec struct {
	Spec ToolDefinition `json:"toolSpec"`
}

type ToolDefinition struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema JSONSchema `json:"inputSchema"`
}

type JSONSchema struct {
	Json *ToolSchema `json:"json,omitempty"`
}

type ToolSchema struct {
	Type       string                        `json:"type"`
	Properties map[string]ToolSchemaProperty `json:"properties"`
	Required   []string                      `json:"required,omitempty"`
}

type ToolSchemaProperty struct {
	Type        string                        `json:"type"`
	Description string                        `json:"description"`
	Default     any                           `json:"default,omitempty"`
	Items       map[string]ToolSchemaProperty `json:"items,omitempty"`
}
