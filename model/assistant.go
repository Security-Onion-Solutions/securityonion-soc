// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import "encoding/json"

type ChatRequest struct {
	Messages      []*ChatMessage  `json:"messages"`
	Model         string          `json:"model,omitempty"`
	MaxTokens     int             `json:"max_tokens,omitempty"`
	Temperature   float64         `json:"temperature,omitempty"`
	TopP          float64         `json:"top_p"`
	TopK          int             `json:"top_k"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
	System        string          `json:"system,omitempty"`
	UserUUID      string          `json:"user_uuid,omitempty"`
	Stream        bool            `json:"stream,omitempty"`
	ToolConfig    json.RawMessage `json:"toolConfig,omitempty"`
}

type ChatMessage struct {
	Role       string          `json:"role"`
	Content    string          `json:"content,omitempty"`
	ToolUseID  string          `json:"tool_use_id,omitempty"`
	ToolResult json.RawMessage `json:"tool_result,omitempty"`
}

type ChatResponse struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Role         string                 `json:"role"`
	Model        string                 `json:"model"`
	Content      []*ChatResponseContent `json:"content"`
	StopReason   string                 `json:"stop_reason"`
	StopSequence string                 `json:"stop_sequence"`
	Usage        *UsageStats            `json:"usage"`
}

type ChatResponseContent struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type UsageStats struct {
	InputTokens              int `json:"input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	OutputTokens             int `json:"output_tokens"`
}

type BalanceResponse struct {
	ApiKey    string  `json:"api_key"`
	KeyId     string  `json:"key_id"`
	CompanyId string  `json:"company_id"`
	Status    string  `json:"status"`
	Balance   float64 `json:"credit_balance"`
}

type ChatOpt func(*ChatConfig)

type ChatConfig struct {
	AutoExecuteTools bool
}

func WithAutoExecuteTools(autoExecute bool) ChatOpt {
	return func(config *ChatConfig) {
		config.AutoExecuteTools = autoExecute
	}
}

func ApplyChatOpts(opts ...ChatOpt) *ChatConfig {
	config := &ChatConfig{
		AutoExecuteTools: false, // Default to false
	}

	for _, opt := range opts {
		opt(config)
	}

	return config
}
