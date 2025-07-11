// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

type ChatRequest struct {
	Messages      []*ChatMessage `json:"messages"`
	Model         string         `json:"model,omitempty"`
	MaxTokens     int            `json:"max_tokens,omitempty"`
	Temperature   float32        `json:"temperature,omitempty"`
	TopP          float32        `json:"top_p"`
	TopK          int            `json:"top_k"`
	StopSequences []string       `json:"stop_sequences,omitempty"`
	System        string         `json:"system,omitempty"`
	UserUUID      string         `json:"user_uuid,omitempty"`
	Stream        bool           `json:"stream,omitempty"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
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
	Type string `json:"type"`
	Text string `json:"text"`
}

type UsageStats struct {
	InputTokens              int `json:"input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	OutputTokens             int `json:"output_tokens"`
}

type BalanceResponse struct {
	CompanyID        string  `json:"company_id"`
	Balance          float64 `json:"balance"`
	AvailableBalance float64 `json:"available_balance"`
	ReservedBalance  float64 `json:"reserved_balance"`
}
