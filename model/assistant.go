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

type StoredChatMessage struct {
	Auditable
	ConversationId string          `json:"conversation_id"`
	Role           string          `json:"role"`
	Content        string          `json:"content"`
	ToolUseID      string          `json:"tool_use_id"`
	ToolResult     json.RawMessage `json:"tool_result"`
}

func (scm *StoredChatMessage) ToChatMessage() *ChatMessage {
	return &ChatMessage{
		Role:       scm.Role,
		Content:    scm.Content,
		ToolUseID:  scm.ToolUseID,
		ToolResult: scm.ToolResult,
	}
}

type ChatMessage struct {
	Role       string          `json:"role"`
	Content    string          `json:"content,omitempty"`
	ToolUseID  string          `json:"tool_use_id,omitempty"`
	ToolResult json.RawMessage `json:"tool_result,omitempty"`
}

func (cm *ChatMessage) MarshalJSON() ([]byte, error) {
	if len(cm.ToolResult) > 0 {
		return json.Marshal(struct {
			Role    string      `json:"role"`
			Content interface{} `json:"content"`
		}{
			Role: cm.Role,
			Content: []map[string]interface{}{
				{
					"type":        "tool_result",
					"tool_use_id": cm.ToolUseID,
					"content":     cm.ToolResult,
				},
			},
		})
	}

	return json.Marshal(struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{
		Role:    cm.Role,
		Content: cm.Content,
	})
}

func (cm *ChatMessage) UnmarshalJSON(data []byte) error {
	var temp struct {
		Role    string      `json:"role"`
		Content interface{} `json:"content"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	cm.Role = temp.Role

	switch content := temp.Content.(type) {
	case string:
		cm.Content = content
	case []interface{}:
		if len(content) > 0 {
			if toolResult, ok := content[0].(map[string]interface{}); ok {
				if toolType, exists := toolResult["type"]; exists && toolType == "tool_result" {
					if toolUseID, exists := toolResult["tool_use_id"].(string); exists {
						cm.ToolUseID = toolUseID
					}
					if toolContent, exists := toolResult["content"]; exists {
						toolContentBytes, _ := json.Marshal(toolContent)
						cm.ToolResult = json.RawMessage(toolContentBytes)
					}
				}
			}
		}
	}

	return nil
}

func (cm *ChatMessage) PrepareForStorage(convId string) *StoredChatMessage {
	return &StoredChatMessage{
		ConversationId: convId,
		Role:           cm.Role,
		Content:        cm.Content,
		ToolUseID:      cm.ToolUseID,
		ToolResult:     cm.ToolResult,
	}
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
	Credits                  int `json:"credits"`
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
