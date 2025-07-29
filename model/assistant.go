// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import "encoding/json"

type ChatRequest struct {
	Messages      []*Message      `json:"messages"`
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

type StoredMessage struct {
	Auditable
	SessionId string   `json:"session_id"`
	Message   *Message `json:"message"`
}

type Message struct {
	Id           string         `json:"id"`
	Type         string         `json:"type"`
	Role         string         `json:"role"`
	Model        string         `json:"model"`
	Content      []ContentBlock `json:"content"`
	StopReason   *string        `json:"stop_reason,omitempty"`
	StopSequence *string        `json:"stop_sequence,omitempty"`
	Usage        *Usage         `json:"usage,omitempty"`
}

type ContentBlock struct {
	Type       string          `json:"type"`
	Id         string          `json:"id,omitempty"`
	Name       string          `json:"name,omitempty"`
	Input      string          `json:"-"`
	Content    string          `json:"content,omitempty"`
	Text       string          `json:"text,omitempty"`
	ToolResult json.RawMessage `json:"tool_result,omitempty"`
	ToolUseID  string          `json:"tool_use_id,omitempty"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	Credits      int `json:"credits"`
}

func (cb *ContentBlock) MarshalJSON() ([]byte, error) {
	if len(cb.ToolResult) > 0 {
		return json.Marshal(struct {
			Type    string `json:"type"`
			Id      string `json:"id,omitempty"`
			Name    string `json:"name,omitempty"`
			Content any    `json:"content,omitempty"`
			Text    string `json:"text,omitempty"`
		}{
			Type: cb.Type,
			Id:   cb.Id,
			Name: cb.Name,
			Text: cb.Text,
			Content: []map[string]interface{}{
				{
					"type":        "tool_result",
					"tool_use_id": cb.ToolUseID,
					"content":     cb.ToolResult,
				},
			},
		})
	}

	return json.Marshal(struct {
		Type    string `json:"type"`
		Id      string `json:"id,omitempty"`
		Name    string `json:"name,omitempty"`
		Content string `json:"content,omitempty"`
		Text    string `json:"text,omitempty"`
	}{
		Type:    cb.Type,
		Id:      cb.Id,
		Name:    cb.Name,
		Content: cb.Content,
		Text:    cb.Text,
	})
}

func (cm *ContentBlock) UnmarshalJSON(data []byte) error {
	var temp struct {
		Type       string          `json:"type"`
		Id         string          `json:"id,omitempty"`
		Name       string          `json:"name,omitempty"`
		Input      string          `json:"-"`
		Content    any             `json:"content,omitempty"`
		Text       string          `json:"text,omitempty"`
		ToolResult json.RawMessage `json:"tool_result,omitempty"`
		ToolUseID  string          `json:"tool_use_id,omitempty"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	cm.Type = temp.Type
	cm.Id = temp.Id
	cm.Name = temp.Name
	cm.Input = temp.Input
	cm.Text = temp.Text
	cm.ToolResult = temp.ToolResult
	cm.ToolUseID = temp.ToolUseID

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

type SimpleMessage struct {
	Role       string          `json:"role"`
	Content    string          `json:"content,omitempty"`
	ToolUseID  string          `json:"tool_use_id,omitempty"`
	ToolResult json.RawMessage `json:"tool_result,omitempty"`
}

func (sm *SimpleMessage) ToMessage() *Message {
	msg := &Message{
		Role:    sm.Role,
		Content: []ContentBlock{},
	}

	if sm.ToolUseID != "" {
		msg.Content = append(msg.Content, ContentBlock{
			Type:       "tool_use",
			ToolUseID:  sm.ToolUseID,
			ToolResult: sm.ToolResult,
		})
	} else {
		msg.Content = append(msg.Content, ContentBlock{
			Type: "text",
			Text: sm.Content,
		})
	}

	return msg
}

func (cm *Message) PrepareForStorage(sessionId string) *StoredMessage {
	return &StoredMessage{
		SessionId: sessionId,
		Message:   cm,
	}
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
