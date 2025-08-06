// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"time"
)

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
	DeletedAt *time.Time `json:"deletedAt,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	SessionId string     `json:"session_id"`
	Message   *Message   `json:"message"`
}

type saveableMessage struct {
	Id            string         `json:"id"`
	Type          string         `json:"type"`
	Role          string         `json:"role"`
	Model         string         `json:"model"`
	ContentStr    string         `json:"contentStr"`
	ContentBlocks []ContentBlock `json:"contentBlocks"`
	StopReason    *string        `json:"stopReason,omitempty"`
	StopSequence  *string        `json:"stopSequence,omitempty"`
	Usage         *Usage         `json:"usage,omitempty"`
}

func (sm *StoredMessage) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Auditable
		SessionId string          `json:"sessionId"`
		DeletedAt *time.Time      `json:"deletedAt,omitempty"`
		Tags      []string        `json:"tags,omitempty"`
		Message   saveableMessage `json:"message"`
	}{
		Auditable: sm.Auditable,
		SessionId: sm.SessionId,
		DeletedAt: sm.DeletedAt,
		Tags:      sm.Tags,
		Message: saveableMessage{
			Id:            sm.Message.Id,
			Type:          sm.Message.Type,
			Role:          sm.Message.Role,
			Model:         sm.Message.Model,
			ContentStr:    sm.Message.ContentStr,
			ContentBlocks: sm.Message.ContentBlocks,
			StopReason:    sm.Message.StopReason,
			StopSequence:  sm.Message.StopSequence,
			Usage:         sm.Message.Usage,
		},
	})
}

func (sm *StoredMessage) UnmarshalJSON(data []byte) error {
	var temp struct {
		Auditable
		SessionId string          `json:"sessionId"`
		DeletedAt *time.Time      `json:"deletedAt,omitempty"`
		Tags      []string        `json:"tags,omitempty"`
		Message   saveableMessage `json:"message"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	sm.Auditable = temp.Auditable
	sm.SessionId = temp.SessionId
	sm.DeletedAt = temp.DeletedAt
	sm.Tags = temp.Tags
	sm.Message = &Message{
		Id:            temp.Message.Id,
		Type:          temp.Message.Type,
		Role:          temp.Message.Role,
		Model:         temp.Message.Model,
		ContentStr:    temp.Message.ContentStr,
		ContentBlocks: temp.Message.ContentBlocks,
		StopReason:    temp.Message.StopReason,
		StopSequence:  temp.Message.StopSequence,
		Usage:         temp.Message.Usage,
	}

	return nil
}

type Message struct {
	Id            string         `json:"id"`
	Type          string         `json:"type"`
	Role          string         `json:"role"`
	Model         string         `json:"model"`
	ContentStr    string         `json:"-"`
	ContentBlocks []ContentBlock `json:"-"`
	StopReason    *string        `json:"stop_reason,omitempty"`
	StopSequence  *string        `json:"stop_sequence,omitempty"`
	Usage         *Usage         `json:"usage,omitempty"`
}

func (msg *Message) MarshalJSON() ([]byte, error) {
	if msg.ContentStr != "" {
		return json.Marshal(struct {
			Id           string  `json:"id"`
			Type         string  `json:"type"`
			Role         string  `json:"role"`
			Model        string  `json:"model"`
			Content      string  `json:"content"`
			StopReason   *string `json:"stop_reason,omitempty"`
			StopSequence *string `json:"stop_sequence,omitempty"`
			Usage        *Usage  `json:"usage,omitempty"`
		}{
			Id:           msg.Id,
			Type:         msg.Type,
			Role:         msg.Role,
			Model:        msg.Model,
			Content:      msg.ContentStr,
			StopReason:   msg.StopReason,
			StopSequence: msg.StopSequence,
			Usage:        msg.Usage,
		})
	}

	return json.Marshal(struct {
		Id           string         `json:"id"`
		Type         string         `json:"type"`
		Role         string         `json:"role"`
		Model        string         `json:"model"`
		Content      []ContentBlock `json:"content"`
		StopReason   *string        `json:"stop_reason,omitempty"`
		StopSequence *string        `json:"stop_sequence,omitempty"`
		Usage        *Usage         `json:"usage,omitempty"`
	}{
		Id:           msg.Id,
		Type:         msg.Type,
		Role:         msg.Role,
		Model:        msg.Model,
		Content:      msg.ContentBlocks,
		StopReason:   msg.StopReason,
		StopSequence: msg.StopSequence,
		Usage:        msg.Usage,
	})
}

func (msg *Message) UnmarshalJSON(data []byte) error {
	var temp struct {
		Id           string          `json:"id"`
		Type         string          `json:"type"`
		Role         string          `json:"role"`
		Model        string          `json:"model"`
		Content      json.RawMessage `json:"content"`
		StopReason   *string         `json:"stop_reason,omitempty"`
		StopSequence *string         `json:"stop_sequence,omitempty"`
		Usage        *Usage          `json:"usage,omitempty"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	msg.Id = temp.Id
	msg.Type = temp.Type
	msg.Role = temp.Role
	msg.Model = temp.Model
	msg.StopReason = temp.StopReason
	msg.StopSequence = temp.StopSequence
	msg.Usage = temp.Usage

	err := json.Unmarshal(temp.Content, &msg.ContentBlocks)
	if err != nil {
		err = json.Unmarshal(temp.Content, &msg.ContentStr)
		if err != nil {
			return err
		}
	}

	return nil
}

type ContentBlock struct {
	Type       string          `json:"type"`
	Id         string          `json:"id,omitempty"`
	Name       string          `json:"name,omitempty"`
	Input      string          `json:"input,omitempty"`
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
			Input   string `json:"input,omitempty"`
		}{
			Type:  cb.Type,
			Id:    cb.Id,
			Name:  cb.Name,
			Text:  cb.Text,
			Input: cb.Input,
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
		Type      string `json:"type"`
		Id        string `json:"id,omitempty"`
		Name      string `json:"name,omitempty"`
		Content   string `json:"content,omitempty"`
		ToolUseID string `json:"tool_use_id,omitempty"`
		Text      string `json:"text,omitempty"`
		Input     string `json:"input,omitempty"`
	}{
		Type:      cb.Type,
		Id:        cb.Id,
		Name:      cb.Name,
		Content:   cb.Content,
		ToolUseID: cb.ToolUseID,
		Text:      cb.Text,
		Input:     cb.Input,
	})
}

func (cm *ContentBlock) UnmarshalJSON(data []byte) error {
	var temp struct {
		Type       string          `json:"type"`
		Id         string          `json:"id,omitempty"`
		Name       string          `json:"name,omitempty"`
		Input      any             `json:"input,omitempty"`
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
	cm.Text = temp.Text
	cm.ToolResult = temp.ToolResult
	cm.ToolUseID = temp.ToolUseID

	switch input := temp.Input.(type) {
	case string:
		cm.Input = input
	default:
		cm.Input = ""
	}

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
		Role:          sm.Role,
		ContentBlocks: []ContentBlock{},
	}

	if sm.ToolUseID != "" {
		msg.ContentBlocks = []ContentBlock{
			{
				Type:       "tool_use",
				ToolUseID:  sm.ToolUseID,
				ToolResult: sm.ToolResult,
			},
		}
	} else {
		msg.ContentBlocks = append(msg.ContentBlocks, ContentBlock{
			Type: "text",
			Text: sm.Content,
		})
	}

	return msg
}

func (msg *Message) PrepareForStorage(sessionId string) *StoredMessage {
	return &StoredMessage{
		SessionId: sessionId,
		Message:   msg,
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
