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
	Stream        bool            `json:"stream,omitempty"`
	ToolConfig    json.RawMessage `json:"toolConfig,omitempty"`
	Metadata      MetaData        `json:"metadata"`
}

type MetaData struct {
	UserId string `json:"user_id,omitempty"`
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
	Role          string         `json:"role"`
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
			Role:          sm.Message.Role,
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
		Role:          temp.Message.Role,
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
	Role          string         `json:"role"`
	ContentStr    string         `json:"-"`
	ContentBlocks []ContentBlock `json:"-"`
	StopReason    *string        `json:"stop_reason,omitempty"`
	StopSequence  *string        `json:"stop_sequence,omitempty"`
	Usage         *Usage         `json:"usage,omitempty"`
}

func (msg *Message) MarshalJSON() ([]byte, error) {
	if msg.ContentStr != "" {
		return json.Marshal(struct {
			Id           string  `json:"id,omitempty"`
			Role         string  `json:"role"`
			Content      string  `json:"content,omitempty"`
			StopReason   *string `json:"stop_reason,omitempty"`
			StopSequence *string `json:"stop_sequence,omitempty"`
			Usage        *Usage  `json:"usage,omitempty"`
		}{
			Id:           msg.Id,
			Role:         msg.Role,
			Content:      msg.ContentStr,
			StopReason:   msg.StopReason,
			StopSequence: msg.StopSequence,
			Usage:        msg.Usage,
		})
	}

	return json.Marshal(struct {
		Id           string         `json:"id,omitempty"`
		Role         string         `json:"role"`
		Content      []ContentBlock `json:"content,omitempty"`
		StopReason   *string        `json:"stop_reason,omitempty"`
		StopSequence *string        `json:"stop_sequence,omitempty"`
		Usage        *Usage         `json:"usage,omitempty"`
	}{
		Id:           msg.Id,
		Role:         msg.Role,
		Content:      msg.ContentBlocks,
		StopReason:   msg.StopReason,
		StopSequence: msg.StopSequence,
		Usage:        msg.Usage,
	})
}

func (msg *Message) UnmarshalJSON(data []byte) error {
	var temp struct {
		Id           string          `json:"id"`
		Role         string          `json:"role"`
		Content      json.RawMessage `json:"content,omitempty"`
		StopReason   *string         `json:"stop_reason,omitempty"`
		StopSequence *string         `json:"stop_sequence,omitempty"`
		Usage        *Usage          `json:"usage,omitempty"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	msg.Id = temp.Id
	msg.Role = temp.Role
	msg.StopReason = temp.StopReason
	msg.StopSequence = temp.StopSequence
	msg.Usage = temp.Usage

	err := json.Unmarshal(temp.Content, &msg.ContentBlocks)
	if err != nil {
		contentStr := ""
		err = json.Unmarshal(temp.Content, &contentStr)
		if err != nil {
			return err
		}
	}

	return nil
}

type ContentBlock struct {
	Type    string          `json:"type,omitempty"`
	Id      string          `json:"id,omitempty"`
	Name    string          `json:"name,omitempty"`
	Input   json.RawMessage `json:"input,omitempty"`
	Json    any             `json:"json,omitempty"`
	Content any             `json:"content,omitempty,omitzero"`
	Text    string          `json:"text,omitempty"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	Credits      int `json:"credits"`
}

func (msg *Message) PrepareForStorage(sessionId string, tags []string) *StoredMessage {
	return &StoredMessage{
		SessionId: sessionId,
		Message:   msg,
		Tags:      tags,
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
