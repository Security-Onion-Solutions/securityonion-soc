// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"time"
)

type IncomingMessage struct {
	Msg       string `json:"msg" example:"What is MITRE?"`
	SessionId string `json:"sessionId" example:"chat_1757086398900_ykhmndscn"`
}

type ChatRequest struct {
	Messages      []*Message      `json:"messages"`
	MaxTokens     int             `json:"max_tokens,omitempty" example:"10000"`
	Temperature   float64         `json:"temperature,omitempty" example:"0.7"`
	TopP          float64         `json:"top_p" example:"1"`
	TopK          int             `json:"top_k" example:"40"`
	StopSequences []string        `json:"stop_sequences,omitempty" example:"end_turn"`
	System        string          `json:"system,omitempty" example:"As a chatbot, your goal is to be helpful."`
	Stream        bool            `json:"stream,omitempty" example:"true"`
	ToolConfig    json.RawMessage `json:"toolConfig,omitempty"`
	UserId        string          `json:"user_uuid,omitempty" example:"8beae4b5-275b-4669-b678-8cff894911b5"`
}

type StoredMessage struct {
	Auditable
	DeletedAt *time.Time `json:"deletedAt,omitempty" example:"2025-09-05T15:33:00.000Z"`
	Tags      []string   `json:"tags,omitempty" example:"investigation"`
	SessionId string     `json:"session_id" example:"chat_1757086398900_ykhmndscn"`
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
	Id            string         `json:"id" example:"c3d44fb8-3bc2-46e2-a7d2-8a8983556d1a"`
	Role          string         `json:"role" example:"user"`
	ContentStr    string         `json:"-"`
	ContentBlocks []ContentBlock `json:"-"`
	StopReason    *string        `json:"stop_reason,omitempty" example:"user_request"`
	StopSequence  *string        `json:"stop_sequence,omitempty" example:"end_turn"`
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
	Type    string          `json:"type,omitempty" example:"text"`
	Id      string          `json:"id,omitempty" example:"tooluse_mT45or7ISwSEUivo63nqow"`
	Name    string          `json:"name,omitempty" example:"tool_use"`
	Input   json.RawMessage `json:"input,omitempty" example:"{\"key\":\"value\"}"`
	Json    any             `json:"json,omitempty" example:"{\"key\":\"value\"}"`
	Content any             `json:"content,omitempty,omitzero" example:"What exactly is an APT?"`
	Text    string          `json:"text,omitempty" example:"What are my latest alerts?"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens" example:"5"`
	OutputTokens int `json:"output_tokens" example:"10"`
	Credits      int `json:"credits" example:"1"`
}

func (msg *Message) PrepareForStorage(sessionId string, tags []string) *StoredMessage {
	return &StoredMessage{
		SessionId: sessionId,
		Message:   msg,
		Tags:      tags,
	}
}

type BalanceResponse struct {
	KeyId     string  `json:"key_id" example:"user-61a9d0ef-29a4-4f9f-83f2-f8bbae462608"`
	CompanyId string  `json:"company_id" example:"SecurityOnionSolutions"`
	Status    string  `json:"status" example:"active"`
	Balance   float64 `json:"credit_balance" example:"123000"`
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
