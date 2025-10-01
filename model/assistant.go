// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"time"
)

// @Description A user message to be added to a session.
type IncomingMessage struct {
	// The content of the message.
	Msg string `json:"msg" example:"What is MITRE?"`
	// The session this message belongs to. Can be empty for a new session.
	SessionId string `json:"sessionId" example:"chat_1757086398900_ykhmndscn"`
}

// @Description A request to initiate a chat session.
type ChatRequest struct {
	// The messages from both the user and the Assistant in a session
	Messages []*Message `json:"messages"`
	// Optionally indicate the max tokens the response should use.
	MaxTokens int `json:"max_tokens,omitempty" example:"10000"`
	// Optionally indicate the temperature for response randomness.
	Temperature float64 `json:"temperature,omitempty" example:"0.7"`
	// Optionally indicate the top-p sampling parameter.
	TopP float64 `json:"top_p" example:"1"`
	// Optionally indicate the top-k sampling parameter.
	TopK int `json:"top_k" example:"40"`
	// Optionally indicate the stop sequences for the response.
	StopSequences []string `json:"stop_sequences,omitempty" example:"end_turn"`
	// Optionally provide an alternative System prompt
	System string `json:"system,omitempty" example:"As a chatbot, your goal is to be helpful."`
	// Indicate if the response should be streaming or not.
	Stream bool `json:"stream,omitempty" example:"true"`
	// Provide details about tools the Assistant can use.
	ToolConfig json.RawMessage `json:"toolConfig,omitempty"`
	// Indicate which user is making the request.
	UserId string `json:"user_uuid,omitempty" example:"8beae4b5-275b-4669-b678-8cff894911b5"`
}

// @Description A stored message in the chat session. This contains metadata about the message and its context not necessary for the conversation with the Assistant.
type StoredMessage struct {
	Auditable
	// Metadata about the message.
	Tags []string `json:"tags,omitempty" example:"investigation"`
	// What session this message belongs to.
	SessionId string `json:"session_id" example:"chat_1757086398900_ykhmndscn"`
	// The message content.
	Message *Message `json:"message"`
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
		Tags      []string        `json:"tags,omitempty"`
		Message   saveableMessage `json:"message"`
	}{
		Auditable: sm.Auditable,
		SessionId: sm.SessionId,
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
		Tags      []string        `json:"tags,omitempty"`
		Message   saveableMessage `json:"message"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	sm.Auditable = temp.Auditable
	sm.SessionId = temp.SessionId
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

// @Description A message in the chat session.
type Message struct {
	// The unique identifier for the message. Not required.
	Id string `json:"id" example:"c3d44fb8-3bc2-46e2-a7d2-8a8983556d1a"`
	// Indicates who authored the message. Either `user` or `assistant`.
	Role string `json:"role" example:"user" enum:"user,assistant"`
	// Sometimes used in place of a Text ContentBlock
	ContentStr string `json:"-"`
	// The structured content of the message.
	ContentBlocks []ContentBlock `json:"-"`
	// The reason the message was stopped.
	StopReason *string `json:"stop_reason,omitempty" example:"user_request"`
	// The sequence in which the message was stopped.
	StopSequence *string `json:"stop_sequence,omitempty" example:"end_turn"`
	// Usage statistics after deducting the costs of the message.
	Usage *Usage `json:"usage,omitempty"`
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

// @Description A block of content in a chat message.
type ContentBlock struct {
	// The type of content (e.g., text, tool_request).
	Type string `json:"type,omitempty" example:"text"`
	// The unique identifier for the content block. Not required.
	Id string `json:"id,omitempty" example:"tooluse_mT45or7ISwSEUivo63nqow"`
	// The name of the content block. Not required.
	Name string `json:"name,omitempty" example:"tool_use"`
	// Reserved for use with tools, this field is how tool input is passed.
	Input json.RawMessage `json:"input,omitempty" example:"{\"key\":\"value\"}"`
	// Reserved for use with tools, this field is how tool output is returned.
	Json any `json:"json,omitempty" example:"{\"key\":\"value\"}"`
	// The structured content of the message.
	Content any `json:"content,omitempty,omitzero" example:"What exactly is an APT?"`
	// The plain text content of the message.
	Text string `json:"text,omitempty" example:"What are my latest alerts?"`
}

// @Description Usage statistics showing token usage and billing information.
type Usage struct {
	// The number of input tokens used.
	InputTokens int `json:"input_tokens" example:"5"`
	// The number of output tokens used.
	OutputTokens int `json:"output_tokens" example:"10"`
	// The number of credits remaining after this message.
	Credits int `json:"credits" example:"1"`
}

func (msg *Message) PrepareForStorage(sessionId string, tags []string) *StoredMessage {
	return &StoredMessage{
		SessionId: sessionId,
		Message:   msg,
		Tags:      tags,
	}
}

// @Description A response containing the user's balance information.
type BalanceResponse struct {
	// An identifier representing the key that was used for the request.
	KeyId string `json:"api_key_prefix" example:"user-61a9d0ef-29a4-4f9f-83f2-f8bbae462608"`
	// An identifier indicating what company the key is registered to.
	CompanyId string `json:"company_id" example:"SecurityOnionSolutions"`
	// The status of the key used.
	Status string `json:"status" example:"active"`
	// The remaining credit balance.
	Balance int64 `json:"credit_balance" example:"123000"`
	// The health status of the service.
	HealthStatus string `json:"health_status" example:"healthy"`
}

type HealthResponse struct {
	Status string `json:"status"`
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

// @Description A session for a user chatting with the Assistant.
type AssistantSession struct {
	Auditable
	// The title of the session. Usually the first message sent by the user.
	Title string `json:"title" example:"Can you write a suricata rule for me?"`
	// The session identifier.
	SessionId string `json:"sessionId" example:"chat_1757086398900_ykhmndscn"`
	// The time the session was deleted.
	DeleteTime *time.Time `json:"deleteTime,omitempty" example:"2025-09-05T15:33:00.000Z"`
	// Metadata about the session.
	Tags []string `json:"tags" example:"investigation"`
}

type UserUsage struct {
	// The Id of the user.
	UserId string `json:"userId" example:"8beae4b5-275b-4669-b678-8cff894911b5"`
	// The total input tokens used by the user in the date range.
	TotalInputTokens int `json:"totalInputTokens" example:"1500"`
	// The total output tokens used by the user in the date range.
	TotalOutputTokens int `json:"totalOutputTokens" example:"3000"`
	// The total credits used by the user in the date range.
	TotalCredits int `json:"totalCredits" example:"5"`
	// The total messages sent by the user in the date range.
	TotalMessages int `json:"totalMessages" example:"25"`
}
