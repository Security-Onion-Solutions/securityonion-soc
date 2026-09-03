// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"

	"github.com/apex/log"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper functions for creating mock ChatCompletion responses and chunks

func createChatCompletionUsage(promptTokens, completionTokens int64) openai.CompletionUsage {
	return openai.CompletionUsage{
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
	}
}

func createMockToolCall(id, name, args string) openai.ChatCompletionMessageToolCallUnion {
	return openai.ChatCompletionMessageToolCallUnion{
		ID:   id,
		Type: "function",
		Function: openai.ChatCompletionMessageFunctionToolCallFunction{
			Name:      name,
			Arguments: args,
		},
	}
}

func createMockChatCompletion(content string, toolCalls []openai.ChatCompletionMessageToolCallUnion, usage openai.CompletionUsage, finishReason string) *openai.ChatCompletion {
	message := openai.ChatCompletionMessage{
		Role:      "assistant",
		Content:   content,
		ToolCalls: toolCalls,
	}

	return &openai.ChatCompletion{
		ID: "chatcmpl_test123",
		Choices: []openai.ChatCompletionChoice{
			{
				Message:      message,
				FinishReason: finishReason,
			},
		},
		Usage: usage,
	}
}

// Streaming chunk creators

func newChatTextDelta(content string) openai.ChatCompletionChunk {
	return openai.ChatCompletionChunk{
		Choices: []openai.ChatCompletionChunkChoice{
			{
				Delta: openai.ChatCompletionChunkChoiceDelta{
					Role:    "assistant",
					Content: content,
				},
			},
		},
	}
}

func newChatToolCallStartDelta(index int, id, name string) openai.ChatCompletionChunk {
	return openai.ChatCompletionChunk{
		Choices: []openai.ChatCompletionChunkChoice{
			{
				Delta: openai.ChatCompletionChunkChoiceDelta{
					Role: "assistant",
					ToolCalls: []openai.ChatCompletionChunkChoiceDeltaToolCall{
						{
							Index: int64(index),
							ID:    id,
							Type:  "function",
							Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{
								Name: name,
							},
						},
					},
				},
			},
		},
	}
}

func newChatToolCallArgumentsDelta(index int, args string) openai.ChatCompletionChunk {
	return openai.ChatCompletionChunk{
		Choices: []openai.ChatCompletionChunkChoice{
			{
				Delta: openai.ChatCompletionChunkChoiceDelta{
					ToolCalls: []openai.ChatCompletionChunkChoiceDeltaToolCall{
						{
							Index: int64(index),
							Function: openai.ChatCompletionChunkChoiceDeltaToolCallFunction{
								Arguments: args,
							},
						},
					},
				},
			},
		},
	}
}

func newChatFinishReasonChunk(finishReason string) openai.ChatCompletionChunk {
	return openai.ChatCompletionChunk{
		Choices: []openai.ChatCompletionChunkChoice{
			{
				FinishReason: finishReason,
			},
		},
	}
}

func newChatCompletionUsageChunk(usage openai.CompletionUsage) openai.ChatCompletionChunk {
	return openai.ChatCompletionChunk{
		Usage: usage,
	}
}

// Test cases

func TestNewOpenAIChatAdapter(t *testing.T) {
	tests := []struct {
		name                  string
		config                map[string]any
		expectError           bool
		errorContains         string
		expectedHealthTimeout int
		validateHealthTimeout bool
	}{
		{
			name: "Success with all config values",
			config: map[string]any{
				"apiUrl":               "https://api.openai.com/v1",
				"apiKey":               "test-key",
				"healthTimeoutSeconds": float64(6),
			},
			expectError:           false,
			expectedHealthTimeout: 6,
			validateHealthTimeout: true,
		},
		{
			name: "Missing apiUrl returns error",
			config: map[string]any{
				"apiKey": "test-key",
			},
			expectError:   true,
			errorContains: "apiUrl",
		},
		{
			name: "Without apiKey succeeds",
			config: map[string]any{
				"apiUrl": "https://api.openai.com/v1",
			},
			expectError: false,
		},
		{
			name: "Default health timeout",
			config: map[string]any{
				"apiUrl": "https://api.openai.com/v1",
			},
			expectError:           false,
			expectedHealthTimeout: DEFAULT_HEALTH_TIMEOUT_SECONDS,
			validateHealthTimeout: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := server.NewFakeUnauthorizedServer()
			adapter, err := NewOpenAIChatAdapter(context.Background(), srv, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, adapter)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, adapter)

				if tt.validateHealthTimeout {
					chatAdapter := adapter.(*OpenAIChatAdapter)
					assert.Equal(t, tt.expectedHealthTimeout, chatAdapter.healthTimeoutSeconds)
				}
			}
		})
	}
}

func TestOpenAIChatAdapter_Protocol(t *testing.T) {
	adapter := &OpenAIChatAdapter{}
	assert.Equal(t, "openai_chat", adapter.Protocol())
}

func TestOpenAIChatAdapter_GetBalance(t *testing.T) {
	adapter := &OpenAIChatAdapter{}
	ctx := context.Background()

	balance, err := adapter.GetBalance(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, balance)
	assert.Equal(t, int64(UNUSED_BALANCE), balance.Balance)
}

func TestOpenAIChatAdapter_GetHealth(t *testing.T) {
	tests := []struct {
		name           string
		modelsListFunc func(ctx context.Context) (*pagination.Page[openai.Model], error)
		expectedStatus string
	}{
		{
			name: "Returns healthy when ModelsList succeeds",
			modelsListFunc: func(ctx context.Context) (*pagination.Page[openai.Model], error) {
				return &pagination.Page[openai.Model]{
					Data: []openai.Model{{ID: "gpt-4"}},
				}, nil
			},
			expectedStatus: "healthy",
		},
		{
			name: "Returns unhealthy when ModelsList fails",
			modelsListFunc: func(ctx context.Context) (*pagination.Page[openai.Model], error) {
				return nil, errors.New("API error")
			},
			expectedStatus: "unhealthy",
		},
		{
			name: "Returns unhealthy when ModelsList returns empty",
			modelsListFunc: func(ctx context.Context) (*pagination.Page[openai.Model], error) {
				return &pagination.Page[openai.Model]{
					Data: []openai.Model{},
				}, nil
			},
			expectedStatus: "unhealthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockOpenAIClient{
				modelsListFunc: tt.modelsListFunc,
			}

			srv := server.NewFakeUnauthorizedServer()
			adapter := &OpenAIChatAdapter{
				client: mockClient,
				srv:    srv,
				IOManager: &detections.ResourceManager{
					Config: srv.Config,
				},
				healthTimeoutSeconds: DEFAULT_HEALTH_TIMEOUT_SECONDS,
			}

			ctx := context.Background()
			health, err := adapter.GetHealth(ctx)

			assert.NoError(t, err)
			assert.NotNil(t, health)
			assert.Equal(t, tt.expectedStatus, health.Status)
		})
	}
}

func TestConvertHistoryToChatCompletions(t *testing.T) {
	logger := log.Log

	tests := []struct {
		name     string
		req      *model.ChatRequest
		validate func(*testing.T, []openai.ChatCompletionMessageParamUnion)
	}{
		{
			name: "empty messages",
			req: &model.ChatRequest{
				Messages: []*model.Message{},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				assert.Empty(t, result)
			},
		},
		{
			name: "single text message from user",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello, world!"},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfUser)
				assert.Equal(t, "Hello, world!", result[0].OfUser.Content.OfString.Value)
			},
		},
		{
			name: "single text message from assistant",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hi there!"},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfAssistant)
				assert.Equal(t, "Hi there!", result[0].OfAssistant.Content.OfString.Value)
			},
		},
		{
			name: "multiple text messages",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "First message"},
						},
					},
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Second message"},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 2)
				require.NotNil(t, result[0].OfUser)
				assert.Equal(t, "First message", result[0].OfUser.Content.OfString.Value)
				require.NotNil(t, result[1].OfAssistant)
				assert.Equal(t, "Second message", result[1].OfAssistant.Content.OfString.Value)
			},
		},
		{
			name: "system prompt with SystemAppend",
			req: &model.ChatRequest{
				System:       "You are a helpful assistant.",
				SystemAppend: "Be concise.",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello"},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 2)
				require.NotNil(t, result[0].OfSystem)
				assert.Contains(t, result[0].OfSystem.Content.OfString.Value, "You are a helpful assistant.")
				assert.Contains(t, result[0].OfSystem.Content.OfString.Value, "Be concise.")
			},
		},
		{
			name: "tool use with valid JSON",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:  "tool_use",
								Id:    "call_123",
								Name:  "search",
								Input: json.RawMessage(`{"query":"test"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfAssistant)
				require.Len(t, result[0].OfAssistant.ToolCalls, 1)
				assert.Equal(t, "call_123", result[0].OfAssistant.ToolCalls[0].OfFunction.ID)
				assert.Equal(t, "search", result[0].OfAssistant.ToolCalls[0].OfFunction.Function.Name)
				assert.Equal(t, `{"query":"test"}`, result[0].OfAssistant.ToolCalls[0].OfFunction.Function.Arguments)
			},
		},
		{
			name: "tool use with invalid JSON",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:  "tool_use",
								Id:    "call_123",
								Name:  "search",
								Input: json.RawMessage(`{invalid`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				// Invalid JSON should be skipped
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfAssistant)
				assert.Empty(t, result[0].OfAssistant.ToolCalls)
			},
		},
		{
			name: "tool result with success",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "tool_result",
								ToolResult: &model.ToolResult{
									ToolUseId: "call_123",
									IsError:   false,
									Content: []model.ToolResultContent{
										{Json: map[string]any{"result": "success"}},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfTool)
				assert.Equal(t, "call_123", result[0].OfTool.ToolCallID)
				assert.Contains(t, result[0].OfTool.Content.OfString.Value, "result")
			},
		},
		{
			name: "tool result with error",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "tool_result",
								ToolResult: &model.ToolResult{
									ToolUseId: "call_123",
									IsError:   true,
									Content: []model.ToolResultContent{
										{Text: "Tool execution failed"},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfTool)
				assert.Equal(t, "call_123", result[0].OfTool.ToolCallID)
				assert.Contains(t, result[0].OfTool.Content.OfString.Value, "error")
			},
		},
		{
			name: "tool result with empty content array",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "tool_result",
								ToolResult: &model.ToolResult{
									ToolUseId: "call_123",
									IsError:   false,
									Content:   []model.ToolResultContent{},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				// Empty content should result in no tool message
				assert.Empty(t, result)
			},
		},
		{
			name: "message with nbsp only (filtered out)",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "&nbsp;"},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				// &nbsp; only messages are filtered out
				assert.Empty(t, result)
			},
		},
		{
			name: "message with nbsp and tool use (nbsp filtered, tool preserved)",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "&nbsp;"},
							{
								Type:  "tool_use",
								Id:    "call_123",
								Name:  "search",
								Input: json.RawMessage(`{"query":"test"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfAssistant)
				// Content should be empty (nbsp filtered)
				assert.Empty(t, result[0].OfAssistant.Content.OfString.Value)
				// Tool call should be present
				require.Len(t, result[0].OfAssistant.ToolCalls, 1)
				assert.Equal(t, "call_123", result[0].OfAssistant.ToolCalls[0].OfFunction.ID)
			},
		},
		{
			name: "mixed content with text and tool use",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Let me search for that."},
							{
								Type:  "tool_use",
								Id:    "call_123",
								Name:  "search",
								Input: json.RawMessage(`{"query":"test"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfAssistant)
				assert.Equal(t, "Let me search for that.", result[0].OfAssistant.Content.OfString.Value)
				require.Len(t, result[0].OfAssistant.ToolCalls, 1)
				assert.Equal(t, "call_123", result[0].OfAssistant.ToolCalls[0].OfFunction.ID)
			},
		},
		{
			name: "empty string content (filtered out)",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: ""},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				assert.Empty(t, result)
			},
		},
		{
			name: "multiple tool uses in single message",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:  "tool_use",
								Id:    "call_1",
								Name:  "search",
								Input: json.RawMessage(`{"query":"first"}`),
							},
							{
								Type:  "tool_use",
								Id:    "call_2",
								Name:  "calculate",
								Input: json.RawMessage(`{"expression":"1+1"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result []openai.ChatCompletionMessageParamUnion) {
				require.Len(t, result, 1)
				require.NotNil(t, result[0].OfAssistant)
				require.Len(t, result[0].OfAssistant.ToolCalls, 2)
				assert.Equal(t, "call_1", result[0].OfAssistant.ToolCalls[0].OfFunction.ID)
				assert.Equal(t, "search", result[0].OfAssistant.ToolCalls[0].OfFunction.Function.Name)
				assert.Equal(t, "call_2", result[0].OfAssistant.ToolCalls[1].OfFunction.ID)
				assert.Equal(t, "calculate", result[0].OfAssistant.ToolCalls[1].OfFunction.Function.Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertHistoryToChatCompletions(logger, tt.req)
			tt.validate(t, result)
		})
	}
}

func TestConvertToolConfigToChatCompletions(t *testing.T) {
	tests := []struct {
		name      string
		req       *model.ChatRequest
		wantNil   bool
		wantCount int
	}{
		{
			name: "nil tool config returns nil",
			req: &model.ChatRequest{
				ToolConfig: nil,
			},
			wantNil: true,
		},
		{
			name: "invalid JSON in tool config returns nil",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{invalid`),
			},
			wantNil: true,
		},
		{
			name: "empty tools list returns nil",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{},
				}),
			},
			wantNil: true,
		},
		{
			name: "single tool with schema",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name: "search",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{Type: "object"},
								},
							},
						},
					},
				}),
			},
			wantNil:   false,
			wantCount: 1,
		},
		{
			name: "multiple tools",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name: "search",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{Type: "object"},
								},
							},
						},
						{
							Spec: model.ToolDefinition{
								Name: "calculate",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{Type: "object"},
								},
							},
						},
					},
				}),
			},
			wantNil:   false,
			wantCount: 2,
		},
		{
			name: "tool with empty InputSchema (skipped)",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name:        "invalid_tool",
								InputSchema: model.JSONSchema{},
							},
						},
					},
				}),
			},
			wantNil: true,
		},
		{
			name: "tool with description",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name:        "search",
								Description: "Search for information",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{Type: "object"},
								},
							},
						},
					},
				}),
			},
			wantNil:   false,
			wantCount: 1,
		},
		{
			name: "tool without description",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name: "search",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{Type: "object"},
								},
							},
						},
					},
				}),
			},
			wantNil:   false,
			wantCount: 1,
		},
		{
			name: "mix of valid and invalid tools - only valid returned",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name:        "valid_tool",
								InputSchema: model.JSONSchema{Json: &model.ToolSchema{Type: "object"}},
							},
						},
						{
							Spec: model.ToolDefinition{
								Name:        "invalid_tool",
								InputSchema: model.JSONSchema{}, // Empty schema
							},
						},
					},
				}),
			},
			wantNil:   false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertToolConfigToChatCompletions(tt.req)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Len(t, result, tt.wantCount)
			}
		})
	}
}

func TestOpenAIChatAdapter_SendMessage(t *testing.T) {
	tests := []struct {
		name         string
		req          *model.ChatRequest
		mockResponse *openai.ChatCompletion
		mockError    error
		validate     func(*testing.T, *model.Message, error)
	}{
		{
			name: "success with text response",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello"},
						},
					},
				},
				System: "You are a helpful assistant",
			},
			mockResponse: createMockChatCompletion(
				"Hello! How can I help you today?",
				nil,
				createChatCompletionUsage(10, 15),
				"stop",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Equal(t, "assistant", message.Role)
				require.Len(t, message.ContentBlocks, 1)
				assert.Equal(t, "text", message.ContentBlocks[0].Type)
				assert.Equal(t, "Hello! How can I help you today?", message.ContentBlocks[0].Text)
				assert.Equal(t, 10, message.Usage.InputTokens)
				assert.Equal(t, 15, message.Usage.OutputTokens)
				assert.Equal(t, "end_turn", *message.StopReason)
			},
		},
		{
			name: "success with function call response",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Search for cats"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"",
				[]openai.ChatCompletionMessageToolCallUnion{
					createMockToolCall("call_123", "search", `{"query":"cats"}`),
				},
				createChatCompletionUsage(12, 8),
				"tool_calls",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				require.Len(t, message.ContentBlocks, 1)
				assert.Equal(t, "tool_use", message.ContentBlocks[0].Type)
				assert.Equal(t, "call_123", message.ContentBlocks[0].Id)
				assert.Equal(t, "search", message.ContentBlocks[0].Name)
				assert.JSONEq(t, `{"query":"cats"}`, string(message.ContentBlocks[0].Input))
				assert.Equal(t, "tool_calls", *message.StopReason)
			},
		},
		{
			name: "mixed content with text and function call",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Search for something"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"Let me search for that.",
				[]openai.ChatCompletionMessageToolCallUnion{
					createMockToolCall("call_456", "search", `{"query":"something"}`),
				},
				createChatCompletionUsage(15, 20),
				"tool_calls",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				require.Len(t, message.ContentBlocks, 2)
				assert.Equal(t, "text", message.ContentBlocks[0].Type)
				assert.Equal(t, "Let me search for that.", message.ContentBlocks[0].Text)
				assert.Equal(t, "tool_use", message.ContentBlocks[1].Type)
				assert.Equal(t, "call_456", message.ContentBlocks[1].Id)
			},
		},
		{
			name: "multiple function calls",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Do multiple things"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"",
				[]openai.ChatCompletionMessageToolCallUnion{
					createMockToolCall("call_1", "search", `{"query":"first"}`),
					createMockToolCall("call_2", "calculate", `{"expression":"1+1"}`),
				},
				createChatCompletionUsage(20, 10),
				"tool_calls",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				require.Len(t, message.ContentBlocks, 2)
				assert.Equal(t, "tool_use", message.ContentBlocks[0].Type)
				assert.Equal(t, "call_1", message.ContentBlocks[0].Id)
				assert.Equal(t, "tool_use", message.ContentBlocks[1].Type)
				assert.Equal(t, "call_2", message.ContentBlocks[1].Id)
			},
		},
		{
			name: "response with system prompt append",
			req: &model.ChatRequest{
				Model:        "gpt-4",
				System:       "You are helpful.",
				SystemAppend: "Be concise.",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"Response",
				nil,
				createChatCompletionUsage(20, 5),
				"stop",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
			},
		},
		{
			name: "empty system prompt",
			req: &model.ChatRequest{
				Model:  "gpt-4",
				System: "",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"Response",
				nil,
				createChatCompletionUsage(10, 5),
				"stop",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
			},
		},
		{
			name: "empty response with no content",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"",
				nil,
				createChatCompletionUsage(10, 0),
				"stop",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Empty(t, message.ContentBlocks)
			},
		},
		{
			name: "response with very large usage numbers",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"Response",
				nil,
				createChatCompletionUsage(1000000, 2000000),
				"stop",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Equal(t, 1000000, message.Usage.InputTokens)
				assert.Equal(t, 2000000, message.Usage.OutputTokens)
			},
		},
		{
			name: "finish reason length preserved",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"Response",
				nil,
				createChatCompletionUsage(10, 5),
				"length",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Equal(t, "length", *message.StopReason)
			},
		},
		{
			name: "API error",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			},
			mockError: errors.New("API error"),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.Error(t, err)
				assert.Nil(t, message)
				assert.Contains(t, err.Error(), "API error")
			},
		},
		{
			name: "empty choices array returns error",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			},
			mockResponse: &openai.ChatCompletion{
				ID:      "test123",
				Choices: []openai.ChatCompletionChoice{},
				Usage:   createChatCompletionUsage(10, 5),
			},
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.Error(t, err)
				assert.Nil(t, message)
				assert.Contains(t, err.Error(), "no choices")
			},
		},
		{
			name: "message ID is preserved",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			},
			mockResponse: createMockChatCompletion(
				"Response",
				nil,
				createChatCompletionUsage(10, 5),
				"stop",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Equal(t, "chatcmpl_test123", message.Id)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockOpenAIClient{
				chatCompletionsNewFunc: func(ctx context.Context, params openai.ChatCompletionNewParams) (*openai.ChatCompletion, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			srv := server.NewFakeUnauthorizedServer()
			adapter := &OpenAIChatAdapter{
				client: mockClient,
				srv:    srv,
				IOManager: &detections.ResourceManager{
					Config: srv.Config,
				},
			}

			ctx := context.Background()
			message, err := adapter.SendMessage(ctx, tt.req)

			tt.validate(t, message, err)
		})
	}
}

func TestOpenAIChatAdapter_SendMessageStream(t *testing.T) {
	tests := []struct {
		name             string
		chunks           []openai.ChatCompletionChunk
		finalUsage       openai.CompletionUsage
		initialStreamErr error
		expectedStatus   int
		expectError      bool
		expectedEvents   []expectedSSEEvent
	}{
		{
			name: "simple text response",
			chunks: []openai.ChatCompletionChunk{
				newChatTextDelta("Hello, world!"),
			},
			finalUsage:     createChatCompletionUsage(10, 5),
			expectedStatus: 200,
			expectedEvents: []expectedSSEEvent{
				{
					eventType: "message_start",
					validate: func(t *testing.T, e map[string]interface{}) {
						msg := e["message"].(map[string]interface{})
						assert.Equal(t, "gpt-4o", msg["model"])
					},
				},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, "text_delta", delta["type"])
						assert.Equal(t, "Hello, world!", delta["text"])
					},
				},
				{eventType: "content_block_stop"},
				{eventType: "message_delta"}, // stop_reason
				{eventType: "message_delta"}, // usage
				{eventType: "message_stop"},
				{eventType: "[DONE]"},
			},
		},
		{
			name: "multiple text deltas",
			chunks: []openai.ChatCompletionChunk{
				newChatTextDelta("Hello"),
				newChatTextDelta(", "),
				newChatTextDelta("world!"),
			},
			finalUsage:     createChatCompletionUsage(10, 5),
			expectedStatus: 200,
			expectedEvents: []expectedSSEEvent{
				{eventType: "message_start"},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, "Hello", delta["text"])
					},
				},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, ", ", delta["text"])
					},
				},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, "world!", delta["text"])
					},
				},
				{eventType: "content_block_stop"},
				{eventType: "message_delta"},
				{eventType: "message_delta"},
				{eventType: "message_stop"},
				{eventType: "[DONE]"},
			},
		},
		{
			name: "function call streaming",
			chunks: []openai.ChatCompletionChunk{
				newChatToolCallStartDelta(0, "call_123", "search"),
				newChatToolCallArgumentsDelta(0, `{"query":`),
				newChatToolCallArgumentsDelta(0, `"cats"}`),
			},
			finalUsage:     createChatCompletionUsage(12, 8),
			expectedStatus: 200,
			expectedEvents: []expectedSSEEvent{
				{eventType: "message_start"},
				{
					eventType: "content_block_start",
					validate: func(t *testing.T, e map[string]interface{}) {
						block := e["content_block"].(map[string]interface{})
						assert.Equal(t, "tool_use", block["type"])
						assert.Equal(t, "call_123", block["id"])
						assert.Equal(t, "search", block["name"])
					},
				},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, "input_json_delta", delta["type"])
					},
				},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, "input_json_delta", delta["type"])
					},
				},
				{eventType: "content_block_stop"},
				{eventType: "message_delta"},
				{eventType: "message_delta"},
				{eventType: "message_stop"},
				{eventType: "[DONE]"},
			},
		},
		{
			name: "repeated tool call headers collapse to one block",
			chunks: []openai.ChatCompletionChunk{
				newChatToolCallStartDelta(0, "call_123", "search"),
				newChatToolCallHeaderWithArgs(0, "call_123", "search", `{"query":`),
				newChatToolCallHeaderWithArgs(0, "call_123", "search", `"cats"}`),
			},
			finalUsage:     createChatCompletionUsage(12, 8),
			expectedStatus: 200,
			expectedEvents: []expectedSSEEvent{
				{eventType: "message_start"},
				{
					eventType: "content_block_start",
					validate: func(t *testing.T, e map[string]interface{}) {
						block := e["content_block"].(map[string]interface{})
						assert.Equal(t, "call_123", block["id"])
					},
				},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, `{"query":`, delta["partial_json"])
					},
				},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, `"cats"}`, delta["partial_json"])
					},
				},
				{eventType: "content_block_stop"},
				{eventType: "message_delta"},
				{eventType: "message_delta"},
				{eventType: "message_stop"},
				{eventType: "[DONE]"},
			},
		},
		{
			name:             "initial stream error",
			initialStreamErr: errors.New("stream connection failed"),
			expectedStatus:   500,
			expectError:      true,
		},
		{
			name: "finish reason stop mapped to end_turn",
			chunks: []openai.ChatCompletionChunk{
				newChatTextDelta("Response"),
				newChatFinishReasonChunk("stop"),
			},
			finalUsage:     createChatCompletionUsage(10, 5),
			expectedStatus: 200,
			expectedEvents: []expectedSSEEvent{
				{eventType: "message_start"},
				{eventType: "content_block_delta"},
				{eventType: "content_block_stop"},
				{
					eventType: "message_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, "end_turn", delta["stop_reason"])
					},
				},
				{eventType: "message_delta"}, // usage
				{eventType: "message_stop"},
				{eventType: "[DONE]"},
			},
		},
		{
			name: "usage in final chunk",
			chunks: []openai.ChatCompletionChunk{
				newChatTextDelta("Text"),
			},
			finalUsage:     createChatCompletionUsage(100, 200),
			expectedStatus: 200,
			expectedEvents: []expectedSSEEvent{
				{eventType: "message_start"},
				{eventType: "content_block_delta"},
				{eventType: "content_block_stop"},
				{eventType: "message_delta"}, // stop_reason
				{
					eventType: "message_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						usage := e["usage"].(map[string]interface{})
						assert.Equal(t, float64(100), usage["input_tokens"])
						assert.Equal(t, float64(200), usage["output_tokens"])
					},
				},
				{eventType: "message_stop"},
				{eventType: "[DONE]"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockOpenAIClient{
				chatCompletionsNewStreamingFunc: func(ctx context.Context, params openai.ChatCompletionNewParams) ChatCompletionStream {
					return newMockChatCompletionStream(tt.chunks, tt.finalUsage, tt.initialStreamErr)
				},
			}

			srv := server.NewFakeUnauthorizedServer()
			adapter := &OpenAIChatAdapter{
				client: mockClient,
				srv:    srv,
				IOManager: &detections.ResourceManager{
					Config: srv.Config,
				},
			}

			req := &model.ChatRequest{
				Model: "gpt-4o",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test"},
						},
					},
				},
			}

			ctx := context.Background()
			resp, _, err := adapter.SendMessageStream(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if len(tt.expectedEvents) > 0 {
				body := readResponseBody(t, resp)
				events := parseSSEEvents(body)

				require.Len(t, events, len(tt.expectedEvents), "number of SSE events should match")

				for i, expected := range tt.expectedEvents {
					event := validateSSEEventType(t, events[i], expected.eventType)
					if expected.validate != nil && event != nil {
						expected.validate(t, event)
					}
				}
			}
		})
	}
}

// SendMessage maps ChatRequest.MaxTokens (the per-sub-session budget cap) onto the
// Chat Completions MaxCompletionTokens param, leaving it unset when zero.
func TestOpenAIChatAdapter_SendMessage_MaxTokens(t *testing.T) {
	cases := []struct {
		name      string
		maxTokens int
		wantValid bool
		wantVal   int64
	}{
		{name: "cap forwarded when set", maxTokens: 1234, wantValid: true, wantVal: 1234},
		{name: "unset when zero", maxTokens: 0, wantValid: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotParams openai.ChatCompletionNewParams

			mockClient := &mockOpenAIClient{
				chatCompletionsNewFunc: func(ctx context.Context, params openai.ChatCompletionNewParams) (*openai.ChatCompletion, error) {
					gotParams = params
					return createMockChatCompletion("ok", nil, createChatCompletionUsage(1, 1), "stop"), nil
				},
			}

			srv := server.NewFakeUnauthorizedServer()
			adapter := &OpenAIChatAdapter{
				client:    mockClient,
				srv:       srv,
				IOManager: &detections.ResourceManager{Config: srv.Config},
			}

			_, err := adapter.SendMessage(context.Background(), &model.ChatRequest{
				Model:     "gpt-4",
				MaxTokens: tc.maxTokens,
				Messages:  []*model.Message{{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}}},
			})

			assert.NoError(t, err)
			assert.Equal(t, tc.wantValid, gotParams.MaxCompletionTokens.Valid())
			if tc.wantValid {
				assert.Equal(t, tc.wantVal, gotParams.MaxCompletionTokens.Or(0))
			}
		})
	}
}
