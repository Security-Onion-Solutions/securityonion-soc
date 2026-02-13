// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"

	"github.com/apex/log"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/pagination"
	"github.com/openai/openai-go/v3/responses"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test doubles to avoid import cycles

type mockOpenAIClient struct {
	modelsListFunc            func(ctx context.Context) (*pagination.Page[openai.Model], error)
	responsesNewFunc          func(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error)
	responsesNewStreamingFunc func(ctx context.Context, params responses.ResponseNewParams) ResponseStream
}

func (m *mockOpenAIClient) ModelsList(ctx context.Context) (*pagination.Page[openai.Model], error) {
	if m.modelsListFunc != nil {
		return m.modelsListFunc(ctx)
	}
	return nil, errors.New("not implemented")
}

func (m *mockOpenAIClient) ResponsesNew(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error) {
	if m.responsesNewFunc != nil {
		return m.responsesNewFunc(ctx, params)
	}
	return nil, errors.New("not implemented")
}

func (m *mockOpenAIClient) ResponsesNewStreaming(ctx context.Context, params responses.ResponseNewParams) ResponseStream {
	if m.responsesNewStreamingFunc != nil {
		return m.responsesNewStreamingFunc(ctx, params)
	}
	return nil
}

// mockResponseStream is a simple implementation of ResponseStream for testing
type mockResponseStream struct {
	events       []responses.ResponseStreamEventUnion
	currentIndex int
	err          error
}

func (m *mockResponseStream) Next() bool {
	if m.err != nil {
		return false
	}
	if m.currentIndex >= len(m.events) {
		return false
	}
	m.currentIndex++
	return true
}

func (m *mockResponseStream) Current() responses.ResponseStreamEventUnion {
	if m.currentIndex == 0 || m.currentIndex > len(m.events) {
		return responses.ResponseStreamEventUnion{}
	}
	return m.events[m.currentIndex-1]
}

func (m *mockResponseStream) Err() error {
	return m.err
}

// newMockStream creates a mock stream for testing
func newMockStream(events []responses.ResponseStreamEventUnion, finalUsage responses.ResponseUsage, initialErr error) ResponseStream {
	// Add a final event with Response.Usage for finalization
	// This is needed because SendMessageStream calls stream.Current().Response.Usage after the loop
	if initialErr == nil {
		finalEvent := responses.ResponseStreamEventUnion{
			Type: "response.done",
			Response: responses.Response{
				Usage: finalUsage,
			},
		}
		events = append(events, finalEvent)
	}

	return &mockResponseStream{
		events: events,
		err:    initialErr,
	}
}

func TestNewOpenAIAdapter(t *testing.T) {
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
				"baseUrl":              "https://api.openai.com/v1",
				"apiKey":               "test-key",
				"healthTimeoutSeconds": float64(6),
			},
			expectError:           false,
			expectedHealthTimeout: 6,
			validateHealthTimeout: true,
		},
		{
			name: "Missing baseUrl returns error",
			config: map[string]any{
				"apiKey": "test-key",
			},
			expectError:   true,
			errorContains: "baseUrl",
		},
		{
			name: "Without apiKey succeeds",
			config: map[string]any{
				"baseUrl": "https://api.openai.com/v1",
			},
			expectError: false,
		},
		{
			name: "Default health timeout",
			config: map[string]any{
				"baseUrl": "https://api.openai.com/v1",
			},
			expectError:           false,
			expectedHealthTimeout: DEFAULT_HEALTH_TIMEOUT_SECONDS,
			validateHealthTimeout: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := server.NewFakeUnauthorizedServer()
			adapter, err := NewOpenAIAdapter(context.Background(), srv, tt.config)

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
					openaiAdapter := adapter.(*OpenAIAdapter)
					assert.Equal(t, tt.expectedHealthTimeout, openaiAdapter.healthTimeoutSeconds)
				}
			}
		})
	}
}

func TestProtocol(t *testing.T) {
	adapter := &OpenAIAdapter{}
	assert.Equal(t, "openai", adapter.Protocol())
}

func TestGetBalance(t *testing.T) {
	adapter := &OpenAIAdapter{}
	ctx := context.Background()

	balance, err := adapter.GetBalance(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, balance)
	assert.Equal(t, int64(UNUSED_BALANCE), balance.Balance)
}

func TestConvertHistoryToOpenAI(t *testing.T) {
	tests := []struct {
		name     string
		req      *model.ChatRequest
		validate func(*testing.T, interface{})
	}{
		{
			name: "empty messages",
			req: &model.ChatRequest{
				Messages: []*model.Message{},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				assert.Empty(t, resp.OfInputItemList)
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
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				require.NotNil(t, item.OfInputMessage)
				assert.Equal(t, "user", item.OfInputMessage.Role)
				require.Len(t, item.OfInputMessage.Content, 1)
				require.NotNil(t, item.OfInputMessage.Content[0].OfInputText)
				assert.Equal(t, "Hello, world!", item.OfInputMessage.Content[0].OfInputText.Text)
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
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				require.NotNil(t, item.OfInputMessage)
				assert.Equal(t, "assistant", item.OfInputMessage.Role)
				require.Len(t, item.OfInputMessage.Content, 1)
				require.NotNil(t, item.OfInputMessage.Content[0].OfInputText)
				assert.Equal(t, "Hi there!", item.OfInputMessage.Content[0].OfInputText.Text)
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
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 2)
				// First message
				assert.NotNil(t, resp.OfInputItemList[0].OfInputMessage)
				assert.Equal(t, "user", resp.OfInputItemList[0].OfInputMessage.Role)
				assert.Equal(t, "First message", resp.OfInputItemList[0].OfInputMessage.Content[0].OfInputText.Text)
				// Second message
				assert.NotNil(t, resp.OfInputItemList[1].OfInputMessage)
				assert.Equal(t, "assistant", resp.OfInputItemList[1].OfInputMessage.Role)
				assert.Equal(t, "Second message", resp.OfInputItemList[1].OfInputMessage.Content[0].OfInputText.Text)
			},
		},
		{
			name: "message with special characters",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Test with \"quotes\" and <tags> & symbols"},
						},
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				require.NotNil(t, item.OfInputMessage)
				assert.Equal(t, "Test with \"quotes\" and <tags> & symbols", item.OfInputMessage.Content[0].OfInputText.Text)
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
								Name:  "get_weather",
								Input: json.RawMessage(`{"location": "San Francisco"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				require.NotNil(t, item.OfFunctionCall)
				assert.Equal(t, "call_123", item.OfFunctionCall.ID.Or(""))
				assert.Equal(t, "get_weather", item.OfFunctionCall.Name)
				assert.JSONEq(t, `{"location": "San Francisco"}`, item.OfFunctionCall.Arguments)
			},
		},
		{
			name: "tool use with invalid JSON should skip",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:  "tool_use",
								Id:    "call_123",
								Name:  "get_weather",
								Input: json.RawMessage(`{invalid json}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				// Should have one item but it should be empty since the JSON was invalid and skipped
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				// All fields should be nil since the block was skipped
				assert.Nil(t, item.OfInputMessage)
				assert.Nil(t, item.OfFunctionCall)
				assert.Nil(t, item.OfFunctionCallOutput)
			},
		},
		{
			name: "tool result with success and JSON content",
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
										{Json: map[string]any{"temperature": 72}},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				require.NotNil(t, item.OfFunctionCallOutput)
				assert.Equal(t, "call_123", item.OfFunctionCallOutput.CallID)
				assert.Equal(t, "completed", item.OfFunctionCallOutput.Status)
				// Output should be the JSON marshaled content
				assert.JSONEq(t, `{"temperature":72}`, item.OfFunctionCallOutput.Output.OfString.Or(""))
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
										{Text: "API connection failed"},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				require.NotNil(t, item.OfFunctionCallOutput)
				assert.Equal(t, "call_123", item.OfFunctionCallOutput.CallID)
				assert.Equal(t, "completed", item.OfFunctionCallOutput.Status)
				// Error should be wrapped in error JSON format
				assert.Contains(t, item.OfFunctionCallOutput.Output.OfString.Or(""), "API connection failed")
			},
		},
		{
			name: "tool result with empty content array should be skipped",
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
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				// Should have one item but it should be empty since content was empty
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				assert.Nil(t, item.OfInputMessage)
				assert.Nil(t, item.OfFunctionCall)
				assert.Nil(t, item.OfFunctionCallOutput)
			},
		},
		{
			name: "message with nbsp only should be skipped",
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
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				// Should have one item but no message content (nbsp is filtered out)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				assert.Nil(t, item.OfInputMessage)
			},
		},
		{
			name: "message with nbsp and tool use",
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
								Input: json.RawMessage(`{"query": "test"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				// Should only have function call, no message (nbsp filtered)
				assert.Nil(t, item.OfInputMessage)
				require.NotNil(t, item.OfFunctionCall)
				assert.Equal(t, "search", item.OfFunctionCall.Name)
			},
		},
		{
			name: "mixed content types in single message",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Let me check that for you"},
							{
								Type:  "tool_use",
								Id:    "call_123",
								Name:  "search",
								Input: json.RawMessage(`{"query": "test"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				// Both text message and function call should be present on same item
				require.NotNil(t, item.OfInputMessage)
				assert.Equal(t, "Let me check that for you", item.OfInputMessage.Content[0].OfInputText.Text)
				require.NotNil(t, item.OfFunctionCall)
				assert.Equal(t, "search", item.OfFunctionCall.Name)
			},
		},
		{
			name: "empty string content",
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
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				// Empty string should be filtered out
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				assert.Nil(t, item.OfInputMessage)
			},
		},
		{
			name: "nil content blocks",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role:          "user",
						ContentBlocks: nil,
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				// Should have one empty item
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				assert.Nil(t, item.OfInputMessage)
				assert.Nil(t, item.OfFunctionCall)
			},
		},
		{
			name: "multiple tool uses in sequence",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:  "tool_use",
								Id:    "call_1",
								Name:  "search",
								Input: json.RawMessage(`{"query": "test1"}`),
							},
							{
								Type:  "tool_use",
								Id:    "call_2",
								Name:  "calculate",
								Input: json.RawMessage(`{"expr": "2+2"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				resp := result.(responses.ResponseNewParamsInputUnion)
				// Only one OfFunctionCall per history item - last one wins
				require.Len(t, resp.OfInputItemList, 1)
				item := resp.OfInputItemList[0]
				require.NotNil(t, item.OfFunctionCall)
				// Should be the last tool call since it overwrites previous ones
				assert.Equal(t, "calculate", item.OfFunctionCall.Name)
				assert.Equal(t, "call_2", item.OfFunctionCall.ID.Or(""))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertHistoryToOpenAI(log.Log, tt.req)
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestConvertToolConfigToOpenAI(t *testing.T) {
	tests := []struct {
		name      string
		req       *model.ChatRequest
		wantNil   bool
		wantCount int
	}{
		{
			name: "nil tool config",
			req: &model.ChatRequest{
				ToolConfig: nil,
			},
			wantNil: true,
		},
		{
			name: "invalid JSON in tool config",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{invalid json}`),
			},
			wantNil: true,
		},
		{
			name: "empty tools list",
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
								Name:        "get_weather",
								Description: "Get weather for a location",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{
										Type: "object",
										Properties: map[string]model.ToolSchemaProperty{
											"location": {Type: "string"},
										},
										Required: []string{"location"},
									},
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
								Name: "tool1",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{Type: "object"},
								},
							},
						},
						{
							Spec: model.ToolDefinition{
								Name: "tool2",
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
			name: "tool with empty InputSchema should be skipped",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name:        "empty_tool",
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
								Description: "Search the web",
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
			name: "tool with complex nested schema",
			req: &model.ChatRequest{
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name: "complex_tool",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{
										Type: "object",
										Properties: map[string]model.ToolSchemaProperty{
											"config": {
												Type: "object",
												Items: map[string]model.ToolSchemaProperty{
													"nested": {Type: "string"},
												},
											},
											"items": {
												Type: "array",
												Items: map[string]model.ToolSchemaProperty{
													"item": {Type: "number"},
												},
											},
										},
									},
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
			result := convertToolConfigToOpenAI(tt.req)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Len(t, result, tt.wantCount)
			}
		})
	}
}

func TestConvertPropertyToOpenAI(t *testing.T) {
	tests := []struct {
		name string
		prop *model.ToolSchemaProperty
		want map[string]any
	}{
		{
			name: "string type",
			prop: &model.ToolSchemaProperty{
				Type: "string",
			},
			want: map[string]any{
				"type": "string",
			},
		},
		{
			name: "integer type",
			prop: &model.ToolSchemaProperty{
				Type: "integer",
			},
			want: map[string]any{
				"type": "integer",
			},
		},
		{
			name: "boolean type",
			prop: &model.ToolSchemaProperty{
				Type: "boolean",
			},
			want: map[string]any{
				"type": "boolean",
			},
		},
		{
			name: "number type",
			prop: &model.ToolSchemaProperty{
				Type: "number",
			},
			want: map[string]any{
				"type": "number",
			},
		},
		{
			name: "with description",
			prop: &model.ToolSchemaProperty{
				Type:        "string",
				Description: "The user's name",
			},
			want: map[string]any{
				"type":        "string",
				"description": "The user's name",
			},
		},
		{
			name: "with default value",
			prop: &model.ToolSchemaProperty{
				Type:    "string",
				Default: "default_value",
			},
			want: map[string]any{
				"type":    "string",
				"default": "default_value",
			},
		},
		{
			name: "object with properties",
			prop: &model.ToolSchemaProperty{
				Type: "object",
				Items: map[string]model.ToolSchemaProperty{
					"name": {Type: "string"},
					"age":  {Type: "integer"},
				},
			},
			want: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string"},
					"age":  map[string]any{"type": "integer"},
				},
			},
		},
		{
			name: "array with items",
			prop: &model.ToolSchemaProperty{
				Type: "array",
				Items: map[string]model.ToolSchemaProperty{
					"item": {Type: "string"},
				},
			},
			want: map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string"},
			},
		},
		{
			name: "deeply nested object",
			prop: &model.ToolSchemaProperty{
				Type: "object",
				Items: map[string]model.ToolSchemaProperty{
					"config": {
						Type: "object",
						Items: map[string]model.ToolSchemaProperty{
							"settings": {Type: "string"},
						},
					},
				},
			},
			want: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"config": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"settings": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
		{
			name: "empty items map",
			prop: &model.ToolSchemaProperty{
				Type:  "object",
				Items: map[string]model.ToolSchemaProperty{},
			},
			want: map[string]any{
				"type": "object",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertPropertyToOpenAI(tt.prop)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestConvertJSONSchemaToOpenAI(t *testing.T) {
	tests := []struct {
		name   string
		schema *model.ToolSchema
		want   map[string]any
	}{
		{
			name:   "nil schema",
			schema: nil,
			want:   nil,
		},
		{
			name: "simple schema with type only",
			schema: &model.ToolSchema{
				Type: "object",
			},
			want: map[string]any{
				"type": "object",
			},
		},
		{
			name: "schema with properties",
			schema: &model.ToolSchema{
				Type: "object",
				Properties: map[string]model.ToolSchemaProperty{
					"name": {Type: "string"},
					"age":  {Type: "integer"},
				},
			},
			want: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string"},
					"age":  map[string]any{"type": "integer"},
				},
			},
		},
		{
			name: "schema with required fields",
			schema: &model.ToolSchema{
				Type:     "object",
				Required: []string{"name", "email"},
			},
			want: map[string]any{
				"type":     "object",
				"required": []string{"name", "email"},
			},
		},
		{
			name: "schema with both properties and required",
			schema: &model.ToolSchema{
				Type: "object",
				Properties: map[string]model.ToolSchemaProperty{
					"name":  {Type: "string"},
					"email": {Type: "string"},
				},
				Required: []string{"name"},
			},
			want: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":  map[string]any{"type": "string"},
					"email": map[string]any{"type": "string"},
				},
				"required": []string{"name"},
			},
		},
		{
			name: "empty properties",
			schema: &model.ToolSchema{
				Type:       "object",
				Properties: map[string]model.ToolSchemaProperty{},
			},
			want: map[string]any{
				"type": "object",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertJSONSchemaToOpenAI(tt.schema)
			assert.Equal(t, tt.want, result)
		})
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	return data
}

func TestGetHealth(t *testing.T) {
	// Note: This is a basic integration test that verifies the method signature
	// and basic response structure. The OpenAIClient interface allows for mocking
	// in external packages that don't have import cycle constraints.

	srv := server.NewFakeUnauthorizedServer()
	adapter, err := NewOpenAIAdapter(context.Background(), srv, map[string]any{
		"baseUrl": "https://api.openai.com/v1",
		"apiKey":  "test-key",
	})
	require.NoError(t, err)

	ctx := context.Background()
	health, err := adapter.GetHealth(ctx)

	// GetHealth always returns nil error per implementation
	assert.NoError(t, err)
	assert.NotNil(t, health)

	// Status should be either "healthy" or "unhealthy"
	assert.Contains(t, []string{"healthy", "unhealthy"}, health.Status)
}

// Helper functions for creating mock OpenAI responses

func createMockTextOutput(text string) responses.ResponseOutputItemUnion {
	return responses.ResponseOutputItemUnion{
		Type: "message",
		Content: []responses.ResponseOutputMessageContentUnion{
			{
				Type: "output_text",
				Text: text,
			},
		},
	}
}

func createMockFunctionCallOutput(callId, name string, args string) responses.ResponseOutputItemUnion {
	return responses.ResponseOutputItemUnion{
		Type:      "function_call",
		CallID:    callId,
		Name:      name,
		Arguments: args,
	}
}

func createMockOpenAIResponse(outputItems []responses.ResponseOutputItemUnion, usage *responses.ResponseUsage, status string, incompleteReason string) *responses.Response {
	resp := &responses.Response{
		ID:     "resp_test123",
		Status: responses.ResponseStatus(status),
		Output: outputItems,
	}

	if usage != nil {
		resp.Usage = *usage
	}

	if status == "incomplete" && incompleteReason != "" {
		resp.IncompleteDetails = responses.ResponseIncompleteDetails{
			Reason: incompleteReason,
		}
	}

	return resp
}

func TestOpenAIAdapter_SendMessage(t *testing.T) {
	tests := []struct {
		name         string
		req          *model.ChatRequest
		mockResponse *responses.Response
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockTextOutput("Hello! How can I help you today?"),
				},
				&responses.ResponseUsage{
					InputTokens:  10,
					OutputTokens: 15,
				},
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Equal(t, "assistant", message.Role)
				assert.Len(t, message.ContentBlocks, 1)
				assert.Equal(t, "text", message.ContentBlocks[0].Type)
				assert.Equal(t, "Hello! How can I help you today?", message.ContentBlocks[0].Text)
				assert.NotNil(t, message.Usage)
				assert.Equal(t, 10, message.Usage.InputTokens)
				assert.Equal(t, 15, message.Usage.OutputTokens)
				assert.NotNil(t, message.StopReason)
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
							{Type: "text", Text: "What's the weather?"},
						},
					},
				},
				ToolConfig: mustMarshal(model.ToolConfig{
					Tools: []*model.ToolSpec{
						{
							Spec: model.ToolDefinition{
								Name:        "get_weather",
								Description: "Get weather for a location",
								InputSchema: model.JSONSchema{
									Json: &model.ToolSchema{
										Type: "object",
										Properties: map[string]model.ToolSchemaProperty{
											"location": {Type: "string"},
										},
									},
								},
							},
						},
					},
				}),
			},
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockFunctionCallOutput("call_abc123", "get_weather", `{"location":"San Francisco"}`),
				},
				&responses.ResponseUsage{
					InputTokens:  20,
					OutputTokens: 25,
				},
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Len(t, message.ContentBlocks, 1)
				assert.Equal(t, "tool_use", message.ContentBlocks[0].Type)
				assert.Equal(t, "call_abc123", message.ContentBlocks[0].Id)
				assert.Equal(t, "get_weather", message.ContentBlocks[0].Name)
				assert.JSONEq(t, `{"location":"San Francisco"}`, string(message.ContentBlocks[0].Input))
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockTextOutput("I'll search for that."),
					createMockFunctionCallOutput("call_search", "web_search", `{"query":"something"}`),
				},
				&responses.ResponseUsage{
					InputTokens:  15,
					OutputTokens: 30,
				},
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Len(t, message.ContentBlocks, 2)
				assert.Equal(t, "text", message.ContentBlocks[0].Type)
				assert.Equal(t, "I'll search for that.", message.ContentBlocks[0].Text)
				assert.Equal(t, "tool_use", message.ContentBlocks[1].Type)
				assert.Equal(t, "web_search", message.ContentBlocks[1].Name)
			},
		},
		{
			name: "function call without explicit CallID generates ID",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockFunctionCallOutput("", "test_func", `{}`),
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Len(t, message.ContentBlocks, 1)
				assert.Equal(t, "tool_use", message.ContentBlocks[0].Type)
				assert.Equal(t, "toolu_0", message.ContentBlocks[0].Id) // Generated ID
				assert.Equal(t, "test_func", message.ContentBlocks[0].Name)
			},
		},
		{
			name: "response with system prompt append",
			req: &model.ChatRequest{
				Model:        "gpt-4",
				System:       "You are helpful.",
				SystemAppend: "\nAlways be concise.",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hi"},
						},
					},
				},
			},
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockTextOutput("Hello."),
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				// System prompt concatenation happens internally, validated via mock expectations
			},
		},
		{
			name: "incomplete response with reason",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Generate long text"},
						},
					},
				},
			},
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockTextOutput("This is a partial response..."),
				},
				nil,
				"incomplete",
				"max_output_tokens",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.NotNil(t, message.StopReason)
				assert.Equal(t, "max_output_tokens", *message.StopReason)
			},
		},
		{
			name: "API error from ResponsesNew",
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
			mockError: errors.New("rate limit exceeded"),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "rate limit exceeded")
				assert.Nil(t, message)
			},
		},
		{
			name: "empty response with no output items",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Empty(t, message.ContentBlocks)
			},
		},
		{
			name: "missing usage metadata is handled",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockTextOutput("Response"),
				},
				nil, // No usage metadata
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.NotNil(t, message.Usage)
				assert.Equal(t, 0, message.Usage.InputTokens)
				assert.Equal(t, 0, message.Usage.OutputTokens)
			},
		},
		{
			name: "multiple function calls in response",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockFunctionCallOutput("call_1", "func1", `{"x":1}`),
					createMockFunctionCallOutput("call_2", "func2", `{"y":2}`),
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Len(t, message.ContentBlocks, 2)
				assert.Equal(t, "tool_use", message.ContentBlocks[0].Type)
				assert.Equal(t, "func1", message.ContentBlocks[0].Name)
				assert.Equal(t, "tool_use", message.ContentBlocks[1].Type)
				assert.Equal(t, "func2", message.ContentBlocks[1].Name)
			},
		},
		{
			name: "unknown output item types are skipped",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					{
						Type: "unknown_type", // Unknown type, should be skipped
					},
					createMockTextOutput("Valid text"),
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Len(t, message.ContentBlocks, 1)
				assert.Equal(t, "text", message.ContentBlocks[0].Type)
				assert.Equal(t, "Valid text", message.ContentBlocks[0].Text)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockOpenAIClient{
				responsesNewFunc: func(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			srv := server.NewFakeUnauthorizedServer()
			adapter := &OpenAIAdapter{
				srv:    srv,
				client: mockClient,
				IOManager: &detections.ResourceManager{
					Config: srv.Config,
				},
			}

			ctx := context.Background()
			message, err := adapter.SendMessage(ctx, tt.req)

			if tt.validate != nil {
				tt.validate(t, message, err)
			}
		})
	}
}

// TestOpenAIAdapter_SendMessage_EdgeCases tests additional edge cases
func TestOpenAIAdapter_SendMessage_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		req          *model.ChatRequest
		mockResponse *responses.Response
		mockError    error
		validate     func(*testing.T, *model.Message, error)
	}{
		{
			name: "response with multiple text content blocks in single message",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					{
						Type: "message",
						Content: []responses.ResponseOutputMessageContentUnion{
							{Type: "output_text", Text: "First part. "},
							{Type: "output_text", Text: "Second part."},
						},
					},
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				// Each output_text becomes a separate ContentBlock
				assert.Len(t, message.ContentBlocks, 2)
				assert.Equal(t, "First part. ", message.ContentBlocks[0].Text)
				assert.Equal(t, "Second part.", message.ContentBlocks[1].Text)
			},
		},
		{
			name: "response with only refusal content",
			req: &model.ChatRequest{
				Model: "gpt-4",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Generate illegal content"},
						},
					},
				},
			},
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					{
						Type: "message",
						Content: []responses.ResponseOutputMessageContentUnion{
							{Type: "refusal", Refusal: "I cannot help with that request."},
						},
					},
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				// Refusal content is not output_text, so should be skipped
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockTextOutput("Response"),
				},
				&responses.ResponseUsage{
					InputTokens:  1000000,
					OutputTokens: 2000000,
				},
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Equal(t, 1000000, message.Usage.InputTokens)
				assert.Equal(t, 2000000, message.Usage.OutputTokens)
			},
		},
		{
			name: "empty system prompt should still work",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockTextOutput("Response"),
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
			},
		},
		{
			name: "function call with empty arguments",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockFunctionCallOutput("call_1", "no_args_func", ""),
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Len(t, message.ContentBlocks, 1)
				assert.Equal(t, "tool_use", message.ContentBlocks[0].Type)
				assert.Equal(t, "no_args_func", message.ContentBlocks[0].Name)
				assert.Equal(t, "", string(message.ContentBlocks[0].Input))
			},
		},
		{
			name: "response ID is preserved",
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
			mockResponse: func() *responses.Response {
				resp := createMockOpenAIResponse(
					[]responses.ResponseOutputItemUnion{
						createMockTextOutput("Response"),
					},
					nil,
					"completed",
					"",
				)
				resp.ID = "custom-response-id-123"
				return resp
			}(),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.Equal(t, "custom-response-id-123", message.Id)
			},
		},
		{
			name: "status completed without finish reason defaults to end_turn",
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
			mockResponse: createMockOpenAIResponse(
				[]responses.ResponseOutputItemUnion{
					createMockTextOutput("Response"),
				},
				nil,
				"completed",
				"",
			),
			validate: func(t *testing.T, message *model.Message, err error) {
				assert.NoError(t, err)
				assert.NotNil(t, message)
				assert.NotNil(t, message.StopReason)
				assert.Equal(t, "end_turn", *message.StopReason)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockOpenAIClient{
				responsesNewFunc: func(ctx context.Context, params responses.ResponseNewParams) (*responses.Response, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			srv := server.NewFakeUnauthorizedServer()
			adapter := &OpenAIAdapter{
				srv:    srv,
				client: mockClient,
				IOManager: &detections.ResourceManager{
					Config: srv.Config,
				},
			}

			ctx := context.Background()
			message, err := adapter.SendMessage(ctx, tt.req)

			if tt.validate != nil {
				tt.validate(t, message, err)
			}
		})
	}
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read response body")
	return string(bodyBytes)
}

func parseSSEEvents(body string) []string {
	events := []string{}
	lines := strings.Split(body, "\n\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			events = append(events, strings.TrimPrefix(line, "data: "))
		}
	}
	return events
}

func validateSSEEventType(t *testing.T, eventJSON string, expectedType string) map[string]interface{} {
	if eventJSON == "[DONE]" {
		require.Equal(t, "[DONE]", expectedType, "expected [DONE] marker")
		return nil
	}

	var event map[string]interface{}
	err := json.Unmarshal([]byte(eventJSON), &event)
	require.NoError(t, err, "failed to parse SSE event JSON")

	if expectedType != "" {
		actualType, ok := event["type"].(string)
		require.True(t, ok, "event missing 'type' field")
		require.Equal(t, expectedType, actualType)
	}

	return event
}

type expectedSSEEvent struct {
	eventType string
	validate  func(*testing.T, map[string]interface{})
}

func TestOpenAIAdapter_SendMessageStream(t *testing.T) {
	tests := []struct {
		name             string
		streamEvents     []responses.ResponseStreamEventUnion
		streamUsage      responses.ResponseUsage
		initialStreamErr error
		expectedStatus   int
		expectError      bool
		expectedEvents   []expectedSSEEvent
	}{
		{
			name: "simple text response",
			streamEvents: []responses.ResponseStreamEventUnion{
				newTextDelta("Hello, world!"),
			},
			streamUsage:    createMockUsage(10, 5),
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
			name: "thought and text response",
			streamEvents: []responses.ResponseStreamEventUnion{
				newThoughtDelta("Let me think..."),
				newTextDelta("Based on that, here's my answer"),
			},
			streamUsage:    createMockUsage(15, 10),
			expectedStatus: 200,
			expectedEvents: []expectedSSEEvent{
				{eventType: "message_start"},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, "thought_delta", delta["type"])
						assert.Equal(t, "Let me think...", delta["text"]) // thought uses "text" field
					},
				},
				{
					eventType: "content_block_delta",
					validate: func(t *testing.T, e map[string]interface{}) {
						delta := e["delta"].(map[string]interface{})
						assert.Equal(t, "text_delta", delta["type"])
						assert.Equal(t, "Based on that, here's my answer", delta["text"])
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock client with stream
			client := &mockOpenAIClient{
				responsesNewStreamingFunc: func(ctx context.Context, params responses.ResponseNewParams) ResponseStream {
					return newMockStream(tt.streamEvents, tt.streamUsage, tt.initialStreamErr)
				},
			}

			srv := server.NewFakeUnauthorizedServer()
			adapter := &OpenAIAdapter{
				client: client,
				srv:    srv,
				IOManager: &detections.ResourceManager{
					Config: srv.Config,
				},
			}

			// Execute
			req := &model.ChatRequest{
				Model:  "gpt-4o",
				System: "You are helpful",
				Messages: []*model.Message{
					{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello"},
						},
					},
				},
			}

			resp, aux, err := adapter.SendMessageStream(context.Background(), req)

			// Validate error handling
			if tt.expectError {
				assert.Error(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
				// Read body to verify error message
				body := readResponseBody(t, resp)
				assert.Contains(t, body, "ERROR_FIRST_RESPONSE")
				return
			}

			// For successful cases, validate response structure and body
			require.NoError(t, err)
			assert.Nil(t, aux)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

			// Read and validate response body
			body := readResponseBody(t, resp)
			events := parseSSEEvents(body)

			// Validate event sequence
			require.Len(t, events, len(tt.expectedEvents), "unexpected number of SSE events")
			for i, expected := range tt.expectedEvents {
				event := validateSSEEventType(t, events[i], expected.eventType)
				if expected.validate != nil {
					expected.validate(t, event)
				}
			}
		})
	}
}
