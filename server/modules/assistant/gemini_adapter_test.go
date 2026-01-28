// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/stretchr/testify/assert"
	"google.golang.org/genai"
)

func TestGetThought(t *testing.T) {
	tests := []struct {
		name     string
		response *genai.GenerateContentResponse
		expected string
	}{
		{
			name: "response with no candidates",
			response: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{},
			},
			expected: "",
		},
		{
			name: "response with candidate but no parts",
			response: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{},
						},
					},
				},
			},
			expected: "",
		},
		{
			name: "single candidate with single thought part",
			response: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "This is a thought", Thought: true},
							},
						},
					},
				},
			},
			expected: "This is a thought",
		},
		{
			name: "single candidate with multiple thought parts",
			response: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "First thought", Thought: true},
								{Text: " second thought", Thought: true},
							},
						},
					},
				},
			},
			expected: "First thought second thought",
		},
		{
			name: "single candidate with non-thought parts",
			response: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "Not a thought", Thought: false},
							},
						},
					},
				},
			},
			expected: "",
		},
		{
			name: "single candidate with mixed thought and non-thought parts",
			response: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "Not a thought", Thought: false},
								{Text: "This is a thought", Thought: true},
								{Text: "Another non-thought", Thought: false},
							},
						},
					},
				},
			},
			expected: "This is a thought",
		},
		{
			name: "multiple candidates with thought parts",
			response: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "First candidate thought", Thought: true},
							},
						},
					},
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: " second candidate thought", Thought: true},
							},
						},
					},
				},
			},
			expected: "First candidate thought second candidate thought",
		},
		{
			name: "empty text in thought part",
			response: &genai.GenerateContentResponse{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{Text: "", Thought: true},
								{Text: "Actual thought", Thought: true},
							},
						},
					},
				},
			},
			expected: "Actual thought",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getThought(tt.response)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFabricateResponse(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		expectedStatus int
	}{
		{
			name:           "HTTP 200 status code",
			statusCode:     200,
			expectedStatus: 200,
		},
		{
			name:           "HTTP 500 status code",
			statusCode:     500,
			expectedStatus: 500,
		},
		{
			name:           "HTTP 404 status code",
			statusCode:     404,
			expectedStatus: 404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, writer := fabricateResponse(tt.statusCode)

			// Verify status code
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Verify Content-Type header
			assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

			// Verify Body is not nil
			assert.NotNil(t, resp.Body)

			// Verify writer is not nil
			assert.NotNil(t, writer)

			// Test write and read interaction
			testData := "test data"
			go func() {
				writer.Write([]byte(testData))
				writer.Close()
			}()

			buf := make([]byte, len(testData))
			n, err := resp.Body.Read(buf)

			assert.NoError(t, err)
			assert.Equal(t, len(testData), n)
			assert.Equal(t, testData, string(buf))

			// Verify EOF after close
			_, err = resp.Body.Read(buf)
			assert.Equal(t, io.EOF, err)
		})
	}
}

func TestConvertToolConfig(t *testing.T) {
	tests := []struct {
		name         string
		req          *model.ChatRequest
		expectTools  bool
		expectConfig bool
		validate     func(t *testing.T, tools []*genai.Tool, config *genai.ToolConfig)
	}{
		{
			name:         "ChatRequest with nil ToolConfig",
			req:          &model.ChatRequest{ToolConfig: nil},
			expectTools:  false,
			expectConfig: false,
			validate: func(t *testing.T, tools []*genai.Tool, config *genai.ToolConfig) {
				assert.Nil(t, tools)
				assert.Nil(t, config)
			},
		},
		{
			name: "ChatRequest with empty ToolConfig JSON",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{}`),
			},
			expectTools:  false,
			expectConfig: false,
			validate: func(t *testing.T, tools []*genai.Tool, config *genai.ToolConfig) {
				assert.Nil(t, tools)
				assert.Nil(t, config)
			},
		},
		{
			name: "Invalid JSON in ToolConfig",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{invalid json`),
			},
			expectTools:  false,
			expectConfig: false,
			validate: func(t *testing.T, tools []*genai.Tool, config *genai.ToolConfig) {
				assert.Nil(t, tools)
				assert.Nil(t, config)
			},
		},
		{
			name: "Valid ToolConfig with no tools",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{"tools":[]}`),
			},
			expectTools:  false,
			expectConfig: false,
			validate: func(t *testing.T, tools []*genai.Tool, config *genai.ToolConfig) {
				assert.Nil(t, tools)
				assert.Nil(t, config)
			},
		},
		{
			name: "Single tool with basic schema",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{
					"tools": [{
						"toolSpec": {
							"name": "test_tool",
							"description": "A test tool",
							"inputSchema": {
								"json": {
									"type": "object",
									"properties": {
										"query": {
											"type": "string",
											"description": "The search query"
										}
									},
									"required": ["query"]
								}
							}
						}
					}]
				}`),
			},
			expectTools:  true,
			expectConfig: true,
			validate: func(t *testing.T, tools []*genai.Tool, config *genai.ToolConfig) {
				assert.Len(t, tools, 1)
				assert.Len(t, tools[0].FunctionDeclarations, 1)
				assert.Equal(t, "test_tool", tools[0].FunctionDeclarations[0].Name)
				assert.Equal(t, "A test tool", tools[0].FunctionDeclarations[0].Description)
				assert.NotNil(t, tools[0].FunctionDeclarations[0].Parameters)
				assert.NotNil(t, config)
				assert.Equal(t, genai.FunctionCallingConfigModeAuto, config.FunctionCallingConfig.Mode)
			},
		},
		{
			name: "Multiple tools with various schema types",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{
					"tools": [
						{
							"toolSpec": {
								"name": "tool1",
								"description": "First tool",
								"inputSchema": {
									"json": {
										"type": "object",
										"properties": {
											"param1": {
												"type": "string",
												"description": "String parameter"
											}
										}
									}
								}
							}
						},
						{
							"toolSpec": {
								"name": "tool2",
								"description": "Second tool",
								"inputSchema": {
									"json": {
										"type": "object",
										"properties": {
											"count": {
												"type": "integer",
												"description": "Integer parameter"
											},
											"flag": {
												"type": "boolean",
												"description": "Boolean parameter"
											}
										}
									}
								}
							}
						}
					]
				}`),
			},
			expectTools:  true,
			expectConfig: true,
			validate: func(t *testing.T, tools []*genai.Tool, config *genai.ToolConfig) {
				assert.Len(t, tools, 2)
				assert.Equal(t, "tool1", tools[0].FunctionDeclarations[0].Name)
				assert.Equal(t, "tool2", tools[1].FunctionDeclarations[0].Name)
				assert.NotNil(t, config)
			},
		},
		{
			name: "Tool with empty InputSchema should be skipped",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{
					"tools": [
						{
							"toolSpec": {
								"name": "empty_tool",
								"description": "Empty tool",
								"inputSchema": {}
							}
						},
						{
							"toolSpec": {
								"name": "valid_tool",
								"description": "Valid tool",
								"inputSchema": {
									"json": {
										"type": "object",
										"properties": {
											"param": {
												"type": "string"
											}
										}
									}
								}
							}
						}
					]
				}`),
			},
			expectTools:  true,
			expectConfig: true,
			validate: func(t *testing.T, tools []*genai.Tool, config *genai.ToolConfig) {
				// Should only have the valid tool
				assert.Len(t, tools, 1)
				assert.Equal(t, "valid_tool", tools[0].FunctionDeclarations[0].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools, config := convertToolConfig(tt.req)
			tt.validate(t, tools, config)
		})
	}
}

func TestConvertHistory(t *testing.T) {
	tests := []struct {
		name     string
		req      *model.ChatRequest
		validate func(t *testing.T, history []*genai.Content)
	}{
		{
			name: "empty messages array",
			req: &model.ChatRequest{
				Messages: []*model.Message{},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 0)
			},
		},
		{
			name: "single text message from user",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello, world!"},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 1)
				assert.Equal(t, genai.RoleUser, history[0].Role)
				assert.Len(t, history[0].Parts, 1)
				assert.Equal(t, "Hello, world!", history[0].Parts[0].Text)
			},
		},
		{
			name: "single text message from assistant",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello back!"},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 1)
				assert.Equal(t, genai.RoleModel, history[0].Role)
				assert.Len(t, history[0].Parts, 1)
				assert.Equal(t, "Hello back!", history[0].Parts[0].Text)
			},
		},
		{
			name: "message with empty text block",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: ""},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				// Empty text should not add a part, so no content added
				assert.Len(t, history, 0)
			},
		},
		{
			name: "message with tool_use block",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:  "tool_use",
								Id:    "tool-123",
								Name:  "search",
								Input: json.RawMessage(`{"query":"test"}`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 1)
				assert.Len(t, history[0].Parts, 1)
				assert.NotNil(t, history[0].Parts[0].FunctionCall)
				assert.Equal(t, "tool-123", history[0].Parts[0].FunctionCall.ID)
				assert.Equal(t, "search", history[0].Parts[0].FunctionCall.Name)
				assert.Equal(t, "test", history[0].Parts[0].FunctionCall.Args["query"])
			},
		},
		{
			name: "message with tool_use with invalid JSON",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:  "tool_use",
								Id:    "tool-123",
								Name:  "search",
								Input: json.RawMessage(`{invalid json`),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				// Invalid JSON should be skipped
				assert.Len(t, history, 0)
			},
		},
		{
			name: "message with tool_use having ThoughtSignature",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:             "tool_use",
								Id:               "tool-123",
								Name:             "search",
								Input:            json.RawMessage(`{}`),
								ThoughtSignature: []byte("signature-data"),
							},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 1)
				assert.Len(t, history[0].Parts, 1)
				assert.NotNil(t, history[0].Parts[0].ThoughtSignature)
				assert.Equal(t, []byte("signature-data"), history[0].Parts[0].ThoughtSignature)
			},
		},
		{
			name: "message with tool_result block",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "tool_result",
								ToolResult: &model.ToolResult{
									ToolUseId: "tool-123",
									Name:      "search",
									Content: []model.ToolResultContent{
										{Text: "Result text"},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 1)
				assert.Len(t, history[0].Parts, 1)
				assert.NotNil(t, history[0].Parts[0].FunctionResponse)
				assert.Equal(t, "tool-123", history[0].Parts[0].FunctionResponse.ID)
				assert.Equal(t, "search", history[0].Parts[0].FunctionResponse.Name)
			},
		},
		{
			name: "message with tool_result using prevToolName",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{
								Type:  "tool_use",
								Id:    "tool-123",
								Name:  "prev_tool",
								Input: json.RawMessage(`{}`),
							},
						},
					},
					{
						Id:   "msg-2",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{
								Type: "tool_result",
								ToolResult: &model.ToolResult{
									ToolUseId: "tool-123",
									// Name is empty, should use prevToolName
									Content: []model.ToolResultContent{
										{Text: "Result"},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 2)
				// Check second message uses prevToolName
				assert.NotNil(t, history[1].Parts[0].FunctionResponse)
				assert.Equal(t, "prev_tool", history[1].Parts[0].FunctionResponse.Name)
			},
		},
		{
			name: "message with multiple content blocks",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "First part"},
							{Type: "text", Text: "Second part"},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 1)
				assert.Len(t, history[0].Parts, 2)
				assert.Equal(t, "First part", history[0].Parts[0].Text)
				assert.Equal(t, "Second part", history[0].Parts[1].Text)
			},
		},
		{
			name: "mixed message sequence",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						Id:   "msg-1",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello"},
						},
					},
					{
						Id:   "msg-2",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hi there"},
						},
					},
					{
						Id:   "msg-3",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "How are you?"},
						},
					},
				},
			},
			validate: func(t *testing.T, history []*genai.Content) {
				assert.Len(t, history, 3)
				assert.Equal(t, genai.RoleUser, history[0].Role)
				assert.Equal(t, genai.RoleModel, history[1].Role)
				assert.Equal(t, genai.RoleUser, history[2].Role)
				assert.Equal(t, "Hello", history[0].Parts[0].Text)
				assert.Equal(t, "Hi there", history[1].Parts[0].Text)
				assert.Equal(t, "How are you?", history[2].Parts[0].Text)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			history := convertHistory(tt.req)
			tt.validate(t, history)
		})
	}
}

func TestBuildClientFromApiKey(t *testing.T) {
	t.Run("empty API key", func(t *testing.T) {
		ctx := context.Background()
		client, err := buildClientFromApiKey(ctx, "")

		// With empty API key, it should return an error
		assert.Error(t, err)
		assert.Nil(t, client)
	})

	t.Run("with API key - integration test", func(t *testing.T) {
		// This test requires a valid API key or will fail
		// In real scenarios, this would be skipped in CI or use a test key
		t.Skip("Skipping integration test - requires valid Gemini API key")

		ctx := context.Background()
		// This would require a real or test API key
		client, err := buildClientFromApiKey(ctx, "test-api-key")

		// Depending on whether the key is valid
		if err != nil {
			assert.Nil(t, client)
		} else {
			assert.NotNil(t, client)
		}
	})
}

func TestConvertPropertyToGemini(t *testing.T) {
	tests := []struct {
		name     string
		prop     *model.ToolSchemaProperty
		validate func(t *testing.T, schema *genai.Schema)
	}{
		{
			name: "simple string property",
			prop: &model.ToolSchemaProperty{
				Type:        "string",
				Description: "A simple string",
			},
			validate: func(t *testing.T, schema *genai.Schema) {
				assert.Equal(t, genai.TypeString, schema.Type)
				assert.Equal(t, "A simple string", schema.Description)
				assert.Nil(t, schema.Items)
				assert.Nil(t, schema.Properties)
			},
		},
		{
			name: "property with default value",
			prop: &model.ToolSchemaProperty{
				Type:        "integer",
				Description: "An integer with default",
				Default:     42,
			},
			validate: func(t *testing.T, schema *genai.Schema) {
				assert.Equal(t, genai.TypeInteger, schema.Type)
				assert.Equal(t, 42, schema.Default)
			},
		},
		{
			name: "array property with nested item schema",
			prop: &model.ToolSchemaProperty{
				Type:        "array",
				Description: "An array of strings",
				Items: map[string]model.ToolSchemaProperty{
					"": {
						Type:        "string",
						Description: "Array item",
					},
				},
			},
			validate: func(t *testing.T, schema *genai.Schema) {
				assert.Equal(t, genai.TypeArray, schema.Type)
				assert.Equal(t, "An array of strings", schema.Description)
				assert.NotNil(t, schema.Items)
				assert.Equal(t, genai.TypeString, schema.Items.Type)
				assert.Equal(t, "Array item", schema.Items.Description)
			},
		},
		{
			name: "object property with nested properties",
			prop: &model.ToolSchemaProperty{
				Type:        "object",
				Description: "An object with nested properties",
				Items: map[string]model.ToolSchemaProperty{
					"name": {
						Type:        "string",
						Description: "Name field",
					},
					"age": {
						Type:        "integer",
						Description: "Age field",
					},
				},
			},
			validate: func(t *testing.T, schema *genai.Schema) {
				assert.Equal(t, genai.TypeObject, schema.Type)
				assert.Equal(t, "An object with nested properties", schema.Description)
				assert.NotNil(t, schema.Properties)
				assert.Len(t, schema.Properties, 2)

				assert.NotNil(t, schema.Properties["name"])
				assert.Equal(t, genai.TypeString, schema.Properties["name"].Type)
				assert.Equal(t, "Name field", schema.Properties["name"].Description)

				assert.NotNil(t, schema.Properties["age"])
				assert.Equal(t, genai.TypeInteger, schema.Properties["age"].Type)
				assert.Equal(t, "Age field", schema.Properties["age"].Description)
			},
		},
		{
			name: "deeply nested recursive structure",
			prop: &model.ToolSchemaProperty{
				Type:        "object",
				Description: "Top level object",
				Items: map[string]model.ToolSchemaProperty{
					"users": {
						Type:        "array",
						Description: "List of users",
						Items: map[string]model.ToolSchemaProperty{
							"": {
								Type:        "object",
								Description: "User object",
								Items: map[string]model.ToolSchemaProperty{
									"id": {
										Type:        "integer",
										Description: "User ID",
									},
									"profile": {
										Type:        "object",
										Description: "User profile",
										Items: map[string]model.ToolSchemaProperty{
											"displayName": {
												Type:        "string",
												Description: "Display name",
											},
											"verified": {
												Type:        "boolean",
												Description: "Verification status",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, schema *genai.Schema) {
				// Top level is object
				assert.Equal(t, genai.TypeObject, schema.Type)
				assert.NotNil(t, schema.Properties)

				// Has "users" property which is an array
				assert.NotNil(t, schema.Properties["users"])
				usersArray := schema.Properties["users"]
				assert.Equal(t, genai.TypeArray, usersArray.Type)
				assert.Equal(t, "List of users", usersArray.Description)

				// Array items are objects
				assert.NotNil(t, usersArray.Items)
				userObject := usersArray.Items
				assert.Equal(t, genai.TypeObject, userObject.Type)
				assert.Equal(t, "User object", userObject.Description)

				// User object has properties
				assert.NotNil(t, userObject.Properties)
				assert.Len(t, userObject.Properties, 2)

				// Check "id" field
				assert.NotNil(t, userObject.Properties["id"])
				assert.Equal(t, genai.TypeInteger, userObject.Properties["id"].Type)
				assert.Equal(t, "User ID", userObject.Properties["id"].Description)

				// Check nested "profile" object
				assert.NotNil(t, userObject.Properties["profile"])
				profileObject := userObject.Properties["profile"]
				assert.Equal(t, genai.TypeObject, profileObject.Type)
				assert.Equal(t, "User profile", profileObject.Description)

				// Profile object has nested properties
				assert.NotNil(t, profileObject.Properties)
				assert.Len(t, profileObject.Properties, 2)

				assert.NotNil(t, profileObject.Properties["displayName"])
				assert.Equal(t, genai.TypeString, profileObject.Properties["displayName"].Type)
				assert.Equal(t, "Display name", profileObject.Properties["displayName"].Description)

				assert.NotNil(t, profileObject.Properties["verified"])
				assert.Equal(t, genai.TypeBoolean, profileObject.Properties["verified"].Type)
				assert.Equal(t, "Verification status", profileObject.Properties["verified"].Description)
			},
		},
		{
			name: "array of arrays (nested arrays)",
			prop: &model.ToolSchemaProperty{
				Type:        "array",
				Description: "Matrix (array of arrays)",
				Items: map[string]model.ToolSchemaProperty{
					"": {
						Type:        "array",
						Description: "Inner array",
						Items: map[string]model.ToolSchemaProperty{
							"": {
								Type:        "number",
								Description: "Matrix element",
							},
						},
					},
				},
			},
			validate: func(t *testing.T, schema *genai.Schema) {
				assert.Equal(t, genai.TypeArray, schema.Type)
				assert.Equal(t, "Matrix (array of arrays)", schema.Description)

				// Check inner array
				assert.NotNil(t, schema.Items)
				innerArray := schema.Items
				assert.Equal(t, genai.TypeArray, innerArray.Type)
				assert.Equal(t, "Inner array", innerArray.Description)

				// Check innermost element
				assert.NotNil(t, innerArray.Items)
				assert.Equal(t, genai.TypeNumber, innerArray.Items.Type)
				assert.Equal(t, "Matrix element", innerArray.Items.Description)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema := convertPropertyToGemini(tt.prop)
			tt.validate(t, schema)
		})
	}
}
