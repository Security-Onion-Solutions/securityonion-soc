// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	detectionsmock "github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNewAssistantCoordinator(t *testing.T) {
	srv := &server.Server{}

	coord := NewAssistantCoordinator(srv)

	assert.NotNil(t, coord)
	assert.Equal(t, srv, coord.srv)
	assert.NotNil(t, coord.IOManager)
}

func TestAssistantCoordinator_PrerequisiteModules(t *testing.T) {
	ac := &AssistantCoordinator{}

	modules := ac.PrerequisiteModules()

	assert.Nil(t, modules)
}

func TestAssistantCoordinator_StartStopIsRunning(t *testing.T) {
	ac := &AssistantCoordinator{}

	// Initially should not be running
	assert.False(t, ac.IsRunning())

	// Start
	err := ac.Start()
	assert.NoError(t, err)
	assert.True(t, ac.IsRunning())

	// Stop
	err = ac.Stop()
	assert.NoError(t, err)
	assert.False(t, ac.IsRunning())
}

func TestBuildToolConfig(t *testing.T) {
	testCases := []struct {
		name            string
		functions       map[string]Tool
		delegates       map[string]Tool
		toolFilter      []string
		delegateFilter  []string
		expectError     bool
		expectNilConfig bool
		expectedLength  int
	}{
		{
			name:            "empty functions map",
			functions:       map[string]Tool{},
			expectError:     false,
			expectNilConfig: true,
		},
		{
			name: "single function",
			functions: map[string]Tool{
				"test_tool": &mockTool{
					name:        "test_tool",
					description: "Test tool description",
					schema: model.JSONSchema{
						Json: &model.ToolSchema{
							Type: "object",
							Properties: map[string]model.ToolSchemaProperty{
								"param1": {Type: "string", Description: "Test parameter"},
							},
						},
					},
				},
			},
			expectError:    false,
			expectedLength: 1,
		},
		{
			name: "multiple functions",
			functions: map[string]Tool{
				"tool_b": &mockTool{name: "tool_b", description: "Tool B"},
				"tool_a": &mockTool{name: "tool_a", description: "Tool A"},
				"tool_c": &mockTool{name: "tool_c", description: "Tool C"},
			},
			expectError:    false,
			expectedLength: 3,
		},
		{
			name: "functions and delegates combined",
			functions: map[string]Tool{
				"tool_a": &mockTool{name: "tool_a", description: "Tool A"},
			},
			delegates: map[string]Tool{
				"delegate_to_Hunter": &mockTool{name: "delegate_to_Hunter", description: "Hunter agent"},
			},
			expectError:    false,
			expectedLength: 2, // one function + one delegate
		},
		{
			name: "tool and delegate filters restrict the included tools",
			functions: map[string]Tool{
				"tool_a": &mockTool{name: "tool_a", description: "Tool A"},
				"tool_b": &mockTool{name: "tool_b", description: "Tool B"},
			},
			delegates: map[string]Tool{
				"delegate_to_Hunter":  &mockTool{name: "delegate_to_Hunter", description: "Hunter agent"},
				"delegate_to_Auditor": &mockTool{name: "delegate_to_Auditor", description: "Auditor agent"},
			},
			toolFilter:     []string{"tool_a"},
			delegateFilter: []string{"delegate_to_Hunter"},
			expectError:    false,
			expectedLength: 2, // only tool_a + delegate_to_Hunter survive the filters
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := buildToolConfig(tc.functions, tc.delegates, tc.toolFilter, tc.delegateFilter)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, config)
			} else if tc.expectNilConfig {
				assert.NoError(t, err)
				assert.Nil(t, config)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)

				// Verify the config can be parsed
				var toolConfig model.ToolConfig
				err = json.Unmarshal(config, &toolConfig)
				assert.NoError(t, err)
				assert.Len(t, toolConfig.Tools, tc.expectedLength)

				// Verify tool choice structure
				assert.Contains(t, toolConfig.ToolChoice, "auto")

				// Verify tools are sorted alphabetically (if multiple). Functions and
				// delegates are each sorted independently and appended in that order, so
				// only assert a global ordering when there are no delegates mixed in.
				if tc.expectedLength > 1 && tc.delegates == nil {
					for i := 1; i < len(toolConfig.Tools); i++ {
						assert.True(t, toolConfig.Tools[i-1].Spec.Name <= toolConfig.Tools[i].Spec.Name,
							"Tools should be sorted alphabetically")
					}
				}
			}
		})
	}
}

func TestAssistantCoordinator_ExecuteTool(t *testing.T) {
	testCases := []struct {
		name           string
		toolName       string
		params         string
		executeFunc    func(ctx context.Context, srv *server.Server, req *model.ToolRequest) (*model.ToolResponse, error)
		expectedResult *model.ToolResponse
		expectedError  error
	}{
		{
			name:     "successful tool execution",
			toolName: "test_tool",
			params:   `{"param1": "value1"}`,
			executeFunc: func(ctx context.Context, srv *server.Server, req *model.ToolRequest) (*model.ToolResponse, error) {
				return &model.ToolResponse{
					ToolName:       "test_tool",
					OnBehalfOfUser: "test-user",
					Result:         "success",
				}, nil
			},
			expectedResult: &model.ToolResponse{
				ToolName:       "test_tool",
				OnBehalfOfUser: "test-user",
				Result:         "success",
			},
			expectedError: nil,
		},
		{
			name:           "tool not found",
			toolName:       "nonexistent_tool",
			params:         `{}`,
			executeFunc:    nil,
			expectedResult: nil,
			expectedError:  ErrToolNotFound,
		},
		{
			name:     "tool execution error",
			toolName: "failing_tool",
			params:   `{"param1": "value1"}`,
			executeFunc: func(ctx context.Context, srv *server.Server, req *model.ToolRequest) (*model.ToolResponse, error) {
				return nil, errors.New("tool execution failed")
			},
			expectedResult: nil,
			expectedError:  errors.New("tool execution failed"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTool := &mockTool{
				name:        tc.toolName,
				executeFunc: tc.executeFunc,
			}

			srv := &server.Server{}
			ac := &AssistantCoordinator{
				srv: srv,
				FunctionLibrary: map[string]Tool{
					"test_tool":    mockTool,
					"failing_tool": mockTool,
				},
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			result, err := ac.ExecuteTool(ctx, tc.toolName, &model.ToolRequest{Params: json.RawMessage(tc.params)})

			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedError.Error(), err.Error())
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func TestAssistantCoordinator_Balance(t *testing.T) {
	testCases := []struct {
		name           string
		apiUrl         string
		setupMocks     func(*detectionsmock.MockIOManager)
		expectedResult *model.BalanceResponse
		expectedError  bool
	}{
		{
			name:   "successful balance request",
			apiUrl: "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager) {
				responseBody := `{"credit_balance": 100, "api_key": "key", "api_key_prefix": "id", "company_id": "company", "status": "status"}`
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(responseBody)),
				}, nil)
			},
			expectedResult: &model.BalanceResponse{
				Balance:   100,
				KeyId:     "id",
				CompanyId: "company",
				Status:    "status",
			},
			expectedError: false,
		},
		{
			name:   "HTTP request error",
			apiUrl: "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(nil, errors.New("network error"))
			},
			expectedResult: nil,
			expectedError:  true,
		},
		{
			name:           "invalid URL",
			apiUrl:         "://invalid-url",
			setupMocks:     func(mockIO *detectionsmock.MockIOManager) {},
			expectedResult: nil,
			expectedError:  true,
		},
		{
			name:   "invalid JSON response",
			apiUrl: "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager) {
				responseBody := `invalid json`
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(responseBody)),
				}, nil)
			},
			expectedResult: nil,
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			tc.setupMocks(mockIO)

			srv := &server.Server{
				Host: &web.Host{Version: "1.0.0"},
				Config: &config.ServerConfig{
					ClientParams: model.ClientParameters{
						AssistantParams: model.AssistantParameters{
							AvailableModels: []model.ModelParameters{
								{
									ID:      "model",
									Adapter: "SOAI",
								},
							},
						},
					},
				},
			}

			ac := &AssistantCoordinator{
				IOManager: mockIO,
				srv:       srv,
				adapters: map[string]server.AssistantAdapter{
					"SOAI": &SOAiCloudAdapter{
						apiUrl:    tc.apiUrl,
						srv:       srv,
						IOManager: mockIO,
					},
				},
			}

			ctx := context.Background()

			result, err := ac.Balance(ctx, "model@SOAI")

			if tc.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func TestSOAiCloudAdapter_Embed(t *testing.T) {
	testCases := []struct {
		name           string
		apiUrl         string
		setupMocks     func(*testing.T, *detectionsmock.MockIOManager)
		expectedResult *model.EmbeddingResponse
		expectedError  bool
	}{
		{
			name:   "successful embed request",
			apiUrl: "https://api.example.com",
			setupMocks: func(t *testing.T, mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).DoAndReturn(func(req *http.Request, _ bool) (*http.Response, error) {
					assert.Equal(t, "/api/embed", req.URL.Path)
					assert.Equal(t, http.MethodPost, req.Method)

					body, err := io.ReadAll(req.Body)
					assert.NoError(t, err)
					er := &model.EmbeddingRequest{}
					assert.NoError(t, json.Unmarshal(body, er))
					assert.Equal(t, "embed-model", er.Model)
					assert.Equal(t, []string{"first input", "second input"}, er.Input)

					return &http.Response{
						StatusCode: 200,
						Body: io.NopCloser(strings.NewReader(
							`{"model":"embed-model","embeddings":[[0.1,0.2],[0.3,0.4]],"usage":{"input_tokens":7}}`)),
					}, nil
				})
			},
			expectedResult: &model.EmbeddingResponse{
				Model:      "embed-model",
				Embeddings: [][]float32{{0.1, 0.2}, {0.3, 0.4}},
				Usage:      &model.Usage{InputTokens: 7},
			},
			expectedError: false,
		},
		{
			name:   "HTTP request error",
			apiUrl: "https://api.example.com",
			setupMocks: func(t *testing.T, mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(nil, errors.New("network error"))
			},
			expectedResult: nil,
			expectedError:  true,
		},
		{
			name:           "invalid URL",
			apiUrl:         "://invalid-url",
			setupMocks:     func(t *testing.T, mockIO *detectionsmock.MockIOManager) {},
			expectedResult: nil,
			expectedError:  true,
		},
		{
			name:   "invalid JSON response",
			apiUrl: "https://api.example.com",
			setupMocks: func(t *testing.T, mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`invalid json`)),
				}, nil)
			},
			expectedResult: nil,
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			tc.setupMocks(t, mockIO)

			adapter := &SOAiCloudAdapter{
				apiUrl:    tc.apiUrl,
				srv:       &server.Server{Host: &web.Host{Version: "1.0.0"}},
				IOManager: mockIO,
			}

			result, err := adapter.Embed(context.Background(), &model.EmbeddingRequest{
				Model: "embed-model",
				Input: []string{"first input", "second input"},
			})

			if tc.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func TestAssistantCoordinator_Send(t *testing.T) {
	testCases := []struct {
		name                  string
		messages              []*model.Message
		chatOpts              []model.ChatOpt
		apiUrl                string
		setupMocks            func(*detectionsmock.MockIOManager, *servermock.MockAssistantstore)
		expectedMessagesCount int
		expectedError         bool
	}{
		{
			name: "successful chat without tool execution",
			messages: []*model.Message{
				{
					Id:   "msg1",
					Role: "user",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hello"},
					},
				},
			},
			chatOpts: []model.ChatOpt{},
			apiUrl:   "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager, mockAssistantstore *servermock.MockAssistantstore) {
				responseBody := `{"id": "resp1", "role": "assistant", "content": [{"type": "text", "text": "Hello back!"}]}`
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(responseBody)),
				}, nil)
			},
			expectedMessagesCount: 1,
			expectedError:         false,
		},
		{
			name: "successful chat with tool execution",
			messages: []*model.Message{
				{
					Id:   "msg1",
					Role: "user",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Execute a tool"},
					},
				},
			},
			chatOpts: []model.ChatOpt{model.WithAutoExecuteTools(true)},
			apiUrl:   "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager, mockAssistantstore *servermock.MockAssistantstore) {
				// First response with tool use
				responseBody := `{
					"id": "resp1", 
					"role": "assistant", 
					"content": [
						{
							"type": "tool_use", 
							"id": "tool1", 
							"name": "test_tool",
							"input": "{\"param1\": \"value1\"}"
						}
					]
				}`
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(responseBody)),
				}, nil)

				// Second response after tool execution
				secondResponseBody := `{"id": "resp2", "role": "assistant", "content": [{"type": "text", "text": "Tool executed successfully"}]}`
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(secondResponseBody)),
				}, nil)
			},
			expectedMessagesCount: 3, // Original response + tool result message + follow-up response
			expectedError:         false,
		},
		{
			name: "HTTP request error",
			messages: []*model.Message{
				{Id: "msg1", Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}}},
			},
			chatOpts: []model.ChatOpt{},
			apiUrl:   "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager, mockAssistantstore *servermock.MockAssistantstore) {
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(nil, errors.New("network error"))
			},
			expectedMessagesCount: 0,
			expectedError:         true,
		},
		{
			name: "invalid URL",
			messages: []*model.Message{
				{Id: "msg1", Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}}},
			},
			chatOpts:              []model.ChatOpt{},
			apiUrl:                "://invalid-url",
			setupMocks:            func(mockIO *detectionsmock.MockIOManager, mockAssistantstore *servermock.MockAssistantstore) {},
			expectedMessagesCount: 0,
			expectedError:         true,
		},
		{
			name: "invalid JSON response",
			messages: []*model.Message{
				{Id: "msg1", Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}}},
			},
			chatOpts: []model.ChatOpt{},
			apiUrl:   "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager, mockAssistantstore *servermock.MockAssistantstore) {
				responseBody := `invalid json`
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(responseBody)),
				}, nil)
			},
			expectedMessagesCount: 0,
			expectedError:         true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			tc.setupMocks(mockIO, mockAssistantstore)

			// Setup tool mock for auto-execute cases
			var testTool Tool
			if len(tc.chatOpts) > 0 {
				testTool = &mockTool{
					name: "test_tool",
					executeFunc: func(ctx context.Context, srv *server.Server, req *model.ToolRequest) (*model.ToolResponse, error) {
						return &model.ToolResponse{
							ToolName:       "test_tool",
							OnBehalfOfUser: "test-user",
							Result:         "tool result",
						}, nil
					},
				}
			} else {
				testTool = &mockTool{name: "test_tool"}
			}

			srv := &server.Server{
				Assistantstore: mockAssistantstore,
				Host:           &web.Host{Version: "1.0.0"},
				Config: &config.ServerConfig{
					ClientParams: model.ClientParameters{
						AssistantParams: model.AssistantParameters{
							AvailableModels: []model.ModelParameters{
								{ID: "test-model", Adapter: "MyAdapter"},
							},
						},
					},
				},
			}

			ac := &AssistantCoordinator{
				srv:       srv,
				IOManager: mockIO,
				FunctionLibrary: map[string]Tool{
					"test_tool": testTool,
				},
				adapters: map[string]server.AssistantAdapter{
					"MyAdapter": &SOAiCloudAdapter{
						apiUrl:    tc.apiUrl,
						srv:       srv,
						IOManager: mockIO,
					},
				},
				toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			result, err := ac.Send(ctx, "test-model@MyAdapter", tc.messages, tc.chatOpts...)

			if tc.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, tc.expectedMessagesCount)
			}
		})
	}
}

// A model that is not present in AvailableModels is a bad request, not a silent
// fallback: Send must return ErrInvalidModel without contacting any adapter.
func TestAssistantCoordinator_Send_InvalidModel(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)

	srv := &server.Server{
		Host: &web.Host{Version: "1.0.0"},
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: []model.ModelParameters{
						{ID: "test-model", Adapter: "MyAdapter"},
					},
				},
			},
		},
	}

	ac := &AssistantCoordinator{
		srv:       srv,
		IOManager: mockIO,
		adapters: map[string]server.AssistantAdapter{
			"MyAdapter": &SOAiCloudAdapter{apiUrl: "https://api.example.com", srv: srv, IOManager: mockIO},
		},
		toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// "other-model" has a registered adapter but no AvailableModels entry.
	result, err := ac.Send(ctx, "other-model@MyAdapter", []*model.Message{
		{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}},
	})

	assert.ErrorIs(t, err, ErrInvalidModel)
	assert.Nil(t, result)
}

func TestAssistantCoordinator_SendStream(t *testing.T) {
	testCases := []struct {
		name        string
		messages    []*model.Message
		apiUrl      string
		setupMocks  func(*detectionsmock.MockIOManager)
		expectError bool
	}{
		{
			name: "successful chat stream",
			messages: []*model.Message{
				{
					Id:   "msg1",
					Role: "user",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hello"},
					},
				},
			},
			apiUrl: "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).DoAndReturn(func(req *http.Request, stream bool) (*http.Response, error) {
					outgoingBody, err := io.ReadAll(req.Body)
					assert.NoError(t, err)

					cr := &model.ChatRequest{}

					err = json.Unmarshal(outgoingBody, cr)
					assert.NoError(t, err)

					assert.Len(t, cr.Messages, 1)
					assert.True(t, cr.Stream)
					assert.NotEmpty(t, cr.ToolConfig)
					assert.Equal(t, "test-user", cr.UserId)

					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(strings.NewReader("data: streaming response")),
					}, nil
				})
			},
			expectError: false,
		},
		{
			name: "HTTP request error",
			messages: []*model.Message{
				{Id: "msg1", Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}}},
			},
			apiUrl: "https://api.example.com",
			setupMocks: func(mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(nil, errors.New("network error"))
			},
			expectError: true,
		},
		{
			name: "invalid URL",
			messages: []*model.Message{
				{Id: "msg1", Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "Hello"}}},
			},
			apiUrl:      "://invalid-url",
			setupMocks:  func(mockIO *detectionsmock.MockIOManager) {},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			tc.setupMocks(mockIO)

			srv := &server.Server{
				Host: &web.Host{Version: "1.0.0"},
				Config: &config.ServerConfig{
					ClientParams: model.ClientParameters{
						AssistantParams: model.AssistantParameters{
							AvailableModels: []model.ModelParameters{
								{ID: "test-model", Adapter: "whatever"},
							},
						},
					},
				},
			}

			ac := &AssistantCoordinator{
				IOManager:  mockIO,
				toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
				srv:        srv,
				adapters: map[string]server.AssistantAdapter{
					"whatever": &SOAiCloudAdapter{
						apiUrl:    tc.apiUrl,
						srv:       srv,
						IOManager: mockIO,
					},
				},
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			result, aux, err := ac.SendStream(ctx, "test-model@whatever", tc.messages)

			assert.Nil(t, aux)
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				// Don't forget to close the response body in real usage
				result.Body.Close()
			}
		})
	}
}

// storedToolUseTurn returns a persisted assistant turn carrying tool_use blocks with
// the given ids -- the turn a tool_result answers. A tool_result continuation
// requires this turn in history before it dispatches (see awaitToolUseTurn).
func storedToolUseTurn(toolUseIds ...string) *model.StoredMessage {
	return storedNamedToolUseTurn("query_events", nil, toolUseIds...)
}

// storedNamedToolUseTurn is storedToolUseTurn for a specific tool name and input,
// for tests whose requests must match the seeded tool_use under validateToolRequest
// (same name, semantically equal params).
func storedNamedToolUseTurn(name string, input json.RawMessage, toolUseIds ...string) *model.StoredMessage {
	blocks := make([]model.ContentBlock, 0, len(toolUseIds))
	for _, id := range toolUseIds {
		blocks = append(blocks, model.ContentBlock{Type: "tool_use", Id: id, Name: name, Input: input})
	}
	return &model.StoredMessage{Message: &model.Message{Role: "assistant", ContentBlocks: blocks}}
}

func newChatInSessionCoordinator(t *testing.T, mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager, apiUrl string) *AssistantCoordinator {
	t.Helper()

	// The continuation paths load the session record once per turn via
	// loadTurnSession(). Default to a bare record with no stored model so these
	// existing tests fall back to the request/parent model exactly as before;
	// tests that exercise the stored-model behavior build their own coordinator
	// with a specific return.
	mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return(
		[]*model.AssistantSession{{SessionId: "default-session"}}, nil).AnyTimes()

	srv := &server.Server{
		Assistantstore: mockAssistantstore,
		Host:           &web.Host{Version: "1.0.0"},
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: []model.ModelParameters{
						{ID: "test-model", Adapter: "MyAdapter"},
					},
				},
			},
		},
	}

	return &AssistantCoordinator{
		srv:       srv,
		IOManager: mockIO,
		adapters: map[string]server.AssistantAdapter{
			"MyAdapter": &SOAiCloudAdapter{
				apiUrl:    apiUrl,
				srv:       srv,
				IOManager: mockIO,
			},
		},
		toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
		// Real polling attempts, but zero delay: tests supply complete history, so
		// the few persist-only cases (no tool_use turn present) mustn't sleep.
		toolUseTurnAttempts: DEFAULT_TOOL_USE_TURN_ATTEMPTS,
	}
}

// assistantOkTextResponse returns a canned 200 assistant response whose single
// content block carries the given text.
func assistantOkTextResponse(text string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Body: io.NopCloser(strings.NewReader(
			`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"` + text + `"}]}`)),
	}
}

func TestAssistantCoordinator_ChatInSession(t *testing.T) {
	const sessionId = "session-1"

	tests := []struct {
		name         string
		history      []*model.StoredMessage
		historyErr   error
		msg          string
		chatType     string
		entityId     string
		wantTitle    string
		wantType     string
		wantEntityId string
	}{
		{
			name:      "empty history creates a new session",
			history:   []*model.StoredMessage{},
			msg:       "hello",
			wantTitle: "hello",
		},
		{
			name:         "entity fields populate the new session",
			history:      []*model.StoredMessage{},
			msg:          "investigate",
			chatType:     "alert_investigation",
			entityId:     "alert-42",
			wantTitle:    "investigate",
			wantType:     "alert_investigation",
			wantEntityId: "alert-42",
		},
		{
			name:       "history not-found is tolerated",
			historyErr: errors.New("session not found"),
			msg:        "hi",
			wantTitle:  "hi",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(tc.history, tc.historyErr)
			mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, session *model.AssistantSession) error {
					assert.Equal(t, sessionId, session.SessionId)
					assert.Equal(t, tc.wantTitle, session.Title)
					assert.Equal(t, tc.wantType, session.Type)
					assert.Equal(t, tc.wantEntityId, session.EntityId)
					return nil
				})

			mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(assistantOkTextResponse("hi"), nil)
			mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

			ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			_, err := ac.ChatInSession(ctx, &model.IncomingMessage{
				Msg:       tc.msg,
				SessionId: sessionId,
				Model:     "test-model@MyAdapter",
			}, tc.chatType, tc.entityId)
			assert.NoError(t, err)
		})
	}
}

func TestAssistantCoordinator_ChatInSession_ExistingHistoryPersistsMessages(t *testing.T) {
	const sessionId = "session-1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	history := []*model.StoredMessage{
		{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
		{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier reply"}}}},
	}
	mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(history, nil)

	mockIO.EXPECT().MakeRequest(gomock.Any(), false).DoAndReturn(func(req *http.Request, _ bool) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		assert.NoError(t, err)
		cr := &model.ChatRequest{}
		assert.NoError(t, json.Unmarshal(body, cr))
		assert.Len(t, cr.Messages, 3) // 2 history + 1 new
		assert.Equal(t, "follow-up", cr.Messages[2].ContentBlocks[0].Text)

		return assistantOkTextResponse("ok"), nil
	})

	// One save for the user message, one for the assistant response.
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	incMsg := &model.IncomingMessage{
		Msg:       "follow-up",
		SessionId: sessionId,
		Model:     "test-model@MyAdapter",
	}

	response, err := ac.ChatInSession(ctx, incMsg, "", "")
	assert.NoError(t, err)
	assert.Len(t, response, 1)
	assert.Equal(t, "ok", response[0].ContentBlocks[0].Text)
}

func TestAssistantCoordinator_ChatInSession_UpstreamErrorPropagates(t *testing.T) {
	const sessionId = "session-1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
	mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(nil, errors.New("network error"))

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	_, err := ac.ChatInSession(ctx, &model.IncomingMessage{
		Msg:       "hi",
		SessionId: sessionId,
		Model:     "test-model@MyAdapter",
	}, "", "")
	assert.Error(t, err)
}

func TestAssistantCoordinator_ChatStreamInSession_FinalizeSavesResponse(t *testing.T) {
	const sessionId = "session-stream-1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
	mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
	// User message is saved before the stream begins.
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, sessionId, stored.SessionId)
			assert.Equal(t, "user", stored.Message.Role)
			return nil
		})

	mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("data: stream")),
	}, nil)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	stream, _, finalize, err := ac.ChatStreamInSession(ctx, &model.IncomingMessage{
		Msg:       "stream me",
		SessionId: sessionId,
		Model:     "test-model@MyAdapter",
	}, "", "")
	assert.NoError(t, err)
	assert.NotNil(t, stream)
	assert.NotNil(t, finalize)
	stream.Body.Close()

	// Now exercise the finalize callback with a synthetic raw SSE blob; the
	// coordinator should parse the assistant message and persist it.
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, sessionId, stored.SessionId)
			assert.Equal(t, "assistant", stored.Message.Role)
			return nil
		})

	raw := `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[]}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}

data: {"type":"content_block_stop","index":0}

data: [DONE]`

	assert.NoError(t, finalize([]byte(raw)))
}

// assistantToolTestRequest is the canonical query_events ToolRequest used by
// the ToolInSession tests.
func assistantToolTestRequest(sessionId string) *model.ToolRequest {
	return &model.ToolRequest{
		SessionId: sessionId,
		ToolUseId: "tool-use-1",
		Params:    json.RawMessage(`{"q":"x"}`),
		Model:     "test-model@MyAdapter",
	}
}

// newToolTestCoordinator wires a chat-in-session coordinator with a
// query_events mock tool that returns the given result/err.
func newToolTestCoordinator(t *testing.T, mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager, execResult *model.ToolResponse, execErr error) *AssistantCoordinator {
	t.Helper()

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ac.FunctionLibrary = map[string]Tool{
		"query_events": &mockTool{
			name: "query_events",
			executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return execResult, execErr
			},
		},
	}
	return ac
}

func TestAssistantCoordinator_ToolInSession(t *testing.T) {
	const sessionId = "session-tool-1"

	tests := []struct {
		name       string
		execResult *model.ToolResponse
		execErr    error
		sendText   string // upstream assistant reply; ignored when sendErr is set
		sendErr    error
		checkChat  func(t *testing.T, cr *model.ChatRequest)
		checkSaves func(t *testing.T, mockAssistantstore *servermock.MockAssistantstore)
		wantErr    bool
		wantText   string
	}{
		{
			name:       "successful tool execution feeds back into Send and persists both messages",
			execResult: &model.ToolResponse{ToolName: "query_events", Result: "ok"},
			sendText:   "done",
			checkChat: func(t *testing.T, cr *model.ChatRequest) {
				// The requesting tool_use turn and its tool_result answer are sent together.
				assert.Len(t, cr.Messages, 2)
				tr := cr.Messages[len(cr.Messages)-1]
				assert.NotNil(t, tr.ContentBlocks[0].ToolResult)
				assert.Equal(t, "tool-use-1", tr.ContentBlocks[0].ToolResult.ToolUseId)
				assert.False(t, tr.ContentBlocks[0].ToolResult.IsError)
			},
			checkSaves: func(t *testing.T, mockAssistantstore *servermock.MockAssistantstore) {
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, stored *model.StoredMessage) error {
						assert.Equal(t, sessionId, stored.SessionId)
						assert.Equal(t, []string{"tool_result"}, stored.Tags)
						assert.NotNil(t, stored.Message.ContentBlocks[0].ToolResult)
						return nil
					})
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, stored *model.StoredMessage) error {
						assert.Equal(t, sessionId, stored.SessionId)
						assert.Nil(t, stored.Tags)
						assert.Equal(t, "assistant", stored.Message.Role)
						return nil
					})
			},
			wantText: "done",
		},
		{
			name:     "tool execution error wraps as error tool_result and chat still proceeds",
			execErr:  errors.New("boom"),
			sendText: "sorry",
			checkChat: func(t *testing.T, cr *model.ChatRequest) {
				tr := cr.Messages[len(cr.Messages)-1]
				assert.True(t, tr.ContentBlocks[0].ToolResult.IsError)
				assert.Equal(t, "error", tr.ContentBlocks[0].ToolResult.Status)
				assert.Equal(t, "boom", tr.ContentBlocks[0].ToolResult.Content[0].Text)
			},
			checkSaves: func(t *testing.T, mockAssistantstore *servermock.MockAssistantstore) {
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)
			},
		},
		{
			name:       "upstream Send error propagates",
			execResult: &model.ToolResponse{ToolName: "query_events", Result: "ok"},
			sendErr:    errors.New("network error"),
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			// Loaded once by validateToolRequest; the continuation reuses the validated history.
			mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
				storedNamedToolUseTurn("query_events", json.RawMessage(`{"q":"x"}`), "tool-use-1"),
			}, nil)

			if tc.sendErr != nil {
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(nil, tc.sendErr)
			} else {
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).DoAndReturn(func(req *http.Request, _ bool) (*http.Response, error) {
					body, err := io.ReadAll(req.Body)
					assert.NoError(t, err)
					cr := &model.ChatRequest{}
					assert.NoError(t, json.Unmarshal(body, cr))
					if tc.checkChat != nil {
						tc.checkChat(t, cr)
					}
					return assistantOkTextResponse(tc.sendText), nil
				})
			}
			if tc.checkSaves != nil {
				tc.checkSaves(t, mockAssistantstore)
			}

			ac := newToolTestCoordinator(t, mockAssistantstore, mockIO, tc.execResult, tc.execErr)
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			resp, err := ac.ToolInSession(ctx, assistantToolTestRequest(sessionId), "query_events")
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Len(t, resp, 1)
			if tc.wantText != "" {
				assert.Equal(t, tc.wantText, resp[0].ContentBlocks[0].Text)
			}
		})
	}
}

func TestAssistantCoordinator_ToolStreamInSession_FinalizeSavesResponse(t *testing.T) {
	const sessionId = "session-tool-stream-1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
		storedNamedToolUseTurn("query_events", json.RawMessage(`{"q":"x"}`), "tool-use-1"),
	}, nil)
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, sessionId, stored.SessionId)
			assert.Equal(t, []string{"tool_result"}, stored.Tags)
			assert.NotNil(t, stored.Message.ContentBlocks[0].ToolResult)
			return nil
		})

	mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("data: stream")),
	}, nil)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ac.FunctionLibrary = map[string]Tool{
		"query_events": &mockTool{
			name: "query_events",
			executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
			},
		},
	}
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
		SessionId: sessionId,
		ToolUseId: "tool-use-1",
		Params:    json.RawMessage(`{"q":"x"}`),
		Model:     "test-model@MyAdapter",
	}, "query_events")
	assert.NoError(t, err)
	assert.NotNil(t, turn)
	assert.NotNil(t, turn.Response)
	assert.NotNil(t, turn.Finalize)
	assert.Equal(t, sessionId, turn.SessionId)
	assert.Nil(t, turn.Marker)
	// The direct-execution path surfaces the tool result so the handler can stream it
	// to the UI inline (no session re-fetch).
	if assert.NotNil(t, turn.ToolResult) {
		assert.Equal(t, "tool-use-1", turn.ToolResult.ToolUseId)
		assert.False(t, turn.ToolResult.IsError)
		if assert.NotEmpty(t, turn.ToolResult.Content) {
			assert.Equal(t, map[string]any{"result": "ok"}, turn.ToolResult.Content[0].Json)
		}
	}
	stream := turn.Response
	finalize := turn.Finalize
	stream.Body.Close()

	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, sessionId, stored.SessionId)
			assert.Equal(t, "assistant", stored.Message.Role)
			return nil
		})

	raw := `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[]}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}

data: {"type":"content_block_stop","index":0}

data: [DONE]`

	assert.NoError(t, finalize([]byte(raw)))
}

// A rejected tool is not executed: the backend records an error tool_result flagged
// "rejected" so the turn resolves and the assistant resumes.
func TestAssistantCoordinator_ToolStreamInSession_RejectedTool(t *testing.T) {
	const sessionId = "session-reject"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{storedToolUseTurn("tool-use-1")}, nil)
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, []string{"tool_result"}, stored.Tags)
			tr := stored.Message.ContentBlocks[0].ToolResult
			if assert.NotNil(t, tr) {
				assert.Equal(t, "tool-use-1", tr.ToolUseId)
				assert.Equal(t, "rejected", tr.Status)
				assert.True(t, tr.IsError)
			}
			return nil
		})
	mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
		StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: stream")),
	}, nil)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	// Executing this tool would fail the test -- a rejected tool must never run.
	ac.FunctionLibrary = map[string]Tool{
		"query_events": &mockTool{
			name: "query_events",
			executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				t.Error("rejected tool must not be executed")
				return nil, nil
			},
		},
	}
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
		SessionId: sessionId, ToolUseId: "tool-use-1", Model: "test-model@MyAdapter", Rejected: true,
	}, "query_events")
	assert.NoError(t, err)
	if assert.NotNil(t, turn) {
		assert.NotNil(t, turn.Response)
		if assert.NotNil(t, turn.ToolResult) {
			assert.Equal(t, "tool-use-1", turn.ToolResult.ToolUseId)
			assert.Equal(t, "rejected", turn.ToolResult.Status)
			assert.True(t, turn.ToolResult.IsError)
		}
		turn.Response.Body.Close()
	}
}

// Rejecting one tool of a parallel turn must not continue the turn while a sibling is
// still unresolved -- it persists the rejection and waits (persist-only), exactly like
// an executed sibling's result.
func TestAssistantCoordinator_ToolStreamInSession_RejectedTool_CoalescesWithSibling(t *testing.T) {
	const sessionId = "session-reject-parallel"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
		storedToolUseTurn("tool-a", "tool-b"),
	}, nil)
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, []string{"tool_result"}, stored.Tags)
			return nil
		})
	// MakeRequest must NOT be called: tool-b is still unresolved.

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
		SessionId: sessionId, ToolUseId: "tool-a", Model: "test-model@MyAdapter", Rejected: true,
	}, "query_events")
	assert.NoError(t, err)
	if assert.NotNil(t, turn) {
		assert.Nil(t, turn.Response) // persist-only: sibling tool-b still unresolved
		if assert.NotNil(t, turn.ToolResult) {
			assert.Equal(t, "tool-a", turn.ToolResult.ToolUseId)
			assert.Equal(t, "rejected", turn.ToolResult.Status)
		}
	}
}

func TestAssistantCoordinator_ToolStreamInSession_DelegationKickoff(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	// The child session is created with linkage back to the parent's delegate tool_use.
	mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, s *model.AssistantSession) error {
			assert.Equal(t, "parent-session", s.ParentSessionId)
			assert.Equal(t, "delegate-tooluse", s.ParentToolUseId)
			// The parent has no stored model (helper returns none), so ParentModel
			// falls back to the request model.
			assert.Equal(t, "AgentClaude@SOAI", s.ParentModel)
			// The child session records its own model (the delegate's agent id) so it
			// resumes as the right agent without trusting the client.
			assert.Equal(t, "test-model@MyAdapter", s.Model)
			assert.Equal(t, "delegation", s.Type)
			assert.Equal(t, "Hunter", s.DelegateAgent)
			assert.NotEmpty(t, s.SessionId)
			return nil
		})

	// The objective is seeded as the child's first user message.
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, "user", stored.Message.Role)
			assert.Contains(t, stored.Message.ContentBlocks[0].Text, "find DNS beacons")
			return nil
		})

	mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("data: stream")),
	}, nil)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	// The delegate's agent id doubles as the child model; use the test model so the
	// adapter/model lookup in SendStream resolves.
	delegate := NewDelegateTool("test-model@MyAdapter", "Hunter", "an event hunting agent")
	ac.DelegationLibrary = map[string]Tool{delegate.GetName(): delegate}

	// validateToolRequest loads the parent history once; the kickoff itself never does.
	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
		storedNamedToolUseTurn(delegate.GetName(), json.RawMessage(`{"objective":"find DNS beacons","context":"c","expected_output":"o"}`), "delegate-tooluse"),
	}, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
		SessionId: "parent-session",
		ToolUseId: "delegate-tooluse",
		Params:    json.RawMessage(`{"objective":"find DNS beacons","context":"c","expected_output":"o"}`),
		Model:     "AgentClaude@SOAI",
	}, delegate.GetName())

	assert.NoError(t, err)
	assert.NotNil(t, turn)
	assert.NotNil(t, turn.Response)
	assert.Equal(t, "test-model@MyAdapter", turn.Model)
	// The parent's delegate tool_use is intentionally NOT resolved here; instead a
	// delegation_start marker tells the UI to nest the sub-agent's output.
	assert.NotNil(t, turn.Marker)
	assert.Equal(t, model.DelegationMarkerStart, turn.Marker.Type)
	assert.Equal(t, "delegate-tooluse", turn.Marker.ParentToolUseId)
	assert.Equal(t, "Hunter", turn.Marker.AgentName)
	assert.Equal(t, turn.SessionId, turn.Marker.ChildSessionId)
	assert.NotEqual(t, "parent-session", turn.SessionId)
	// A delegation kickoff has no immediate result; it resolves through the marker
	// path, so no tool_result event is emitted for the delegate tool_use.
	assert.Nil(t, turn.ToolResult)

	turn.Response.Body.Close()
}

// Same kickoff flow in agentic mode: the child session stores the agent name
// as its model and the child's first turn resolves it through the agent's
// model mapping back to the real model/adapter pair.
func TestAssistantCoordinator_ToolStreamInSession_DelegationKickoffAgentName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	// validateToolRequest loads the parent history once; the kickoff itself never does.
	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
		storedNamedToolUseTurn("delegate_to_Test_Hunter", json.RawMessage(`{"objective":"find DNS beacons","context":"c","expected_output":"o"}`), "delegate-tooluse"),
	}, nil)

	mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, s *model.AssistantSession) error {
			// The child session records the agent name as its model so it resumes
			// as the right agent even when agents share an id@adapter pair.
			assert.Equal(t, "Test Hunter", s.Model)
			assert.Equal(t, "Test Hunter", s.DelegateAgent)
			assert.Equal(t, "delegation", s.Type)
			return nil
		})

	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)

	// The child's first turn reaches the adapter with the real model id and the
	// agent's prompt, proving the agent name stored on the child session
	// resolved through the agent mapping in SendStream.
	mockIO.EXPECT().MakeRequest(gomock.Any(), true).DoAndReturn(func(req *http.Request, _ bool) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		assert.NoError(t, err)
		cr := &model.ChatRequest{}
		assert.NoError(t, json.Unmarshal(body, cr))
		assert.Equal(t, "test-model", cr.Model)
		assert.Equal(t, "hunt things", cr.System)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("data: stream")),
		}, nil
	})

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ac.srv.Config.ClientParams.AssistantParams.AvailableModels = []model.ModelParameters{
		{ID: "test-model", Adapter: "MyAdapter", Enabled: true},
	}
	ac.isAgentic = true
	ac.agents = map[string]model.Agent{
		"Test Hunter": {Name: "Test Hunter", Prompt: "hunt things", AllowedSkills: []string{}, Enabled: true},
	}
	ac.agentMapping = map[string]string{"Test Hunter": "test-model@MyAdapter"}

	delegate := NewDelegateTool("Test Hunter", "Test Hunter", "an event hunting agent")
	assert.Equal(t, "delegate_to_Test_Hunter", delegate.GetName())
	ac.DelegationLibrary = map[string]Tool{delegate.GetName(): delegate}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
		SessionId: "parent-session",
		ToolUseId: "delegate-tooluse",
		Params:    json.RawMessage(`{"objective":"find DNS beacons","context":"c","expected_output":"o"}`),
		Model:     "AgentClaude@SOAI",
	}, delegate.GetName())

	assert.NoError(t, err)
	assert.NotNil(t, turn)
	assert.NotNil(t, turn.Response)
	assert.Equal(t, "Test Hunter", turn.Model)
	assert.NotNil(t, turn.Marker)
	assert.Equal(t, model.DelegationMarkerStart, turn.Marker.Type)
	assert.Equal(t, "Test Hunter", turn.Marker.AgentName)

	turn.Response.Body.Close()
}

// A tool approval resumes the session on the session's OWN stored model (a
// sub-agent's agent id), not the client-supplied model. This is the regression
// guard for the wrong-model-continues-a-sub-agent bug. The helper installs a
// permissive GetSessions, so these build their coordinator inline to return a
// specific session model.
// newSessionModelCoordinator builds the coordinator used by the
// ToolStreamInSession session-model tests: a query_events mock tool and a
// single valid test-model@MyAdapter.
func newSessionModelCoordinator(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) *AssistantCoordinator {
	srv := &server.Server{
		Assistantstore: mockAssistantstore,
		Host:           &web.Host{Version: "1.0.0"},
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: []model.ModelParameters{{ID: "test-model", Adapter: "MyAdapter"}},
				},
			},
		},
	}
	return &AssistantCoordinator{
		srv:       srv,
		IOManager: mockIO,
		adapters: map[string]server.AssistantAdapter{
			"MyAdapter": &SOAiCloudAdapter{apiUrl: "https://api.example.com", srv: srv, IOManager: mockIO},
		},
		toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
		FunctionLibrary: map[string]Tool{
			"query_events": &mockTool{
				name: "query_events",
				executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
					return &model.ToolResponse{ToolName: "query_events", Result: "No events found"}, nil
				},
			},
		},
		toolUseTurnAttempts: DEFAULT_TOOL_USE_TURN_ATTEMPTS, // zero delay: tests must not sleep
	}
}

func TestAssistantCoordinator_ToolStreamInSession_UsesSessionModel(t *testing.T) {
	tests := []struct {
		name        string
		sessionId   string
		storedModel string
		reqModel    string
		wantModel   string
	}{
		{
			// The sub-agent session records its own (valid) model. The client posts a
			// model with an unknown adapter; if the backend trusted it, SendStream would
			// fail ErrInvalidModel. It must use the stored model instead.
			name:        "stored session model overrides the client model",
			sessionId:   "child-session",
			storedModel: "test-model@MyAdapter",
			reqModel:    "wrong-model@NopeAdapter",
			wantModel:   "test-model@MyAdapter",
		},
		{
			// Legacy session: no Model. The backend must fall back to the request model.
			name:      "legacy session without a stored model falls back to the request model",
			sessionId: "legacy-session",
			reqModel:  "test-model@MyAdapter",
			wantModel: "test-model@MyAdapter",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return([]*model.AssistantSession{
				{SessionId: tc.sessionId, Model: tc.storedModel},
			}, nil)
			mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{storedToolUseTurn("tu")}, nil)
			mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)
			mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("data: stream")),
			}, nil)

			ac := newSessionModelCoordinator(mockAssistantstore, mockIO)
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
				SessionId: tc.sessionId,
				ToolUseId: "tu",
				Params:    json.RawMessage(`{}`),
				Model:     tc.reqModel,
			}, "query_events")
			assert.NoError(t, err)
			assert.NotNil(t, turn)
			assert.Equal(t, tc.wantModel, turn.Model)
			turn.Response.Body.Close()
		})
	}
}

func TestAssistantCoordinator_ResolveDelegationStream(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	// Parent history still has the unanswered delegate tool_use.
	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
		{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{
			{Type: "tool_use", Id: "delegate-tooluse", Name: "delegate_to_Hunter"},
		}}},
	}, nil)

	// The parent is resumed with the sub-agent's answer wrapped as a tool_result.
	mockIO.EXPECT().MakeRequest(gomock.Any(), true).DoAndReturn(func(req *http.Request, _ bool) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		assert.NoError(t, err)
		cr := &model.ChatRequest{}
		assert.NoError(t, json.Unmarshal(body, cr))
		last := cr.Messages[len(cr.Messages)-1]
		assert.Equal(t, "user", last.Role)
		assert.NotNil(t, last.ContentBlocks[0].ToolResult)
		assert.Equal(t, "delegate-tooluse", last.ContentBlocks[0].ToolResult.ToolUseId)

		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("data: stream")),
		}, nil
	})

	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, []string{"tool_result"}, stored.Tags)
			return nil
		})

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	childSession := &model.AssistantSession{
		SessionId:       "child-session",
		ParentSessionId: "parent-session",
		ParentToolUseId: "delegate-tooluse",
		ParentModel:     "test-model@MyAdapter",
	}

	turn, err := ac.ResolveDelegationStream(ctx, childSession, "found 3 suspicious domains")
	assert.NoError(t, err)
	assert.NotNil(t, turn)
	assert.Equal(t, "parent-session", turn.SessionId)
	assert.NotNil(t, turn.Marker)
	assert.Equal(t, model.DelegationMarkerResolved, turn.Marker.Type)
	assert.Equal(t, "parent-session", turn.Marker.ParentSessionId)
	assert.Equal(t, "delegate-tooluse", turn.Marker.ParentToolUseId)

	turn.Response.Body.Close()
}

// A client that disconnects while a sub-agent is still running cancels the request
// context. Folding the finished sub-agent's answer back into its parent must still
// happen, so ResolveDelegationStream detaches before any elastic read or persistence.
// We prove it by cancelling the inbound context up front and asserting every
// store/upstream call receives a live (non-cancelled) context.
func TestAssistantCoordinator_ResolveDelegationStream_DetachesFromRequestCtx(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *model.AssistantSession) ([]*model.StoredMessage, error) {
			assert.NoError(t, ctx.Err(), "history load must run on a detached, non-cancelled context")
			return []*model.StoredMessage{storedToolUseTurn("delegate-tooluse")}, nil
		})

	mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("data: stream")),
	}, nil)

	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *model.StoredMessage) error {
			assert.NoError(t, ctx.Err(), "tool_result persistence must run on a detached, non-cancelled context")
			return nil
		})

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user"))
	cancel() // simulate the client disconnecting before resolution runs

	childSession := &model.AssistantSession{
		SessionId:       "child-session",
		ParentSessionId: "parent-session",
		ParentToolUseId: "delegate-tooluse",
		ParentModel:     "test-model@MyAdapter",
	}

	turn, err := ac.ResolveDelegationStream(ctx, childSession, "found 3 suspicious domains")
	assert.NoError(t, err)
	assert.NotNil(t, turn)
	assert.Equal(t, "parent-session", turn.SessionId)

	turn.Response.Body.Close()
}

// ToolStreamInSession must also detach up front so that, on an early client
// disconnect, the tool still executes to completion and its tool_result is persisted
// (no dangling tool_use). Cancel the inbound context and assert the tool execution,
// history load, and persistence all see a live context.
func TestAssistantCoordinator_ToolStreamInSession_DetachesFromRequestCtx(t *testing.T) {
	const sessionId = "session-tool-detach"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *model.AssistantSession) ([]*model.StoredMessage, error) {
			assert.NoError(t, ctx.Err(), "history load must run on a detached, non-cancelled context")
			return []*model.StoredMessage{storedNamedToolUseTurn("query_events", json.RawMessage(`{"q":"x"}`), "tool-use-1")}, nil
		})

	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ *model.StoredMessage) error {
			assert.NoError(t, ctx.Err(), "tool_result persistence must run on a detached, non-cancelled context")
			return nil
		})

	mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("data: stream")),
	}, nil)

	toolExecuted := false
	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ac.FunctionLibrary = map[string]Tool{
		"query_events": &mockTool{
			name: "query_events",
			executeFunc: func(ctx context.Context, _ *server.Server, _ *model.ToolRequest) (*model.ToolResponse, error) {
				toolExecuted = true
				assert.NoError(t, ctx.Err(), "tool execution must run on a detached, non-cancelled context")
				return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
			},
		},
	}

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user"))
	cancel() // simulate the client disconnecting mid-turn

	turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
		SessionId: sessionId,
		ToolUseId: "tool-use-1",
		Params:    json.RawMessage(`{"q":"x"}`),
		Model:     "test-model@MyAdapter",
	}, "query_events")
	assert.NoError(t, err)
	assert.NotNil(t, turn)
	assert.True(t, toolExecuted, "tool should execute despite the cancelled request context")

	turn.Response.Body.Close()
}

// An agentic request routes through the agent->model mapping and setupAgent
// (per-agent prompt + tool config) rather than the coordinator's shared
// prompt/tools.
func TestAssistantCoordinator_SendStream_Agentic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockIO.EXPECT().MakeRequest(gomock.Any(), true).DoAndReturn(func(req *http.Request, _ bool) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		assert.NoError(t, err)
		cr := &model.ChatRequest{}
		assert.NoError(t, json.Unmarshal(body, cr))
		// setupAgent installs the agent's own prompt and tool config.
		assert.Equal(t, "You are a hunting agent.", cr.System)
		assert.NotEmpty(t, cr.ToolConfig)
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("data: streaming response")),
		}, nil
	})

	srv := &server.Server{
		Host: &web.Host{Version: "1.0.0"},
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: []model.ModelParameters{
						{ID: "test-model", DisplayName: "TestModel", Adapter: "whatever", Enabled: true},
					},
				},
			},
		},
	}

	ac := &AssistantCoordinator{
		IOManager:       mockIO,
		toolConfig:      []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
		srv:             srv,
		isAgentic:       true,
		FunctionLibrary: map[string]Tool{"query_events": &mockTool{name: "query_events", description: "events"}},
		SkillLibrary: map[string]model.Skill{
			"Hunt": {Name: "Hunt", Tools: []string{"query_events"}, Enabled: true},
		},
		agents: map[string]model.Agent{
			"Hunter": {Name: "Hunter", Prompt: "You are a hunting agent.", AllowedSkills: []string{"Hunt"}, Enabled: true},
		},
		agentMapping: map[string]string{"Hunter": "test-model@whatever"},
		adapters: map[string]server.AssistantAdapter{
			"whatever": &SOAiCloudAdapter{apiUrl: "https://api.example.com", srv: srv, IOManager: mockIO},
		},
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	res, _, err := ac.SendStream(ctx, "Hunter", []*model.Message{
		{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}},
	})
	assert.NoError(t, err)
	assert.NotNil(t, res)
	res.Body.Close()
}

// A model with no AvailableModels entry is a client error, not a silent fallback.
func TestAssistantCoordinator_SendStream_InvalidModel(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)

	srv := &server.Server{
		Host: &web.Host{Version: "1.0.0"},
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: []model.ModelParameters{{ID: "test-model", Adapter: "whatever"}},
				},
			},
		},
	}

	ac := &AssistantCoordinator{
		IOManager:  mockIO,
		toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
		srv:        srv,
		adapters: map[string]server.AssistantAdapter{
			"whatever": &SOAiCloudAdapter{apiUrl: "https://api.example.com", srv: srv, IOManager: mockIO},
		},
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	res, _, err := ac.SendStream(ctx, "other-model@whatever", []*model.Message{
		{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}},
	})
	assert.ErrorIs(t, err, ErrInvalidModel)
	assert.Nil(t, res)
}

func TestAssistantCoordinator_SetupAgent(t *testing.T) {
	ac := &AssistantCoordinator{
		FunctionLibrary: map[string]Tool{
			"query_events": &mockTool{name: "query_events", description: "events"},
		},
		DelegationLibrary: map[string]Tool{
			"delegate_to_Hunter": &mockTool{name: "delegate_to_Hunter", description: "hunter"},
		},
		SkillLibrary: map[string]model.Skill{
			"Hunt": {Name: "Hunt", Tools: []string{"query_events"}, AdditionalPrompt: "Hunt skill prompt.", Enabled: true},
		},
	}

	req := &model.ChatRequest{SystemAppend: "leftover"}
	agentParams := &model.Agent{
		Prompt:        "You are a hunting agent.",
		AllowedSkills: []string{"Hunt"},
		CanDelegateTo: []string{"delegate_to_Hunter"},
	}

	err := ac.setupAgent(context.Background(), req, agentParams)
	assert.NoError(t, err)
	// The agent's own prompt replaces the system prompt, and the append is rebuilt
	// from the agent's skill prompts (plus any systemPromptAddendum).
	assert.Equal(t, "You are a hunting agent.", req.System)
	assert.Contains(t, req.SystemAppend, "Hunt skill prompt.")
	assert.NotEmpty(t, req.ToolConfig)

	var tc model.ToolConfig
	assert.NoError(t, json.Unmarshal(req.ToolConfig, &tc))
	assert.Len(t, tc.Tools, 2) // the skill's tool + the allowed delegate
}

func TestAssistantCoordinator_SetupAgent_UnknownSkill(t *testing.T) {
	ac := &AssistantCoordinator{
		FunctionLibrary: map[string]Tool{
			"query_events": &mockTool{name: "query_events", description: "events"},
		},
		SkillLibrary: map[string]model.Skill{
			"Hunt": {Name: "Hunt", Tools: []string{"query_events"}, AdditionalPrompt: "Hunt skill prompt.", Enabled: true},
		},
	}

	req := &model.ChatRequest{SystemAppend: "leftover"}
	agentParams := &model.Agent{
		Prompt:        "You are a hunting agent.",
		AllowedSkills: []string{"Bogus"},
	}

	err := ac.setupAgent(context.Background(), req, agentParams)
	assert.NoError(t, err)
	// The unknown skill is dropped: it contributes no prompt and no tools.
	assert.Equal(t, "You are a hunting agent.", req.System)
	assert.Empty(t, req.SystemAppend)

	assert.Nil(t, req.ToolConfig)
}

func TestAssistantCoordinator_SetupAgent_DisabledSkill(t *testing.T) {
	ac := &AssistantCoordinator{
		FunctionLibrary: map[string]Tool{
			"query_events": &mockTool{name: "query_events", description: "events"},
			"query_cases":  &mockTool{name: "query_cases", description: "cases"},
		},
		SkillLibrary: map[string]model.Skill{
			"Hunt":    {Name: "Hunt", Tools: []string{"query_events"}, AdditionalPrompt: "Hunt skill prompt.", Enabled: true},
			"Respond": {Name: "Respond", Tools: []string{"query_cases"}, AdditionalPrompt: "Respond skill prompt.", Enabled: false},
		},
	}

	req := &model.ChatRequest{}
	agentParams := &model.Agent{
		Prompt:        "You are a hunting agent.",
		AllowedSkills: []string{"Hunt", "Respond"},
	}

	err := ac.setupAgent(context.Background(), req, agentParams)
	assert.NoError(t, err)

	// The disabled skill grants neither guidance nor tools; the enabled one is unaffected.
	assert.Equal(t, "Hunt skill prompt.", req.SystemAppend)

	var tc model.ToolConfig
	assert.NoError(t, json.Unmarshal(req.ToolConfig, &tc))
	assert.Len(t, tc.Tools, 1)
	assert.Equal(t, "query_events", tc.Tools[0].Spec.Name)
}

func TestAssistantCoordinator_SetupAgent_PersonaAddendum(t *testing.T) {
	ac := &AssistantCoordinator{
		FunctionLibrary: map[string]Tool{
			"query_events": &mockTool{name: "query_events", description: "events"},
		},
		SkillLibrary: map[string]model.Skill{
			"Hunt": {
				Name:             "Hunt",
				Tools:            []string{"query_events"},
				AdditionalPrompt: "Hunt skill prompt.",
				PersonaAddendum:  "Prefer narrow time ranges.",
				Enabled:          true,
			},
		},
	}

	req := &model.ChatRequest{}
	agentParams := &model.Agent{
		Prompt:          "You are a hunting agent.",
		PersonaAddendum: "Always cite the index you queried.",
		AllowedSkills:   []string{"Hunt"},
	}

	err := ac.setupAgent(context.Background(), req, agentParams)
	assert.NoError(t, err)

	assert.Equal(t, "You are a hunting agent.\n\nAlways cite the index you queried.", req.System)
	assert.Equal(t, "Hunt skill prompt.\n\nPrefer narrow time ranges.", req.SystemAppend)
}

func TestAssistantCoordinator_SetupAgent_DuplicateSkill(t *testing.T) {
	ac := &AssistantCoordinator{
		FunctionLibrary: map[string]Tool{
			"query_events": &mockTool{name: "query_events", description: "events"},
		},
		SkillLibrary: map[string]model.Skill{
			"Hunt": {Name: "Hunt", Tools: []string{"query_events"}, AdditionalPrompt: "Hunt skill prompt.", Enabled: true},
		},
	}

	req := &model.ChatRequest{SystemAppend: "leftover"}
	agentParams := &model.Agent{
		Prompt:        "You are a hunting agent.",
		AllowedSkills: []string{"Hunt", "Hunt"},
	}

	err := ac.setupAgent(context.Background(), req, agentParams)
	assert.NoError(t, err)
	// The duplicate skill is dropped: its prompt and tool appear only once.
	assert.Equal(t, 1, strings.Count(req.SystemAppend, "Hunt skill prompt."))

	var tc model.ToolConfig
	assert.NoError(t, json.Unmarshal(req.ToolConfig, &tc))
	assert.Len(t, tc.Tools, 1)
}

func TestAssistantCoordinator_ToolInSession_EdgeCases(t *testing.T) {
	const sessionId = "session-tool-edge"

	tests := []struct {
		name    string
		setup   func(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager)
		wantErr bool
	}{
		{
			name: "history load error propagates",
			setup: func(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return(nil, errors.New("network error"))
			},
			wantErr: true,
		},
		{
			// Send already succeeded and was billed; the response is still saved
			// and returned even when the tool_result save fails.
			name: "save tool_result failure does not discard the billed response",
			setup: func(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{storedToolUseTurn("tu")}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(assistantOkTextResponse("done"), nil)
				// First persistence is the tool_result message; fail it. The
				// assistant response is still saved.
				gomock.InOrder(
					mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save failed")),
					mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil),
				)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
			tc.setup(mockAssistantstore, mockIO)

			ac := newToolTestCoordinator(t, mockAssistantstore, mockIO, &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			response, err := ac.ToolInSession(ctx, &model.ToolRequest{
				SessionId: sessionId, ToolUseId: "tu", Params: json.RawMessage(`{}`), Model: "test-model@MyAdapter",
			}, "query_events")
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, response)
			}
		})
	}
}

func TestAssistantCoordinator_ToolInSession_AsyncToolNilResult(t *testing.T) {
	const sessionId = "session-tool-edge"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	// An async tool's turn ends at execution, so history is only loaded once, by
	// validateToolRequest.
	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
		storedNamedToolUseTurn("async_tool", nil, "tu"),
	}, nil)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ac.FunctionLibrary = map[string]Tool{
		"async_tool": &mockTool{
			name: "async_tool",
			executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return nil, nil
			},
		},
	}
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	resp, err := ac.ToolInSession(ctx, &model.ToolRequest{
		SessionId: sessionId, ToolUseId: "tu", Params: json.RawMessage(`{}`), Model: "test-model@MyAdapter",
	}, "async_tool")
	assert.NoError(t, err)
	assert.Nil(t, resp)
}

func TestAssistantCoordinator_ToolInSession_DelegationKickoffParksForApproval(t *testing.T) {
	const sessionId = "session-tool-edge"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	// validateToolRequest loads the parent history once; the parked kickoff never does.
	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
		storedNamedToolUseTurn("delegate_to_Hunter", nil, "tu"),
	}, nil)
	// The child session is created and its objective seeded; then the sub-agent's
	// first turn is run via Send (non-streaming).
	mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	// The sub-agent's first turn requests a tool, so it is returned for approval.
	mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
		StatusCode: 200,
		Body: io.NopCloser(strings.NewReader(
			`{"id":"r","role":"assistant","content":[{"type":"tool_use","id":"sub-tu","name":"query_events","input":{}}]}`)),
	}, nil)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ac.DelegationLibrary = map[string]Tool{
		"delegate_to_Hunter": &mockTool{
			name: "delegate_to_Hunter",
			executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return &model.ToolResponse{
					ToolName: "delegate_to_Hunter",
					Result:   model.DelegationKickoff{ChildSessionId: "child-1", ChildModel: "test-model@MyAdapter", Objective: "o", AgentName: "Hunter"},
				}, nil
			},
		},
	}
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	resp, err := ac.ToolInSession(ctx, &model.ToolRequest{
		SessionId: sessionId, ToolUseId: "tu", Params: json.RawMessage(`{}`), Model: "test-model@MyAdapter",
	}, "delegate_to_Hunter")
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.True(t, messageHasToolUse(resp[0]))
	assert.Equal(t, "query_events", resp[0].ContentBlocks[0].Name)
}

// newDelegationSyncCoordinator builds a coordinator wired with a delegate tool,
// used by the non-streaming delegation chain tests. Tests supply their own
// session-aware GetSessions expectation so loadTurnSession can link a child
// back to its parent.
func newDelegationSyncCoordinator(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) *AssistantCoordinator {
	srv := &server.Server{
		Assistantstore: mockAssistantstore,
		Host:           &web.Host{Version: "1.0.0"},
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: []model.ModelParameters{{ID: "test-model", Adapter: "MyAdapter"}},
				},
			},
		},
	}
	return &AssistantCoordinator{
		srv:       srv,
		IOManager: mockIO,
		adapters: map[string]server.AssistantAdapter{
			"MyAdapter": &SOAiCloudAdapter{apiUrl: "https://api.example.com", srv: srv, IOManager: mockIO},
		},
		toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
		DelegationLibrary: map[string]Tool{
			"delegate_to_Hunter": &mockTool{
				name: "delegate_to_Hunter",
				executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
					return &model.ToolResponse{
						ToolName: "delegate_to_Hunter",
						Result:   model.DelegationKickoff{ChildSessionId: "child-1", ChildModel: "test-model@MyAdapter", Objective: "o", AgentName: "Hunter"},
					}, nil
				},
			},
		},
		toolUseTurnAttempts: DEFAULT_TOOL_USE_TURN_ATTEMPTS, // zero delay: tests must not sleep
	}
}

// delegationTestSessions is a session-aware GetSessions stub: the child links
// back to a top-level parent.
func delegationTestSessions(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
	o := &model.GetSessionsOpts{}
	for _, opt := range opts {
		opt(o)
	}
	switch o.SessionId() {
	case "child-1":
		return []*model.AssistantSession{{
			SessionId:       "child-1",
			Model:           "test-model@MyAdapter",
			ParentSessionId: "parent-session",
			ParentToolUseId: "delegate-tooluse",
			ParentModel:     "test-model@MyAdapter",
		}}, nil
	case "parent-session":
		return []*model.AssistantSession{{SessionId: "parent-session", Model: "test-model@MyAdapter"}}, nil
	}
	return nil, nil
}

// delegationParentToolRequest is the parent-side delegate tool_use request used
// by the delegation chain tests.
func delegationParentToolRequest() *model.ToolRequest {
	return &model.ToolRequest{
		SessionId: "parent-session",
		ToolUseId: "delegate-tooluse",
		Params:    json.RawMessage(`{}`),
		Model:     "test-model@MyAdapter",
	}
}

// TestAssistantCoordinator_ToolInSession_Delegation covers the non-streaming
// delegation chain: a sub-agent turn is folded back into the parent's
// delegate tool_use and the parent is resumed, all within one call.
func TestAssistantCoordinator_ToolInSession_Delegation(t *testing.T) {
	tests := []struct {
		name               string
		subAgentBody       string // the sub-agent's first (and only) turn
		wantToolUseId      string // asserted on the folded tool_result when non-empty
		wantIsError        bool
		wantResultContains string // asserted on the folded tool_result content when non-empty
		parentText         string // the parent's final reply after the fold-back
	}{
		{
			// Sub-agent's first turn is text-only, so it resolves into the parent.
			name:          "text-only sub-agent result folds into parent and returns the parent's turn",
			subAgentBody:  `{"id":"r","role":"assistant","content":[{"type":"text","text":"child done"}]}`,
			wantToolUseId: "delegate-tooluse",
			parentText:    "parent done",
		},
		{
			// Sub-agent returns no text at all.
			name:               "empty sub-agent result yields an error tool_result to the parent",
			subAgentBody:       `{"id":"r","role":"assistant","content":[]}`,
			wantIsError:        true,
			wantResultContains: "ERROR_DELEGATION_NO_RESULT",
			parentText:         "acknowledged",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			// GetSessions is session-aware: the child links back to a top-level parent.
			mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(delegationTestSessions).AnyTimes()
			mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
			// Loaded twice: once by validateToolRequest, once by the delegation fold-back
			// continuation, which runs after the lock was released and so reloads.
			mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
				storedNamedToolUseTurn("delegate_to_Hunter", nil, "delegate-tooluse"),
			}, nil).Times(2)
			mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

			turn := 0
			mockIO.EXPECT().MakeRequest(gomock.Any(), false).DoAndReturn(func(r *http.Request, _ bool) (*http.Response, error) {
				turn++
				if turn == 1 {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.subAgentBody))}, nil
				}
				// Parent resume: the sub-agent's answer is wrapped as the delegate tool_result.
				body, _ := io.ReadAll(r.Body)
				cr := &model.ChatRequest{}
				assert.NoError(t, json.Unmarshal(body, cr))
				last := cr.Messages[len(cr.Messages)-1]
				assert.NotNil(t, last.ContentBlocks[0].ToolResult)
				if tc.wantToolUseId != "" {
					assert.Equal(t, tc.wantToolUseId, last.ContentBlocks[0].ToolResult.ToolUseId)
				}
				assert.Equal(t, tc.wantIsError, last.ContentBlocks[0].ToolResult.IsError)
				if tc.wantResultContains != "" {
					assert.Contains(t, last.ContentBlocks[0].ToolResult.Content[0].Text, tc.wantResultContains)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
					`{"id":"r","role":"assistant","content":[{"type":"text","text":"` + tc.parentText + `"}]}`))}, nil
			}).Times(2)

			ac := newDelegationSyncCoordinator(mockAssistantstore, mockIO)
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			resp, err := ac.ToolInSession(ctx, delegationParentToolRequest(), "delegate_to_Hunter")
			assert.NoError(t, err)
			assert.Len(t, resp, 1)
			assert.Equal(t, tc.parentText, resp[0].ContentBlocks[0].Text)
		})
	}
}

// delegationTestKickoff is the canonical kickoff used by the startDelegation tests.
func delegationTestKickoff() model.DelegationKickoff {
	return model.DelegationKickoff{
		ChildSessionId: "child-1",
		ChildModel:     "test-model@MyAdapter",
		Objective:      "find DNS beacons",
		AgentName:      "Hunter",
	}
}

// delegationKickoffToolRequest is the parent-side request handed to startDelegation.
func delegationKickoffToolRequest() *model.ToolRequest {
	return &model.ToolRequest{SessionId: "parent-session", ToolUseId: "delegate-tooluse", Model: "AgentClaude@SOAI"}
}

func TestAssistantCoordinator_StartDelegation_ErrorPaths(t *testing.T) {
	tests := []struct {
		name  string
		setup func(mockAssistantstore *servermock.MockAssistantstore)
	}{
		{
			name: "create child session error propagates",
			setup: func(mockAssistantstore *servermock.MockAssistantstore) {
				mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(errors.New("create failed"))
			},
		},
		{
			name: "save objective error propagates",
			setup: func(mockAssistantstore *servermock.MockAssistantstore) {
				mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save failed"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
			tc.setup(mockAssistantstore)

			ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			_, err := ac.startDelegation(ctx, delegationKickoffToolRequest(), delegationTestKickoff())
			assert.Error(t, err)
		})
	}
}

func TestAssistantCoordinator_StartDelegation_KickoffStreamErrorResolvesParent(t *testing.T) {
	// The child session already exists, so a failed kickoff must NOT just propagate:
	// it folds an error tool_result onto the parent's delegate tool_use and resumes
	// the parent, so the delegation resolves instead of spinning forever on reload.
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
	mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
	mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
		storedNamedToolUseTurn("delegate_to_Hunter", nil, "delegate-tooluse"),
	}, nil).AnyTimes()
	// Two saves: the child's objective, then the parent's error tool_result.
	var savedTags [][]string
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			savedTags = append(savedTags, stored.Tags)
			return nil
		}).Times(2)

	// First MakeRequest is the failing kickoff; the second is the parent's
	// continuation after the error result is folded in.
	callCount := 0
	mockIO.EXPECT().MakeRequest(gomock.Any(), true).DoAndReturn(
		func(_ *http.Request, _ bool) (*http.Response, error) {
			callCount++
			if callCount == 1 {
				return nil, errors.New("network error")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: stream"))}, nil
		}).Times(2)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	// Resolvable parent model so the continuation after the folded error can stream.
	req := &model.ToolRequest{SessionId: "parent-session", ToolUseId: "delegate-tooluse", Model: "test-model@MyAdapter"}
	turn, err := ac.startDelegation(ctx, req, delegationTestKickoff())
	assert.NoError(t, err)
	if assert.NotNil(t, turn) {
		assert.Nil(t, turn.Marker) // no delegation_start/resolved marker for a failed kickoff
		if assert.NotNil(t, turn.ToolResult) {
			assert.Equal(t, "delegate-tooluse", turn.ToolResult.ToolUseId)
			assert.True(t, turn.ToolResult.IsError)
		}
		if turn.Response != nil {
			turn.Response.Body.Close()
		}
	}
	assert.Contains(t, savedTags, []string{"tool_result"})
}

func TestAssistantCoordinator_StartDelegation_FinalizePersistsSubAgentMessage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
	mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
	// One save for the seeded objective before streaming begins.
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)
	mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("data: stream")),
	}, nil)

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	turn, err := ac.startDelegation(ctx, delegationKickoffToolRequest(), delegationTestKickoff())
	assert.NoError(t, err)
	assert.NotNil(t, turn)
	turn.Response.Body.Close()

	// finalize parses the sub-agent's turn and persists it to the child session.
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, stored *model.StoredMessage) error {
			assert.Equal(t, "child-1", stored.SessionId)
			assert.Equal(t, "assistant", stored.Message.Role)
			return nil
		})

	raw := `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[]}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"done"}}

data: {"type":"content_block_stop","index":0}

data: [DONE]`
	assert.NoError(t, turn.Finalize([]byte(raw)))
}

func TestAssistantCoordinator_ContinueWithToolResult_ErrorPaths(t *testing.T) {
	const sessionId = "session-continue-err"
	sess := func() *model.AssistantSession {
		return &model.AssistantSession{SessionId: sessionId}
	}
	toolMsg := func() *model.Message {
		return buildToolResultMessage("tu1", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)
	}

	tests := []struct {
		name    string
		setup   func(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager)
		wantErr bool
	}{
		{
			name: "history load error propagates",
			setup: func(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return(nil, errors.New("network error"))
			},
			wantErr: true,
		},
		{
			name: "upstream stream error propagates",
			setup: func(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{storedToolUseTurn("tu1")}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(nil, errors.New("network error"))
			},
			wantErr: true,
		},
		{
			// SendStream already succeeded and is billing; the turn is still
			// returned so finalize can save it and its usage.
			name: "save tool_result failure does not abandon the billed stream",
			setup: func(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{storedToolUseTurn("tu1")}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("data: stream")),
				}, nil)
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save failed"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
			tc.setup(mockAssistantstore, mockIO)

			ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			turn, err := ac.continueWithToolResult(ctx, sess(), sessionId, "test-model@MyAdapter", toolMsg(), nil, waitForLock)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if assert.NotNil(t, turn) {
					assert.NotNil(t, turn.Response)
					assert.NotNil(t, turn.Finalize)
				}
			}
		})
	}
}

// Every provider's tool_result status is success-or-error; internal markers like
// "rejected" must be collapsed for the wire (here, once and centrally) without
// mutating storage. cleanupMessages owns that canonicalization for all adapters.
func TestCleanupMessages_CanonicalizesToolResultStatus(t *testing.T) {
	rejected := &model.ToolResult{ToolUseId: "t1", Status: "rejected", IsError: true}
	in := []*model.Message{
		{Role: "user", ContentBlocks: []model.ContentBlock{{ToolResult: rejected}}},
	}

	out := cleanupMessages(in)
	assert.Equal(t, "error", out[0].ContentBlocks[0].ToolResult.Status, "wire status must be provider-accepted")
	assert.Equal(t, "rejected", rejected.Status, "stored status must be left untouched")

	// Canonical / empty statuses are preserved exactly.
	for _, s := range []string{"", "success", "error"} {
		got := cleanupMessages([]*model.Message{
			{Role: "user", ContentBlocks: []model.ContentBlock{{ToolResult: &model.ToolResult{Status: s}}}},
		})
		assert.Equal(t, s, got[0].ContentBlocks[0].ToolResult.Status)
	}
}

func TestCleanupMessages(t *testing.T) {
	testCases := []struct {
		name            string
		inputMessages   []*model.Message
		expectedResults []*model.Message
	}{
		{
			name:            "nil messages",
			inputMessages:   nil,
			expectedResults: []*model.Message{},
		},
		{
			name:            "empty messages",
			inputMessages:   []*model.Message{},
			expectedResults: []*model.Message{},
		},
		{
			name: "messages with fields to clean",
			inputMessages: []*model.Message{
				{
					Id:           "msg1",
					Role:         "user",
					StopReason:   stringPtr("stop"),
					StopSequence: stringPtr("seq"),
					Usage: &model.Usage{
						InputTokens:  10,
						OutputTokens: 20,
					},
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hello"},
					},
				},
				{
					Id:           "msg2",
					Role:         "assistant",
					StopReason:   stringPtr("length"),
					StopSequence: nil,
					Usage:        nil,
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hi back"},
					},
					Thoughts: "Assistant reasoning",
				},
			},
			expectedResults: []*model.Message{
				{
					Id:           "msg1",
					Role:         "user",
					StopReason:   nil, // Cleaned
					StopSequence: nil, // Cleaned
					Usage:        nil, // Cleaned
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hello"},
					},
				},
				{
					Id:           "msg2",
					Role:         "assistant",
					StopReason:   nil, // Cleaned
					StopSequence: nil, // Already nil
					Usage:        nil, // Already nil
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hi back"},
					},
					Thoughts: "Assistant reasoning",
				},
			},
		},
		{
			name: "ToolUse w/out text",
			inputMessages: []*model.Message{
				{
					Id:           "msg1",
					Role:         "user",
					StopReason:   stringPtr("stop"),
					StopSequence: stringPtr("seq"),
					Usage: &model.Usage{
						InputTokens:  10,
						OutputTokens: 20,
					},
					ContentBlocks: []model.ContentBlock{
						{Type: "tool_use", Input: []byte(`{"param1": "value1"}`)},
					},
				},
				{
					Id:         "msg2",
					Role:       "assistant",
					StopReason: stringPtr("length"),
					ContentBlocks: []model.ContentBlock{
						{Type: "tool_use", Input: []byte(`{"param1": "value1"}`)},
					},
				},
			},
			expectedResults: []*model.Message{
				{
					Id:   "msg1",
					Role: "user",
					ContentBlocks: []model.ContentBlock{
						{Type: "tool_use", Input: []byte(`{"param1": "value1"}`)},
					},
				},
				{
					Id:   "msg2",
					Role: "assistant",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "&nbsp;"},
						{Type: "tool_use", Input: []byte(`{"param1": "value1"}`)},
					},
				},
			},
		},
		{
			// Parallel tool calls: results are stored as separate messages but must be
			// sent as one user turn, or the model/gateway rejects the conversation.
			name: "merges consecutive tool_result messages into one user turn",
			inputMessages: []*model.Message{
				{
					Id:   "asst",
					Role: "assistant",
					ContentBlocks: []model.ContentBlock{
						{Type: "tool_use", Id: "tool-a", Input: []byte(`{}`)},
						{Type: "tool_use", Id: "tool-b", Input: []byte(`{}`)},
					},
				},
				{
					Id:            "res-a",
					Role:          "user",
					ContentBlocks: []model.ContentBlock{{ToolResult: &model.ToolResult{ToolUseId: "tool-a"}}},
				},
				{
					Id:            "res-b",
					Role:          "user",
					ContentBlocks: []model.ContentBlock{{ToolResult: &model.ToolResult{ToolUseId: "tool-b"}}},
				},
			},
			expectedResults: []*model.Message{
				{
					Id:   "asst",
					Role: "assistant",
					ContentBlocks: []model.ContentBlock{
						{Type: "tool_use", Id: "tool-a", Input: []byte(`{}`)},
						{Type: "tool_use", Id: "tool-b", Input: []byte(`{}`)},
					},
				},
				{
					Id:   "res-a", // merged into the first result message
					Role: "user",
					ContentBlocks: []model.ContentBlock{
						{ToolResult: &model.ToolResult{ToolUseId: "tool-a"}},
						{ToolResult: &model.ToolResult{ToolUseId: "tool-b"}},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := cleanupMessages(tc.inputMessages)

			assert.Equal(t, len(tc.expectedResults), len(result))

			for i, expectedMsg := range tc.expectedResults {
				if i < len(result) {
					actualMsg := result[i]
					assert.Equal(t, expectedMsg.Id, actualMsg.Id)
					assert.Equal(t, expectedMsg.Role, actualMsg.Role)
					assert.Nil(t, actualMsg.StopReason)
					assert.Nil(t, actualMsg.StopSequence)
					assert.Nil(t, actualMsg.Usage)
					assert.Equal(t, expectedMsg.ContentBlocks, actualMsg.ContentBlocks)
					assert.Equal(t, expectedMsg.Thoughts, actualMsg.Thoughts)

					// Verify original messages are not modified
					if i < len(tc.inputMessages) {
						originalMsg := tc.inputMessages[i]
						// The cleanup should create copies, not modify originals
						assert.NotSame(t, originalMsg, actualMsg)
					}
				}
			}
		})
	}
}

func TestBuildApiKey(t *testing.T) {
	// an expired test key
	license := `H4sIAAziJWgC/z2NW4+iQBSE/8qEV2YiCC3gGzcvKALSoONms2mgQZSbNFc3+98XZ5JJ6qFO6qs6fykcxzhs0g5TS2rOzMEHAz5YABlm+aUL9U7hoUpr1KRl8cMsPlgezrklkCa9mALlrwUXh22dNuObVUz4m12XU5ZGU5LUKEzxnwaTJkPBn9cMA1gwxVka4oLgV339Bb3Bb2jKYoyatsaEWv76/U61BNeTZaZ3ZYS/HSlDr86m7kRHqEE/B0mT4qs8nbuw6Ub6wm2eUb6wNUmQK+Q/R77J284zPDXT+dPdcRcFOEjrDd5Vea/LKwuuDgBZUazDLpk57PFuNX3VPZkTUK0EtIdkmHf0eNKGWrwLW6vnxj4k3W5XpAYnMwa5XirVZnucc9sWbV1QrfW4T7vOPaQsvc8VDrXPvSL4RyHbrOJS05HoJP1Je9SEjVMZGJxipot6iLz8qNKFMhb051otF0JM3w4mHYnyeYBzwUEQDHQYHUS1gFgY1MZktoocKMFKSmlxDe73HMbXlSQrSsjbZ4ueXc+fkOgqv9YJseX98NgwXDK2+Ix6ceRZfy88ofGQLG8UzN3xiFwZ841emhpub+LNWxCvz/Kszcx2P7K+thPVI6NwQUcLRmhZCdekz+21daPOCPNNU0vZfjazNdX0g4VuwCowUNQn5AIln547vL+y1xrcOkiaH9LHg+d7/tnVW77zN7JK63UYeD68MOx4+RRNQcCVfXYDseP5EpQKgSa4XE+wthTAtIRd6WJgtqHjHg0mvzm3ZsfZ1L//d3LBEekCAAA=`
	licensing.Init(license)

	key := buildApiKey()

	assert.Equal(t, key, "sk-46736dfccdc375085dfb8f701ea7f327860c51b4aac3629592649ae8a7bb7e29")
}

func TestAssistantCoordinator_GetPrompt(t *testing.T) {

	// Convert hex to bytes

	promptHexBytes := "1F8B08000000000000030BC9C82C5600A2928C5485D4DCA4D49494D41485E2CAE292D45C8582A2FCDC82120047F61F0E22000000"
	promptBytes, err := hex.DecodeString(promptHexBytes)
	if err != nil {
		t.Fatalf("failed to decode hex string: %v", err)
	}
	testCases := []struct {
		name           string
		embeddedPrompt []byte
		envVarValue    string
		setupMock      func(*detectionsmock.MockIOManager)
		expectedPrompt string
	}{
		{
			name:           "embedded prompt provided",
			embeddedPrompt: promptBytes,
			envVarValue:    "",
			setupMock:      func(mockIO *detectionsmock.MockIOManager) {},
			expectedPrompt: "This is the embedded system prompt",
		},
		{
			name:           "embedded prompt empty, env var set, file loads successfully",
			embeddedPrompt: []byte(""),
			envVarValue:    "/path/to/prompt.txt",
			setupMock: func(mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().ReadFile("/path/to/prompt.txt").Return([]byte("Prompt from file"), nil)
			},
			expectedPrompt: "Prompt from file",
		},
		{
			name:           "embedded prompt empty, env var not set",
			embeddedPrompt: []byte(""),
			envVarValue:    "",
			setupMock:      func(mockIO *detectionsmock.MockIOManager) {},
			expectedPrompt: "",
		},
		{
			name:           "embedded prompt empty, env var set, file read fails",
			embeddedPrompt: []byte(""),
			envVarValue:    "/path/to/nonexistent.txt",
			setupMock: func(mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().ReadFile("/path/to/nonexistent.txt").Return(nil, errors.New("file not found"))
			},
			expectedPrompt: "",
		},
		{
			name:           "embedded prompt empty, env var set, file has invalid UTF-8",
			embeddedPrompt: []byte(""),
			envVarValue:    "/path/to/invalid.txt",
			setupMock: func(mockIO *detectionsmock.MockIOManager) {
				mockIO.EXPECT().ReadFile("/path/to/invalid.txt").Return([]byte{0xff, 0xfe, 0xfd}, nil)
			},
			expectedPrompt: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Save and restore original embeddedSystemPrompt
			originalPrompt := embeddedSystemPrompt
			defer func() {
				embeddedSystemPrompt = originalPrompt
			}()
			embeddedSystemPrompt = tc.embeddedPrompt

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			tc.setupMock(mockIO)

			// Set environment variable (empty string to unset, or actual value)
			t.Setenv("SO_AI_SYSTEM_PROMPT_PATH", tc.envVarValue)

			srv := &server.Server{
				Context: context.Background(),
			}

			ac := &AssistantCoordinator{
				srv:       srv,
				IOManager: mockIO,
			}

			ac.getPrompt()

			assert.Equal(t, tc.expectedPrompt, ac.systemPrompt)
		})
	}
}

func TestAssistantCoordinator_Init(t *testing.T) {
	const fakeProtocol = "fake_protocol"
	const failProtocol = "fail_protocol"

	// Save and restore the protocols map and embeddedSystemPrompt.
	origProtocols := protocols
	origPrompt := embeddedSystemPrompt
	t.Cleanup(func() {
		protocols = origProtocols
		embeddedSystemPrompt = origPrompt
	})

	// Disable embedded prompt so getPrompt() is a no-op.
	embeddedSystemPrompt = []byte{}

	protocols = map[string]ProtocolConstructor{
		fakeProtocol: func(_ context.Context, _ *server.Server, cfg map[string]any) (server.AssistantAdapter, error) {
			return &mockAdapter{protocol: fakeProtocol}, nil
		},
		failProtocol: func(_ context.Context, _ *server.Server, cfg map[string]any) (server.AssistantAdapter, error) {
			return nil, errors.New("constructor failed")
		},
	}

	validAdapter := func(name, proto string) map[string]any {
		return map[string]any{"name": name, "protocol": proto}
	}

	testCases := []struct {
		name                  string
		config                module.ModuleConfig
		expectedAdapterNames  []string
		expectedAvailAdapters []model.AdapterParameters
		expectedAddendum      string
	}{
		{
			name:                  "no adapters key in config",
			config:                module.ModuleConfig{},
			expectedAdapterNames:  nil,
			expectedAvailAdapters: []model.AdapterParameters{},
			expectedAddendum:      "",
		},
		{
			name:                  "adapters key is nil",
			config:                module.ModuleConfig{"adapters": nil},
			expectedAdapterNames:  nil,
			expectedAvailAdapters: []model.AdapterParameters{},
			expectedAddendum:      "",
		},
		{
			name:                  "empty adapters array",
			config:                module.ModuleConfig{"adapters": []any{}},
			expectedAdapterNames:  nil,
			expectedAvailAdapters: []model.AdapterParameters{},
			expectedAddendum:      "",
		},
		{
			name: "single valid adapter",
			config: module.ModuleConfig{
				"adapters": []any{
					validAdapter("myAdapter", fakeProtocol),
				},
			},
			expectedAdapterNames: []string{"myAdapter"},
			expectedAvailAdapters: []model.AdapterParameters{
				{Name: "myAdapter", Protocol: fakeProtocol},
			},
			expectedAddendum: "",
		},
		{
			name: "multiple valid adapters",
			config: module.ModuleConfig{
				"adapters": []any{
					validAdapter("first", fakeProtocol),
					validAdapter("second", fakeProtocol),
				},
			},
			expectedAdapterNames: []string{"first", "second"},
			expectedAvailAdapters: []model.AdapterParameters{
				{Name: "first", Protocol: fakeProtocol},
				{Name: "second", Protocol: fakeProtocol},
			},
			expectedAddendum: "",
		},
		{
			name: "adapter entry is not a map - skipped",
			config: module.ModuleConfig{
				"adapters": []any{
					"not-a-map",
					validAdapter("good", fakeProtocol),
				},
			},
			expectedAdapterNames: []string{"good"},
			expectedAvailAdapters: []model.AdapterParameters{
				{Name: "good", Protocol: fakeProtocol},
			},
			expectedAddendum: "",
		},
		{
			name: "missing name field - skipped",
			config: module.ModuleConfig{
				"adapters": []any{
					map[string]any{"protocol": fakeProtocol},
					validAdapter("good", fakeProtocol),
				},
			},
			expectedAdapterNames: []string{"good"},
			expectedAvailAdapters: []model.AdapterParameters{
				{Name: "good", Protocol: fakeProtocol},
			},
			expectedAddendum: "",
		},
		{
			name: "missing protocol field - skipped",
			config: module.ModuleConfig{
				"adapters": []any{
					map[string]any{"name": "noProto"},
					validAdapter("good", fakeProtocol),
				},
			},
			expectedAdapterNames: []string{"good"},
			expectedAvailAdapters: []model.AdapterParameters{
				{Name: "good", Protocol: fakeProtocol},
			},
			expectedAddendum: "",
		},
		{
			name: "unknown protocol - skipped",
			config: module.ModuleConfig{
				"adapters": []any{
					validAdapter("unknown", "no_such_protocol"),
					validAdapter("good", fakeProtocol),
				},
			},
			expectedAdapterNames: []string{"good"},
			expectedAvailAdapters: []model.AdapterParameters{
				{Name: "good", Protocol: fakeProtocol},
			},
			expectedAddendum: "",
		},
		{
			name: "constructor returns error - skipped",
			config: module.ModuleConfig{
				"adapters": []any{
					validAdapter("broken", failProtocol),
					validAdapter("good", fakeProtocol),
				},
			},
			expectedAdapterNames: []string{"good"},
			expectedAvailAdapters: []model.AdapterParameters{
				{Name: "good", Protocol: fakeProtocol},
			},
			expectedAddendum: "",
		},
		{
			name: "systemPromptAddendum within limit",
			config: module.ModuleConfig{
				"systemPromptAddendum": "custom addendum",
			},
			expectedAdapterNames:  nil,
			expectedAvailAdapters: []model.AdapterParameters{},
			expectedAddendum:      "custom addendum",
		},
		{
			name: "systemPromptAddendum truncated to maxLength",
			config: module.ModuleConfig{
				"systemPromptAddendum":          "abcdefghij",
				"systemPromptAddendumMaxLength": float64(5),
			},
			expectedAdapterNames:  nil,
			expectedAvailAdapters: []model.AdapterParameters{},
			expectedAddendum:      "abcde",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &server.Server{
				Context: context.Background(),
				Config: &config.ServerConfig{
					ClientParams: model.ClientParameters{
						AssistantParams: model.AssistantParameters{},
					},
				},
			}

			ac := NewAssistantCoordinator(srv)

			err := ac.Init(tc.config)
			assert.NoError(t, err)

			// AssistantManager should be set to the coordinator.
			assert.Equal(t, ac, srv.AssistantManager)

			// Verify loaded adapters map.
			if tc.expectedAdapterNames == nil {
				assert.Empty(t, ac.adapters)
			} else {
				assert.Len(t, ac.adapters, len(tc.expectedAdapterNames))
				for _, name := range tc.expectedAdapterNames {
					assert.Contains(t, ac.adapters, name)
				}
			}

			// Verify AvailableAdapters on server config.
			assert.Equal(t, tc.expectedAvailAdapters, srv.Config.ClientParams.AssistantParams.AvailableAdapters)

			// Verify systemPromptAddendum.
			assert.Equal(t, tc.expectedAddendum, ac.systemPromptAddendum)
		})
	}
}

// Init reads awaitToolUseTurn's polling bounds from the module config, falling
// back to the defaults when unset.
func TestAssistantCoordinator_Init_ToolUseTurnPollingConfig(t *testing.T) {
	newAC := func() *AssistantCoordinator {
		return NewAssistantCoordinator(&server.Server{
			Context: context.Background(),
			Config: &config.ServerConfig{
				ClientParams: model.ClientParameters{
					AssistantParams: model.AssistantParameters{},
				},
			},
		})
	}

	tests := []struct {
		name         string
		moduleConfig module.ModuleConfig
		wantAttempts int
		wantDelay    time.Duration
	}{
		{
			name:         "defaults when unconfigured",
			moduleConfig: module.ModuleConfig{},
			wantAttempts: DEFAULT_TOOL_USE_TURN_ATTEMPTS,
			wantDelay:    DEFAULT_TOOL_USE_TURN_DELAY_MS * time.Millisecond,
		},
		{
			name: "configured values override the defaults",
			// Numbers decode from config as float64, matching the other int options.
			moduleConfig: module.ModuleConfig{
				"toolUseTurnAttempts": float64(3),
				"toolUseTurnDelayMs":  float64(25),
			},
			wantAttempts: 3,
			wantDelay:    25 * time.Millisecond,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac := newAC()
			assert.NoError(t, ac.Init(tc.moduleConfig))
			assert.Equal(t, tc.wantAttempts, ac.toolUseTurnAttempts)
			assert.Equal(t, tc.wantDelay, ac.toolUseTurnDelay)
		})
	}
}

// Helper types and functions for testing

type mockAdapter struct {
	protocol string
}

func (m *mockAdapter) Protocol() string { return m.protocol }
func (m *mockAdapter) SendMessage(context.Context, *model.ChatRequest) (*model.Message, error) {
	return nil, nil
}
func (m *mockAdapter) SendMessageStream(context.Context, *model.ChatRequest) (*http.Response, *model.AuxMessageData, error) {
	return nil, nil, nil
}
func (m *mockAdapter) GetBalance(context.Context) (*model.BalanceResponse, error) { return nil, nil }
func (m *mockAdapter) GetHealth(context.Context) (*model.HealthResponse, error)   { return nil, nil }
func (m *mockAdapter) Embed(context.Context, *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
	return nil, nil
}

func (m *mockAdapter) SupportsEmbeddings() bool {
	return false
}

type mockTool struct {
	name        string
	description string
	schema      model.JSONSchema
	executeFunc func(ctx context.Context, srv *server.Server, req *model.ToolRequest) (*model.ToolResponse, error)
}

func (m *mockTool) GetName() string {
	return m.name
}

func (m *mockTool) GetDescription() string {
	return m.description
}

func (m *mockTool) GetSchema() model.JSONSchema {
	return m.schema
}

func (m *mockTool) Execute(ctx context.Context, srv *server.Server, req *model.ToolRequest) (*model.ToolResponse, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, srv, req)
	}
	return &model.ToolResponse{
		ToolName: m.name,
		Result:   "mock result",
	}, nil
}

func TestEstimateRequestChars(t *testing.T) {
	tests := []struct {
		name     string
		req      *model.ChatRequest
		expected int
	}{
		{
			name:     "empty request",
			req:      &model.ChatRequest{},
			expected: 0,
		},
		{
			name: "system prompt only",
			req: &model.ChatRequest{
				System:       "You are a helpful assistant.",
				SystemAppend: "Additional context.",
			},
			expected: len("You are a helpful assistant.") + len("Additional context."),
		},
		{
			name: "messages with text blocks",
			req: &model.ChatRequest{
				System: "System",
				Messages: []*model.Message{
					{
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello"},
						},
					},
					{
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hi there!"},
						},
					},
				},
			},
			expected: len("System") + len("Hello") + len("Hi there!"),
		},
		{
			name: "message with content string",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{ContentStr: "Plain text message"},
				},
			},
			expected: len("Plain text message"),
		},
		{
			name: "message with tool result",
			req: &model.ChatRequest{
				Messages: []*model.Message{
					{
						ContentBlocks: []model.ContentBlock{
							{
								ToolResult: &model.ToolResult{
									Content: []model.ToolResultContent{
										{Text: "tool output data"},
									},
								},
							},
						},
					},
				},
			},
			expected: len("tool output data"),
		},
		{
			name: "tool config included",
			req: &model.ChatRequest{
				ToolConfig: json.RawMessage(`{"tools": [{"name": "query_events"}]}`),
			},
			expected: len(`{"tools": [{"name": "query_events"}]}`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := estimateRequestChars(tc.req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCheckRequestSize(t *testing.T) {
	tests := []struct {
		name        string
		req         *model.ChatRequest
		models      []model.ModelParameters
		selector    string
		expectError bool
	}{
		{
			name:        "no model params found, skip check",
			req:         &model.ChatRequest{System: strings.Repeat("a", 10000)},
			models:      []model.ModelParameters{},
			selector:    "unknown@SOAI",
			expectError: false,
		},
		{
			name: "charsPerTokenEstimate is zero, skip check",
			req:  &model.ChatRequest{System: strings.Repeat("a", 10000)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", ContextLimitSmall: 1000, CharsPerTokenEstimate: 0},
			},
			selector:    "model1@SOAI",
			expectError: false,
		},
		{
			name: "within limit",
			req:  &model.ChatRequest{System: strings.Repeat("a", 100)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", ContextLimitLarge: 1000, CharsPerTokenEstimate: 4.0},
			},
			selector: "model1@SOAI",
			// maxChars = 1000 * 4.0 * 1.1 = 4400, usedChars = 100
			expectError: false,
		},
		{
			name: "exceeds limit",
			req:  &model.ChatRequest{System: strings.Repeat("a", 5000)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", ContextLimitLarge: 1000, CharsPerTokenEstimate: 4.0},
			},
			selector: "model1@SOAI",
			// maxChars = 1000 * 4.0 * 1.1 = 4400, usedChars = 5000
			expectError: true,
		},
		{
			name: "exceeds limit, resolved by bare id",
			req:  &model.ChatRequest{System: strings.Repeat("a", 5000)},
			models: []model.ModelParameters{
				{ID: "model1", DisplayName: "Model One", Adapter: "SOAI", ContextLimitLarge: 1000, CharsPerTokenEstimate: 4.0},
			},
			selector: "model1",
			// maxChars = 1000 * 4.0 * 1.1 = 4400, usedChars = 5000
			expectError: true,
		},
		{
			name: "falls back to small context limit",
			req:  &model.ChatRequest{System: strings.Repeat("a", 500)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", ContextLimitSmall: 100, CharsPerTokenEstimate: 4.0},
			},
			selector: "model1@SOAI",
			// maxChars = 100 * 4.0 * 1.1 = 440, usedChars = 500
			expectError: true,
		},
		{
			name: "context limits both zero, skip check",
			req:  &model.ChatRequest{System: strings.Repeat("a", 10000)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", CharsPerTokenEstimate: 4.0},
			},
			selector:    "model1@SOAI",
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AssistantCoordinator{
				srv: &server.Server{
					Config: &config.ServerConfig{
						ClientParams: model.ClientParameters{
							AssistantParams: model.AssistantParameters{
								AvailableModels: tc.models,
							},
						},
					},
				},
			}

			err := ac.checkRequestSize(tc.req, ac.resolveModel(tc.selector))
			if tc.expectError {
				assert.ErrorIs(t, err, ErrRequestTooLarge)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func newResolveTestCoordinator(models []model.ModelParameters) *AssistantCoordinator {
	return &AssistantCoordinator{
		srv: &server.Server{
			Config: &config.ServerConfig{
				ClientParams: model.ClientParameters{
					AssistantParams: model.AssistantParameters{
						AvailableModels: models,
					},
				},
			},
		},
	}
}

func TestResolveModel(t *testing.T) {
	models := []model.ModelParameters{
		{ID: "gemini-3.5-flash", DisplayName: "Agent Gemini", Adapter: "Gemini", Enabled: true},
		{ID: "plain-model", Adapter: "SOAI", Enabled: true},
		{ID: "dual", Adapter: "A", Enabled: false},
		{ID: "dual", Adapter: "B", Enabled: true},
	}
	ac := newResolveTestCoordinator(models)

	tests := []struct {
		name        string
		selector    string
		wantNil     bool
		wantID      string
		wantAdapter string
		wantEnabled bool
	}{
		{
			name:        "id@adapter resolves to the matching model",
			selector:    "gemini-3.5-flash@Gemini",
			wantID:      "gemini-3.5-flash",
			wantAdapter: "Gemini",
			wantEnabled: true,
		},
		{
			name:        "bare id resolves and uses the model's own adapter",
			selector:    "plain-model",
			wantID:      "plain-model",
			wantAdapter: "SOAI",
			wantEnabled: true,
		},
		{
			name:        "bare id prefers an enabled model over an earlier disabled one",
			selector:    "dual",
			wantID:      "dual",
			wantAdapter: "B",
			wantEnabled: true,
		},
		{
			name:        "disabled model is returned only when no enabled model matches id and adapter",
			selector:    "dual@A",
			wantID:      "dual",
			wantAdapter: "A",
			wantEnabled: false,
		},
		{
			name:     "display name never resolves",
			selector: "Agent Gemini",
			wantNil:  true,
		},
		{
			name:     "unknown or empty selector resolves to nil (unknown id@adapter)",
			selector: "nope@Nowhere",
			wantNil:  true,
		},
		{
			name:     "unknown or empty selector resolves to nil (unknown bare id)",
			selector: "Nope",
			wantNil:  true,
		},
		{
			name:     "unknown or empty selector resolves to nil (empty selector)",
			selector: "",
			wantNil:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := ac.resolveModel(tc.selector)
			if tc.wantNil {
				assert.Nil(t, params)
				return
			}
			assert.NotNil(t, params)
			assert.Equal(t, tc.wantID, params.ID)
			assert.Equal(t, tc.wantAdapter, params.Adapter)
			assert.Equal(t, tc.wantEnabled, params.Enabled)
		})
	}
}

func TestResolveAdapterName(t *testing.T) {
	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "gemini-3.5-flash", DisplayName: "Agent Gemini", Adapter: "Gemini", Enabled: true},
	})

	// Canonical id@adapter selector routes through the configured model.
	assert.Equal(t, "Gemini", ac.resolveAdapterName("gemini-3.5-flash@Gemini"))
	// A bare id routes through the configured model's own adapter.
	assert.Equal(t, "Gemini", ac.resolveAdapterName("gemini-3.5-flash"))
	// Unconfigured model falls back to the "@adapter" split so a registered
	// adapter without an AvailableModels entry can still answer.
	assert.Equal(t, "MyAdapter", ac.resolveAdapterName("other@MyAdapter"))
	// A bare, unresolved selector is returned verbatim, not a phantom default.
	assert.Equal(t, "unknown", ac.resolveAdapterName("unknown"))
}

// Regression guard: an agent mapped by bare model id to a non-SOAI adapter must
// route to that model's real adapter, as the non-agentic selector path does.
func TestResolveAdapterNameAgenticHonorsModelAdapter(t *testing.T) {
	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "sonnet", DisplayName: "Claude Sonnet", Adapter: "SOAIDEV", Enabled: true},
	})
	ac.isAgentic = true
	ac.agents = map[string]model.Agent{"Orchestrator": {Name: "Orchestrator", Enabled: true}}
	ac.agentMapping = map[string]string{"Orchestrator": "sonnet"}

	assert.Equal(t, "SOAIDEV", ac.resolveAdapterName("Orchestrator"))
}

// captureAdapter records the ChatRequest handed to it so tests can assert what
// would be sent upstream.
type captureAdapter struct {
	lastReq *model.ChatRequest
}

func (a *captureAdapter) Protocol() string { return "capture" }

func (a *captureAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	a.lastReq = req
	return &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "ok"}}}, nil
}

func (a *captureAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, *model.AuxMessageData, error) {
	a.lastReq = req
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("")),
	}, &model.AuxMessageData{}, nil
}

func (a *captureAdapter) GetBalance(ctx context.Context) (*model.BalanceResponse, error) {
	return &model.BalanceResponse{}, nil
}

func (a *captureAdapter) GetHealth(ctx context.Context) (*model.HealthResponse, error) {
	return &model.HealthResponse{Status: "ok"}, nil
}

func (a *captureAdapter) Embed(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
	return nil, ErrEmbeddingsUnsupported
}

func (a *captureAdapter) SupportsEmbeddings() bool {
	return false
}

// Selecting a model by id@adapter (or bare id) must send the bare model id
// upstream, never the full selector.
func TestAssistantCoordinator_Send_ModelSelector(t *testing.T) {
	adapter := &captureAdapter{}

	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "test-model", DisplayName: "Agent Test", Adapter: "MyAdapter"},
	})
	ac.adapters = map[string]server.AssistantAdapter{"MyAdapter": adapter}
	ac.toolConfig = []byte(`{"tools": [], "tool_choice": {"auto": {}}}`)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	for _, selector := range []string{"test-model@MyAdapter", "test-model"} {
		adapter.lastReq = nil

		result, err := ac.Send(ctx, selector, []*model.Message{
			{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}},
		})

		assert.NoError(t, err, selector)
		assert.Len(t, result, 1, selector)
		assert.NotNil(t, adapter.lastReq, selector)
		assert.Equal(t, "test-model", adapter.lastReq.Model, selector)
	}
}

// In agentic mode a selector that is not an agent name falls through to model
// resolution (e.g. a session saved before agentic mode was enabled), taking the
// plain prompt/tool setup rather than setupAgent. A selector matching neither
// an agent nor a model is a client error.
func TestAssistantCoordinator_Send_AgenticFallsThroughToModelSelector(t *testing.T) {
	adapter := &captureAdapter{}

	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "test-model", Adapter: "MyAdapter", Enabled: true},
	})
	ac.adapters = map[string]server.AssistantAdapter{"MyAdapter": adapter}
	ac.toolConfig = []byte(`{"tools": [], "tool_choice": {"auto": {}}}`)
	ac.systemPrompt = "default prompt"
	ac.isAgentic = true
	ac.agents = map[string]model.Agent{
		"Hunter": {Name: "Hunter", Prompt: "agent prompt", AllowedSkills: []string{}, Enabled: true},
	}
	ac.agentMapping = map[string]string{"Hunter": "test-model@MyAdapter"}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
	msgs := []*model.Message{
		{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}},
	}

	result, err := ac.Send(ctx, "test-model@MyAdapter", msgs)
	assert.NoError(t, err)
	assert.Len(t, result, 1)
	assert.NotNil(t, adapter.lastReq)
	assert.Equal(t, "test-model", adapter.lastReq.Model)
	assert.Equal(t, "default prompt", adapter.lastReq.System)
	assert.Equal(t, ac.toolConfig, adapter.lastReq.ToolConfig)

	result, err = ac.Send(ctx, "Nope", msgs)
	assert.ErrorIs(t, err, ErrInvalidModel)
	assert.Nil(t, result)
}

// A delegate registered under multiple keys (selector + tool name) must appear
// only once in the tool spec sent to the model.
func TestBuildToolConfig_DedupesDelegates(t *testing.T) {
	delegate := NewDelegateTool("Hunter", "Hunter", "desc")
	delegates := map[string]Tool{
		"Hunter":           delegate,
		delegate.GetName(): delegate,
	}

	countDelegateSpecs := func(raw json.RawMessage) int {
		var tc model.ToolConfig
		assert.NoError(t, json.Unmarshal(raw, &tc))
		count := 0
		for _, spec := range tc.Tools {
			if spec.Spec.Name == delegate.GetName() {
				count++
			}
		}
		return count
	}

	tests := []struct {
		name           string
		toolFilter     []string
		delegateFilter []string
	}{
		{
			name:           "nil filter includes the delegate once",
			toolFilter:     nil,
			delegateFilter: nil,
		},
		{
			name:           "filter matching both keys includes the delegate once",
			toolFilter:     []string{},
			delegateFilter: []string{"Hunter", delegate.GetName()},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := buildToolConfig(map[string]Tool{}, delegates, tc.toolFilter, tc.delegateFilter)
			assert.NoError(t, err)
			assert.Equal(t, 1, countDelegateSpecs(raw))
		})
	}
}

// newSelectorLogCoordinator builds a coordinator whose srv.Context logs to an
// in-memory handler so tests can assert on the entries emitted by selector
// validation and delegate registration.
func newSelectorLogCoordinator(models []model.ModelParameters) (*AssistantCoordinator, *memory.Handler) {
	h := memory.New()
	ctx := log.NewContext(context.Background(), &log.Logger{Handler: h, Level: log.DebugLevel})

	ac := newResolveTestCoordinator(models)
	ac.srv.Context = ctx
	ac.DelegationLibrary = map[string]Tool{}

	return ac, h
}

// logMessagesAt returns the messages of all captured entries at the given level.
func logMessagesAt(h *memory.Handler, level log.Level) []string {
	msgs := []string{}
	for _, e := range h.Entries {
		if e.Level == level {
			msgs = append(msgs, e.Message)
		}
	}
	return msgs
}

func TestValidateModelSelectors(t *testing.T) {
	tests := []struct {
		name             string
		models           []model.ModelParameters
		wantErrContains  string
		wantWarnContains string
		wantEmpty        bool
		validate         func(t *testing.T, ac *AssistantCoordinator)
	}{
		{
			name: "clean config logs nothing",
			models: []model.ModelParameters{
				{ID: "model-a", DisplayName: "Agent A", Adapter: "SOAI", Enabled: true},
				{ID: "model-b", DisplayName: "Agent B", Adapter: "SOAI", Enabled: true},
			},
			wantEmpty: true,
		},
		{
			name: "missing displayName is fine: it is optional, cosmetic-only",
			models: []model.ModelParameters{
				{ID: "model-a", DisplayName: "Agent A", Adapter: "SOAI", Enabled: true},
				{ID: "model-c", Adapter: "SOAI", Enabled: true},
			},
			wantEmpty: true,
			validate: func(t *testing.T, ac *AssistantCoordinator) {
				// The model stays enabled in the config slice the frontend is served from.
				stored := ac.srv.Config.ClientParams.AssistantParams.AvailableModels
				assert.True(t, stored[0].Enabled)
				assert.True(t, stored[1].Enabled)
			},
		},
		{
			name: "duplicate enabled id@adapter pairs log an error, first wins",
			models: []model.ModelParameters{
				{ID: "model-a", DisplayName: "Hunter", Adapter: "A", Enabled: true},
				{ID: "model-a", DisplayName: "Hunter Two", Adapter: "A", Enabled: true},
			},
			wantErrContains: "duplicate model selector",
			// An exact duplicate must not also fire the bare-id ambiguity warning.
		},
		{
			name: "two enabled models sharing an id on different adapters warn about bare-id ambiguity",
			models: []model.ModelParameters{
				{ID: "model-a", Adapter: "A", Enabled: true},
				{ID: "model-a", Adapter: "B", Enabled: true},
			},
			wantWarnContains: "share an id",
		},
		{
			name: "duplicate involving a disabled model logs nothing",
			models: []model.ModelParameters{
				{ID: "model-a", Adapter: "A", Enabled: true},
				{ID: "model-a", Adapter: "A", Enabled: false},
			},
			wantEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac, h := newSelectorLogCoordinator(tc.models)

			ac.validateModelSelectors()

			if tc.wantEmpty {
				assert.Empty(t, h.Entries)
			} else {
				errors := logMessagesAt(h, log.ErrorLevel)
				if tc.wantErrContains != "" {
					assert.Len(t, errors, 1)
					assert.Contains(t, errors[0], tc.wantErrContains)
				} else {
					assert.Empty(t, errors)
				}

				warns := logMessagesAt(h, log.WarnLevel)
				if tc.wantWarnContains != "" {
					assert.Len(t, warns, 1)
					assert.Contains(t, warns[0], tc.wantWarnContains)
				} else {
					assert.Empty(t, warns)
				}
			}

			if tc.validate != nil {
				tc.validate(t, ac)
			}
		})
	}
}

func TestRegisterDelegateTools(t *testing.T) {
	t.Run("registers a delegate under the agent name and tool name", func(t *testing.T) {
		ac, _ := newSelectorLogCoordinator(nil)
		ac.agents = map[string]model.Agent{
			"Hunter": {Name: "Hunter", Description: "an event hunter", Enabled: true},
		}

		ac.registerDelegateTools()

		assert.Len(t, ac.DelegationLibrary, 2)
		assert.Contains(t, ac.DelegationLibrary, "Hunter")
		assert.Contains(t, ac.DelegationLibrary, "delegate_to_Hunter")
		assert.Contains(t, ac.DelegationLibrary["Hunter"].GetDescription(), "an event hunter")
	})

	t.Run("sanitized tool name collision skips the second entirely", func(t *testing.T) {
		// "A B" and "A_B" are distinct agent names but sanitize to the same
		// tool name. Registration is sorted, so "A B" wins and "A_B" collides.
		ac, h := newSelectorLogCoordinator(nil)
		ac.agents = map[string]model.Agent{
			"A B": {Name: "A B", Enabled: true},
			"A_B": {Name: "A_B", Enabled: true},
		}

		ac.registerDelegateTools()

		assert.Len(t, ac.DelegationLibrary, 2)
		assert.Contains(t, ac.DelegationLibrary, "A B")
		assert.Contains(t, ac.DelegationLibrary, "delegate_to_A_B")
		assert.NotContains(t, ac.DelegationLibrary, "A_B")

		errors := logMessagesAt(h, log.ErrorLevel)
		assert.Len(t, errors, 1)
		assert.Contains(t, errors[0], "delegate tool name collides")
	})

	t.Run("no agents registers nothing", func(t *testing.T) {
		ac, _ := newSelectorLogCoordinator(nil)
		ac.agents = map[string]model.Agent{}

		ac.registerDelegateTools()

		assert.Empty(t, ac.DelegationLibrary)
	})
}

// Streaming twin of TestAssistantCoordinator_Send_ModelSelector: the
// id@adapter selector resolves and the adapter receives the bare model id.
func TestAssistantCoordinator_SendStream_ModelSelector(t *testing.T) {
	adapter := &captureAdapter{}

	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "test-model", DisplayName: "Agent Test", Adapter: "MyAdapter"},
	})
	ac.adapters = map[string]server.AssistantAdapter{"MyAdapter": adapter}
	ac.toolConfig = []byte(`{"tools": [], "tool_choice": {"auto": {}}}`)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	res, _, err := ac.SendStream(ctx, "test-model@MyAdapter", []*model.Message{
		{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}},
	})

	assert.NoError(t, err)
	assert.NotNil(t, res)
	res.Body.Close()
	assert.NotNil(t, adapter.lastReq)
	assert.Equal(t, "test-model", adapter.lastReq.Model)
	assert.True(t, adapter.lastReq.Stream)
}

// Balance and Health accept any selector form: id@adapter, a bare id, and
// (leniently) an id@adapter with no configured model.
func TestAssistantCoordinator_BalanceAndHealth_SelectorResolution(t *testing.T) {
	newAC := func() *AssistantCoordinator {
		ac := newResolveTestCoordinator([]model.ModelParameters{
			{ID: "gemini-x", DisplayName: "Agent Gemini", Adapter: "Gemini"},
		})
		ac.adapters = map[string]server.AssistantAdapter{"Gemini": &captureAdapter{}}
		return ac
	}

	ctx := context.Background()

	balance := func(ac *AssistantCoordinator, selector string) (any, error) {
		return ac.Balance(ctx, selector)
	}
	health := func(ac *AssistantCoordinator, selector string) (any, error) {
		return ac.Health(ctx, selector)
	}

	tests := []struct {
		name            string
		invoke          func(*AssistantCoordinator, string) (any, error)
		selectors       []string
		wantErrContains string
		validate        func(t *testing.T, res any)
	}{
		{
			name:      "balance resolves id@adapter and bare-id selectors",
			invoke:    balance,
			selectors: []string{"gemini-x@Gemini", "gemini-x"},
		},
		{
			name:            "balance errors for an unknown adapter",
			invoke:          balance,
			selectors:       []string{"whatever@Missing"},
			wantErrContains: "assistant adapter not found",
		},
		{
			name:      "health resolves id@adapter and bare-id selectors",
			invoke:    health,
			selectors: []string{"gemini-x@Gemini", "gemini-x"},
			validate: func(t *testing.T, res any) {
				assert.Equal(t, "ok", res.(*model.HealthResponse).Status)
			},
		},
		{
			name:            "health errors for an unknown adapter",
			invoke:          health,
			selectors:       []string{"whatever@Missing"},
			wantErrContains: "assistant adapter not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac := newAC()
			for _, selector := range tc.selectors {
				res, err := tc.invoke(ac, selector)
				if tc.wantErrContains != "" {
					assert.ErrorContains(t, err, tc.wantErrContains)
					assert.Nil(t, res)
					continue
				}
				assert.NoError(t, err, selector)
				assert.NotNil(t, res, selector)
				if tc.validate != nil {
					tc.validate(t, res)
				}
			}
		})
	}
}

// A selector that resolves to a configured model whose adapter is not
// registered fails with an adapter error (after resolution, before any send).
func TestAssistantCoordinator_SendAndSendStream_AdapterNotFound(t *testing.T) {
	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "test-model", DisplayName: "Ghost Agent", Adapter: "Ghost"},
	})
	ac.adapters = map[string]server.AssistantAdapter{}
	ac.toolConfig = []byte(`{"tools": [], "tool_choice": {"auto": {}}}`)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
	msgs := []*model.Message{
		{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}},
	}

	result, err := ac.Send(ctx, "test-model@Ghost", msgs)
	assert.ErrorContains(t, err, "assistant adapter not found")
	assert.Nil(t, result)

	res, _, err := ac.SendStream(ctx, "test-model@Ghost", msgs)
	assert.ErrorContains(t, err, "assistant adapter not found")
	assert.Nil(t, res)
}

// A context missing the requestor id (only possible on a non-HTTP call path)
// must surface as an error from request preparation, not a panic.
func TestAssistantCoordinator_SendAndSendStream_MissingRequestorId(t *testing.T) {
	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "test-model", DisplayName: "Agent Test", Adapter: "MyAdapter"},
	})
	ac.toolConfig = []byte(`{"tools": [], "tool_choice": {"auto": {}}}`)

	msgs := []*model.Message{
		{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}},
	}

	result, err := ac.Send(context.Background(), "test-model@MyAdapter", msgs)
	assert.ErrorContains(t, err, "missing requestor id")
	assert.Nil(t, result)

	res, _, err := ac.SendStream(context.Background(), "test-model@MyAdapter", msgs)
	assert.ErrorContains(t, err, "missing requestor id")
	assert.Nil(t, res)
}

func TestBuildToolResultMessage_NilResultNoError(t *testing.T) {
	// A tool that returns neither a result nor an error (e.g. an async tool) must
	// not panic when its tool_result message is built on the streaming path.
	msg := buildToolResultMessage("tooluse-1", nil, nil)

	assert.NotNil(t, msg)
	assert.Equal(t, "user", msg.Role)
	assert.Len(t, msg.ContentBlocks, 1)

	tr := msg.ContentBlocks[0].ToolResult
	assert.NotNil(t, tr)
	assert.Equal(t, "tooluse-1", tr.ToolUseId)
	assert.Empty(t, tr.Name)
	assert.False(t, tr.IsError)
}

func TestBuildToolResultMessage_Error(t *testing.T) {
	msg := buildToolResultMessage("tooluse-2", nil, errors.New("boom"))

	tr := msg.ContentBlocks[0].ToolResult
	assert.NotNil(t, tr)
	assert.True(t, tr.IsError)
	assert.Equal(t, "error", tr.Status)
	assert.Equal(t, "boom", tr.Content[0].Text)
}

func TestBuildToolResultMessage_Result(t *testing.T) {
	msg := buildToolResultMessage("tooluse-3", &model.ToolResponse{ToolName: "query_events", Result: "data"}, nil)

	tr := msg.ContentBlocks[0].ToolResult
	assert.NotNil(t, tr)
	assert.Equal(t, "query_events", tr.Name)
	assert.False(t, tr.IsError)
	assert.NotNil(t, tr.Content[0].Json)
}

// loadTurnSession issues exactly one GetSessions call per turn, skipping the
// message-meta query and requesting usage aggregation only when the sub-session
// budget is enabled.
func TestAssistantCoordinator_loadTurnSession(t *testing.T) {
	cases := []struct {
		name          string
		maxSubSession int
		wantUsage     bool
	}{
		{name: "budget disabled skips usage aggregation", maxSubSession: 0, wantUsage: false},
		{name: "budget enabled requests usage aggregation", maxSubSession: 500, wantUsage: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
			mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
					o := &model.GetSessionsOpts{}
					for _, opt := range opts {
						opt(o)
					}
					assert.Equal(t, "sess-1", o.SessionId())
					assert.True(t, o.IncludeDeleted())
					assert.False(t, o.MessageMeta())
					assert.Equal(t, tc.wantUsage, o.Usage())
					return []*model.AssistantSession{{SessionId: "sess-1"}}, nil
				}).Times(1)

			ac := &AssistantCoordinator{
				srv: &server.Server{Assistantstore: mockAssistantstore},
			}
			ac.maxSubSessionTokens.Store(int64(tc.maxSubSession))

			sess := ac.loadTurnSession(context.Background(), "sess-1")
			assert.NotNil(t, sess)
			assert.Equal(t, "sess-1", sess.SessionId)
		})
	}
}

func TestAssistantCoordinator_loadTurnSession_EmptySessionId(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
	mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Times(0)

	ac := &AssistantCoordinator{srv: &server.Server{Assistantstore: mockAssistantstore}}

	assert.Nil(t, ac.loadTurnSession(context.Background(), ""))
}

func TestAssistantCoordinator_subSessionOutputBudget(t *testing.T) {
	tests := []struct {
		name              string
		maxSubSession     int
		sess              *model.AssistantSession
		expectedIsSub     bool
		expectedRemaining int
	}{
		{
			name:          "budget disabled is never capped",
			maxSubSession: 0,
			sess:          &model.AssistantSession{SessionId: "child", ParentSessionId: "top"},
		},
		{
			name:          "nil session (not found or lookup error) disables the cap",
			maxSubSession: 1000,
			sess:          nil,
		},
		{
			name:          "top-level session is not capped",
			maxSubSession: 1000,
			sess:          &model.AssistantSession{SessionId: "top", Usage: &model.SessionUsage{TotalOutputTokens: 500}},
		},
		{
			name:              "sub-session reports remaining output budget",
			maxSubSession:     1000,
			sess:              &model.AssistantSession{SessionId: "child", ParentSessionId: "top", Usage: &model.SessionUsage{TotalOutputTokens: 300}},
			expectedIsSub:     true,
			expectedRemaining: 700,
		},
		{
			name:              "exhausted sub-session reports non-positive remaining",
			maxSubSession:     1000,
			sess:              &model.AssistantSession{SessionId: "child", ParentSessionId: "top", Usage: &model.SessionUsage{TotalOutputTokens: 1200}},
			expectedIsSub:     true,
			expectedRemaining: -200,
		},
		{
			name:              "sub-session with no usage yet has full budget",
			maxSubSession:     1000,
			sess:              &model.AssistantSession{SessionId: "child", ParentSessionId: "top"},
			expectedIsSub:     true,
			expectedRemaining: 1000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac := &AssistantCoordinator{}
			ac.maxSubSessionTokens.Store(int64(tc.maxSubSession))

			isSub, remaining := ac.subSessionOutputBudget(tc.sess)

			assert.Equal(t, tc.expectedIsSub, isSub)
			if tc.expectedIsSub {
				assert.Equal(t, tc.expectedRemaining, remaining)
			}
		})
	}
}

// continueWithToolResultSync halts an exhausted sub-session: it persists the tool
// result and a budget-exhausted notice as the final turn and returns that notice
// (which the chaining loop folds back to the parent) WITHOUT making a model call.
func TestAssistantCoordinator_continueWithToolResultSync_HardStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	// Exactly two writes: the pending tool result, then the halt notice. No model
	// call and no session lookup — the turn's session record is passed in.
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	ac := &AssistantCoordinator{
		srv: &server.Server{Assistantstore: mockAssistantstore},
	}
	ac.maxSubSessionTokens.Store(500)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
	toolMsg := buildToolResultMessage("tu_1", &model.ToolResponse{ToolName: "x", Result: "r"}, nil)

	// The sub-session has already spent its budget (1000 > 500).
	sess := &model.AssistantSession{SessionId: "child", ParentSessionId: "parent", Usage: &model.SessionUsage{TotalOutputTokens: 1000}}
	resp, err := ac.continueWithToolResultSync(ctx, sess, "child", "model@Adapter", toolMsg, nil, waitForLock)

	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "assistant", resp[0].Role)
	assert.Contains(t, messageText(resp[0]), "halted")
}

// newDelegationSession stamps the child's delegation depth as parent depth + 1.
func TestAssistantCoordinator_newDelegationSession_Depth(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
	mockAssistantstore.EXPECT().
		GetSessions(gomock.Any(), gomock.Any(), gomock.Any()).
		Return([]*model.AssistantSession{{SessionId: "parent", Depth: 2, Model: "m@A"}}, nil)

	ac := &AssistantCoordinator{srv: &server.Server{Assistantstore: mockAssistantstore}}

	child := ac.newDelegationSession(
		context.Background(),
		&model.ToolRequest{SessionId: "parent", ToolUseId: "tu", Model: "m@A"},
		model.DelegationKickoff{ChildSessionId: "child", ChildModel: "c@A", AgentName: "Hunter", Objective: "obj"},
	)

	assert.Equal(t, 3, child.Depth)
	assert.Equal(t, "parent", child.ParentSessionId)
}

// delegationDepthRefusal refuses a delegation only when the new child (delegating
// depth + 1) would exceed maxDelegationDepth, and is a no-op when the limit is off.
func TestAssistantCoordinator_delegationDepthRefusal(t *testing.T) {
	tests := []struct {
		name          string
		maxDepth      int
		parentDepth   int
		expectLookup  bool
		expectRefusal bool
	}{
		{name: "disabled does not look up", maxDepth: 0, parentDepth: 5, expectLookup: false, expectRefusal: false},
		{name: "under limit allowed", maxDepth: 3, parentDepth: 1, expectLookup: true, expectRefusal: false},
		{name: "child equal to limit allowed", maxDepth: 3, parentDepth: 2, expectLookup: true, expectRefusal: false},
		{name: "child over limit refused", maxDepth: 3, parentDepth: 3, expectLookup: true, expectRefusal: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
			if tc.expectLookup {
				mockAssistantstore.EXPECT().
					GetSessions(gomock.Any(), gomock.Any(), gomock.Any()).
					Return([]*model.AssistantSession{{SessionId: "s", Depth: tc.parentDepth}}, nil)
			}

			ac := &AssistantCoordinator{
				srv: &server.Server{Assistantstore: mockAssistantstore},
			}
			ac.maxDelegationDepth.Store(int64(tc.maxDepth))

			refusal := ac.delegationDepthRefusal(context.Background(), &model.ToolRequest{SessionId: "s", ToolUseId: "tu"})

			if !tc.expectRefusal {
				assert.Nil(t, refusal)
				return
			}

			assert.NotNil(t, refusal)
			assert.Equal(t, "delegation", refusal.ContentBlocks[0].ToolResult.Name)
			resultMap, ok := refusal.ContentBlocks[0].ToolResult.Content[0].Json.(map[string]any)
			assert.True(t, ok)
			assert.Contains(t, resultMap["result"].(string), "depth")
		})
	}
}

func TestAllToolUsesResolved(t *testing.T) {
	mkAssistant := func(toolUseIds ...string) *model.Message {
		m := &model.Message{Role: "assistant"}
		for _, id := range toolUseIds {
			m.ContentBlocks = append(m.ContentBlocks, model.ContentBlock{Type: "tool_use", Id: id})
		}
		return m
	}
	mkResult := func(toolUseId string) *model.Message {
		return &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{ToolResult: &model.ToolResult{ToolUseId: toolUseId}}}}
	}

	tests := []struct {
		name     string
		messages []*model.Message
		want     bool
	}{
		{
			name:     "no tool uses",
			messages: []*model.Message{{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}}},
			want:     true,
		},
		{
			name:     "single tool use resolved",
			messages: []*model.Message{mkAssistant("a"), mkResult("a")},
			want:     true,
		},
		{
			name:     "parallel: one resolved, one pending",
			messages: []*model.Message{mkAssistant("a", "b"), mkResult("a")},
			want:     false,
		},
		{
			name:     "parallel: both resolved",
			messages: []*model.Message{mkAssistant("a", "b"), mkResult("a"), mkResult("b")},
			want:     true,
		},
		{
			name:     "parked delegate (no result) counts as unresolved",
			messages: []*model.Message{mkAssistant("delegate-1")},
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, allToolUsesResolved(tc.messages))
		})
	}
}

func TestAssistantCoordinator_ContinueWithToolResult_CoalescesParallelTools(t *testing.T) {
	const sessionId = "session-parallel"

	tests := []struct {
		name         string
		history      []*model.StoredMessage
		toolUseId    string
		toolName     string
		wantContinue bool
	}{
		{
			name: "waits (persist-only) while a sibling tool_use is unresolved",
			// One assistant turn requested two tools; neither is resolved yet.
			history: []*model.StoredMessage{
				{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{
					{Type: "tool_use", Id: "tool-a"},
					{Type: "tool_use", Id: "tool-b"},
				}}},
			},
			toolUseId:    "tool-a",
			toolName:     "query_events",
			wantContinue: false,
		},
		{
			name: "continues once the last sibling resolves",
			// Two tools requested; tool-a already resolved. Resolving tool-b completes the set.
			history: []*model.StoredMessage{
				{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{
					{Type: "tool_use", Id: "tool-a"},
					{Type: "tool_use", Id: "tool-b"},
				}}},
				{Tags: []string{"tool_result"}, Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{
					{ToolResult: &model.ToolResult{ToolUseId: "tool-a"}},
				}}},
			},
			toolUseId:    "tool-b",
			toolName:     "get_playbooks",
			wantContinue: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).Return(tc.history, nil)
			if tc.wantContinue {
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
					StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: stream")),
				}, nil)
			} else {
				// The executed tool's result is persisted, but NO model turn is dispatched
				// (MakeRequest must not be called -- sending now would orphan the sibling).
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, stored *model.StoredMessage) error {
						assert.Equal(t, []string{"tool_result"}, stored.Tags)
						return nil
					})
			}

			ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			toolMsg := buildToolResultMessage(tc.toolUseId, &model.ToolResponse{ToolName: tc.toolName, Result: "ok"}, nil)
			turn, err := ac.continueWithToolResult(ctx, &model.AssistantSession{SessionId: sessionId}, sessionId, "test-model@MyAdapter", toolMsg, nil, waitForLock)
			assert.NoError(t, err)
			if assert.NotNil(t, turn) {
				if tc.wantContinue {
					assert.NotNil(t, turn.Response) // continued: model turn dispatched
					turn.Response.Body.Close()
				} else {
					assert.Nil(t, turn.Response) // persist-only: no continuation
					if assert.NotNil(t, turn.ToolResult) {
						assert.Equal(t, tc.toolUseId, turn.ToolResult.ToolUseId)
					}
				}
			}
		})
	}
}

func TestToolUseInHistory(t *testing.T) {
	assistant := func(ids ...string) *model.Message {
		blocks := make([]model.ContentBlock, 0, len(ids))
		for _, id := range ids {
			blocks = append(blocks, model.ContentBlock{Type: "tool_use", Id: id})
		}
		return &model.Message{Role: "assistant", ContentBlocks: blocks}
	}
	result := func(id string) *model.Message {
		return &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{ToolResult: &model.ToolResult{ToolUseId: id}}}}
	}

	assert.True(t, toolUseInHistory([]*model.Message{assistant("a", "b")}, "b"))
	assert.False(t, toolUseInHistory([]*model.Message{assistant("a")}, "b"))
	assert.False(t, toolUseInHistory([]*model.Message{result("a")}, "a")) // a tool_result is not a tool_use
	assert.False(t, toolUseInHistory(nil, ""))
}

func TestFindToolUse(t *testing.T) {
	history := []*model.Message{
		nil,
		{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "tool_use", Id: "u"}}},         // wrong role
		{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "&nbsp;"}}}, // no tool_use
		{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "tool_use", Id: "a", Name: "query_events"}, {Type: "tool_use", Id: "b", Name: "ack_alerts"}}},
	}

	if cb := findToolUse(history, "b"); assert.NotNil(t, cb) {
		assert.Equal(t, "ack_alerts", cb.Name)
	}
	assert.Nil(t, findToolUse(history, "u"), "a non-assistant turn's block is not a tool request")
	assert.Nil(t, findToolUse(history, "missing"))
	assert.Nil(t, findToolUse(history, ""))
	assert.Nil(t, findToolUse(nil, "a"))
}

func TestJsonEqual(t *testing.T) {
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }

	// All spellings of "no params" are equivalent.
	assert.True(t, jsonEqual(nil, nil))
	assert.True(t, jsonEqual(raw(""), nil))
	assert.True(t, jsonEqual(raw("  "), raw("null")))
	assert.True(t, jsonEqual(raw("{}"), nil)) // UI sends {} for a zero-arg tool; stored Input is nil
	assert.True(t, jsonEqual(raw("{}"), raw("null")))

	// Key order, whitespace, and nesting are compared semantically.
	assert.True(t, jsonEqual(raw(`{"a":1,"b":[1,2]}`), raw(` { "b": [1, 2], "a": 1 } `)))
	assert.True(t, jsonEqual(raw(`{"a":{"x":"y"}}`), raw(`{"a": {"x": "y"}}`)))
	assert.True(t, jsonEqual(raw(`{"n":1.0}`), raw(`{"n":1}`)))

	// Mismatches.
	assert.False(t, jsonEqual(raw(`{"q":"x"}`), raw(`{"q":"y"}`)))
	assert.False(t, jsonEqual(raw(`{"q":"x"}`), nil))
	assert.False(t, jsonEqual(raw(`{"a":[1,2]}`), raw(`{"a":[2,1]}`)))
	assert.False(t, jsonEqual(raw(`{"a":1}`), raw(`{"a":1,"b":2}`)))

	// Unparseable input never matches, even against itself.
	assert.False(t, jsonEqual(raw(`{"broken`), raw(`{"broken`)))
	assert.False(t, jsonEqual(raw(`{"broken`), nil))
}

// continueWithToolResult must not dispatch a model turn while the assistant turn
// that requested the tool is still absent from history. The turn that emitted the
// tool_use is persisted asynchronously, so a fast continuation can load history
// lacking its own tool_use; sending then would orphan the tool_result (the gateway
// rejects it). Instead it persists the result and waits (persist-only).
func TestAssistantCoordinator_ContinueWithToolResult_AwaitsToolUseTurn(t *testing.T) {
	const sessionId = "session-await"

	tests := []struct {
		name            string
		historyProvider func(calls int) ([]*model.StoredMessage, error)
		wantContinue    bool
		postCheck       func(t *testing.T, calls int)
	}{
		{
			name: "waits (persist-only) when the tool_use turn has not landed yet",
			// The requesting tool_use turn never appears (its async finalize hasn't run).
			historyProvider: func(int) ([]*model.StoredMessage, error) {
				return []*model.StoredMessage{}, nil
			},
			wantContinue: false,
		},
		{
			name: "continues once the tool_use turn becomes visible on reload",
			// First load races the async persist and misses the tool_use turn; a reload
			// (awaitToolUseTurn) sees it once finalize lands.
			historyProvider: func(calls int) ([]*model.StoredMessage, error) {
				if calls == 1 {
					return []*model.StoredMessage{}, nil
				}
				return []*model.StoredMessage{storedToolUseTurn("tool-x")}, nil
			},
			wantContinue: true,
			postCheck: func(t *testing.T, calls int) {
				assert.GreaterOrEqual(t, calls, 2, "should have reloaded until the tool_use turn appeared")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			calls := 0
			mockAssistantstore.EXPECT().GetChatMessages(gomock.Any(), gomock.Any()).DoAndReturn(
				func(context.Context, *model.AssistantSession) ([]*model.StoredMessage, error) {
					calls++
					return tc.historyProvider(calls)
				}).AnyTimes()
			if tc.wantContinue {
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
					StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: stream")),
				}, nil)
			} else {
				// The result is persisted, but NO model turn is dispatched (MakeRequest must
				// not be called -- sending an orphaned tool_result errors at the gateway).
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, stored *model.StoredMessage) error {
						assert.Equal(t, []string{"tool_result"}, stored.Tags)
						return nil
					})
			}

			ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			toolMsg := buildToolResultMessage("tool-x", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)
			turn, err := ac.continueWithToolResult(ctx, &model.AssistantSession{SessionId: sessionId}, sessionId, "test-model@MyAdapter", toolMsg, nil, waitForLock)
			assert.NoError(t, err)
			if assert.NotNil(t, turn) {
				if tc.wantContinue {
					assert.NotNil(t, turn.Response) // continued after the turn landed
					turn.Response.Body.Close()
				} else {
					assert.Nil(t, turn.Response) // persist-only: no orphaned continuation
					if assert.NotNil(t, turn.ToolResult) {
						assert.Equal(t, "tool-x", turn.ToolResult.ToolUseId)
					}
				}
			}

			if tc.postCheck != nil {
				tc.postCheck(t, calls)
			}
		})
	}
}

func TestEmbed(t *testing.T) {
	adapter := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		return &model.EmbeddingResponse{Model: req.Model, Embeddings: [][]float32{{0.1}, {0.2}}}, nil
	}}

	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "embed-model", Adapter: "EmbedAdapter", Enabled: true},
	})
	ac.adapters = map[string]server.AssistantAdapter{"EmbedAdapter": adapter}

	resp, err := ac.Embed(context.Background(), "embed-model@EmbedAdapter", []string{"a", "b"})

	assert.NoError(t, err)
	if assert.NotNil(t, resp) {
		assert.Equal(t, "embed-model", resp.Model)
		assert.Len(t, resp.Embeddings, 2)
	}
	// the adapter must receive the bare model id and the inputs verbatim
	if assert.NotNil(t, adapter.lastEmbedReq) {
		assert.Equal(t, "embed-model", adapter.lastEmbedReq.Model)
		assert.Equal(t, []string{"a", "b"}, adapter.lastEmbedReq.Input)
	}
}

func TestEmbedUnknownModel(t *testing.T) {
	ac := newResolveTestCoordinator(nil)
	ac.adapters = map[string]server.AssistantAdapter{}

	_, err := ac.Embed(context.Background(), "missing-model", []string{"a"})

	assert.ErrorIs(t, err, ErrInvalidModel)
}

func TestEmbedUnknownAdapter(t *testing.T) {
	ac := newResolveTestCoordinator([]model.ModelParameters{
		{ID: "embed-model", Adapter: "EmbedAdapter", Enabled: true},
	})
	ac.adapters = map[string]server.AssistantAdapter{}

	_, err := ac.Embed(context.Background(), "embed-model@EmbedAdapter", []string{"a"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assistant adapter not found")
}
