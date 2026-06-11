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

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	detectionsmock "github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

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
		name           string
		functions      map[string]Tool
		delegates      map[string]Tool
		toolFilter     []string
		delegateFilter []string
		expectError    bool
		expectedLength int
	}{
		{
			name:           "empty functions map",
			functions:      map[string]Tool{},
			expectError:    false,
			expectedLength: 0,
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

				// Expect save chat to be called
				mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)
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

func newChatInSessionCoordinator(t *testing.T, ctrl *gomock.Controller, mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager, apiUrl string) *AssistantCoordinator {
	t.Helper()

	// The continuation paths derive their model from the session record via
	// sessionModel(). Default to "no stored model" so these existing tests fall
	// back to the request/parent model exactly as before; tests that exercise the
	// stored-model behavior build their own coordinator with a specific return.
	mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

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
	}
}

func TestAssistantCoordinator_ChatInSession(t *testing.T) {
	const sessionId = "session-1"

	t.Run("existing history persists user and response messages", func(t *testing.T) {
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

			return &http.Response{
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(
					`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"ok"}]}`)),
			}, nil
		})

		// One save for the user message, one for the assistant response.
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
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
	})

	t.Run("empty history creates a new session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, session *model.AssistantSession) error {
				assert.Equal(t, sessionId, session.SessionId)
				assert.Equal(t, "hello", session.Title)
				assert.Empty(t, session.Type)
				assert.Empty(t, session.EntityId)
				return nil
			})

		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
			StatusCode: 200,
			Body: io.NopCloser(strings.NewReader(
				`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"hi"}]}`)),
		}, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		incMsg := &model.IncomingMessage{
			Msg:       "hello",
			SessionId: sessionId,
			Model:     "test-model@MyAdapter",
		}

		_, err := ac.ChatInSession(ctx, incMsg, "", "")
		assert.NoError(t, err)
	})

	t.Run("entity fields populate the new session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, session *model.AssistantSession) error {
				assert.Equal(t, "alert_investigation", session.Type)
				assert.Equal(t, "alert-42", session.EntityId)
				return nil
			})

		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
			StatusCode: 200,
			Body: io.NopCloser(strings.NewReader(
				`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"hi"}]}`)),
		}, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ChatInSession(ctx, &model.IncomingMessage{
			Msg:       "investigate",
			SessionId: sessionId,
			Model:     "test-model@MyAdapter",
		}, "alert_investigation", "alert-42")
		assert.NoError(t, err)
	})

	t.Run("history not-found is tolerated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(nil, errors.New("session not found"))
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
			StatusCode: 200,
			Body: io.NopCloser(strings.NewReader(
				`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"hi"}]}`)),
		}, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ChatInSession(ctx, &model.IncomingMessage{
			Msg:       "hi",
			SessionId: sessionId,
			Model:     "test-model@MyAdapter",
		}, "", "")
		assert.NoError(t, err)
	})

	t.Run("upstream error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(nil, errors.New("network error"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ChatInSession(ctx, &model.IncomingMessage{
			Msg:       "hi",
			SessionId: sessionId,
			Model:     "test-model@MyAdapter",
		}, "", "")
		assert.Error(t, err)
	})
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

	ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
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

func TestAssistantCoordinator_ToolInSession(t *testing.T) {
	const sessionId = "session-tool-1"

	makeReq := func() *model.ToolRequest {
		return &model.ToolRequest{
			SessionId: sessionId,
			ToolUseId: "tool-use-1",
			Params:    json.RawMessage(`{"q":"x"}`),
			Model:     "test-model@MyAdapter",
		}
	}

	t.Run("successful tool execution feeds back into Send and persists both messages", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)

		mockIO.EXPECT().MakeRequest(gomock.Any(), false).DoAndReturn(func(req *http.Request, _ bool) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			assert.NoError(t, err)
			cr := &model.ChatRequest{}
			assert.NoError(t, json.Unmarshal(body, cr))
			// The tool_result message should be the only message sent to Send.
			assert.Len(t, cr.Messages, 1)
			assert.NotNil(t, cr.Messages[0].ContentBlocks[0].ToolResult)
			assert.Equal(t, "tool-use-1", cr.Messages[0].ContentBlocks[0].ToolResult.ToolUseId)
			assert.False(t, cr.Messages[0].ContentBlocks[0].ToolResult.IsError)
			return &http.Response{
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(
					`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"done"}]}`)),
			}, nil
		})

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

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ac.FunctionLibrary = map[string]Tool{
			"query_events": &mockTool{
				name: "query_events",
				executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
					return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
				},
			},
		}
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		resp, err := ac.ToolInSession(ctx, makeReq(), "query_events")
		assert.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "done", resp[0].ContentBlocks[0].Text)
	})

	t.Run("tool execution error wraps as error tool_result and chat still proceeds", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)

		mockIO.EXPECT().MakeRequest(gomock.Any(), false).DoAndReturn(func(req *http.Request, _ bool) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			cr := &model.ChatRequest{}
			assert.NoError(t, json.Unmarshal(body, cr))
			assert.True(t, cr.Messages[0].ContentBlocks[0].ToolResult.IsError)
			assert.Equal(t, "error", cr.Messages[0].ContentBlocks[0].ToolResult.Status)
			assert.Equal(t, "boom", cr.Messages[0].ContentBlocks[0].ToolResult.Content[0].Text)
			return &http.Response{
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(
					`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"sorry"}]}`)),
			}, nil
		})
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ac.FunctionLibrary = map[string]Tool{
			"query_events": &mockTool{
				name: "query_events",
				executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
					return nil, errors.New("boom")
				},
			},
		}
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		resp, err := ac.ToolInSession(ctx, makeReq(), "query_events")
		assert.NoError(t, err)
		assert.Len(t, resp, 1)
	})

	t.Run("upstream Send error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(nil, errors.New("network error"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ac.FunctionLibrary = map[string]Tool{
			"query_events": &mockTool{
				name: "query_events",
				executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
					return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
				},
			},
		}
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ToolInSession(ctx, makeReq(), "query_events")
		assert.Error(t, err)
	})
}

func TestAssistantCoordinator_ToolStreamInSession_FinalizeSavesResponse(t *testing.T) {
	const sessionId = "session-tool-stream-1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
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

	ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
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

	ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
	// The delegate's agent id doubles as the child model; use the test model so the
	// adapter/model lookup in SendStream resolves.
	delegate := NewDelegateTool("test-model@MyAdapter", "Hunter", "an event hunting agent")
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
	assert.Equal(t, "test-model@MyAdapter", turn.Model)
	// The parent's delegate tool_use is intentionally NOT resolved here; instead a
	// delegation_start marker tells the UI to nest the sub-agent's output.
	assert.NotNil(t, turn.Marker)
	assert.Equal(t, model.DelegationMarkerStart, turn.Marker.Type)
	assert.Equal(t, "delegate-tooluse", turn.Marker.ParentToolUseId)
	assert.Equal(t, "Hunter", turn.Marker.AgentName)
	assert.Equal(t, turn.SessionId, turn.Marker.ChildSessionId)
	assert.NotEqual(t, "parent-session", turn.SessionId)

	turn.Response.Body.Close()
}

// A tool approval resumes the session on the session's OWN stored model (a
// sub-agent's agent id), not the client-supplied model. This is the regression
// guard for the wrong-model-continues-a-sub-agent bug. The helper installs a
// permissive GetSessions, so these build their coordinator inline to return a
// specific session model.
func TestAssistantCoordinator_ToolStreamInSession_UsesSessionModel(t *testing.T) {
	buildAC := func(mockAssistantstore *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) *AssistantCoordinator {
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
		}
	}

	t.Run("stored session model overrides the client model", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		// The sub-agent session records its own (valid) model. The client posts a
		// model with an unknown adapter; if the backend trusted it, SendStream would
		// fail ErrInvalidModel. It must use the stored model instead.
		mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return([]*model.AssistantSession{
			{SessionId: "child-session", Model: "test-model@MyAdapter"},
		}, nil)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), "child-session").Return(nil, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("data: stream")),
		}, nil)

		ac := buildAC(mockAssistantstore, mockIO)
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
			SessionId: "child-session",
			ToolUseId: "tu",
			Params:    json.RawMessage(`{}`),
			Model:     "wrong-model@NopeAdapter",
		}, "query_events")
		assert.NoError(t, err)
		assert.NotNil(t, turn)
		assert.Equal(t, "test-model@MyAdapter", turn.Model)
		turn.Response.Body.Close()
	})

	t.Run("legacy session without a stored model falls back to the request model", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		// Legacy session: no Model. The backend must fall back to the request model.
		mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return([]*model.AssistantSession{
			{SessionId: "legacy-session"},
		}, nil)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), "legacy-session").Return(nil, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("data: stream")),
		}, nil)

		ac := buildAC(mockAssistantstore, mockIO)
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		turn, err := ac.ToolStreamInSession(ctx, &model.ToolRequest{
			SessionId: "legacy-session",
			ToolUseId: "tu",
			Params:    json.RawMessage(`{}`),
			Model:     "test-model@MyAdapter",
		}, "query_events")
		assert.NoError(t, err)
		assert.NotNil(t, turn)
		assert.Equal(t, "test-model@MyAdapter", turn.Model)
		turn.Response.Body.Close()
	})
}

func TestAssistantCoordinator_ResolveDelegationStream(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

	// Parent history still has the unanswered delegate tool_use.
	mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), "parent-session").Return([]*model.StoredMessage{
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

	ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
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

// An agentic model routes through setupAgent (per-agent prompt + tool config)
// rather than the coordinator's shared prompt/tools.
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
						{ID: "test-model", Adapter: "whatever", IsAgentic: true, AgentPrompt: "You are a hunting agent.", AllowedTools: []string{"query_events"}},
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
		adapters: map[string]server.AssistantAdapter{
			"whatever": &SOAiCloudAdapter{apiUrl: "https://api.example.com", srv: srv, IOManager: mockIO},
		},
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	res, _, err := ac.SendStream(ctx, "test-model@whatever", []*model.Message{
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
	}

	req := &model.ChatRequest{SystemAppend: "leftover"}
	modelParams := &model.ModelParameters{
		AgentPrompt:   "You are a hunting agent.",
		AllowedTools:  []string{"query_events"},
		CanDelegateTo: []string{"delegate_to_Hunter"},
	}

	err := ac.setupAgent(req, modelParams)
	assert.NoError(t, err)
	// The agent's own prompt replaces the system prompt and clears any append.
	assert.Equal(t, "You are a hunting agent.", req.System)
	assert.Empty(t, req.SystemAppend)
	assert.NotEmpty(t, req.ToolConfig)

	var tc model.ToolConfig
	assert.NoError(t, json.Unmarshal(req.ToolConfig, &tc))
	assert.Len(t, tc.Tools, 2) // the allowed tool + the allowed delegate
}

func TestAssistantCoordinator_ToolInSession_EdgeCases(t *testing.T) {
	const sessionId = "session-tool-edge"

	t.Run("async tool with neither result nor error returns nil", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
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
	})

	t.Run("delegation kickoff whose sub-agent requests a tool parks for approval", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

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

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
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
	})

	t.Run("history load error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(nil, errors.New("network error"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ac.FunctionLibrary = map[string]Tool{
			"query_events": &mockTool{
				name: "query_events",
				executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
					return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
				},
			},
		}
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ToolInSession(ctx, &model.ToolRequest{
			SessionId: sessionId, ToolUseId: "tu", Params: json.RawMessage(`{}`), Model: "test-model@MyAdapter",
		}, "query_events")
		assert.Error(t, err)
	})

	t.Run("save tool_result error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
			StatusCode: 200,
			Body: io.NopCloser(strings.NewReader(
				`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"done"}]}`)),
		}, nil)
		// First persistence is the tool_result message; fail it.
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save failed"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ac.FunctionLibrary = map[string]Tool{
			"query_events": &mockTool{
				name: "query_events",
				executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
					return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
				},
			},
		}
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ToolInSession(ctx, &model.ToolRequest{
			SessionId: sessionId, ToolUseId: "tu", Params: json.RawMessage(`{}`), Model: "test-model@MyAdapter",
		}, "query_events")
		assert.Error(t, err)
	})
}

// newDelegationSyncCoordinator builds a coordinator wired with a delegate tool,
// used by the non-streaming delegation chain tests. Tests supply their own
// session-aware GetSessions expectation so loadSession/sessionModel can link a
// child back to its parent.
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
	}
}

// TestAssistantCoordinator_ToolInSession_Delegation covers the non-streaming
// delegation chain: a text-only sub-agent turn is folded back into the parent's
// delegate tool_use and the parent is resumed, all within one call.
func TestAssistantCoordinator_ToolInSession_Delegation(t *testing.T) {
	// GetSessions is session-aware: the child links back to a top-level parent.
	sessions := func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
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

	req := func() *model.ToolRequest {
		return &model.ToolRequest{
			SessionId: "parent-session",
			ToolUseId: "delegate-tooluse",
			Params:    json.RawMessage(`{}`),
			Model:     "test-model@MyAdapter",
		}
	}

	t.Run("text-only sub-agent result folds into parent and returns the parent's turn", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(sessions).AnyTimes()
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), "parent-session").Return(nil, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		turn := 0
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).DoAndReturn(func(r *http.Request, _ bool) (*http.Response, error) {
			turn++
			if turn == 1 {
				// Sub-agent's first turn is text-only, so it resolves into the parent.
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
					`{"id":"r","role":"assistant","content":[{"type":"text","text":"child done"}]}`))}, nil
			}
			// Parent resume: the sub-agent's answer is wrapped as the delegate tool_result.
			body, _ := io.ReadAll(r.Body)
			cr := &model.ChatRequest{}
			assert.NoError(t, json.Unmarshal(body, cr))
			last := cr.Messages[len(cr.Messages)-1]
			assert.NotNil(t, last.ContentBlocks[0].ToolResult)
			assert.Equal(t, "delegate-tooluse", last.ContentBlocks[0].ToolResult.ToolUseId)
			assert.False(t, last.ContentBlocks[0].ToolResult.IsError)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
				`{"id":"r","role":"assistant","content":[{"type":"text","text":"parent done"}]}`))}, nil
		}).Times(2)

		ac := newDelegationSyncCoordinator(mockAssistantstore, mockIO)
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		resp, err := ac.ToolInSession(ctx, req(), "delegate_to_Hunter")
		assert.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "parent done", resp[0].ContentBlocks[0].Text)
	})

	t.Run("empty sub-agent result yields an error tool_result to the parent", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(sessions).AnyTimes()
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), "parent-session").Return(nil, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		turn := 0
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).DoAndReturn(func(r *http.Request, _ bool) (*http.Response, error) {
			turn++
			if turn == 1 {
				// Sub-agent returns no text at all.
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
					`{"id":"r","role":"assistant","content":[]}`))}, nil
			}
			body, _ := io.ReadAll(r.Body)
			cr := &model.ChatRequest{}
			assert.NoError(t, json.Unmarshal(body, cr))
			last := cr.Messages[len(cr.Messages)-1]
			assert.NotNil(t, last.ContentBlocks[0].ToolResult)
			assert.True(t, last.ContentBlocks[0].ToolResult.IsError)
			assert.Contains(t, last.ContentBlocks[0].ToolResult.Content[0].Text, "ERROR_DELEGATION_NO_RESULT")
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
				`{"id":"r","role":"assistant","content":[{"type":"text","text":"acknowledged"}]}`))}, nil
		}).Times(2)

		ac := newDelegationSyncCoordinator(mockAssistantstore, mockIO)
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		resp, err := ac.ToolInSession(ctx, req(), "delegate_to_Hunter")
		assert.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "acknowledged", resp[0].ContentBlocks[0].Text)
	})
}

func TestAssistantCoordinator_StartDelegation_ErrorPaths(t *testing.T) {
	kickoff := model.DelegationKickoff{
		ChildSessionId: "child-1",
		ChildModel:     "test-model@MyAdapter",
		Objective:      "find DNS beacons",
		AgentName:      "Hunter",
	}
	toolReq := func() *model.ToolRequest {
		return &model.ToolRequest{SessionId: "parent-session", ToolUseId: "delegate-tooluse", Model: "AgentClaude@SOAI"}
	}

	t.Run("create child session error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(errors.New("create failed"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.startDelegation(ctx, toolReq(), kickoff)
		assert.Error(t, err)
	})

	t.Run("save objective error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save failed"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.startDelegation(ctx, toolReq(), kickoff)
		assert.Error(t, err)
	})

	t.Run("upstream stream error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(nil, errors.New("network error"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.startDelegation(ctx, toolReq(), kickoff)
		assert.Error(t, err)
	})

	t.Run("finalize persists the sub-agent's assistant message", func(t *testing.T) {
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

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		turn, err := ac.startDelegation(ctx, toolReq(), kickoff)
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
	})
}

func TestAssistantCoordinator_ContinueWithToolResult_ErrorPaths(t *testing.T) {
	const sessionId = "session-continue-err"
	toolMsg := func() *model.Message {
		return buildToolResultMessage("tu1", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)
	}

	t.Run("history load error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(nil, errors.New("network error"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.continueWithToolResult(ctx, sessionId, "test-model@MyAdapter", toolMsg())
		assert.Error(t, err)
	})

	t.Run("upstream stream error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(nil, errors.New("network error"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.continueWithToolResult(ctx, sessionId, "test-model@MyAdapter", toolMsg())
		assert.Error(t, err)
	})

	t.Run("save tool_result error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("data: stream")),
		}, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save failed"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.continueWithToolResult(ctx, sessionId, "test-model@MyAdapter", toolMsg())
		assert.Error(t, err)
	})
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
		modelId     string
		adapterName string
		expectError bool
	}{
		{
			name:        "no model params found, skip check",
			req:         &model.ChatRequest{System: strings.Repeat("a", 10000)},
			models:      []model.ModelParameters{},
			modelId:     "unknown",
			adapterName: "SOAI",
			expectError: false,
		},
		{
			name: "charsPerTokenEstimate is zero, skip check",
			req:  &model.ChatRequest{System: strings.Repeat("a", 10000)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", ContextLimitSmall: 1000, CharsPerTokenEstimate: 0},
			},
			modelId:     "model1",
			adapterName: "SOAI",
			expectError: false,
		},
		{
			name: "within limit",
			req:  &model.ChatRequest{System: strings.Repeat("a", 100)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", ContextLimitLarge: 1000, CharsPerTokenEstimate: 4.0},
			},
			modelId:     "model1",
			adapterName: "SOAI",
			// maxChars = 1000 * 4.0 * 1.1 = 4400, usedChars = 100
			expectError: false,
		},
		{
			name: "exceeds limit",
			req:  &model.ChatRequest{System: strings.Repeat("a", 5000)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", ContextLimitLarge: 1000, CharsPerTokenEstimate: 4.0},
			},
			modelId:     "model1",
			adapterName: "SOAI",
			// maxChars = 1000 * 4.0 * 1.1 = 4400, usedChars = 5000
			expectError: true,
		},
		{
			name: "falls back to small context limit",
			req:  &model.ChatRequest{System: strings.Repeat("a", 500)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", ContextLimitSmall: 100, CharsPerTokenEstimate: 4.0},
			},
			modelId:     "model1",
			adapterName: "SOAI",
			// maxChars = 100 * 4.0 * 1.1 = 440, usedChars = 500
			expectError: true,
		},
		{
			name: "context limits both zero, skip check",
			req:  &model.ChatRequest{System: strings.Repeat("a", 10000)},
			models: []model.ModelParameters{
				{ID: "model1", Adapter: "SOAI", CharsPerTokenEstimate: 4.0},
			},
			modelId:     "model1",
			adapterName: "SOAI",
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

			err := ac.checkRequestSize(tc.req, tc.modelId, tc.adapterName)
			if tc.expectError {
				assert.ErrorIs(t, err, ErrRequestTooLarge)
			} else {
				assert.NoError(t, err)
			}
		})
	}
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

func TestAssistantCoordinator_subSessionOutputBudget(t *testing.T) {
	tests := []struct {
		name              string
		maxSubSession     int
		sessionId         string
		sessions          []*model.AssistantSession
		getErr            error
		expectLookup      bool
		expectedIsSub     bool
		expectedRemaining int
	}{
		{
			name:          "budget disabled does not look up usage",
			maxSubSession: 0,
			sessionId:     "child",
			expectLookup:  false,
		},
		{
			name:          "empty session id does not look up usage",
			maxSubSession: 1000,
			sessionId:     "",
			expectLookup:  false,
		},
		{
			name:          "top-level session is not capped",
			maxSubSession: 1000,
			sessionId:     "top",
			expectLookup:  true,
			sessions: []*model.AssistantSession{
				{SessionId: "top", Usage: &model.SessionUsage{TotalOutputTokens: 500}},
			},
			expectedIsSub: false,
		},
		{
			name:          "sub-session reports remaining output budget",
			maxSubSession: 1000,
			sessionId:     "child",
			expectLookup:  true,
			sessions: []*model.AssistantSession{
				{SessionId: "child", ParentSessionId: "top", Usage: &model.SessionUsage{TotalOutputTokens: 300}},
			},
			expectedIsSub:     true,
			expectedRemaining: 700,
		},
		{
			name:          "exhausted sub-session reports non-positive remaining",
			maxSubSession: 1000,
			sessionId:     "child",
			expectLookup:  true,
			sessions: []*model.AssistantSession{
				{SessionId: "child", ParentSessionId: "top", Usage: &model.SessionUsage{TotalOutputTokens: 1200}},
			},
			expectedIsSub:     true,
			expectedRemaining: -200,
		},
		{
			name:          "sub-session with no usage yet has full budget",
			maxSubSession: 1000,
			sessionId:     "child",
			expectLookup:  true,
			sessions: []*model.AssistantSession{
				{SessionId: "child", ParentSessionId: "top"},
			},
			expectedIsSub:     true,
			expectedRemaining: 1000,
		},
		{
			name:          "lookup error disables the cap",
			maxSubSession: 1000,
			sessionId:     "child",
			expectLookup:  true,
			getErr:        errors.New("boom"),
			expectedIsSub: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
			if tc.expectLookup {
				mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any(), gomock.Any()).Return(tc.sessions, tc.getErr)
			}

			ac := &AssistantCoordinator{
				srv:                 &server.Server{Assistantstore: mockAssistantstore},
				maxSubSessionTokens: tc.maxSubSession,
			}

			isSub, remaining := ac.subSessionOutputBudget(context.Background(), tc.sessionId)

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

	// The sub-session has already spent its budget (1000 > 500).
	mockAssistantstore.EXPECT().
		GetSessions(gomock.Any(), gomock.Any(), gomock.Any()).
		Return([]*model.AssistantSession{
			{SessionId: "child", ParentSessionId: "parent", Usage: &model.SessionUsage{TotalOutputTokens: 1000}},
		}, nil)

	// Exactly two writes: the pending tool result, then the halt notice. No model call.
	mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	ac := &AssistantCoordinator{
		srv:                 &server.Server{Assistantstore: mockAssistantstore},
		maxSubSessionTokens: 500,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
	toolMsg := buildToolResultMessage("tu_1", &model.ToolResponse{ToolName: "x", Result: "r"}, nil)

	resp, err := ac.continueWithToolResultSync(ctx, "child", "model@Adapter", toolMsg)

	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "assistant", resp[0].Role)
	assert.Contains(t, messageText(resp[0]), "halted")
}
