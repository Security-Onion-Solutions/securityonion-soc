// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/mock"
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := buildToolConfig(tc.functions)

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

				// Verify tools are sorted alphabetically (if multiple)
				if tc.expectedLength > 1 {
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
		setupMocks     func(*mock.MockTool)
		expectedResult *model.ToolResponse
		expectedError  error
	}{
		{
			name:     "successful tool execution",
			toolName: "test_tool",
			params:   `{"param1": "value1"}`,
			setupMocks: func(mockTool *mock.MockTool) {
				mockTool.EXPECT().Execute(gomock.Any(), gomock.Any(), `{"param1": "value1"}`).Return(&model.ToolResponse{
					ToolName:       "test_tool",
					OnBehalfOfUser: "test-user",
					Result:         "success",
				}, nil)
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
			setupMocks:     func(mockTool *mock.MockTool) {},
			expectedResult: nil,
			expectedError:  ErrToolNotFound,
		},
		{
			name:     "tool execution error",
			toolName: "failing_tool",
			params:   `{"param1": "value1"}`,
			setupMocks: func(mockTool *mock.MockTool) {
				mockTool.EXPECT().Execute(gomock.Any(), gomock.Any(), `{"param1": "value1"}`).Return(nil, errors.New("tool execution failed"))
			},
			expectedResult: nil,
			expectedError:  errors.New("tool execution failed"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTool := mock.NewMockTool(ctrl)
			tc.setupMocks(mockTool)

			srv := &server.Server{}
			ac := &AssistantCoordinator{
				srv: srv,
				FunctionLibrary: map[string]Tool{
					"test_tool":    mockTool,
					"failing_tool": mockTool,
				},
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			result, err := ac.ExecuteTool(ctx, tc.toolName, tc.params)

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
				responseBody := `{"credit_balance": 100.50, "api_key": "key", "key_id": "id", "company_id": "company", "status": "status"}`
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(responseBody)),
				}, nil)
			},
			expectedResult: &model.BalanceResponse{
				Balance:   100.50,
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

			ac := &AssistantCoordinator{
				apiUrl:    tc.apiUrl,
				IOManager: mockIO,
			}

			ctx := context.Background()

			result, err := ac.Balance(ctx)

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

func TestAssistantCoordinator_Chat(t *testing.T) {
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
			mockTool := mock.NewMockTool(ctrl)

			tc.setupMocks(mockIO, mockAssistantstore)

			// Setup tool mock for auto-execute cases
			if len(tc.chatOpts) > 0 {
				mockTool.EXPECT().Execute(gomock.Any(), gomock.Any(), gomock.Any()).Return(&model.ToolResponse{
					ToolName:       "test_tool",
					OnBehalfOfUser: "test-user",
					Result:         "tool result",
				}, nil).AnyTimes()
			}

			srv := &server.Server{
				Assistantstore: mockAssistantstore,
			}

			ac := &AssistantCoordinator{
				srv:       srv,
				apiUrl:    tc.apiUrl,
				IOManager: mockIO,
				FunctionLibrary: map[string]Tool{
					"test_tool": mockTool,
				},
				toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			result, err := ac.Chat(ctx, tc.messages, tc.chatOpts...)

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

func TestAssistantCoordinator_ChatStream(t *testing.T) {
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
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("data: streaming response")),
				}, nil)
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

			ac := &AssistantCoordinator{
				apiUrl:     tc.apiUrl,
				IOManager:  mockIO,
				toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			result, err := ac.ChatStream(ctx, tc.messages)

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

// Helper types and functions for testing

type mockTool struct {
	name        string
	description string
	schema      model.JSONSchema
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

func (m *mockTool) Execute(ctx context.Context, srv *server.Server, params string) (*model.ToolResponse, error) {
	return &model.ToolResponse{
		ToolName: m.name,
		Result:   "mock result",
	}, nil
}
