// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// MockElasticEventstore is a mock that implements both Eventstore and EventstoreUpdater
type MockElasticEventstore struct {
	*mock.MockEventstore
	addUpdateScriptsCalled bool
	updateFunc             func(context.Context, *model.EventUpdateCriteria) (*model.EventUpdateResults, error)
}

func (m *MockElasticEventstore) AddUpdateScripts(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, ack bool, esc bool, inv bool, userId string, sessionId ...string) {
	m.addUpdateScriptsCalled = true
	// Add a dummy script to simulate the behavior
	updateCriteria.AddUpdateScript("ctx._source.event.investigated = true")
}

func (m *MockElasticEventstore) Update(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, criteria)
	}
	return m.MockEventstore.Update(ctx, criteria)
}

func TestPostChat(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.AssistantManager = mockManager
	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data with sessionId (history is now looked up by sessionId)
	sessionId := "test-session-123"
	requestBody := map[string]interface{}{
		"msg":       "What is my current balance?",
		"sessionId": sessionId,
		"model":     "test-model",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock the history lookup to return previous messages
	mockHistoryMessages := []*model.StoredMessage{
		{
			SessionId: sessionId,
			Message: &model.Message{
				Role: "user",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "Hello, I need help with my account",
					},
				},
			},
		},
		{
			SessionId: sessionId,
			Message: &model.Message{
				Role: "assistant",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "I'd be happy to help you with your account. What specific information do you need?",
					},
				},
			},
		},
	}

	mockAssistantStore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(mockHistoryMessages, nil)

	// Set up mock expectations
	var capturedMessages []*model.Message
	mockManager.EXPECT().Chat(gomock.Any(), "test-model", gomock.Any()).DoAndReturn(
		func(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error) {
			assert.Len(t, opts, 0)
			capturedMessages = messages

			return []*model.Message{{
				Role: "assistant",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "Mock response with history",
					},
				},
			}}, nil
		},
	)

	mockAssistantStore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify that the mock received the correct number of messages
	expectedMessageCount := 3 // 2 from history + 1 new user message
	assert.Len(t, capturedMessages, expectedMessageCount)

	// Verify the last message is the new user message
	lastMessage := capturedMessages[len(capturedMessages)-1]
	assert.Equal(t, "user", lastMessage.Role)
	assert.Equal(t, "What is my current balance?", lastMessage.ContentBlocks[0].Text)

	// Verify history is preserved - first message should be user from history
	assert.Equal(t, "user", capturedMessages[0].Role)
	assert.Equal(t, "Hello, I need help with my account", capturedMessages[0].ContentBlocks[0].Text)
}

func TestPostChatWithoutHistory(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.AssistantManager = mockManager
	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data without sessionId (new session)
	requestBody := map[string]interface{}{
		"msg":   "Hello",
		"model": "test-model",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetChatHistory to return empty history for new session (will generate new sessionId)
	mockAssistantStore.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{}, nil)
	mockAssistantStore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)

	// Set up mock expectations
	var capturedMessages []*model.Message
	mockManager.EXPECT().Chat(gomock.Any(), "test-model", gomock.Any()).DoAndReturn(
		func(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error) {
			assert.Len(t, opts, 0)
			capturedMessages = messages

			return []*model.Message{{
				Role: "assistant",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "Mock response",
					},
				},
			}}, nil
		},
	)

	mockAssistantStore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify that the mock received exactly 1 message (new session with no history)
	expectedMessageCount := 1
	assert.Len(t, capturedMessages, expectedMessageCount)

	// Verify the message content
	assert.Equal(t, "user", capturedMessages[0].Role)
	assert.Equal(t, "Hello", capturedMessages[0].ContentBlocks[0].Text)
}

func TestPostChatUnauthorized(t *testing.T) {
	// Create mock server with unauthorized user
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: false},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.AssistantManager = mockManager
	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	requestBody := map[string]any{
		"msg": "Hello",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPostTool(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.AssistantManager = mockManager
	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"
	toolUseId := "tooluse_test_123"
	requestBody := model.ToolRequest{
		SessionId: sessionId,
		ToolUseId: toolUseId,
		Params:    json.RawMessage(`{"query": "test query"}`),
		Model:     "test-model",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/assistant/tool/query_events", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Set URL param for tool name
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "query_events")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock the tool execution
	mockToolResponse := &model.ToolResponse{
		ToolName: "query_events",
		Result:   map[string]interface{}{"events": []string{"event1", "event2"}},
	}
	mockManager.EXPECT().ExecuteTool(gomock.Any(), "query_events", `{"query":"test query"}`, "").Return(mockToolResponse, nil)

	// Mock saving the tool result message
	mockAssistantStore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Do(
		func(ctx context.Context, msg *model.StoredMessage) {
			assert.Equal(t, sessionId, msg.SessionId)
			assert.Equal(t, []string{"tool_result"}, msg.Tags)
			assert.Equal(t, "user", msg.Message.Role)
			assert.Len(t, msg.Message.ContentBlocks, 1)
			assert.NotNil(t, msg.Message.ContentBlocks[0].ToolResult)
			assert.Equal(t, "tooluse_test_123", msg.Message.ContentBlocks[0].ToolResult.ToolUseId)
			assert.False(t, msg.Message.ContentBlocks[0].ToolResult.IsError)
			assert.Equal(t, map[string]any{"result": mockToolResponse.Result}, msg.Message.ContentBlocks[0].ToolResult.Content[0].Json)
		},
	).Return(nil)

	// Mock the history lookup to return previous messages including the new tool result
	mockHistoryMessages := []*model.StoredMessage{
		{
			SessionId: sessionId,
			Message: &model.Message{
				Role: "user",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "Get me some events",
					},
				},
			},
		},
		{
			SessionId: sessionId,
			Message: &model.Message{
				Role: "user",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "tool_result",
						ToolResult: &model.ToolResult{
							ToolUseId: toolUseId,
							Content: []model.ToolResultContent{
								{
									Json: map[string]any{"result": mockToolResponse.Result},
								},
							},
							IsError: false,
						},
					},
				},
			},
		},
	}
	mockAssistantStore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(mockHistoryMessages, nil)

	// Mock the chat response after tool execution
	var capturedMessages []*model.Message
	mockManager.EXPECT().Chat(gomock.Any(), "test-model", gomock.Any()).DoAndReturn(
		func(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error) {
			capturedMessages = messages
			return []*model.Message{{
				Role: "assistant",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "I found 2 events for you based on your query.",
					},
				},
			}}, nil
		},
	)

	// Mock saving the assistant response
	mockAssistantStore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Do(
		func(ctx context.Context, msg *model.StoredMessage) {
			assert.Equal(t, sessionId, msg.SessionId)
			assert.Nil(t, msg.Tags)
			assert.Equal(t, "assistant", msg.Message.Role)
			assert.Len(t, msg.Message.ContentBlocks, 1)
			assert.Equal(t, "text", msg.Message.ContentBlocks[0].Type)
			assert.Equal(t, "I found 2 events for you based on your query.", msg.Message.ContentBlocks[0].Text)
		},
	).Return(nil)

	// Execute the handler
	handler.PostTool(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify that the chat was called with the correct number of messages
	assert.Len(t, capturedMessages, 2)

	// Verify the tool result message was included
	toolResultMsg := capturedMessages[1]
	assert.Equal(t, "user", toolResultMsg.Role)
	assert.NotNil(t, toolResultMsg.ContentBlocks[0].ToolResult)
	assert.Equal(t, toolUseId, toolResultMsg.ContentBlocks[0].ToolResult.ToolUseId)
	assert.Equal(t, map[string]any{"result": mockToolResponse.Result}, toolResultMsg.ContentBlocks[0].ToolResult.Content[0].Json)
}

func TestGetBalance(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
		Config: &config.ServerConfig{
			AirgapEnabled: false,
		},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	defer ctrl.Finish()

	srv.AssistantManager = mockManager

	handler := NewAssistantHandler(srv)

	req := httptest.NewRequest("GET", "/assistant/balance", nil)

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Set up mock expectations
	mockManager.EXPECT().Health(gomock.Any(), gomock.Any()).Return(&model.HealthResponse{Status: "healthy"}, nil)
	mockManager.EXPECT().Balance(gomock.Any(), gomock.Any()).Return(&model.BalanceResponse{Balance: 10000}, nil)

	// Execute the handler
	handler.GetBalance(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// assert response value
	var response model.BalanceResponse

	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, int64(10000), response.Balance)
	assert.Equal(t, "healthy", response.HealthStatus)
}

func TestGetBalanceUnhealthy(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
		Config: &config.ServerConfig{
			AirgapEnabled: false,
		},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	defer ctrl.Finish()

	srv.AssistantManager = mockManager

	handler := NewAssistantHandler(srv)

	req := httptest.NewRequest("GET", "/assistant/balance", nil)

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Set up mock expectations
	mockManager.EXPECT().Health(gomock.Any(), gomock.Any()).Return(nil, errors.New("service unreachable"))

	// Execute the handler
	handler.GetBalance(w, req)

	// Verify response
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
func TestGetBalanceAirgapEnabled(t *testing.T) {
	// Create mock server with airgap enabled
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
		Config: &config.ServerConfig{
			AirgapEnabled: true,
		},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	defer ctrl.Finish()

	srv.AssistantManager = mockManager

	handler := NewAssistantHandler(srv)

	req := httptest.NewRequest("GET", "/assistant/balance", nil)

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// No mock expectations needed - should return early due to airgap

	// Execute the handler
	handler.GetBalance(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, []byte("\"ERROR_SERVICE_NOT_AVAILABLE\""), w.Body.Bytes())
}

func TestGetUsage(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	params := url.Values{
		"range":    {"2025-01-01 00:00:00 - 2025-01-31 23:59:59"},
		"format":   {"2006-01-02 15:04:05"},
		"timezone": {"UTC"},
	}

	params.Encode()

	req := httptest.NewRequest("POST", "/assistant/admin/stats?"+params.Encode(), nil)
	req.Header.Set("Content-Type", "application/json")

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock expected usage data
	expectedUsage := []*model.UserUsage{
		{
			UserId:            "user-1",
			TotalInputTokens:  1000,
			TotalOutputTokens: 2000,
			TotalCredits:      150,
			TotalMessages:     100,
			TotalSessions:     10,
		},
		{
			UserId:            "user-2",
			TotalInputTokens:  500,
			TotalOutputTokens: 1000,
			TotalCredits:      75,
			TotalMessages:     5,
			TotalSessions:     1,
		},
	}

	// Set up mock expectations
	mockAssistantStore.EXPECT().GetUsage(gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedUsage, nil)

	// Execute the handler
	handler.GetUsage(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response body contains expected usage data
	var responseUsage []*model.UserUsage
	err := json.Unmarshal(w.Body.Bytes(), &responseUsage)
	assert.NoError(t, err)
	assert.Equal(t, expectedUsage, responseUsage)
}

func TestManageSessionHistory(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	userId := "test-user-123"
	sessionId := "test-session-456"

	req := httptest.NewRequest("GET", fmt.Sprintf("/assistant/admin/%s/%s", userId, sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("userId", userId)
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "admin-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-789")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock session data
	mockSessions := []*model.AssistantSession{
		{
			Auditable: model.Auditable{
				UserId: userId,
			},
			SessionId: sessionId,
		},
	}

	// Mock history data
	mockHistory := []*model.StoredMessage{
		{
			SessionId: sessionId,
			Message: &model.Message{
				Role: "user",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "What are my recent alerts?",
					},
				},
			},
		},
		{
			SessionId: sessionId,
			Message: &model.Message{
				Role: "assistant",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "Let me check your recent alerts for you.",
					},
				},
			},
		},
	}

	// Set up mock expectations
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
	).Return(mockSessions, nil)

	mockAssistantStore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(mockHistory, nil)

	// Execute the handler
	handler.ManageSessionHistory(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response body
	var responseHistory []*model.StoredMessage
	err := json.Unmarshal(w.Body.Bytes(), &responseHistory)
	assert.NoError(t, err)
	assert.Equal(t, mockHistory, responseHistory)
}

func TestManageSessionHistoryNotFound(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	userId := "test-user-123"
	sessionId := "nonexistent-session"

	req := httptest.NewRequest("GET", fmt.Sprintf("/assistant/admin/%s/%s", userId, sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("userId", userId)
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "admin-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-789")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetSessions to return empty result
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{}, nil)

	// Execute the handler
	handler.ManageSessionHistory(w, req)

	// Verify response
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestManageSessionHistoryUnauthorized(t *testing.T) {
	// Create mock server with unauthorized user
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: false},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	userId := "test-user-123"
	sessionId := "test-session-456"

	req := httptest.NewRequest("GET", fmt.Sprintf("/assistant/admin/%s/%s", userId, sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("userId", userId)
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "unauthorized-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-789")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the handler
	handler.ManageSessionHistory(w, req)

	// Verify response
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUnstreamResponse(t *testing.T) {
	data := `data: {"type":"message_start","message":{"id":"assistant","type":"message","role":"assistant","content":[],"model":"us.anthropic.claude-sonnet-4-20250514-v1:0","stop_reason":null,"stop_sequence":null}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I'll get"}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" your 5 newest alerts for you"}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":". Since you're"}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" asking for the \"newest\" alerts, I'll query"}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" for recent individual alert"}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" events without grouping."}}

data: {"type":"content_block_stop","index":0}

data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tooluse_9xXi7Q0YQG-LjR-ezEZYqQ","name":"query_events","input":{}}}

data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":""}}

data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"oql_query"}}

data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\": \"tags:"}}

data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"ale"}}

data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"rt\""}}

data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":", \"limit\""}}

data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":": 5}"}}

data: {"type":"content_block_stop","index":1}

data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null}}

data: {"type":"message_delta","usage":{"input_tokens":3031,"output_tokens":111,"credits":3586}}

data: {"type":"message_stop"}

data: [DONE]`

	msg, err := unstreamResponse(context.Background(), data, nil)

	assert.NoError(t, err)
	assert.NotNil(t, msg)
	assert.Equal(t, model.Message{
		Id:   "assistant",
		Role: "assistant",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: `I'll get your 5 newest alerts for you. Since you're asking for the "newest" alerts, I'll query for recent individual alert events without grouping.`,
			},
			{
				Type:  "tool_use",
				Id:    "tooluse_9xXi7Q0YQG-LjR-ezEZYqQ",
				Name:  "query_events",
				Input: json.RawMessage(`{"oql_query": "tags:alert", "limit": 5}`),
			},
		},
		StopReason: util.Ptr("tool_use"),
		Usage: &model.Usage{
			InputTokens:  3031,
			OutputTokens: 111,
			Credits:      3586,
		},
	}, *msg)
}

func TestHistoryToContext(t *testing.T) {
	tests := []struct {
		name            string
		history         []*model.StoredMessage
		expectedContext []*model.Message
	}{
		{
			name: "simple history, no compression",
			history: []*model.StoredMessage{
				{
					Message: &model.Message{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello"},
						},
					},
				},
				{
					Message: &model.Message{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hi there! How can I assist you?"},
						},
					},
				},
			},
			expectedContext: []*model.Message{
				{
					Role: "user",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hello"},
					},
				},
				{
					Role: "assistant",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Hi there! How can I assist you?"},
					},
				},
			},
		},
		{
			name: "compressed history",
			history: []*model.StoredMessage{
				{
					Message: &model.Message{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello"},
						},
					},
				},
				{
					Message: &model.Message{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hi there! How can I assist you?"},
						},
					},
					Tags: []string{"something_else"},
				},
				{
					Message: &model.Message{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Can you do a thing for me?"},
						},
					},
				},
				{
					Message: &model.Message{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Sure thing, that generated a lot of data"},
						},
					},
				},
				{
					Message: &model.Message{
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Compress it"},
						},
					},
					Tags: []string{model.MessageTagContextCompression},
				},
				{
					Message: &model.Message{
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Less data"},
						},
					},
				},
			},
			expectedContext: []*model.Message{
				{
					Role: "user",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Compress it"},
					},
				},
				{
					Role: "assistant",
					ContentBlocks: []model.ContentBlock{
						{Type: "text", Text: "Less data"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextMessages := historyToContext(tt.history)
			assert.Equal(t, tt.expectedContext, contextMessages)
		})
	}
}

func TestCheckAssistantAvailable_AirgapEnabled(t *testing.T) {
	// Create mock server with airgap enabled
	srv := &Server{
		Config: &config.ServerConfig{
			AirgapEnabled: true,
		},
	}

	handler := NewAssistantHandler(srv)

	req := httptest.NewRequest("GET", "/assistant/test", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the check
	result := handler.checkAssistantAvailable(ctx, w, req)

	// Verify result is false
	assert.False(t, result)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, []byte("\"ERROR_SERVICE_NOT_AVAILABLE\""), w.Body.Bytes())
}

func TestCheckAssistantAvailable_AirgapDisabled(t *testing.T) {
	// Create mock server with airgap disabled
	srv := &Server{
		Config: &config.ServerConfig{
			AirgapEnabled: false,
		},
	}

	handler := NewAssistantHandler(srv)

	req := httptest.NewRequest("GET", "/assistant/test", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the check
	result := handler.checkAssistantAvailable(ctx, w, req)

	// Verify result is true
	assert.True(t, result)

	// Verify no response was written
	assert.Nil(t, w.Body.Bytes())
}

func TestGetSessionDetails(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"

	req := httptest.NewRequest("GET", fmt.Sprintf("/assistant/sessions/%s", sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock session data
	mockSessions := []*model.AssistantSession{
		{
			Auditable: model.Auditable{
				UserId: "test-user-123",
			},
			SessionId: sessionId,
			Title:     "Test Session",
		},
	}

	// Mock history data
	mockHistory := []*model.StoredMessage{
		{
			SessionId: sessionId,
			Message: &model.Message{
				Role: "user",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "Hello, can you help me?",
					},
				},
			},
		},
		{
			SessionId: sessionId,
			Message: &model.Message{
				Role: "assistant",
				ContentBlocks: []model.ContentBlock{
					{
						Type: "text",
						Text: "Of course! How can I assist you today?",
					},
				},
			},
		},
	}

	// Set up mock expectations
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
	).DoAndReturn(func(ctx context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
		opt := &model.GetSessionsOpts{}
		for _, o := range opts {
			o(opt)
		}

		assert.Equal(t, sessionId, opt.SessionId())
		assert.True(t, opt.IncludeDeleted())
		assert.True(t, opt.Usage())

		return mockSessions, nil
	})

	mockAssistantStore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(mockHistory, nil)

	// Execute the handler
	handler.GetSessionDetails(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response body
	var responseDetails model.AssistantSessionDetails
	err := json.Unmarshal(w.Body.Bytes(), &responseDetails)
	assert.NoError(t, err)
	assert.Equal(t, mockSessions[0], responseDetails.Session)
	assert.Equal(t, mockHistory, responseDetails.History)
}

func TestGetSessionDetailsNotFound(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "nonexistent-session"

	req := httptest.NewRequest("GET", fmt.Sprintf("/assistant/sessions/%s", sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetSessions to return empty result
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{}, nil)

	// Execute the handler
	handler.GetSessionDetails(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify response body returns empty session details
	var responseDetails model.AssistantSessionDetails
	err := json.Unmarshal(w.Body.Bytes(), &responseDetails)
	assert.NoError(t, err)
	assert.Nil(t, responseDetails.Session)
	assert.Nil(t, responseDetails.History)
}

func TestGetSessionDetailsMissingSessionId(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	req := httptest.NewRequest("GET", "/assistant/sessions/", nil)

	// Set URL params with empty sessionId
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the handler
	handler.GetSessionDetails(w, req)

	// Verify response
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSessionDetailsUnauthorized(t *testing.T) {
	// Create mock server with unauthorized user
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: false},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"

	req := httptest.NewRequest("GET", fmt.Sprintf("/assistant/sessions/%s", sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "unauthorized-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the handler
	handler.GetSessionDetails(w, req)

	// Verify response
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateSession(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"
	requestBody := model.UpdateSessionRequest{
		Action: "add",
		Tag:    "case-1234",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/assistant/sessions/%s", sessionId), bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock existing session data
	mockSession := []*model.AssistantSession{
		{
			Auditable: model.Auditable{
				UserId: "test-user-123",
			},
			SessionId: sessionId,
			Title:     "Test Session",
			Tags:      []string{"existing-tag"},
		},
	}

	// Set up mock expectations
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return(mockSession, nil)

	mockAssistantStore.EXPECT().UpdateSessionTags(
		gomock.Any(),
		sessionId,
		[]string{"existing-tag", "case-1234"},
	).Return(nil)

	// Execute the handler
	handler.UpdateSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestUpdateSessionRemoveTag(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	mockCaseStore := mock.NewMockCasestore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore
	srv.Casestore = mockCaseStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"
	requestBody := model.UpdateSessionRequest{
		Action: "remove",
		Tag:    "case-1234",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/assistant/sessions/%s", sessionId), bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock existing session data with the tag to remove
	mockSession := []*model.AssistantSession{
		{
			Auditable: model.Auditable{
				UserId: "test-user-123",
			},
			SessionId: sessionId,
			Title:     "Test Session",
			Tags:      []string{"case-1234", "other-tag"},
		},
	}

	// Set up mock expectations
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return(mockSession, nil)

	// Mock that the session is not attached to any cases
	mockCaseStore.EXPECT().GetCaseIdsWithArtifact(
		gomock.Any(),
		"assistant_chat",
		sessionId,
	).Return([]string{}, nil)

	mockAssistantStore.EXPECT().UpdateSessionTags(
		gomock.Any(),
		sessionId,
		[]string{"other-tag"},
	).Return(nil)

	// Execute the handler
	handler.UpdateSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestUpdateSessionNotFound(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "nonexistent-session"
	requestBody := model.UpdateSessionRequest{
		Action: "add",
		Tag:    "case-1234",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/assistant/sessions/%s", sessionId), bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetSessions to return empty result
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{}, nil)

	// Execute the handler
	handler.UpdateSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateSessionUnauthorized(t *testing.T) {
	// Create mock server with unauthorized user
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: false},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"
	requestBody := model.UpdateSessionRequest{
		Action: "add",
		Tag:    "case-1234",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/assistant/sessions/%s", sessionId), bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "unauthorized-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the handler
	handler.UpdateSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestUpdateSessionMissingSessionId(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	requestBody := model.UpdateSessionRequest{
		Action: "add",
		Tag:    "case-1234",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("PUT", "/assistant/sessions/", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Set URL params with empty sessionId
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the handler
	handler.UpdateSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateSessionTagAlreadyExists(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"
	requestBody := model.UpdateSessionRequest{
		Action: "add",
		Tag:    "existing-tag",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/assistant/sessions/%s", sessionId), bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock existing session data with the tag already present
	mockSession := []*model.AssistantSession{
		{
			Auditable: model.Auditable{
				UserId: "test-user-123",
			},
			SessionId: sessionId,
			Title:     "Test Session",
			Tags:      []string{"existing-tag"},
		},
	}

	// Set up mock expectations
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return(mockSession, nil)

	// Execute the handler
	handler.UpdateSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestUpdateSessionRemoveTagAttachedToCase(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	mockCaseStore := mock.NewMockCasestore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore
	srv.Casestore = mockCaseStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"
	requestBody := model.UpdateSessionRequest{
		Action: "remove",
		Tag:    "case-1234",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("PUT", fmt.Sprintf("/assistant/sessions/%s", sessionId), bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock existing session data with the tag to remove
	mockSession := []*model.AssistantSession{
		{
			Auditable: model.Auditable{
				UserId: "test-user-123",
			},
			SessionId: sessionId,
			Title:     "Test Session",
			Tags:      []string{"case-1234"},
		},
	}

	// Set up mock expectations
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return(mockSession, nil)

	// Mock that the session is attached to cases (cannot remove)
	mockCaseStore.EXPECT().GetCaseIdsWithArtifact(
		gomock.Any(),
		"assistant_chat",
		sessionId,
	).Return([]string{"case-1", "case-2"}, nil)

	// Execute the handler
	handler.UpdateSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestRemoveAuxData(t *testing.T) {
	tests := []struct {
		name     string
		messages []*model.StoredMessage
		validate func(t *testing.T, messages []*model.StoredMessage)
	}{
		{
			name:     "nil messages slice",
			messages: nil,
			validate: func(t *testing.T, messages []*model.StoredMessage) {
				// Should not panic
			},
		},
		{
			name:     "empty messages slice",
			messages: []*model.StoredMessage{},
			validate: func(t *testing.T, messages []*model.StoredMessage) {
				// Should not panic
			},
		},
		{
			name: "message with no content blocks",
			messages: []*model.StoredMessage{
				{
					Message: &model.Message{
						Id:            "msg-1",
						Role:          "user",
						ContentBlocks: []model.ContentBlock{},
					},
				},
			},
			validate: func(t *testing.T, messages []*model.StoredMessage) {
				assert.Len(t, messages[0].Message.ContentBlocks, 0)
			},
		},
		{
			name: "message with content blocks but no ThoughtSignature",
			messages: []*model.StoredMessage{
				{
					Message: &model.Message{
						Id:   "msg-1",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello"},
							{Type: "text", Text: "World"},
						},
					},
				},
			},
			validate: func(t *testing.T, messages []*model.StoredMessage) {
				for _, block := range messages[0].Message.ContentBlocks {
					assert.Nil(t, block.ThoughtSignature)
				}
			},
		},
		{
			name: "single message with ThoughtSignature",
			messages: []*model.StoredMessage{
				{
					Message: &model.Message{
						Id:   "msg-1",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "tool_use", Name: "test_tool", ThoughtSignature: []byte("signature1")},
						},
					},
				},
			},
			validate: func(t *testing.T, messages []*model.StoredMessage) {
				assert.Len(t, messages[0].Message.ContentBlocks, 1)
				assert.Nil(t, messages[0].Message.ContentBlocks[0].ThoughtSignature)
			},
		},
		{
			name: "multiple messages with mixed content blocks",
			messages: []*model.StoredMessage{
				{
					Message: &model.Message{
						Id:   "msg-1",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Hello", ThoughtSignature: []byte("sig1")},
						},
					},
				},
				{
					Message: &model.Message{
						Id:   "msg-2",
						Role: "assistant",
						ContentBlocks: []model.ContentBlock{
							{Type: "text", Text: "Response", ThoughtSignature: []byte("sig2")},
							{Type: "tool_use", Name: "tool1", ThoughtSignature: []byte("sig3")},
						},
					},
				},
				{
					Message: &model.Message{
						Id:   "msg-3",
						Role: "user",
						ContentBlocks: []model.ContentBlock{
							{Type: "tool_result", ToolResult: &model.ToolResult{}, ThoughtSignature: []byte("sig4")},
						},
					},
				},
			},
			validate: func(t *testing.T, messages []*model.StoredMessage) {
				for _, msg := range messages {
					for _, block := range msg.Message.ContentBlocks {
						assert.Nil(t, block.ThoughtSignature, "ThoughtSignature should be nil for all blocks")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the function
			removeAuxData(tt.messages)

			// Validate the results
			tt.validate(t, tt.messages)
		})
	}
}

func TestPostChatWithEntityTypeAndId(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddUpdateScripts
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return &model.EventUpdateResults{
				UpdatedCount:   1,
				UnchangedCount: 0,
			}, nil
		},
	}

	srv.AssistantManager = mockManager
	srv.Assistantstore = mockAssistantStore
	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	// Test data with entityType and entityId
	entityType := "alert_investigation"
	entityId := "alert-123"
	requestBody := map[string]interface{}{
		"msg":   "Investigate this alert",
		"model": "test-model",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/assistant/chat?entityType="+entityType+"&entityId="+entityId, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetChatHistory to return empty history for new session
	mockAssistantStore.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{}, nil)

	// Mock CreateSession - verify it's called with investigation type
	mockAssistantStore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, session *model.AssistantSession) error {
			assert.Equal(t, entityType, session.Type)
			assert.Equal(t, entityId, session.EntityId)
			return nil
		},
	)

	// Mock Chat
	mockManager.EXPECT().Chat(gomock.Any(), "test-model", gomock.Any()).Return([]*model.Message{{
		Role: "assistant",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: "I'll help you investigate this alert",
			},
		},
	}}, nil)

	mockAssistantStore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPostChatWithEntityTypeAndIdMarkFails(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddUpdateScripts but fails on Update
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return nil, errors.New("update failed")
		},
	}

	srv.AssistantManager = mockManager
	srv.Assistantstore = mockAssistantStore
	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	// Test data with entityType and entityId
	entityType := "alert_investigation"
	entityId := "alert-123"
	requestBody := map[string]interface{}{
		"msg":   "Investigate this alert",
		"model": "test-model",
	}

	jsonBody, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/assistant/chat?entityType="+entityType+"&entityId="+entityId, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetChatHistory to return empty history for new session
	mockAssistantStore.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{}, nil)

	// Mock CreateSession
	mockAssistantStore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)

	// Mock Chat - should still be called even if marking fails
	mockManager.EXPECT().Chat(gomock.Any(), "test-model", gomock.Any()).Return([]*model.Message{{
		Role: "assistant",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: "I'll help you investigate this alert",
			},
		},
	}}, nil)

	mockAssistantStore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response - should still succeed even though marking failed
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMarkAlertAsInvestigated(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddUpdateScripts
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			// Verify the criteria has the correct query
			assert.NotNil(t, criteria.ParsedQuery)
			return &model.EventUpdateResults{
				UpdatedCount:   1,
				UnchangedCount: 0,
			}, nil
		},
	}

	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	socId := "alert-123"
	sessionId := "session-456"

	// Execute the function
	err := handler.markAlertAsInvestigated(ctx, socId, sessionId)

	// Verify no error
	assert.NoError(t, err)
}

func TestMarkAlertAsInvestigatedUnauthorized(t *testing.T) {
	// Create mock server with unauthorized user
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: false},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	socId := "alert-123"
	sessionId := "session-456"

	// Execute the function
	err := handler.markAlertAsInvestigated(ctx, socId, sessionId)

	// Verify error
	assert.Error(t, err)
}

func TestMarkAlertAsInvestigatedNoAlert(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddUpdateScripts but returns no updates
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return &model.EventUpdateResults{
				UpdatedCount:   0,
				UnchangedCount: 0,
			}, nil
		},
	}

	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	socId := "nonexistent-alert"
	sessionId := "session-456"

	// Execute the function
	err := handler.markAlertAsInvestigated(ctx, socId, sessionId)

	// Verify error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no alert found")
}

func TestDeleteSession(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/assistant/sessions/%s", sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetSessions to return a non-investigation session
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{
		{
			SessionId: sessionId,
			Type:      "general",
		},
	}, nil)

	// Mock DeleteSession
	mockAssistantStore.EXPECT().DeleteSession(gomock.Any(), sessionId).Return(nil)

	// Execute the handler
	handler.DeleteSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteSessionInvestigation(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	mockEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore
	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"
	entityId := "alert-456"

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/assistant/sessions/%s", sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetSessions to return an investigation session
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{
		{
			SessionId: sessionId,
			Type:      "alert_investigation",
			EntityId:  entityId,
		},
	}, nil)

	// Mock the eventstore Update call to clear investigation_session_id
	mockEventStore.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return &model.EventUpdateResults{
				UpdatedCount:   1,
				UnchangedCount: 0,
			}, nil
		},
	)

	// Mock DeleteSession
	mockAssistantStore.EXPECT().DeleteSession(gomock.Any(), sessionId).Return(nil)

	// Execute the handler
	handler.DeleteSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteSessionInvestigationClearFails(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	mockEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore
	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"
	entityId := "alert-456"

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/assistant/sessions/%s", sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Mock GetSessions to return an investigation session
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{
		{
			SessionId: sessionId,
			Type:      "alert_investigation",
			EntityId:  entityId,
		},
	}, nil)

	// Mock the eventstore Update call to fail - should continue with deletion
	mockEventStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil, errors.New("update failed"))

	// Mock DeleteSession - should still be called
	mockAssistantStore.EXPECT().DeleteSession(gomock.Any(), sessionId).Return(nil)

	// Execute the handler
	handler.DeleteSession(w, req)

	// Verify response - should still succeed
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteSessionMissingSessionId(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	req := httptest.NewRequest("DELETE", "/assistant/sessions/", nil)

	// Set URL params with empty sessionId
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user-123")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the handler
	handler.DeleteSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSessionUnauthorized(t *testing.T) {
	// Create mock server with unauthorized user
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: false},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	// Test data
	sessionId := "test-session-123"

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/assistant/sessions/%s", sessionId), nil)

	// Set URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Add required context values
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "unauthorized-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-456")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	// Execute the handler
	handler.DeleteSession(w, req)

	// Verify response
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestClearInvestigationSessionFromAlert(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	socId := "alert-123"
	sessionId := "session-456"

	// Mock the eventstore Update call
	mockEventStore.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			// Verify the criteria has the correct query and script
			assert.NotNil(t, criteria.ParsedQuery)
			assert.NotEmpty(t, criteria.UpdateScripts)
			return &model.EventUpdateResults{
				UpdatedCount:   1,
				UnchangedCount: 0,
			}, nil
		},
	)

	// Execute the function
	err := handler.clearInvestigationSessionFromAlert(ctx, socId, sessionId)

	// Verify no error
	assert.NoError(t, err)
}

func TestClearInvestigationSessionFromAlertUnauthorized(t *testing.T) {
	// Create mock server with unauthorized user
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: false},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	socId := "alert-123"
	sessionId := "session-456"

	// Execute the function
	err := handler.clearInvestigationSessionFromAlert(ctx, socId, sessionId)

	// Verify error
	assert.Error(t, err)
}

func TestClearInvestigationSessionFromAlertUpdateFails(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	socId := "alert-123"
	sessionId := "session-456"

	// Mock the eventstore Update call to fail
	mockEventStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil, errors.New("update failed"))

	// Execute the function
	err := handler.clearInvestigationSessionFromAlert(ctx, socId, sessionId)

	// Verify error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update failed")
}

func TestHandleEntityAssociation(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddUpdateScripts
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return &model.EventUpdateResults{
				UpdatedCount:   1,
				UnchangedCount: 0,
			}, nil
		},
	}

	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	entityType := "alert_investigation"
	entityId := "alert-123"
	sessionId := "session-456"

	// Execute the function
	err := handler.handleEntityAssociation(ctx, entityType, entityId, sessionId)

	// Verify no error
	assert.NoError(t, err)
}

func TestHandleEntityAssociationNonAlertType(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	handler := NewAssistantHandler(srv)

	ctx := context.Background()

	entityType := "other_type"
	entityId := "entity-123"
	sessionId := "session-456"

	// Execute the function - should return nil without doing anything
	err := handler.handleEntityAssociation(ctx, entityType, entityId, sessionId)

	// Verify no error
	assert.NoError(t, err)
}

func TestHandleEntityAssociationMarkFails(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that fails on Update
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return nil, errors.New("update failed")
		},
	}

	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	entityType := "alert_investigation"
	entityId := "alert-123"
	sessionId := "session-456"

	// Execute the function
	err := handler.handleEntityAssociation(ctx, entityType, entityId, sessionId)

	// Verify error is returned
	assert.Error(t, err)
}

func TestHandleInvestigationSessionCleanup(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	mockEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore
	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	sessionId := "session-456"
	entityId := "alert-123"

	// Mock GetSessions to return an investigation session
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{
		{
			SessionId: sessionId,
			Type:      "alert_investigation",
			EntityId:  entityId,
		},
	}, nil)

	// Mock the eventstore Update call
	mockEventStore.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return &model.EventUpdateResults{
				UpdatedCount:   1,
				UnchangedCount: 0,
			}, nil
		},
	)

	// Execute the function
	handler.handleInvestigationSessionCleanup(ctx, sessionId)

	// No assertions needed - function returns void, just verify no panic
}

func TestHandleInvestigationSessionCleanupNonInvestigationSession(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	ctx := context.Background()

	sessionId := "session-456"

	// Mock GetSessions to return a non-investigation session
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{
		{
			SessionId: sessionId,
			Type:      "general",
		},
	}, nil)

	// Execute the function - should not call clearInvestigationSessionFromAlert
	handler.handleInvestigationSessionCleanup(ctx, sessionId)

	// No assertions needed - function returns void, just verify no panic
}

func TestHandleInvestigationSessionCleanupGetSessionsFails(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore

	handler := NewAssistantHandler(srv)

	ctx := context.Background()

	sessionId := "session-456"

	// Mock GetSessions to fail
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return(nil, errors.New("database error"))

	// Execute the function - should handle error gracefully
	handler.handleInvestigationSessionCleanup(ctx, sessionId)

	// No assertions needed - function returns void and logs error, just verify no panic
}

func TestHandleInvestigationSessionCleanupClearFails(t *testing.T) {
	// Create mock server
	srv := &Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: true},
	}
	ctrl := gomock.NewController(t)
	mockAssistantStore := mock.NewMockAssistantstore(ctrl)
	mockEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	srv.Assistantstore = mockAssistantStore
	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	sessionId := "session-456"
	entityId := "alert-123"

	// Mock GetSessions to return an investigation session
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
	).Return([]*model.AssistantSession{
		{
			SessionId: sessionId,
			Type:      "alert_investigation",
			EntityId:  entityId,
		},
	}, nil)

	// Mock the eventstore Update call to fail
	mockEventStore.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil, errors.New("update failed"))

	// Execute the function - should handle error gracefully
	handler.handleInvestigationSessionCleanup(ctx, sessionId)

	// No assertions needed - function returns void and logs error, just verify no panic
}
