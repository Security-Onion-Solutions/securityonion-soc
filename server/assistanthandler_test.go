// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

	expectedText := fmt.Sprintf("ToolUseId: %s, Error: <nil>, Result: %s", toolUseId, `{"events":["event1","event2"]}`)

	// Mock saving the tool result message
	mockAssistantStore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Do(
		func(ctx context.Context, msg *model.StoredMessage) {
			assert.Equal(t, sessionId, msg.SessionId)
			assert.Equal(t, []string{"tool_result"}, msg.Tags)
			assert.Equal(t, "user", msg.Message.Role)
			assert.Len(t, msg.Message.ContentBlocks, 1)
			assert.Equal(t, "text", msg.Message.ContentBlocks[0].Type)
			assert.Equal(t, expectedText, msg.Message.ContentBlocks[0].Text)
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
						Type: "text",
						Text: expectedText,
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
	assert.Contains(t, toolResultMsg.ContentBlocks[0].Text, toolUseId)
	assert.Contains(t, toolResultMsg.ContentBlocks[0].Text, `{"events":["event1","event2"]}`)
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
	mockManager.EXPECT().Health(gomock.Any()).Return(&model.HealthResponse{Status: "healthy"}, nil)
	mockManager.EXPECT().Balance(gomock.Any()).Return(&model.BalanceResponse{Balance: 10000}, nil)

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
	mockManager.EXPECT().Health(gomock.Any()).Return(nil, errors.New("service unreachable"))

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

	msg, err := unstreamResponse(context.Background(), data)

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
