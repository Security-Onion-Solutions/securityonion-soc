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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// MockElasticEventstore is a mock that implements both Eventstore and EventstoreUpdater
type MockElasticEventstore struct {
	*mock.MockEventstore
	addInvestigationUpdateScriptsCalled bool
	updateFunc                          func(context.Context, *model.EventUpdateCriteria) (*model.EventUpdateResults, error)
}

func (m *MockElasticEventstore) AddInvestigationUpdateScripts(updateCriteria *model.EventUpdateCriteria, timeNow time.Time, userId string, isDelete bool, sessionId ...string) {
	m.addInvestigationUpdateScriptsCalled = true
	// Add a dummy script to simulate the behavior
	if isDelete {
		updateCriteria.AddUpdateScript("ctx._source.event.remove('investigation_session_id')")
	} else {
		updateCriteria.AddUpdateScript("ctx._source.event.investigated = true")
	}
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

	mockAssistantStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", sessionId).Return(true, true, nil)

	var capturedIncMsg *model.IncomingMessage
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), "", "").DoAndReturn(
		func(ctx context.Context, incMsg *model.IncomingMessage, entityType, entityId string) ([]*model.Message, error) {
			capturedIncMsg = incMsg
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

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify the handler forwarded the request to ChatInSession unchanged
	assert.Equal(t, sessionId, capturedIncMsg.SessionId)
	assert.Equal(t, "What is my current balance?", capturedIncMsg.Msg)
	assert.Equal(t, "test-model", capturedIncMsg.Model)
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

	mockAssistantStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", gomock.Any()).Return(false, false, nil)

	var capturedIncMsg *model.IncomingMessage
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), "", "").DoAndReturn(
		func(ctx context.Context, incMsg *model.IncomingMessage, entityType, entityId string) ([]*model.Message, error) {
			capturedIncMsg = incMsg

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

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// The handler should auto-generate a session ID for new sessions before
	// dispatching to ChatInSession.
	assert.NotEmpty(t, capturedIncMsg.SessionId)
	assert.Equal(t, "Hello", capturedIncMsg.Msg)
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

	mockAssistantStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", sessionId).Return(true, true, nil)

	var capturedToolReq *model.ToolRequest
	mockManager.EXPECT().ToolInSession(gomock.Any(), gomock.Any(), "query_events").DoAndReturn(
		func(ctx context.Context, toolReq *model.ToolRequest, toolName string) ([]*model.Message, error) {
			capturedToolReq = toolReq
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

	// Execute the handler
	handler.PostTool(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify the handler forwarded the decoded ToolRequest unchanged.
	assert.Equal(t, sessionId, capturedToolReq.SessionId)
	assert.Equal(t, toolUseId, capturedToolReq.ToolUseId)
	assert.Equal(t, "test-model", capturedToolReq.Model)
}

// sseTextResponse builds a minimal SSE body for a text-only assistant turn.
func sseTextResponse(text string) *http.Response {
	body := "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"role\":\"assistant\",\"content\":[]}}\n\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + text + "\"}}\n\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"data: [DONE]\n\n"
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// sseToolUseResponse builds a minimal SSE body for a turn that requests a tool.
func sseToolUseResponse(toolName string) *http.Response {
	body := "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"role\":\"assistant\",\"content\":[]}}\n\n" +
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"" + toolName + "\"}}\n\n" +
		"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
		"data: [DONE]\n\n"
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func newToolStreamRequest(t *testing.T, sessionId, toolName string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	body, _ := json.Marshal(model.ToolRequest{SessionId: sessionId, ToolUseId: "tu1", Model: "test-model"})
	req := httptest.NewRequest("POST", "/assistant/tool/"+toolName, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", toolName)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, "test-user")
	req = req.WithContext(ctx)

	return req, httptest.NewRecorder()
}

func noopFinalize([]byte) error { return nil }

// A top-level tool turn that ends with text (no tool_use) stops the loop without
// resolving any delegation.
func TestPostTool_StreamingTopLevelStops(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockManager := mock.NewMockAssistantManager(ctrl)
	mockStore := mock.NewMockAssistantstore(ctrl)
	srv.AssistantManager = mockManager
	srv.Assistantstore = mockStore

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "top").Return(true, true, nil)

	// The turn carries its session record; it has no parent, so the loop stops
	// without any store lookup.
	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), "query_events").Return(
		&model.StreamedTurn{Response: sseTextResponse("done"), SessionId: "top", Model: "test-model", Finalize: noopFinalize,
			Session: &model.AssistantSession{SessionId: "top"}}, nil)

	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Times(0)
	mockManager.EXPECT().ResolveDelegationStream(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	req, w := newToolStreamRequest(t, "top", "query_events")
	NewAssistantHandler(srv).PostTool(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "done")
	assert.NotContains(t, w.Body.String(), "delegation_resolved")
}

// A sub-agent turn that ends with text is resolved by the backend: the parent's
// resumed turn is streamed on the same response with a delegation_resolved marker.
func TestPostTool_StreamingDelegationResolves(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockManager := mock.NewMockAssistantManager(ctrl)
	mockStore := mock.NewMockAssistantstore(ctrl)
	srv.AssistantManager = mockManager
	srv.Assistantstore = mockStore

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "parent").Return(true, true, nil)

	// First turn: the child sub-agent answers with text only. The turn carries the
	// child's session record with its parent linkage — no store lookups needed.
	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), "query_events").Return(
		&model.StreamedTurn{Response: sseTextResponse("child answer"), SessionId: "child", Model: "sonnet", Finalize: noopFinalize,
			Session: &model.AssistantSession{SessionId: "child", ParentSessionId: "parent", ParentToolUseId: "delegate-tu", ParentModel: "agent"}}, nil)

	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Times(0)

	// The backend resolves the delegation and streams the parent's turn, which
	// carries the parent's (top-level) session record so the loop stops after it.
	mockManager.EXPECT().ResolveDelegationStream(gomock.Any(), gomock.Any(), "child answer").DoAndReturn(
		func(_ context.Context, sess *model.AssistantSession, finalText string) (*model.StreamedTurn, error) {
			assert.Equal(t, "child", sess.SessionId)
			return &model.StreamedTurn{
				Response:  sseTextResponse("parent wrap up"),
				SessionId: "parent",
				Model:     "agent",
				Finalize:  noopFinalize,
				Session:   &model.AssistantSession{SessionId: "parent"},
				Marker:    &model.DelegationMarker{Type: model.DelegationMarkerResolved, ParentSessionId: "parent", ParentToolUseId: "delegate-tu"},
			}, nil
		})

	req, w := newToolStreamRequest(t, "parent", "query_events")
	NewAssistantHandler(srv).PostTool(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	out := w.Body.String()
	assert.Contains(t, out, "child answer")
	assert.Contains(t, out, "delegation_resolved")
	assert.Contains(t, out, "parent wrap up")
}

// When backend resolution of a finished sub-agent fails, the loop still emits a
// delegation_resolved marker so the client un-nests and closes the delegate card
// instead of leaving it spinning forever.
func TestPostTool_StreamingDelegationResolveErrorStillCloses(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockManager := mock.NewMockAssistantManager(ctrl)
	mockStore := mock.NewMockAssistantstore(ctrl)
	srv.AssistantManager = mockManager
	srv.Assistantstore = mockStore

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "parent").Return(true, true, nil)

	// The child sub-agent answers with text only; its turn carries the child's
	// session record with the parent linkage.
	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), "query_events").Return(
		&model.StreamedTurn{Response: sseTextResponse("child answer"), SessionId: "child", Model: "sonnet", Finalize: noopFinalize,
			Session: &model.AssistantSession{SessionId: "child", ParentSessionId: "parent", ParentToolUseId: "delegate-tu", ParentModel: "agent"}}, nil)

	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Times(0)

	// Resolution fails, but the boundary must still be closed on the client.
	mockManager.EXPECT().ResolveDelegationStream(gomock.Any(), gomock.Any(), "child answer").Return(
		nil, errors.New("resolve boom"))

	req, w := newToolStreamRequest(t, "parent", "query_events")
	NewAssistantHandler(srv).PostTool(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	out := w.Body.String()
	assert.Contains(t, out, "child answer")
	// The synthetic resolved marker closes the delegate card despite the failure.
	assert.Contains(t, out, "delegation_resolved")
	assert.Contains(t, out, "delegate-tu")
}

// A turn that requests a tool stops the loop so the client can approve it; no
// delegation resolution is attempted.
func TestPostTool_StreamingToolUseStops(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockManager := mock.NewMockAssistantManager(ctrl)
	mockStore := mock.NewMockAssistantstore(ctrl)
	srv.AssistantManager = mockManager
	srv.Assistantstore = mockStore

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "parent").Return(true, true, nil)

	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), "delegate_to_Hunter").Return(
		&model.StreamedTurn{
			Response:  sseToolUseResponse("query_events"),
			SessionId: "child",
			Model:     "sonnet",
			Finalize:  noopFinalize,
			Marker:    &model.DelegationMarker{Type: model.DelegationMarkerStart, ChildSessionId: "child", ParentToolUseId: "delegate-tu", AgentName: "Hunter"},
		}, nil)

	// Because the turn requested a tool, neither loadSession nor resolution runs.
	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Times(0)
	mockManager.EXPECT().ResolveDelegationStream(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	req, w := newToolStreamRequest(t, "parent", "delegate_to_Hunter")
	NewAssistantHandler(srv).PostTool(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	out := w.Body.String()
	assert.Contains(t, out, "delegation_start")
	assert.Contains(t, out, "tool_use")
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

	// Set up mock expectations; the management view must include memory sessions
	mockAssistantStore.EXPECT().GetSessions(
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
		gomock.Any(),
	).DoAndReturn(func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
		applied := &model.GetSessionsOpts{}
		for _, opt := range opts {
			opt(applied)
		}
		assert.True(t, applied.IncludeMemorySessions())

		return mockSessions, nil
	})

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

	msg, err := UnstreamResponse(context.Background(), data, nil)

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
		gomock.Any(),
	).DoAndReturn(func(ctx context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
		opt := &model.GetSessionsOpts{}
		for _, o := range opts {
			o(opt)
		}

		assert.Equal(t, sessionId, opt.SessionId())
		assert.True(t, opt.IncludeDeleted())
		assert.True(t, opt.Usage())
		assert.True(t, opt.Descendants())

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

func TestGetSessionDetails_WithSubSessions(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	ctrl := gomock.NewController(t)
	mockStore := mock.NewMockAssistantstore(ctrl)
	defer ctrl.Finish()
	srv.Assistantstore = mockStore
	handler := NewAssistantHandler(srv)

	sessionId := "root-1"
	req := httptest.NewRequest("GET", "/assistant/sessions/"+sessionId, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("sessionId", sessionId)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, "test-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request-sub")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// GetSessions returns the root plus a delegated child (descendants opt set).
	root := &model.AssistantSession{SessionId: sessionId, Title: "Root"}
	child := &model.AssistantSession{SessionId: "child-1", Title: "Hunter", ParentSessionId: sessionId, ParentToolUseId: "tu-1", DelegateAgent: "Hunter"}
	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
		[]*model.AssistantSession{root, child}, nil)

	rootHistory := []*model.StoredMessage{{SessionId: sessionId, Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "delegating"}}}}}
	childHistory := []*model.StoredMessage{{SessionId: "child-1", Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "found 3 domains"}}}}}
	mockStore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(rootHistory, nil)
	mockStore.EXPECT().GetChatHistory(gomock.Any(), "child-1").Return(childHistory, nil)

	handler.GetSessionDetails(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var details model.AssistantSessionDetails
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &details))
	assert.Equal(t, sessionId, details.Session.SessionId)
	assert.Len(t, details.History, 1)
	assert.Len(t, details.SubSessions, 1)
	assert.Equal(t, "child-1", details.SubSessions[0].Session.SessionId)
	assert.Equal(t, "tu-1", details.SubSessions[0].Session.ParentToolUseId)
	assert.Len(t, details.SubSessions[0].History, 1)
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

func TestUpdateSessionReservedTag(t *testing.T) {
	type testCase struct {
		Action string
		Tag    string
	}

	cases := []testCase{}
	for _, tag := range model.MemorySessionTags {
		cases = append(cases, testCase{Action: "add", Tag: tag}, testCase{Action: "remove", Tag: tag})
	}

	// guard is case-insensitive
	cases = append(cases, testCase{Action: "add", Tag: "Memory"})

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s-%s", tc.Action, tc.Tag), func(t *testing.T) {
			srv := &Server{
				Authorizer: &rbac.FakeAuthorizer{Authorized: true},
			}
			ctrl := gomock.NewController(t)
			mockAssistantStore := mock.NewMockAssistantstore(ctrl)
			defer ctrl.Finish()

			srv.Assistantstore = mockAssistantStore

			handler := NewAssistantHandler(srv)

			sessionId := "test-session-123"
			requestBody := model.UpdateSessionRequest{
				Action: tc.Action,
				Tag:    tc.Tag,
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

			// No store expectations: any GetSessions/UpdateSessionTags call means
			// the guard fell through and gomock fails the test.
			handler.UpdateSession(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
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

	mockAssistantStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", gomock.Any()).Return(false, false, nil)

	// The handler should forward the entityType/entityId to ChatInSession.
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), entityType, entityId).Return([]*model.Message{{
		Role: "assistant",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: "I'll help you investigate this alert",
			},
		},
	}}, nil)

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

	mockAssistantStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", gomock.Any()).Return(false, false, nil)

	// ChatInSession should still be called even when alert-mark fails.
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), entityType, entityId).Return([]*model.Message{{
		Role: "assistant",
		ContentBlocks: []model.ContentBlock{
			{
				Type: "text",
				Text: "I'll help you investigate this alert",
			},
		},
	}}, nil)

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
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddInvestigationUpdateScripts
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return &model.EventUpdateResults{
				UpdatedCount:   1,
				UnchangedCount: 0,
			}, nil
		},
	}

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
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddInvestigationUpdateScripts but fails on Update
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return nil, errors.New("update failed")
		},
	}

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
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddInvestigationUpdateScripts
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			// Verify the criteria has the correct query and script
			assert.NotNil(t, criteria.ParsedQuery)
			assert.NotEmpty(t, criteria.UpdateScripts)
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
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddInvestigationUpdateScripts but fails on Update
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return nil, errors.New("update failed")
		},
	}

	srv.Eventstore = mockEventStore

	handler := NewAssistantHandler(srv)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	socId := "alert-123"
	sessionId := "session-456"

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
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddInvestigationUpdateScripts
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return &model.EventUpdateResults{
				UpdatedCount:   1,
				UnchangedCount: 0,
			}, nil
		},
	}

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
	mockBaseEventStore := mock.NewMockEventstore(ctrl)
	defer ctrl.Finish()

	// Create custom mock that supports AddInvestigationUpdateScripts but fails on Update
	mockEventStore := &MockElasticEventstore{
		MockEventstore: mockBaseEventStore,
		updateFunc: func(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
			return nil, errors.New("update failed")
		},
	}

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

	// Execute the function - should handle error gracefully
	handler.handleInvestigationSessionCleanup(ctx, sessionId)

	// No assertions needed - function returns void and logs error, just verify no panic
}

// nonFlushResponseWriter implements http.ResponseWriter but deliberately NOT
// http.Flusher, used to exercise the "streaming not supported" branches.
type nonFlushResponseWriter struct {
	header http.Header
	code   int
	buf    bytes.Buffer
}

func (w *nonFlushResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *nonFlushResponseWriter) Write(b []byte) (int, error) { return w.buf.Write(b) }
func (w *nonFlushResponseWriter) WriteHeader(code int)        { w.code = code }

func newAssistantTestServer(t *testing.T, authorized bool) (*Server, *mock.MockAssistantManager, *mock.MockAssistantstore) {
	t.Helper()
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: authorized}}
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	mockManager := mock.NewMockAssistantManager(ctrl)
	mockStore := mock.NewMockAssistantstore(ctrl)
	srv.AssistantManager = mockManager
	srv.Assistantstore = mockStore
	return srv, mockManager, mockStore
}

func withAssistantContext(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request")
	return req.WithContext(ctx)
}

func TestGetSessions(t *testing.T) {
	srv, _, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	// A child (delegated) session must be filtered out of the top-level list.
	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
		applied := &model.GetSessionsOpts{}
		for _, opt := range opts {
			opt(applied)
		}
		// The user-facing list must keep the default memory-session exclusion.
		assert.False(t, applied.IncludeMemorySessions())

		return []*model.AssistantSession{
			{SessionId: "top-1"},
			{SessionId: "child-1", ParentSessionId: "top-1"},
			{SessionId: "top-2"},
		}, nil
	})

	req := withAssistantContext(httptest.NewRequest("GET", "/assistant/sessions", nil))
	w := httptest.NewRecorder()

	handler.GetSessions(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var got []*model.AssistantSession
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 2)
	for _, s := range got {
		assert.Empty(t, s.ParentSessionId)
	}
}

func TestGetSessionsAdmin_IncludesMemorySessions(t *testing.T) {
	srv, _, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
		applied := &model.GetSessionsOpts{}
		for _, opt := range opts {
			opt(applied)
		}
		// The management view returns everything, memory sessions included.
		assert.True(t, applied.IncludeMemorySessions())
		assert.True(t, applied.IncludeDeleted())

		return []*model.AssistantSession{{SessionId: "chat-1-memory", Tags: []string{model.SessionTagMemory}}}, nil
	})

	params := url.Values{
		"range":    {"2025-01-01 00:00:00 - 2025-01-31 23:59:59"},
		"format":   {"2006-01-02 15:04:05"},
		"timezone": {"UTC"},
	}
	req := withAssistantContext(httptest.NewRequest("GET", "/assistant/admin/sessions?"+params.Encode(), nil))
	w := httptest.NewRecorder()

	handler.GetSessionsAdmin(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var got []*model.AssistantSession
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 1)
}

func TestGetSessions_StoreError(t *testing.T) {
	srv, _, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return(nil, errors.New("store unavailable"))

	req := withAssistantContext(httptest.NewRequest("GET", "/assistant/sessions", nil))
	w := httptest.NewRecorder()

	handler.GetSessions(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPostChat_DecodeError(t *testing.T) {
	srv, _, _ := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBufferString("{not valid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPostChat_NonStreamingUpstreamErrors(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{name: "client error surfaces as 400", err: errors.New("ERROR_ASSISTANT_INVALID_MODEL"), wantCode: http.StatusBadRequest},
		{name: "internal error surfaces as 500", err: errors.New("boom"), wantCode: http.StatusInternalServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv, mockManager, mockStore := newAssistantTestServer(t, true)
			handler := NewAssistantHandler(srv)

			mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(true, true, nil)
			mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), "", "").Return(nil, tc.err)

			body, _ := json.Marshal(map[string]any{"msg": "hi", "sessionId": "s1", "model": "m"})
			req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.PostChat(w, req)

			assert.Equal(t, tc.wantCode, w.Code)
		})
	}
}

func TestPostChat_Streaming(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(true, true, nil)
	mockManager.EXPECT().ChatStreamInSession(gomock.Any(), gomock.Any(), "", "").Return(
		sseTextResponse("hello"), &model.AuxMessageData{}, noopFinalize, nil)

	body, _ := json.Marshal(map[string]any{"msg": "hi", "sessionId": "s1", "model": "m"})
	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	w := httptest.NewRecorder()

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "hello")
}

func TestPostChat_StreamingUpstreamError(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(true, true, nil)
	mockManager.EXPECT().ChatStreamInSession(gomock.Any(), gomock.Any(), "", "").Return(
		nil, nil, nil, errors.New("boom"))

	body, _ := json.Marshal(map[string]any{"msg": "hi", "sessionId": "s1", "model": "m"})
	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	w := httptest.NewRecorder()

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDecodeIncomingMessage(t *testing.T) {
	testCases := []struct {
		name          string
		body          string
		wantErr       bool
		wantSessionId string
	}{
		{
			name:          "valid body preserves session id",
			body:          `{"msg":"hi","sessionId":"s1","model":"m"}`,
			wantSessionId: "s1",
		},
		{
			name: "missing session id gets generated",
			body: `{"msg":"hi"}`,
		},
		{
			name:    "malformed body returns an error",
			body:    "{not valid json",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/assistant/chat", bytes.NewBufferString(tc.body))

			incMsg, err := decodeIncomingMessage(req)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, incMsg)
				return
			}

			assert.NoError(t, err)
			if tc.wantSessionId != "" {
				assert.Equal(t, tc.wantSessionId, incMsg.SessionId)
			} else {
				assert.NotEmpty(t, incMsg.SessionId)
			}
		})
	}
}

func TestStreamingAccepted(t *testing.T) {
	testCases := []struct {
		name          string
		accept        string
		wantStreaming bool
		wantAccept    string
	}{
		{name: "text/event-stream enables streaming", accept: "text/event-stream", wantStreaming: true, wantAccept: "text/event-stream"},
		{name: "accept header is case-insensitive", accept: "Text/Event-Stream", wantStreaming: true, wantAccept: "Text/Event-Stream"},
		{name: "accept header is trimmed", accept: "  text/event-stream  ", wantStreaming: true, wantAccept: "text/event-stream"},
		{name: "application/json is non-streaming", accept: "application/json", wantAccept: "application/json"},
		{name: "missing accept header is non-streaming", accept: "", wantAccept: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/assistant/chat", nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}

			streaming, accept := streamingAccepted(req)

			assert.Equal(t, tc.wantStreaming, streaming)
			assert.Equal(t, tc.wantAccept, accept)
		})
	}
}

func TestRespondChatError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{name: "invalid model surfaces as 400", err: errors.New("ERROR_ASSISTANT_INVALID_MODEL"), wantCode: http.StatusBadRequest, wantBody: "ERROR_ASSISTANT_INVALID_MODEL"},
		{name: "request too large surfaces as 400", err: errors.New("ERROR_ASSISTANT_REQUEST_TOO_LARGE"), wantCode: http.StatusBadRequest, wantBody: "ERROR_ASSISTANT_REQUEST_TOO_LARGE"},
		{name: "internal error surfaces as 500", err: errors.New("boom"), wantCode: http.StatusInternalServerError, wantBody: "ERROR_UPSTREAM_SERVICE_ERROR"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newAssistantTestServer(t, true)
			handler := NewAssistantHandler(srv)

			req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", nil))
			w := httptest.NewRecorder()

			handler.respondChatError(w, req, log.FromContext(req.Context()), tc.err, "test chat error")

			assert.Equal(t, tc.wantCode, w.Code)
			assert.Contains(t, w.Body.String(), tc.wantBody)
		})
	}
}

func TestPostChat_SessionNotOwned(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	// The session exists but belongs to a different user than the requestor
	// ("test-user"), so the chat must be rejected before reaching the manager.
	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(false, true, nil)
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	mockManager.EXPECT().ChatStreamInSession(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	body, _ := json.Marshal(map[string]any{"msg": "hi", "sessionId": "s1", "model": "m"})
	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPostChat_SessionLookupError(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(false, false, errors.New("es unavailable"))
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	body, _ := json.Marshal(map[string]any{"msg": "hi", "sessionId": "s1", "model": "m"})
	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPostChat_NewSessionAllowed(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	// A session that doesn't exist yet isn't owned by anyone; the chat proceeds
	// and the session is created as the caller's own.
	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(false, false, nil)
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), "", "").Return([]*model.Message{}, nil)

	body, _ := json.Marshal(map[string]any{"msg": "hi", "sessionId": "s1", "model": "m"})
	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPostChat_DefaultsSessionId(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", gomock.Any()).Return(false, false, nil)

	var capturedIncMsg *model.IncomingMessage
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), "", "").DoAndReturn(
		func(_ context.Context, incMsg *model.IncomingMessage, _, _ string) ([]*model.Message, error) {
			capturedIncMsg = incMsg
			return []*model.Message{}, nil
		})

	body, _ := json.Marshal(map[string]any{"msg": "hi", "model": "m"})
	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, capturedIncMsg)
	assert.NotEmpty(t, capturedIncMsg.SessionId)
}

func TestPostChat_StreamingDowngradeToNonStreaming(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(true, true, nil)

	// The writer is not an http.Flusher, so despite the SSE Accept header the
	// handler must fall back to the buffered ChatInSession path.
	mockManager.EXPECT().ChatInSession(gomock.Any(), gomock.Any(), "", "").Return([]*model.Message{}, nil)

	body, _ := json.Marshal(map[string]any{"msg": "hi", "sessionId": "s1", "model": "m"})
	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	w := &nonFlushResponseWriter{}

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusOK, w.code)
}

func TestPostChat_StreamingFinalizeCalled(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(true, true, nil)

	finalized := make(chan []byte, 1)
	finalize := func(rawResponse []byte) error {
		finalized <- rawResponse
		return nil
	}
	mockManager.EXPECT().ChatStreamInSession(gomock.Any(), gomock.Any(), "", "").Return(
		sseTextResponse("hello"), &model.AuxMessageData{}, finalize, nil)

	body, _ := json.Marshal(map[string]any{"msg": "hi", "sessionId": "s1", "model": "m"})
	req := withAssistantContext(httptest.NewRequest("POST", "/assistant/chat", bytes.NewBuffer(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	w := httptest.NewRecorder()

	handler.PostChat(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// finalize runs in a goroutine after the stream completes, so wait for it.
	select {
	case raw := <-finalized:
		assert.Equal(t, w.Body.String(), string(raw))
		assert.Contains(t, string(raw), "hello")
	case <-time.After(5 * time.Second):
		t.Fatal("finalize was not called within timeout")
	}
}

func TestPostTool_DecodeError(t *testing.T) {
	srv, _, _ := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	req := httptest.NewRequest("POST", "/assistant/tool/query_events", bytes.NewBufferString("{not valid json"))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "query_events")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = withAssistantContext(req)
	w := httptest.NewRecorder()

	handler.PostTool(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPostTool_NonStreamingUpstreamErrors(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{name: "client error surfaces as 400", err: errors.New("ERROR_ASSISTANT_REQUEST_TOO_LARGE"), wantCode: http.StatusBadRequest},
		{name: "internal error surfaces as 500", err: errors.New("boom"), wantCode: http.StatusInternalServerError},
		{name: "unknown tool_use surfaces as 404", err: ErrToolUseNotFound, wantCode: http.StatusNotFound},
		{name: "already resolved tool_use surfaces as 400", err: ErrToolAlreadyResolved, wantCode: http.StatusBadRequest},
		{name: "mismatched tool request surfaces as 400", err: ErrToolRequestMismatch, wantCode: http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv, mockManager, mockStore := newAssistantTestServer(t, true)
			handler := NewAssistantHandler(srv)

			mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(true, true, nil)
			mockManager.EXPECT().ToolInSession(gomock.Any(), gomock.Any(), "query_events").Return(nil, tc.err)

			body, _ := json.Marshal(model.ToolRequest{SessionId: "s1", ToolUseId: "tu1", Model: "m"})
			req := httptest.NewRequest("POST", "/assistant/tool/query_events", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("name", "query_events")
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			req = withAssistantContext(req)
			w := httptest.NewRecorder()

			handler.PostTool(w, req)

			assert.Equal(t, tc.wantCode, w.Code)
		})
	}
}

func TestStreamResponse_NotFlushable(t *testing.T) {
	w := &nonFlushResponseWriter{}
	req := withAssistantContext(httptest.NewRequest("GET", "/assistant/chat", nil))

	entire, err := streamResponse(req.Context(), w, req, sseTextResponse("hi"))

	assert.NoError(t, err)
	assert.Nil(t, entire)
	assert.Equal(t, http.StatusInternalServerError, w.code)
}

func TestUnstreamResponse_EdgeCases(t *testing.T) {
	// Backstop rows ("message-less stream..."): a message-less stream (empty / no
	// message_start) must never panic, even with a non-nil aux (the exact shape
	// that previously crashed the handler).
	messageLessAux := &model.AuxMessageData{ThoughtSignatures: map[string][]byte{"t1": []byte("sig")}}

	testCases := []struct {
		name             string
		data             string
		aux              *model.AuxMessageData
		wantErrSubstring string // non-empty: expect an error containing this and a nil message
		wantNilMsg       bool   // expect no error and a nil message
		wantThoughts     string // non-empty: assert msg.Thoughts
		wantSignature    []byte // non-nil: assert msg.ContentBlocks[0].ThoughtSignature
	}{
		{
			name: "error event returns an error",
			data: `data: {"type":"error","error":{"type":"overloaded","message":"too busy"}}

data: [DONE]`,
			wantErrSubstring: "too busy",
		},
		{
			name: "thought delta accumulates into Thoughts and malformed lines are skipped",
			data: `data: {"type":"message_start","message":{"id":"m","role":"assistant","content":[]}}

data: {not valid json}

data: {"type":"content_block_delta","index":0,"delta":{"type":"thought_delta","text":"thinking..."}}

data: {"type":"content_block_stop","index":0}

data: [DONE]`,
			wantThoughts: "thinking...",
		},
		{
			name: "aux thought signatures are applied to tool_use blocks",
			data: `data: {"type":"message_start","message":{"id":"m","role":"assistant","content":[]}}

data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"query_events","input":{}}}

data: {"type":"content_block_stop","index":0}

data: [DONE]`,
			aux:           &model.AuxMessageData{ThoughtSignatures: map[string][]byte{"t1": []byte("sig-123")}},
			wantSignature: []byte("sig-123"),
		},
		// A first-chunk LLM failure now arrives as an SSE error event (see
		// handleStreamError); it must surface as a real error, not a nil-deref panic.
		{
			name: "error event surfaces the real message",
			data: `data: {"type":"error","error":{"type":"error","message":"quota exceeded"}}

data: [DONE]`,
			wantErrSubstring: "quota exceeded",
		},
		{
			name:       "message-less stream with aux returns nil without panicking: empty stream",
			data:       "",
			aux:        messageLessAux,
			wantNilMsg: true,
		},
		{
			name:       "message-less stream with aux returns nil without panicking: done only",
			data:       "data: [DONE]",
			aux:        messageLessAux,
			wantNilMsg: true,
		},
		{
			name:       "message-less stream with aux returns nil without panicking: orphan delta",
			data:       "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"orphan\"}}\n\ndata: [DONE]",
			aux:        messageLessAux,
			wantNilMsg: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := UnstreamResponse(context.Background(), tc.data, tc.aux)

			if tc.wantErrSubstring != "" {
				assert.Error(t, err)
				assert.Nil(t, msg)
				assert.Contains(t, err.Error(), tc.wantErrSubstring)
				return
			}

			assert.NoError(t, err)
			if tc.wantNilMsg {
				assert.Nil(t, msg)
				return
			}

			assert.NotNil(t, msg)
			if tc.wantThoughts != "" {
				assert.Equal(t, tc.wantThoughts, msg.Thoughts)
			}
			if tc.wantSignature != nil {
				assert.Equal(t, tc.wantSignature, msg.ContentBlocks[0].ThoughtSignature)
			}
		})
	}
}

func assistantMsg(blocks ...model.ContentBlock) *model.StoredMessage {
	return &model.StoredMessage{Message: &model.Message{Role: "assistant", ContentBlocks: blocks}}
}

func toolResultMsg(toolUseId string) *model.StoredMessage {
	return &model.StoredMessage{
		Tags:    []string{"tool_result"},
		Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{ToolResult: &model.ToolResult{ToolUseId: toolUseId}}}},
	}
}

func TestPendingToolApproval(t *testing.T) {
	toolUse := model.ContentBlock{Type: "tool_use", Id: "tu-1", Name: "query_events", Input: json.RawMessage(`{"q":"dns"}`)}
	delegate := model.ContentBlock{Type: "tool_use", Id: "del-1", Name: "delegate_to_Hunter", Input: json.RawMessage(`{}`)}

	testCases := []struct {
		name          string
		sessionId     string
		history       []*model.StoredMessage
		delegated     map[string]struct{}
		wantNil       bool
		wantToolUseId string
		wantToolName  string
		wantInput     string
	}{
		{
			name:      "trailing unresolved tool_use is pending",
			sessionId: "child-1",
			history: []*model.StoredMessage{
				{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "go"}}}},
				assistantMsg(toolUse),
			},
			wantToolUseId: "tu-1",
			wantToolName:  "query_events",
			wantInput:     `{"q":"dns"}`,
		},
		{
			name:      "tool_use with a following tool_result is resolved (nil)",
			sessionId: "child-1",
			history: []*model.StoredMessage{
				assistantMsg(toolUse),
				toolResultMsg("tu-1"),
				assistantMsg(model.ContentBlock{Type: "text", Text: "done"}),
			},
			wantNil: true,
		},
		{
			name:      "delegate tool_use that spawned a sub-session is running, not pending (nil)",
			sessionId: "parent",
			history:   []*model.StoredMessage{assistantMsg(delegate)},
			delegated: map[string]struct{}{"del-1": {}},
			wantNil:   true,
		},
		{
			name:      "no tool_use yields nil",
			sessionId: "s",
			history:   []*model.StoredMessage{assistantMsg(model.ContentBlock{Type: "text", Text: "hi"})},
			wantNil:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pending := pendingToolApproval(tc.sessionId, tc.history, tc.delegated)

			if tc.wantNil {
				assert.Nil(t, pending)
				return
			}

			assert.NotNil(t, pending)
			assert.Equal(t, tc.sessionId, pending.SessionId)
			assert.Equal(t, tc.wantToolUseId, pending.ToolUseId)
			assert.Equal(t, tc.wantToolName, pending.ToolName)
			assert.JSONEq(t, tc.wantInput, string(pending.Input))
		})
	}
}

func TestPostTool_StreamingUpstreamErrors(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{name: "client error surfaces as 400", err: errors.New("ERROR_ASSISTANT_INVALID_MODEL"), wantCode: http.StatusBadRequest},
		{name: "internal error surfaces as 500", err: errors.New("boom"), wantCode: http.StatusInternalServerError},
		{name: "unknown tool_use surfaces as 404", err: ErrToolUseNotFound, wantCode: http.StatusNotFound},
		{name: "already resolved tool_use surfaces as 400", err: ErrToolAlreadyResolved, wantCode: http.StatusBadRequest},
		{name: "mismatched tool request surfaces as 400", err: ErrToolRequestMismatch, wantCode: http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv, mockManager, mockStore := newAssistantTestServer(t, true)
			handler := NewAssistantHandler(srv)

			mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(true, true, nil)
			mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), "query_events").Return(nil, tc.err)

			req, w := newToolStreamRequest(t, "s1", "query_events")
			// The error path responds via web.Respond, which needs request timing context.
			ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
			ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request")
			req = req.WithContext(ctx)
			handler.PostTool(w, req)

			assert.Equal(t, tc.wantCode, w.Code)
		})
	}
}

// newToolRequest builds a non-streaming PostTool request for session "s1".
func newToolRequest(t *testing.T) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	body, _ := json.Marshal(model.ToolRequest{SessionId: "s1", ToolUseId: "tu1", Model: "m"})
	req := httptest.NewRequest("POST", "/assistant/tool/query_events", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "query_events")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	return withAssistantContext(req), httptest.NewRecorder()
}

func TestPostTool_SessionNotOwned(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	// The session exists but belongs to a different user than the requestor
	// ("test-user"), so the tool call must be rejected before reaching the manager.
	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(false, true, nil)
	mockManager.EXPECT().ToolInSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	req, w := newToolRequest(t)
	handler.PostTool(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPostTool_SessionNotFound(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	// Unlike PostChat, a tool result can never start a new session: a nonexistent
	// session is a 404, not an implicit create.
	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(false, false, nil)
	mockManager.EXPECT().ToolInSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	req, w := newToolRequest(t)
	handler.PostTool(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPostTool_SessionLookupError(t *testing.T) {
	srv, mockManager, mockStore := newAssistantTestServer(t, true)
	handler := NewAssistantHandler(srv)

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "s1").Return(false, false, errors.New("es unavailable"))
	mockManager.EXPECT().ToolInSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	req, w := newToolRequest(t)
	handler.PostTool(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPostTool_Unauthorized(t *testing.T) {
	srv, _, _ := newAssistantTestServer(t, false)
	handler := NewAssistantHandler(srv)

	body, _ := json.Marshal(model.ToolRequest{SessionId: "s1", ToolUseId: "tu1", Model: "m"})
	req := httptest.NewRequest("POST", "/assistant/tool/query_events", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "query_events")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = withAssistantContext(req)
	w := httptest.NewRecorder()

	handler.PostTool(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPostTool_Unavailable(t *testing.T) {
	srv, _, _ := newAssistantTestServer(t, true)
	srv.Config = &config.ServerConfig{AirgapEnabled: true}
	handler := NewAssistantHandler(srv)

	body, _ := json.Marshal(model.ToolRequest{SessionId: "s1", ToolUseId: "tu1", Model: "m"})
	req := httptest.NewRequest("POST", "/assistant/tool/query_events", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "query_events")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = withAssistantContext(req)
	w := httptest.NewRecorder()

	handler.PostTool(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// When resolving a finished sub-agent fails, the chain stops cleanly: the child's
// turn has already been streamed, so the response is still 200.
func TestPostTool_StreamingDelegationResolveError(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockManager := mock.NewMockAssistantManager(ctrl)
	mockStore := mock.NewMockAssistantstore(ctrl)
	srv.AssistantManager = mockManager
	srv.Assistantstore = mockStore

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "parent").Return(true, true, nil)

	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), "query_events").Return(
		&model.StreamedTurn{Response: sseTextResponse("child answer"), SessionId: "child", Model: "sonnet", Finalize: noopFinalize,
			Session: &model.AssistantSession{SessionId: "child", ParentSessionId: "parent", ParentToolUseId: "delegate-tu", ParentModel: "agent"}}, nil)

	mockStore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Times(0)

	mockManager.EXPECT().ResolveDelegationStream(gomock.Any(), gomock.Any(), "child answer").Return(nil, errors.New("resolve failed"))

	req, w := newToolStreamRequest(t, "parent", "query_events")
	NewAssistantHandler(srv).PostTool(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "child answer")
}

// disconnectingWriter is an http.ResponseWriter+Flusher that fails every Write,
// simulating a client that disconnected (e.g. a browser refresh) before any bytes
// of the turn could be delivered. It records the status code only.
type disconnectingWriter struct {
	header http.Header
	code   int
}

func (d *disconnectingWriter) Header() http.Header {
	if d.header == nil {
		d.header = http.Header{}
	}
	return d.header
}
func (d *disconnectingWriter) WriteHeader(code int)      { d.code = code }
func (d *disconnectingWriter) Write([]byte) (int, error) { return 0, errors.New("client disconnected") }
func (d *disconnectingWriter) Flush()                    {}

// paddedSSE prefixes a real SSE body with a >1KB message_start whose id is huge, so
// the body spans multiple 1024-byte reads. This is what makes the disconnect tests
// meaningful: the meaningful events sit beyond the first read, so a streamBody that
// abandoned the upstream read on the first failed client write would buffer only a
// truncated, unparseable prefix.
func paddedSSE(eventsAfterStart string) *http.Response {
	bigId := strings.Repeat("x", 2000)
	body := "data: {\"type\":\"message_start\",\"message\":{\"id\":\"" + bigId + "\",\"role\":\"assistant\",\"content\":[]}}\n\n" +
		eventsAfterStart +
		"data: [DONE]\n\n"
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// subSession is the delegated child session shape shared by the client-disconnect
// tests below.
func subSession() *model.AssistantSession {
	return &model.AssistantSession{SessionId: "child", ParentSessionId: "parent", ParentToolUseId: "delegate-tu", ParentModel: "agent"}
}

// A client that disconnects mid-turn must not cost us the turn: streamBody keeps
// draining the upstream body so finalize receives the FULL response and the parse
// correctly classifies it. This is the regression behind the "dead sub-session /
// never-resolving delegation" bug. Two shapes are exercised (one per test below):
//   - the sub-agent's continuation requests another tool: the loop must recognize the
//     tool_use (parse the full body) and break WITHOUT resolving the delegation, so a
//     pending tool is left for the user to resume on reload.
//   - the sub-agent's continuation is final text: the full text must reach
//     ResolveDelegationStream so the delegation folds back into its parent.
//
// Here: tool_use continuation — full turn finalized, no premature resolution.
func TestPostTool_StreamingClientDisconnect_PersistsTurnWithoutDelegation(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockManager := mock.NewMockAssistantManager(ctrl)
	mockStore := mock.NewMockAssistantstore(ctrl)
	srv.AssistantManager = mockManager
	srv.Assistantstore = mockStore

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "parent").Return(true, true, nil)

	finalized := make(chan []byte, 1)
	toolUseResp := paddedSSE(
		"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t2\",\"name\":\"query_events\"}}\n\n" +
			"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n")

	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), "query_events").Return(
		&model.StreamedTurn{Response: toolUseResp, SessionId: "child", Model: "sonnet", Session: subSession(),
			Finalize: func(raw []byte) error { finalized <- raw; return nil }}, nil)

	// The continuation requests a tool, so the chain must NOT resolve the delegation.
	mockManager.EXPECT().ResolveDelegationStream(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	req, _ := newToolStreamRequest(t, "parent", "query_events")
	w := &disconnectingWriter{}
	NewAssistantHandler(srv).PostTool(w, req)

	select {
	case raw := <-finalized:
		msg, err := UnstreamResponse(context.Background(), string(raw), nil)
		assert.NoError(t, err)
		if assert.NotNil(t, msg, "finalize must receive the full turn even though the client was gone") {
			assert.True(t, messageHasToolUse(msg), "the persisted turn must contain the sub-agent's tool_use")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("finalize was never called with the turn")
	}
}

// Client-disconnect, final-text continuation: full child text reaches delegation
// resolution. See TestPostTool_StreamingClientDisconnect_PersistsTurnWithoutDelegation
// for the full background.
func TestPostTool_StreamingClientDisconnect_ResolvesDelegation(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockManager := mock.NewMockAssistantManager(ctrl)
	mockStore := mock.NewMockAssistantstore(ctrl)
	srv.AssistantManager = mockManager
	srv.Assistantstore = mockStore

	mockStore.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user", "parent").Return(true, true, nil)

	textResp := paddedSSE(
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"child answer\"}}\n\n" +
			"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n")

	mockManager.EXPECT().ToolStreamInSession(gomock.Any(), gomock.Any(), "query_events").Return(
		&model.StreamedTurn{Response: textResp, SessionId: "child", Model: "sonnet", Session: subSession(), Finalize: noopFinalize}, nil)

	// The full child text must survive the disconnect and drive resolution. A
	// truncated read would deliver empty/partial text and fail this matcher.
	resolved := make(chan string, 1)
	mockManager.EXPECT().ResolveDelegationStream(gomock.Any(), gomock.Any(), "child answer").DoAndReturn(
		func(_ context.Context, _ *model.AssistantSession, childText string) (*model.StreamedTurn, error) {
			resolved <- childText
			// A top-level parent turn ends the chain.
			return &model.StreamedTurn{Response: paddedSSE(""), SessionId: "parent", Model: "agent",
				Session: &model.AssistantSession{SessionId: "parent"}, Finalize: noopFinalize}, nil
		})

	req, _ := newToolStreamRequest(t, "parent", "query_events")
	w := &disconnectingWriter{}
	NewAssistantHandler(srv).PostTool(w, req)

	select {
	case childText := <-resolved:
		assert.Equal(t, "child answer", childText)
	case <-time.After(2 * time.Second):
		t.Fatal("ResolveDelegationStream was never called")
	}
}

// decodeToolResultEvent asserts the SSE framing of a writeToolResultEvent body
// ("data: " prefix, "\n\n" suffix) and decodes its JSON payload.
func decodeToolResultEvent(t *testing.T, body string) (eventType string, toolResult *model.ToolResult) {
	t.Helper()

	assert.True(t, strings.HasPrefix(body, "data: "))
	assert.True(t, strings.HasSuffix(body, "\n\n"))

	var payload struct {
		Type       string            `json:"type"`
		ToolResult *model.ToolResult `json:"toolResult"`
	}
	assert.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(body, "data: "))), &payload))
	return payload.Type, payload.ToolResult
}

func TestWriteToolResultEvent(t *testing.T) {
	testCases := []struct {
		name          string
		toolResult    *model.ToolResult
		wantToolUseId string // non-empty: assert the decoded ToolUseId
		wantIsError   bool
		wantText      string // non-empty: assert the decoded Content[0].Text
	}{
		{
			name: "success result",
			toolResult: &model.ToolResult{
				Name:      "query_events",
				ToolUseId: "tool-use-1",
				Content:   []model.ToolResultContent{{Json: map[string]any{"result": "ok"}}},
			},
			wantToolUseId: "tool-use-1",
			wantIsError:   false,
		},
		{
			name: "error result",
			toolResult: &model.ToolResult{
				ToolUseId: "tool-use-2",
				Status:    "error",
				IsError:   true,
				Content:   []model.ToolResultContent{{Text: "boom"}},
			},
			wantIsError: true,
			wantText:    "boom",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			assert.NoError(t, writeToolResultEvent(w, tc.toolResult))

			eventType, toolResult := decodeToolResultEvent(t, w.Body.String())
			assert.Equal(t, "tool_result", eventType)
			if assert.NotNil(t, toolResult) {
				if tc.wantToolUseId != "" {
					assert.Equal(t, tc.wantToolUseId, toolResult.ToolUseId)
				}
				assert.Equal(t, tc.wantIsError, toolResult.IsError)
				if tc.wantText != "" {
					assert.Equal(t, tc.wantText, toolResult.Content[0].Text)
				}
			}
		})
	}
}

// HTTP/2 forbids hop-by-hop headers; forwarding them (or a per-turn Content-Length,
// which the chained multi-turn response would violate) makes the client reset the
// stream with PROTOCOL_ERROR. writeStreamHeaders must drop them while preserving the
// content type and any benign headers.
func TestWriteStreamHeaders_StripsHopByHopHeaders(t *testing.T) {
	upstream := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":      []string{"text/event-stream"},
			"Connection":        []string{"keep-alive"},
			"Keep-Alive":        []string{"timeout=5"},
			"Transfer-Encoding": []string{"chunked"},
			"Content-Length":    []string{"1234"},
			"Upgrade":           []string{"h2c"},
			"X-Request-Id":      []string{"abc"},
		},
	}

	w := httptest.NewRecorder()
	writeStreamHeaders(w, upstream)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	assert.Equal(t, "abc", w.Header().Get("X-Request-Id"))
	for _, h := range []string{"Connection", "Keep-Alive", "Transfer-Encoding", "Content-Length", "Upgrade"} {
		assert.Empty(t, w.Header().Get(h), "hop-by-hop header %q must not be forwarded", h)
	}
}

// The persist-only SSE response must not set the HTTP/2-forbidden Connection header.
func TestWriteSSEHeaders_OmitsConnectionHeader(t *testing.T) {
	w := httptest.NewRecorder()
	writeSSEHeaders(w)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
	assert.Empty(t, w.Header().Get("Connection"))
}

// respondToolTurnError maps a tool-turn error to the right HTTP status: 409 for a
// busy session (so the client retries), 400 for a client error, 500 otherwise.
func TestRespondToolTurnError(t *testing.T) {
	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: true}}
	handler := NewAssistantHandler(srv)

	newReqRec := func() (*http.Request, *httptest.ResponseRecorder) {
		req := httptest.NewRequest("POST", "/assistant/tool/query_events", nil)
		ctx := context.WithValue(req.Context(), web.ContextKeyRequestorId, "test-user")
		ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
		ctx = context.WithValue(ctx, web.ContextKeyRequestId, "test-request")
		return req.WithContext(ctx), httptest.NewRecorder()
	}

	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"busy session", ErrToolTurnBusy, http.StatusConflict},
		{"unknown tool_use", ErrToolUseNotFound, http.StatusNotFound},
		{"already resolved tool_use", ErrToolAlreadyResolved, http.StatusBadRequest},
		{"mismatched tool request", ErrToolRequestMismatch, http.StatusBadRequest},
		{"client error (request too large)", errors.New("ERROR_ASSISTANT_REQUEST_TOO_LARGE"), http.StatusBadRequest},
		{"client error (invalid model)", errors.New("ERROR_ASSISTANT_INVALID_MODEL"), http.StatusBadRequest},
		{"upstream/internal error", errors.New("boom"), http.StatusInternalServerError},
		{"wrapped busy error", fmt.Errorf("continuation failed: %w", ErrToolTurnBusy), http.StatusConflict},
		{"wrapped unknown tool_use", fmt.Errorf("validation failed: %w", ErrToolUseNotFound), http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, w := newReqRec()
			handler.respondToolTurnError(w, req, log.FromContext(req.Context()), tc.err, "unable to chat with assistant after tool execution")
			assert.Equal(t, tc.wantCode, w.Code)
		})
	}
}

// The handler maps the manager's errors by message; the assistant module owns the
// real values, which the server package cannot import.
var (
	errSystemImmutableStub = errors.New("ERROR_SYSTEM_AGENT_IMMUTABLE")
	errNotFoundStub        = errors.New("ERROR_AGENT_NOT_FOUND")
)

// agentConfigRouter wires the real routes so tests exercise chi's path handling.
func agentConfigRouter(t *testing.T) (*chi.Mux, *mock.MockAssistantManager) {
	t.Helper()

	return agentConfigRouterAuthorized(t, true)
}

func agentConfigRouterAuthorized(t *testing.T, authorized bool) (*chi.Mux, *mock.MockAssistantManager) {
	t.Helper()

	srv := &Server{Authorizer: &rbac.FakeAuthorizer{Authorized: authorized}}
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	manager := mock.NewMockAssistantManager(ctrl)
	srv.AssistantManager = manager

	r := chi.NewRouter()
	RegisterAssistantRoutes(srv, r, "/assistant")

	return r, manager
}

func agentConfigRequest(method, target string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}

	req := httptest.NewRequest(method, target, &buf)
	req.Header.Set("Content-Type", "application/json")

	return req.WithContext(agentConfigContext(req.Context()))
}

// web.Respond reads the request start time and id from the context.
func agentConfigContext(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, "test-user")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	return context.WithValue(ctx, web.ContextKeyRequestId, "test-request")
}

func TestSaveAgentDecodesNameFromPath(t *testing.T) {
	// chi hands back the raw segment for some of these and the decoded form for
	// others, so the handler has to normalize it: "Hunter (copy)" is the name the
	// Agent Studio's Duplicate button generates.
	names := []string{"Hunter (copy)", "My Agent", "a+b", "café", "a/b", "50%"}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			r, manager := agentConfigRouter(t)

			var gotOriginal string
			var gotAgent *model.StoredAgent
			manager.EXPECT().SaveAgent(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, originalName string, agent *model.StoredAgent) error {
					gotOriginal = originalName
					gotAgent = agent
					return nil
				})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, agentConfigRequest(http.MethodPut, "/assistant/agents/"+url.PathEscape(name), model.StoredAgent{Name: name}))

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, name, gotOriginal)
			assert.Equal(t, name, gotAgent.Name)
		})
	}
}

func TestSaveAgentFallsBackToPathName(t *testing.T) {
	r, manager := agentConfigRouter(t)

	var gotAgent *model.StoredAgent
	manager.EXPECT().SaveAgent(gomock.Any(), "Hunter", gomock.Any()).DoAndReturn(
		func(ctx context.Context, originalName string, agent *model.StoredAgent) error {
			gotAgent = agent
			return nil
		})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, agentConfigRequest(http.MethodPut, "/assistant/agents/Hunter", model.StoredAgent{}))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Hunter", gotAgent.Name, "a body without a name keeps the one in the path")
}

func TestDeleteAgentDecodesNameAndMapsErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "deleted", err: nil, wantStatus: http.StatusOK},
		{name: "system", err: errSystemImmutableStub, wantStatus: http.StatusForbidden},
		{name: "missing", err: errNotFoundStub, wantStatus: http.StatusNotFound},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, manager := agentConfigRouter(t)
			manager.EXPECT().DeleteAgent(gomock.Any(), "My Agent").Return(c.err)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, agentConfigRequest(http.MethodDelete, "/assistant/agents/My%20Agent", nil))

			assert.Equal(t, c.wantStatus, w.Code)
		})
	}
}

func TestSaveSkillDecodesNameFromPath(t *testing.T) {
	r, manager := agentConfigRouter(t)

	manager.EXPECT().SaveSkill(gomock.Any(), "Threat Hunting", gomock.Any()).Return(nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, agentConfigRequest(http.MethodPut, "/assistant/skills/"+url.PathEscape("Threat Hunting"), model.StoredSkill{Name: "Threat Hunting"}))

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetBalanceDecodesSelectorFromPath(t *testing.T) {
	// The picker sends encodeURIComponent(selector), so an agent or duplicated model
	// named "test test123 (copy)" reached Health still percent-encoded and matched no
	// adapter.
	selectors := []string{"test test123 (copy)", "Model A", "google/gemini", "sonnet-4.5@SOAI"}

	for _, selector := range selectors {
		t.Run(selector, func(t *testing.T) {
			r, manager := agentConfigRouter(t)

			var gotHealth, gotBalance string
			manager.EXPECT().Health(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, m string) (*model.HealthResponse, error) {
					gotHealth = m
					return &model.HealthResponse{Status: "ok"}, nil
				})
			manager.EXPECT().Balance(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, m string) (*model.BalanceResponse, error) {
					gotBalance = m
					return &model.BalanceResponse{}, nil
				})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, agentConfigRequest(http.MethodGet, "/assistant/balance/"+url.PathEscape(selector), nil))

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, selector, gotHealth)
			assert.Equal(t, selector, gotBalance)
		})
	}
}

// The mock manager has no EXPECT calls, so reaching it fails the test: a denied
// request must not mutate configuration.
func TestAgentConfigRoutesRequireConfigWrite(t *testing.T) {
	cases := []struct {
		method string
		target string
		body   any
	}{
		{http.MethodPut, "/assistant/agents/Hunter", model.StoredAgent{Name: "Hunter"}},
		{http.MethodDelete, "/assistant/agents/Hunter", nil},
		{http.MethodPut, "/assistant/skills/Hunting", model.StoredSkill{Name: "Hunting"}},
		{http.MethodDelete, "/assistant/skills/Hunting", nil},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.target, func(t *testing.T) {
			r, _ := agentConfigRouterAuthorized(t, false)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, agentConfigRequest(c.method, c.target, c.body))

			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.Contains(t, w.Body.String(), "ERROR_PERMISSION_DENIED")
		})
	}
}

func TestSaveAgentRejectsBadBody(t *testing.T) {
	r, _ := agentConfigRouter(t)

	req := httptest.NewRequest(http.MethodPut, "/assistant/agents/Hunter", bytes.NewBufferString("{not json"))
	req = req.WithContext(agentConfigContext(req.Context()))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMemoriesPassesFilterThrough(t *testing.T) {
	r, manager := agentConfigRouter(t)

	var got *model.MemoryFilter
	manager.EXPECT().ListMemories(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, filter *model.MemoryFilter) (*model.MemoryResults, error) {
			got = filter
			return &model.MemoryResults{Memories: []*model.MemoryRecord{{Id: "mem-1"}}, Total: 1}, nil
		})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, agentConfigRequest(http.MethodGet, "/assistant/memories?scope=self&userId=user-2&q=dark+mode&limit=10&offset=20", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "self", got.Scope)
	assert.Equal(t, "user-2", got.TargetUserId)
	assert.Equal(t, "dark mode", got.Query)
	assert.Equal(t, 10, got.Limit)
	assert.Equal(t, 20, got.Offset)
	assert.Contains(t, w.Body.String(), "mem-1")
}

func TestGetMemoriesMapsErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "unauthorized", err: errors.New("ERROR_MEMORY_UNAUTHORIZED"), wantStatus: http.StatusForbidden},
		{name: "server", err: errors.New("boom"), wantStatus: http.StatusInternalServerError},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, manager := agentConfigRouter(t)
			manager.EXPECT().ListMemories(gomock.Any(), gomock.Any()).Return(nil, c.err)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, agentConfigRequest(http.MethodGet, "/assistant/memories", nil))

			assert.Equal(t, c.wantStatus, w.Code)
		})
	}
}

func TestCreateMemoryDefaultsTargetToRequestor(t *testing.T) {
	r, manager := agentConfigRouter(t)

	var got *model.Memory
	manager.EXPECT().SaveMemory(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, mem *model.Memory) error {
			got = mem
			return nil
		})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, agentConfigRequest(http.MethodPost, "/assistant/memories", model.MemoryRequest{
		MemoryText: "prefers dark mode",
		Scope:      "user",
	}))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, got.Id)
	assert.Equal(t, "prefers dark mode", got.MemoryText)

	if assert.NotNil(t, got.TargetUserId) {
		assert.Equal(t, "test-user", *got.TargetUserId)
	}
}

func TestCreateMemoryGlobalHasNoTarget(t *testing.T) {
	r, manager := agentConfigRouter(t)

	var got *model.Memory
	manager.EXPECT().SaveMemory(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, mem *model.Memory) error {
			got = mem
			return nil
		})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, agentConfigRequest(http.MethodPost, "/assistant/memories", model.MemoryRequest{
		MemoryText: "the DMZ is 10.4.0.0/16",
		Scope:      "global",
	}))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Nil(t, got.TargetUserId)
	assert.Contains(t, w.Body.String(), `"scope":"global"`)
}

func TestUpdateMemoryUsesPathId(t *testing.T) {
	r, manager := agentConfigRouter(t)

	var got *model.Memory
	manager.EXPECT().SaveMemory(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, mem *model.Memory) error {
			got = mem
			return nil
		})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, agentConfigRequest(http.MethodPut, "/assistant/memories/mem-1", model.MemoryRequest{
		MemoryText:   "prefers light mode",
		Scope:        "user",
		TargetUserId: "user-2",
	}))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "mem-1", got.Id)

	if assert.NotNil(t, got.TargetUserId) {
		assert.Equal(t, "user-2", *got.TargetUserId, "an explicit target is not replaced by the requestor")
	}
}

func TestSaveMemoryMapsErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "empty", err: errors.New("ERROR_MEMORY_TEXT_REQUIRED"), wantStatus: http.StatusBadRequest},
		{name: "unauthorized", err: errors.New("ERROR_MEMORY_UNAUTHORIZED"), wantStatus: http.StatusForbidden},
		{name: "missing", err: errors.New("ERROR_MEMORY_NOT_FOUND"), wantStatus: http.StatusNotFound},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, manager := agentConfigRouter(t)
			manager.EXPECT().SaveMemory(gomock.Any(), gomock.Any()).Return(c.err)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, agentConfigRequest(http.MethodPut, "/assistant/memories/mem-1", model.MemoryRequest{MemoryText: "x"}))

			assert.Equal(t, c.wantStatus, w.Code)
		})
	}
}

func TestSaveMemoryRejectsInvalidBody(t *testing.T) {
	r, _ := agentConfigRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/assistant/memories", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req.WithContext(agentConfigContext(req.Context())))

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteMemoryMapsErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "deleted", err: nil, wantStatus: http.StatusOK},
		{name: "unauthorized", err: errors.New("ERROR_MEMORY_UNAUTHORIZED"), wantStatus: http.StatusForbidden},
		{name: "missing", err: errors.New("ERROR_MEMORY_NOT_FOUND"), wantStatus: http.StatusNotFound},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, manager := agentConfigRouter(t)
			manager.EXPECT().RemoveMemory(gomock.Any(), "mem-1").Return(c.err)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, agentConfigRequest(http.MethodDelete, "/assistant/memories/mem-1", nil))

			assert.Equal(t, c.wantStatus, w.Code)
		})
	}
}
