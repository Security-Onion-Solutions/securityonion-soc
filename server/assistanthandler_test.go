// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type mockAssistantManager struct {
	lastMessages []*model.ChatMessage
}

func (m *mockAssistantManager) Chat(ctx context.Context, msg string) (*model.ChatResponse, error) {
	return &model.ChatResponse{
		Content: []*model.ChatResponseContent{
			{Type: "text", Text: "Mock response"},
		},
	}, nil
}

func (m *mockAssistantManager) ChatWithHistory(ctx context.Context, messages []*model.ChatMessage) (*model.ChatResponse, error) {
	m.lastMessages = messages
	return &model.ChatResponse{
		Content: []*model.ChatResponseContent{
			{Type: "text", Text: "Mock response with history"},
		},
	}, nil
}

func (m *mockAssistantManager) Balance(ctx context.Context) (*model.BalanceResponse, error) {
	return &model.BalanceResponse{Balance: 100.0}, nil
}

func TestPostChatWithHistory(t *testing.T) {
	// Create mock server
	srv := &Server{}
	mockManager := &mockAssistantManager{}
	srv.AssistantManager = mockManager

	handler := NewAssistantHandler(srv)

	// Test data with message history
	requestBody := map[string]interface{}{
		"msg": "What is my current balance?",
		"messages": []map[string]string{
			{"role": "assistant", "content": "Hello! I'm your AI Assistant for Security Onion. How can I help you today?"},
			{"role": "user", "content": "Hello, I need help with my account"},
			{"role": "assistant", "content": "I'd be happy to help you with your account. What specific information do you need?"},
		},
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
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify that the mock received the correct number of messages
	expectedMessageCount := 4 // 3 from history + 1 new user message
	if len(mockManager.lastMessages) != expectedMessageCount {
		t.Errorf("Expected %d messages, got %d", expectedMessageCount, len(mockManager.lastMessages))
	}

	// Verify the last message is the new user message
	lastMessage := mockManager.lastMessages[len(mockManager.lastMessages)-1]
	if lastMessage.Role != "user" || lastMessage.Content != "What is my current balance?" {
		t.Errorf("Last message should be the new user message, got: %+v", lastMessage)
	}

	// Verify history is preserved
	if mockManager.lastMessages[0].Role != "assistant" {
		t.Errorf("First message should be from assistant, got: %+v", mockManager.lastMessages[0])
	}
}

func TestPostChatWithoutHistory(t *testing.T) {
	// Create mock server
	srv := &Server{}
	mockManager := &mockAssistantManager{}
	srv.AssistantManager = mockManager

	handler := NewAssistantHandler(srv)

	// Test data without message history (backward compatibility)
	requestBody := map[string]interface{}{
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
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify that the mock received exactly 1 message (backward compatibility)
	expectedMessageCount := 1
	if len(mockManager.lastMessages) != expectedMessageCount {
		t.Errorf("Expected %d messages, got %d", expectedMessageCount, len(mockManager.lastMessages))
	}

	// Verify the message content
	if mockManager.lastMessages[0].Role != "user" || mockManager.lastMessages[0].Content != "Hello" {
		t.Errorf("Message should be the user message, got: %+v", mockManager.lastMessages[0])
	}
}
