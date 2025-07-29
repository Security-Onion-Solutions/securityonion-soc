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
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestPostChat(t *testing.T) {
	// Create mock server
	srv := &Server{}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	defer ctrl.Finish()

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

	// Set up mock expectations
	var capturedMessages []*model.SimpleMessage
	mockManager.EXPECT().Chat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, messages []*model.SimpleMessage, opts ...model.ChatOpt) (*model.Message, error) {
			assert.Len(t, opts, 0)
			capturedMessages = messages

			return &model.Message{
				Role: "assistant",
				Content: []model.ContentBlock{
					{
						Type: "text",
						Text: "Mock response with history",
					},
				},
			}, nil
		},
	)

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify that the mock received the correct number of messages
	expectedMessageCount := 4 // 3 from history + 1 new user message
	assert.Len(t, capturedMessages, expectedMessageCount)

	// Verify the last message is the new user message
	lastMessage := capturedMessages[len(capturedMessages)-1]
	assert.Equal(t, "user", lastMessage.Role)
	assert.Equal(t, "What is my current balance?", lastMessage.Content)

	// Verify history is preserved
	assert.Equal(t, "assistant", capturedMessages[0].Role)
}

func TestPostChatWithoutHistory(t *testing.T) {
	// Create mock server
	srv := &Server{}
	ctrl := gomock.NewController(t)
	mockManager := mock.NewMockAssistantManager(ctrl)
	defer ctrl.Finish()

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

	// Set up mock expectations
	var capturedMessages []*model.SimpleMessage
	mockManager.EXPECT().Chat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, messages []*model.SimpleMessage, opts ...model.ChatOpt) (*model.Message, error) {
			assert.Len(t, opts, 0)
			capturedMessages = messages

			return &model.Message{
				Role: "assistant",
				Content: []model.ContentBlock{
					{
						Type: "text",
						Text: "Mock response",
					},
				},
			}, nil
		},
	)

	// Execute the handler
	handler.PostChat(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify that the mock received exactly 1 message (backward compatibility)
	expectedMessageCount := 1
	assert.Len(t, capturedMessages, expectedMessageCount)

	// Verify the message content
	assert.Equal(t, "user", capturedMessages[0].Role)
	assert.Equal(t, "Hello", capturedMessages[0].Content)
}
