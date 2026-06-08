// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	detectionsmock "github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestLoadHistory(t *testing.T) {
	const sessionId = "session-load-1"

	t.Run("existing history returns messages and isNew=false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{
			{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}}},
		}, nil)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")

		messages, isNew, err := ac.loadHistory(context.Background(), sessionId)
		assert.NoError(t, err)
		assert.False(t, isNew)
		assert.Len(t, messages, 1)
	})

	t.Run("empty history reports isNew=true", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")

		messages, isNew, err := ac.loadHistory(context.Background(), sessionId)
		assert.NoError(t, err)
		assert.True(t, isNew)
		assert.Empty(t, messages)
	})

	t.Run("not-found error is tolerated as a new session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(nil, errors.New("session not found"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")

		messages, isNew, err := ac.loadHistory(context.Background(), sessionId)
		assert.NoError(t, err)
		assert.True(t, isNew)
		assert.Empty(t, messages)
	})

	t.Run("non-not-found error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(nil, errors.New("network error"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")

		_, _, err := ac.loadHistory(context.Background(), sessionId)
		assert.Error(t, err)
	})
}

func TestBuildNoTimeoutCtx(t *testing.T) {
	t.Run("preserves requestor id and drops any deadline", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

		out := buildNoTimeoutCtx(ctx)

		assert.Equal(t, "user-1", out.Value(web.ContextKeyRequestorId))
		assert.Nil(t, out.Value(web.ContextKeyRunAsUsername))
		_, hasDeadline := out.Deadline()
		assert.False(t, hasDeadline)
	})

	t.Run("preserves run-as username when present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
		ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "admin")

		out := buildNoTimeoutCtx(ctx)

		assert.Equal(t, "user-1", out.Value(web.ContextKeyRequestorId))
		assert.Equal(t, "admin", out.Value(web.ContextKeyRunAsUsername))
	})
}

func TestAssistantCoordinator_ChatInSession_ErrorPaths(t *testing.T) {
	const sessionId = "session-cis-err"

	incMsg := func() *model.IncomingMessage {
		return &model.IncomingMessage{Msg: "hi", SessionId: sessionId, Model: "test-model@MyAdapter"}
	}

	// The assistant response that Send must return before any persistence happens.
	okResponse := func() (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body: io.NopCloser(strings.NewReader(
				`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"ok"}]}`)),
		}, nil
	}

	t.Run("create session error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
		// A new session records the model it runs on, so it can later be resumed
		// server-side without trusting the client-supplied model.
		mockAssistantstore.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, s *model.AssistantSession) error {
				assert.Equal(t, "test-model@MyAdapter", s.Model)
				assert.Equal(t, sessionId, s.SessionId)
				return errors.New("create failed")
			})

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ChatInSession(ctx, incMsg(), "", "")
		assert.Error(t, err)
	})

	t.Run("save user message error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		// Non-empty history keeps isNew=false so CreateSession is skipped.
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{
			{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
		}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save user failed"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ChatInSession(ctx, incMsg(), "", "")
		assert.Error(t, err)
	})

	t.Run("save response message error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{
			{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
		}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
		// First save (user) succeeds, second save (assistant response) fails.
		gomock.InOrder(
			mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil),
			mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save response failed")),
		)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, err := ac.ChatInSession(ctx, incMsg(), "", "")
		assert.Error(t, err)
	})
}

func TestAssistantCoordinator_ChatStreamInSession_ErrorPaths(t *testing.T) {
	const sessionId = "session-css-err"

	incMsg := func() *model.IncomingMessage {
		return &model.IncomingMessage{Msg: "stream me", SessionId: sessionId, Model: "test-model@MyAdapter"}
	}

	t.Run("history load error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(nil, errors.New("network error"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		stream, _, finalize, err := ac.ChatStreamInSession(ctx, incMsg(), "", "")
		assert.Error(t, err)
		assert.Nil(t, stream)
		assert.Nil(t, finalize)
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

		_, _, _, err := ac.ChatStreamInSession(ctx, incMsg(), "", "")
		assert.Error(t, err)
	})

	t.Run("save user message error propagates", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		// Non-empty history keeps isNew=false so CreateSession is skipped.
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{
			{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
		}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("data: stream")),
		}, nil)
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save user failed"))

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		_, _, _, err := ac.ChatStreamInSession(ctx, incMsg(), "", "")
		assert.Error(t, err)
	})

	t.Run("finalize tolerates a terminal-only stream with no assistant message", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIO := detectionsmock.NewMockIOManager(ctrl)
		mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
		mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{
			{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
		}, nil)
		mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("data: stream")),
		}, nil)
		// Only the user message is saved; the [DONE]-only finalize yields no assistant message.
		mockAssistantstore.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)

		ac := newChatInSessionCoordinator(t, ctrl, mockAssistantstore, mockIO, "https://api.example.com")
		ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

		stream, _, finalize, err := ac.ChatStreamInSession(ctx, incMsg(), "", "")
		assert.NoError(t, err)
		stream.Body.Close()

		assert.NoError(t, finalize([]byte("data: [DONE]")))
	})
}
