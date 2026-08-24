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

	testCases := []struct {
		name          string
		historyReturn []*model.StoredMessage
		historyErr    error
		wantIsNew     bool
		wantLen       int
		wantErr       bool
	}{
		{
			name: "existing history returns messages and isNew=false",
			historyReturn: []*model.StoredMessage{
				{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}}},
			},
			wantIsNew: false,
			wantLen:   1,
		},
		{
			name:          "empty history reports isNew=true",
			historyReturn: []*model.StoredMessage{},
			wantIsNew:     true,
			wantLen:       0,
		},
		{
			name:       "not-found error is tolerated as a new session",
			historyErr: errors.New("session not found"),
			wantIsNew:  true,
			wantLen:    0,
		},
		{
			name:       "non-not-found error propagates",
			historyErr: errors.New("network error"),
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)
			mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(tc.historyReturn, tc.historyErr)

			ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")

			messages, isNew, err := ac.loadHistory(context.Background(), sessionId)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.wantIsNew, isNew)
			assert.Len(t, messages, tc.wantLen)
		})
	}
}

func TestBuildNoTimeoutCtx(t *testing.T) {
	testCases := []struct {
		name            string
		ctxBuilder      func() context.Context
		wantRequestorId any
		wantRunAs       any
		checkNoDeadline bool
	}{
		{
			name: "preserves requestor id and drops any deadline",
			ctxBuilder: func() context.Context {
				return context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
			},
			wantRequestorId: "user-1",
			wantRunAs:       nil,
			checkNoDeadline: true,
		},
		{
			name: "preserves run-as username when present",
			ctxBuilder: func() context.Context {
				ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
				return context.WithValue(ctx, web.ContextKeyRunAsUsername, "admin")
			},
			wantRequestorId: "user-1",
			wantRunAs:       "admin",
		},
		{
			name:            "missing requestor id does not panic",
			ctxBuilder:      context.Background,
			wantRequestorId: nil,
			wantRunAs:       nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := buildNoTimeoutCtx(tc.ctxBuilder())

			assert.Equal(t, tc.wantRequestorId, out.Value(web.ContextKeyRequestorId))
			assert.Equal(t, tc.wantRunAs, out.Value(web.ContextKeyRunAsUsername))

			if tc.checkNoDeadline {
				_, hasDeadline := out.Deadline()
				assert.False(t, hasDeadline)
			}
		})
	}
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

	testCases := []struct {
		name  string
		setup func(t *testing.T, store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager)
	}{
		{
			name: "create session error propagates",
			setup: func(t *testing.T, store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				store.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
				// A new session records the model it runs on, so it can later be resumed
				// server-side without trusting the client-supplied model.
				store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, s *model.AssistantSession) error {
						assert.Equal(t, "test-model@MyAdapter", s.Model)
						assert.Equal(t, sessionId, s.SessionId)
						return errors.New("create failed")
					})
			},
		},
		{
			name: "save user message error propagates",
			setup: func(t *testing.T, store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				// Non-empty history keeps isNew=false so CreateSession is skipped.
				store.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{
					{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
				}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
				store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save user failed"))
			},
		},
		{
			name: "save response message error propagates",
			setup: func(t *testing.T, store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				store.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{
					{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
				}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
				// First save (user) succeeds, second save (assistant response) fails.
				gomock.InOrder(
					store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil),
					store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save response failed")),
				)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			tc.setup(t, mockAssistantstore, mockIO)

			ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			_, err := ac.ChatInSession(ctx, incMsg(), "", "")
			assert.Error(t, err)
		})
	}
}

// chatStreamSessionIncMsg builds the incoming message used by the
// ChatStreamInSession tests.
func chatStreamSessionIncMsg(sessionId string) *model.IncomingMessage {
	return &model.IncomingMessage{Msg: "stream me", SessionId: sessionId, Model: "test-model@MyAdapter"}
}

func TestAssistantCoordinator_ChatStreamInSession_ErrorPaths(t *testing.T) {
	const sessionId = "session-css-err"

	testCases := []struct {
		name           string
		setup          func(store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager)
		wantNilReturns bool
	}{
		{
			name: "history load error propagates",
			setup: func(store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				store.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return(nil, errors.New("network error"))
			},
			wantNilReturns: true,
		},
		{
			name: "upstream stream error propagates",
			setup: func(store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				store.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(nil, errors.New("network error"))
			},
		},
		{
			name: "save user message error propagates",
			setup: func(store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				// Non-empty history keeps isNew=false so CreateSession is skipped.
				store.EXPECT().GetChatHistory(gomock.Any(), sessionId).Return([]*model.StoredMessage{
					{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
				}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("data: stream")),
				}, nil)
				store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save user failed"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			tc.setup(mockAssistantstore, mockIO)

			ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

			stream, _, finalize, err := ac.ChatStreamInSession(ctx, chatStreamSessionIncMsg(sessionId), "", "")
			assert.Error(t, err)

			if tc.wantNilReturns {
				assert.Nil(t, stream)
				assert.Nil(t, finalize)
			}
		})
	}
}

func TestAssistantCoordinator_ChatStreamInSession_FinalizeToleratesTerminalOnlyStream(t *testing.T) {
	const sessionId = "session-css-err"

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

	ac := newChatInSessionCoordinator(t, mockAssistantstore, mockIO, "https://api.example.com")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	stream, _, finalize, err := ac.ChatStreamInSession(ctx, chatStreamSessionIncMsg(sessionId), "", "")
	assert.NoError(t, err)
	stream.Body.Close()

	assert.NoError(t, finalize([]byte("data: [DONE]")))
}
