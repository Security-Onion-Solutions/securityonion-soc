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

	session := &model.AssistantSession{SessionId: sessionId}

	testCases := []struct {
		name          string
		sessionReturn []*model.AssistantSession
		sessionErr    error
		historyReturn []*model.StoredMessage
		historyErr    error
		wantIsNew     bool
		wantLen       int
		wantErr       bool
	}{
		{
			name:          "existing history returns messages and isNew=false",
			sessionReturn: []*model.AssistantSession{session},
			historyReturn: []*model.StoredMessage{
				{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hi"}}}},
			},
			wantIsNew: false,
			wantLen:   1,
		},
		{
			name:          "empty history reports isNew=true",
			sessionReturn: []*model.AssistantSession{session},
			historyReturn: []*model.StoredMessage{},
			wantIsNew:     true,
			wantLen:       0,
		},
		{
			name:      "missing session reports isNew=true without reading messages",
			wantIsNew: true,
			wantLen:   0,
		},
		{
			// Partials are dropped from the context sent to the model, but they are
			// still stored messages: calling the session new would create it twice.
			name:          "history of only partials reports isNew=false",
			sessionReturn: []*model.AssistantSession{session},
			historyReturn: []*model.StoredMessage{
				{
					Tags:    []string{model.MessageTagPartial},
					Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "half a th"}}},
				},
			},
			wantIsNew: false,
			wantLen:   0,
		},
		{
			name:          "history error propagates",
			sessionReturn: []*model.AssistantSession{session},
			historyErr:    errors.New("network error"),
			wantErr:       true,
		},
		{
			name:       "session lookup error propagates",
			sessionErr: errors.New("network error"),
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			mockAssistantstore := servermock.NewMockAssistantstore(ctrl)

			// The chat lookup must not filter out deleted, memory, or automation
			// sessions, and nothing on this path reads message metadata.
			mockAssistantstore.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
					applied := &model.GetSessionsOpts{}
					for _, opt := range opts {
						opt(applied)
					}
					assert.Equal(t, sessionId, applied.SessionId())
					assert.True(t, applied.IncludeDeleted())
					assert.True(t, applied.IncludeMemorySessions())
					assert.True(t, applied.IncludeAutomationSessions())
					assert.False(t, applied.MessageMeta())

					return tc.sessionReturn, tc.sessionErr
				})

			if tc.sessionErr == nil && len(tc.sessionReturn) > 0 {
				mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), session).Return(tc.historyReturn, tc.historyErr)
			}

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

// A browser refresh cancels the request context mid-turn; the billed turn must
// still be saved and returned.
func TestChatInSession_SurvivesRequestCancellation(t *testing.T) {
	const sessionId = "session-cis-cancel"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	store := servermock.NewMockAssistantstore(ctrl)

	store.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{}, nil)
	mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
		StatusCode: 200,
		Body: io.NopCloser(strings.NewReader(
			`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"ok"}]}`)),
	}, nil)
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
		func(callCtx context.Context, _ *model.AssistantSession) error {
			return callCtx.Err()
		})
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(
		func(callCtx context.Context, _ *model.StoredMessage) error {
			return callCtx.Err()
		}).Times(2)

	ac := newChatInSessionCoordinator(t, store, mockIO, "https://api.example.com")

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user"))
	cancel()

	response, err := ac.ChatInSession(ctx, &model.IncomingMessage{Msg: "hi", SessionId: sessionId, Model: "test-model@MyAdapter"}, "", "")

	assert.NoError(t, err)
	assert.Len(t, response, 1)
}

func TestCreateSessionIfNeeded_IncognitoTag(t *testing.T) {
	const sessionId = "session-incognito"

	testCases := []struct {
		name      string
		streaming bool
		incognito bool
		wantTags  []string
	}{
		{name: "non-streaming incognito", incognito: true, wantTags: []string{model.SessionTagIncognito}},
		{name: "non-streaming default", incognito: false, wantTags: nil},
		{name: "streaming incognito", streaming: true, incognito: true, wantTags: []string{model.SessionTagIncognito}},
		{name: "streaming default", streaming: true, incognito: false, wantTags: nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := detectionsmock.NewMockIOManager(ctrl)
			store := servermock.NewMockAssistantstore(ctrl)

			store.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{}, nil)
			store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, s *model.AssistantSession) error {
					assert.Equal(t, tc.wantTags, s.Tags)
					return nil
				})
			store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

			ac := newChatInSessionCoordinator(t, store, mockIO, "https://api.example.com")
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
			incMsg := &model.IncomingMessage{Msg: "hi", SessionId: sessionId, Model: "test-model@MyAdapter"}
			if tc.incognito {
				incMsg.Tags = []string{model.SessionTagIncognito}
			}

			if tc.streaming {
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(&http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("data: stream")),
				}, nil)
				_, _, _, err := ac.ChatStreamInSession(ctx, incMsg, "", "")
				assert.NoError(t, err)
			} else {
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(&http.Response{
					StatusCode: 200,
					Body: io.NopCloser(strings.NewReader(
						`{"id":"resp1","role":"assistant","content":[{"type":"text","text":"ok"}]}`)),
				}, nil)
				_, err := ac.ChatInSession(ctx, incMsg, "", "")
				assert.NoError(t, err)
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
		name    string
		setup   func(t *testing.T, store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager)
		wantErr bool
	}{
		{
			// Send already succeeded and was billed, so the response is still
			// saved and returned.
			name: "create session failure does not discard the billed response",
			setup: func(t *testing.T, store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				store.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
				// A new session records the model it runs on, so it can later be resumed
				// server-side without trusting the client-supplied model.
				store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, s *model.AssistantSession) error {
						assert.Equal(t, "test-model@MyAdapter", s.Model)
						assert.Equal(t, sessionId, s.SessionId)
						return errors.New("create failed")
					})
				// The user message and the assistant response are still saved.
				store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)
			},
		},
		{
			name: "save user message failure does not discard the billed response",
			setup: func(t *testing.T, store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				// Non-empty history keeps isNew=false so CreateSession is skipped.
				store.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
					{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
				}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
				// First save (user) fails, the assistant response is still saved.
				gomock.InOrder(
					store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save user failed")),
					store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil),
				)
			},
		},
		{
			name: "save response message error propagates",
			setup: func(t *testing.T, store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				store.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
					{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "earlier"}}}},
				}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), false).Return(okResponse())
				// First save (user) succeeds, second save (assistant response) fails.
				gomock.InOrder(
					store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil),
					store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save response failed")),
				)
			},
			wantErr: true,
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

			response, err := ac.ChatInSession(ctx, incMsg(), "", "")
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, response, 1)
			}
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
		wantErr        bool
	}{
		{
			name: "history load error propagates",
			setup: func(store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				store.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return(nil, errors.New("network error"))
			},
			wantNilReturns: true,
			wantErr:        true,
		},
		{
			name: "upstream stream error propagates",
			setup: func(store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				store.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{}, nil)
				mockIO.EXPECT().MakeRequest(gomock.Any(), true).Return(nil, errors.New("network error"))
			},
			wantErr: true,
		},
		{
			// SendStream already succeeded and is billing; the stream and finalize
			// are still returned so the turn's usage can be saved.
			name: "save user message failure does not abandon the billed stream",
			setup: func(store *servermock.MockAssistantstore, mockIO *detectionsmock.MockIOManager) {
				// Non-empty history keeps isNew=false so CreateSession is skipped.
				store.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
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
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, stream)
				assert.NotNil(t, finalize)
			}

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
	mockAssistantstore.EXPECT().GetChatHistory(gomock.Any(), gomock.Any()).Return([]*model.StoredMessage{
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
