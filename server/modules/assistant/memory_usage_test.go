// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func newUsageTestCoordinator(store server.Assistantstore) *AssistantCoordinator {
	return &AssistantCoordinator{
		srv: &server.Server{
			Assistantstore: store,
		},
	}
}

func TestRecordAgentSessionSavesExchange(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	usage := &model.Usage{InputTokens: 11, OutputTokens: 3, Credits: 2}

	request := &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "reconcile these"}}}
	response := textResponse(`{"operations":[]}`)
	response.Usage = usage

	var sessionId string
	var saved []*model.StoredMessage

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, session *model.AssistantSession) error {
		sessionId = session.SessionId
		assert.Regexp(t, `^[A-Za-z0-9-_]{5,50}$`, session.SessionId)
		assert.Equal(t, []string{model.SessionTagReconcile}, session.Tags)
		assert.Equal(t, "src-1", session.EntityId)
		assert.Equal(t, "rec-model@Adapter", session.Model)
		assert.NotEmpty(t, session.Title)
		assert.Empty(t, session.ParentSessionId)

		return nil
	})
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, sm *model.StoredMessage) error {
		saved = append(saved, sm)
		return nil
	}).Times(2)

	ac := newUsageTestCoordinator(store)

	ac.recordAgentSession(context.Background(), model.SessionTagReconcile, "src-1", "rec-model@Adapter", []*model.Message{request, response})

	// both messages land in the newly created session, request first, the
	// response carrying the usage
	if assert.Len(t, saved, 2) {
		assert.Equal(t, sessionId, saved[0].SessionId)
		assert.Equal(t, sessionId, saved[1].SessionId)
		assert.Equal(t, "rec-model@Adapter", saved[0].Model)
		assert.Equal(t, "user", saved[0].Message.Role)
		assert.Equal(t, "assistant", saved[1].Message.Role)
		assert.Nil(t, saved[0].Message.Usage)
		assert.Equal(t, usage, saved[1].Message.Usage)
	}
}

func TestRecordAgentSessionCreatesNewSessionPerCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sessionIds := map[string]bool{}

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, session *model.AssistantSession) error {
		sessionIds[session.SessionId] = true
		return nil
	}).Times(2)
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).Times(2)

	ac := newUsageTestCoordinator(store)

	// same source, same tag: still two independent throwaway sessions
	ac.recordAgentSession(context.Background(), model.SessionTagMemory, "src-1", "m", []*model.Message{textResponse("one")})
	ac.recordAgentSession(context.Background(), model.SessionTagMemory, "src-1", "m", []*model.Message{textResponse("two")})

	assert.Len(t, sessionIds, 2)
}

func TestRecordAgentSessionNoOps(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// no expectations: none of these may touch the store
	store := servermock.NewMockAssistantstore(ctrl)

	ac := newUsageTestCoordinator(store)
	ac.recordAgentSession(context.Background(), model.SessionTagMemory, "src-1", "m", nil)

	noSrv := &AssistantCoordinator{}
	noSrv.recordAgentSession(context.Background(), model.SessionTagMemory, "src-1", "m", []*model.Message{textResponse("hi")})

	noStore := &AssistantCoordinator{srv: &server.Server{}}
	noStore.recordAgentSession(context.Background(), model.SessionTagMemory, "src-1", "m", []*model.Message{textResponse("hi")})
}

// AI calls with no originating chat session (re-embed passes, memory search,
// manual memory saves) still record their spend, just without an EntityId.
func TestRecordAgentSessionWithoutSourceSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, session *model.AssistantSession) error {
		assert.Regexp(t, `^[A-Za-z0-9-_]{5,50}$`, session.SessionId)
		assert.Empty(t, session.EntityId)
		assert.Equal(t, "embed usage", session.Title)
		assert.Equal(t, []string{model.SessionTagEmbed}, session.Tags)

		return nil
	})
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil)

	ac := newUsageTestCoordinator(store)

	ac.recordAgentSession(context.Background(), model.SessionTagEmbed, "", "m", []*model.Message{textResponse("hi")})
}

func TestRecordAgentSessionSwallowsStoreErrors(t *testing.T) {
	t.Run("create fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// no SaveChat expectation: a failed create skips the saves entirely
		store := servermock.NewMockAssistantstore(ctrl)
		store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(errors.New("create down"))

		ac := newUsageTestCoordinator(store)

		assert.NotPanics(t, func() {
			ac.recordAgentSession(context.Background(), model.SessionTagMemory, "src-1", "m", []*model.Message{textResponse("hi")})
		})
	})

	t.Run("save fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// the second message is still attempted after the first save fails
		store := servermock.NewMockAssistantstore(ctrl)
		store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil)
		store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(errors.New("save down")).Times(2)

		ac := newUsageTestCoordinator(store)

		assert.NotPanics(t, func() {
			ac.recordAgentSession(context.Background(), model.SessionTagMemory, "src-1", "m", []*model.Message{textResponse("in"), textResponse("out")})
		})
	})
}

func TestRecordEmbedUsage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	usage := &model.Usage{InputTokens: 7}

	var saved []*model.StoredMessage

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, session *model.AssistantSession) error {
		assert.Equal(t, []string{model.SessionTagEmbed}, session.Tags)
		assert.Equal(t, "src-1", session.EntityId)

		return nil
	})
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, sm *model.StoredMessage) error {
		saved = append(saved, sm)
		return nil
	}).Times(2)

	ac := newUsageTestCoordinator(store)

	ac.recordEmbedUsage(context.Background(), "src-1", "embed-model@Adapter", &model.EmbeddingResponse{
		Model:      "embed-model",
		Embeddings: [][]float32{{0.1}, {0.2}},
		Usage:      usage,
	}, []string{"fact one", "fact two"})

	if assert.Len(t, saved, 2) {
		// the request mirrors the embedded inputs
		assert.Equal(t, "user", saved[0].Message.Role)
		if assert.Len(t, saved[0].Message.ContentBlocks, 2) {
			assert.Equal(t, "fact one", saved[0].Message.ContentBlocks[0].Text)
			assert.Equal(t, "fact two", saved[0].Message.ContentBlocks[1].Text)
		}

		// the response carries the usage
		assert.Equal(t, "assistant", saved[1].Message.Role)
		assert.NotEmpty(t, saved[1].Message.Id)
		assert.Equal(t, usage, saved[1].Message.Usage)
		if assert.Len(t, saved[1].Message.ContentBlocks, 1) {
			assert.Equal(t, "Embedded 2 input(s) using embed-model", saved[1].Message.ContentBlocks[0].Text)
		}
	}

	// a nil response must not touch the store
	ac2 := newUsageTestCoordinator(servermock.NewMockAssistantstore(ctrl))
	ac2.recordEmbedUsage(context.Background(), "src-1", "embed-model@Adapter", nil, []string{"fact"})
}

func TestRecordEmbedUsageSummary(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	usage := model.Usage{InputTokens: 123, Credits: 4}

	var saved []*model.StoredMessage

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, session *model.AssistantSession) error {
		assert.Equal(t, []string{model.SessionTagEmbed}, session.Tags)
		assert.Empty(t, session.EntityId)

		return nil
	})
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, sm *model.StoredMessage) error {
		saved = append(saved, sm)
		return nil
	})

	ac := newUsageTestCoordinator(store)

	ac.recordEmbedUsageSummary(context.Background(), "Re-embedded 42 memories using embed-model@Adapter", usage, "embed-model@Adapter")

	if assert.Len(t, saved, 1) {
		assert.Equal(t, "assistant", saved[0].Message.Role)
		assert.Equal(t, &usage, saved[0].Message.Usage)
		if assert.Len(t, saved[0].Message.ContentBlocks, 1) {
			assert.Equal(t, "Re-embedded 42 memories using embed-model@Adapter", saved[0].Message.ContentBlocks[0].Text)
		}
	}

	// zero usage must not touch the store
	ac2 := newUsageTestCoordinator(servermock.NewMockAssistantstore(ctrl))
	ac2.recordEmbedUsageSummary(context.Background(), "Re-embedded 0 memories using embed-model@Adapter", model.Usage{}, "embed-model@Adapter")
}
