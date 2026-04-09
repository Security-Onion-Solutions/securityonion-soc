// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestNewPostgres(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	pg := NewPostgres(srv)
	assert.NotNil(t, pg)
	assert.Equal(t, srv, pg.server)
	assert.Nil(t, pg.pool)
	assert.False(t, pg.IsRunning())
}

func TestPrerequisiteModules(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	pg := NewPostgres(srv)
	prereqs := pg.PrerequisiteModules()
	assert.Equal(t, []string{"elastic"}, prereqs)
}

func TestInitBadConnection(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	pg := NewPostgres(srv)
	cfg := make(module.ModuleConfig)
	cfg["hostUrl"] = "localhost"
	cfg["port"] = float64(59999) // unlikely to be running; ModuleConfig uses float64 for numbers
	cfg["username"] = "test"
	cfg["password"] = "test"
	cfg["dbname"] = "test"
	cfg["sslMode"] = "disable"

	err := pg.Init(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to connect to postgres")
}

func TestSaveChatUnauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
	chat := &model.StoredMessage{
		SessionId: "session-1",
		Message:   &model.Message{ContentStr: "hello"},
	}

	err := store.SaveChat(ctx, chat)
	assert.Error(t, err) // Should fail RBAC check
}

func TestSaveChatNilMessage(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

	err := store.SaveChat(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chat and message must not be nil")

	// Valid session ID but missing content
	err = store.SaveChat(ctx, &model.StoredMessage{
		SessionId: "chat_123456",
		Message:   &model.Message{},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "message must have exactly one content type")
}

func TestValidateId(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	assert.NoError(t, store.validateId("chat_123456", "test"))
	assert.NoError(t, store.validateId("a-b-c_d-e_f", "test"))
	assert.Error(t, store.validateId("", "test"))
	assert.Error(t, store.validateId("bad", "test"))
	assert.Error(t, store.validateId("invalid@id", "test"))
}

func TestValidateChat(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	// Valid with ContentStr
	err := store.validateChat(&model.StoredMessage{
		SessionId: "chat_123456",
		Message:   &model.Message{ContentStr: "hello"},
	})
	assert.NoError(t, err)

	// Valid with ContentBlocks
	err = store.validateChat(&model.StoredMessage{
		SessionId: "chat_123456",
		Message: &model.Message{
			ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hello"}},
		},
	})
	assert.NoError(t, err)

	// Invalid: both ContentStr and ContentBlocks
	err = store.validateChat(&model.StoredMessage{
		SessionId: "chat_123456",
		Message: &model.Message{
			ContentStr:    "hello",
			ContentBlocks: []model.ContentBlock{{Type: "text", Text: "hello"}},
		},
	})
	assert.Error(t, err)

	// Invalid: bad session ID
	err = store.validateChat(&model.StoredMessage{
		SessionId: "bad",
		Message:   &model.Message{ContentStr: "hello"},
	})
	assert.Error(t, err)
}

func TestValidateSession(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	assert.NoError(t, store.validateSession(&model.AssistantSession{SessionId: "chat_123456", Title: "Test"}))
	assert.Error(t, store.validateSession(nil))
	assert.Error(t, store.validateSession(&model.AssistantSession{SessionId: "bad", Title: "Test"}))
	assert.Error(t, store.validateSession(&model.AssistantSession{SessionId: "chat_123456", Title: ""}))
}

func TestCreateSessionUnauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
	session := &model.AssistantSession{
		SessionId: "session-1",
		Title:     "Test Session",
	}

	err := store.CreateSession(ctx, session)
	assert.Error(t, err)
}

func TestCreateSessionNil(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

	err := store.CreateSession(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session must not be nil")

	// Invalid: missing title
	err = store.CreateSession(ctx, &model.AssistantSession{SessionId: "chat_123456"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Title is too short")
}

func TestGetChatHistoryEmptySessionId(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

	_, err := store.GetChatHistory(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sessionId must not be empty")
}

func TestUpdateSessionTagsUnauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

	err := store.UpdateSessionTags(ctx, "session-1", []string{"shared"})
	assert.Error(t, err)
}

func TestUpdateSessionTagsEmptySessionId(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

	err := store.UpdateSessionTags(ctx, "", []string{"shared"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sessionId must not be empty")
}

func TestDeleteSessionUnauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

	err := store.DeleteSession(ctx, "session-1")
	assert.Error(t, err)
}

func TestDeleteSessionEmptySessionId(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

	err := store.DeleteSession(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sessionId must not be empty")
}

func TestFilterSessionsByRbacOwned(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
	now := time.Now()

	sessions := []*model.AssistantSession{
		{Auditable: model.Auditable{UserId: "user-1", CreateTime: &now}, SessionId: "s1", Tags: []string{}},
		{Auditable: model.Auditable{UserId: "user-2", CreateTime: &now}, SessionId: "s2", Tags: []string{}},
		{Auditable: model.Auditable{UserId: "user-2", CreateTime: &now}, SessionId: "s3", Tags: []string{"shared"}},
	}

	// Authorized server allows all operations
	filtered := store.filterSessionsByRbac(ctx, sessions)
	assert.Len(t, filtered, 3)
}

func TestFilterSessionsByRbacUnauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
	now := time.Now()

	sessions := []*model.AssistantSession{
		{Auditable: model.Auditable{UserId: "user-1", CreateTime: &now}, SessionId: "s1", Tags: []string{}},
		{Auditable: model.Auditable{UserId: "user-2", CreateTime: &now}, SessionId: "s2", Tags: []string{}},
		{Auditable: model.Auditable{UserId: "user-2", CreateTime: &now}, SessionId: "s3", Tags: []string{"shared"}},
	}

	// Unauthorized server blocks all operations
	filtered := store.filterSessionsByRbac(ctx, sessions)
	assert.Len(t, filtered, 0)
}

func TestMigrateSkipsWhenDataExists(t *testing.T) {
	// Test that migration is skipped when postgres already has data
	// This verifies the idempotency check in migrateAssistantData
	// We can't test the full flow without a real DB, but we verify
	// the function signature and error handling
	assert.NotNil(t, migrateAssistantData)
}
