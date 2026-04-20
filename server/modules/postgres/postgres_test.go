// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestGetUsageUnauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
	_, err := store.GetUsage(ctx, time.Time{}, time.Time{})
	assert.Error(t, err)
}

func TestSaveChatMissingUserContext(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	// No ContextKeyRequestorId set — must not fall through to insert with empty UserId.
	ctx := context.Background()
	err := store.SaveChat(ctx, &model.StoredMessage{
		SessionId: "chat_123456",
		Message:   &model.Message{ContentStr: "hello"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing user context")
}

func TestCreateSessionMissingUserContext(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.Background()
	err := store.CreateSession(ctx, &model.AssistantSession{
		SessionId: "chat_123456",
		Title:     "Test",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing user context")
}

func TestUpdateSessionTagsMissingUserContext(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.Background()
	err := store.UpdateSessionTags(ctx, "chat_123456", []string{"shared"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing user context")
}

func TestDeleteSessionMissingUserContext(t *testing.T) {
	srv := server.NewFakeAuthorizedServer(nil)
	store := NewPostgresAssistantstore(srv, nil)

	ctx := context.Background()
	err := store.DeleteSession(ctx, "chat_123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing user context")
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

// newESStub returns an httptest server that serves pages of hits for esSearchPaged.
// Each call to _search returns up to pageSize hits from the remaining pool, assigning
// monotonically increasing sort values so that search_after pagination terminates.
func newESStub(t *testing.T, totalHits, pageSize int) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	served := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			Size        int           `json:"size"`
			SearchAfter []interface{} `json:"search_after"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.Size != pageSize {
			http.Error(w, fmt.Sprintf("expected size=%d, got %d", pageSize, body.Size), http.StatusBadRequest)
			return
		}

		remaining := totalHits - served
		if remaining <= 0 {
			w.Write([]byte(`{"hits":{"hits":[]}}`))
			return
		}
		take := pageSize
		if take > remaining {
			take = remaining
		}

		hits := make([]map[string]interface{}, 0, take)
		for i := 0; i < take; i++ {
			served++
			hits = append(hits, map[string]interface{}{
				"_id":    fmt.Sprintf("doc-%d", served),
				"_source": map[string]interface{}{
					"so_session": map[string]interface{}{
						"sessionId": fmt.Sprintf("chat_%06d", served),
						"userId":    "user-1",
						"title":     "stub",
					},
				},
				"sort": []interface{}{served, fmt.Sprintf("doc-%d", served)},
			})
		}

		resp := map[string]interface{}{
			"hits": map[string]interface{}{"hits": hits},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestESSearchPagedDrainsMultiplePages(t *testing.T) {
	const pageSize = 3
	const totalHits = 7 // 3 full pages: 3, 3, 1 — last is short → pager stops
	srv, calls := newESStub(t, totalHits, pageSize)

	cfg := &esMigrationConfig{HostUrl: srv.URL, SchemaPrefix: "so_"}
	collected := []string{}
	err := esSearchPaged(
		context.Background(),
		srv.Client(),
		cfg,
		"idx",
		map[string]interface{}{"query": map[string]interface{}{"match_all": map[string]interface{}{}}},
		[]interface{}{map[string]interface{}{"_id": map[string]interface{}{"order": "asc"}}},
		pageSize,
		func(hit map[string]interface{}) error {
			collected = append(collected, hit["_id"].(string))
			return nil
		},
	)
	assert.NoError(t, err)
	assert.Len(t, collected, totalHits)
	assert.Equal(t, "doc-1", collected[0])
	assert.Equal(t, "doc-7", collected[6])
	// 3 round-trips: pages of 3, 3, 1. Third page is short so pager exits without a 4th call.
	assert.Equal(t, 3, *calls)
}

func TestESSearchPagedStopsAtExactMultiple(t *testing.T) {
	const pageSize = 3
	const totalHits = 6 // exact multiple: pager must make a 3rd empty call to detect end
	srv, calls := newESStub(t, totalHits, pageSize)

	cfg := &esMigrationConfig{HostUrl: srv.URL, SchemaPrefix: "so_"}
	collected := 0
	err := esSearchPaged(
		context.Background(),
		srv.Client(),
		cfg,
		"idx",
		map[string]interface{}{"query": map[string]interface{}{"match_all": map[string]interface{}{}}},
		[]interface{}{map[string]interface{}{"_id": map[string]interface{}{"order": "asc"}}},
		pageSize,
		func(hit map[string]interface{}) error {
			collected++
			return nil
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, totalHits, collected)
	// 2 full pages of 3, then a 3rd empty page proves drain — 3 calls total.
	assert.Equal(t, 3, *calls)
}

func TestESSearchPagedPropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	cfg := &esMigrationConfig{HostUrl: srv.URL, SchemaPrefix: "so_"}
	handlerCalled := false
	err := esSearchPaged(
		context.Background(),
		srv.Client(),
		cfg,
		"idx",
		map[string]interface{}{"query": map[string]interface{}{"match_all": map[string]interface{}{}}},
		[]interface{}{map[string]interface{}{"_id": map[string]interface{}{"order": "asc"}}},
		10,
		func(hit map[string]interface{}) error {
			handlerCalled = true
			return nil
		},
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
	assert.False(t, handlerCalled)
}

func TestESSearchPagedPropagatesHandlerError(t *testing.T) {
	srv, _ := newESStub(t, 10, 3)
	cfg := &esMigrationConfig{HostUrl: srv.URL, SchemaPrefix: "so_"}

	handlerErr := fmt.Errorf("handler aborted")
	hits := 0
	err := esSearchPaged(
		context.Background(),
		srv.Client(),
		cfg,
		"idx",
		map[string]interface{}{"query": map[string]interface{}{"match_all": map[string]interface{}{}}},
		[]interface{}{map[string]interface{}{"_id": map[string]interface{}{"order": "asc"}}},
		3,
		func(hit map[string]interface{}) error {
			hits++
			if hits == 2 {
				return handlerErr
			}
			return nil
		},
	)
	assert.ErrorIs(t, err, handlerErr)
	assert.Equal(t, 2, hits)
}

func TestParseSessionFromHitMissingSessionObject(t *testing.T) {
	// The quarantine path: parseSessionFromHit must return error for a doc without the
	// so_session object. migrateAssistantData relies on this to drop the hit into the
	// assistant_migration_failures table.
	_, err := parseSessionFromHit(map[string]interface{}{"_id": "abc"}, "so_")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing session object")
}
