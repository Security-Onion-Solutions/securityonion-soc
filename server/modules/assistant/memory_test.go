// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	pgvector "github.com/pgvector/pgvector-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func sqlContains(substr string) any {
	return mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, substr)
	})
}

func nilStringPtr() any {
	return mock.MatchedBy(func(s *string) bool {
		return s == nil
	})
}

func stringPtrTo(expected string) any {
	return mock.MatchedBy(func(s *string) bool {
		return s != nil && *s == expected
	})
}

// scriptedAdapter is a captureAdapter whose SendMessage response is supplied by
// the test, for driving the memory extraction/reconciliation paths.
type scriptedAdapter struct {
	captureAdapter
	send func(ctx context.Context, req *model.ChatRequest) (*model.Message, error)
}

func (a *scriptedAdapter) SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
	a.lastReq = req
	return a.send(ctx, req)
}

func textResponse(texts ...string) *model.Message {
	blocks := make([]model.ContentBlock, 0, len(texts))
	for _, txt := range texts {
		blocks = append(blocks, model.ContentBlock{Type: "text", Text: txt})
	}

	return &model.Message{Role: "assistant", ContentBlocks: blocks}
}

type nearbyRowFixture struct {
	id, userId, memoryText, modelId string
	sessionId, targetUserId         *string
	embedding                       []float32
	similarity                      float64
}

// expectNearbyRow scripts one Scan call on mRows, filling the ten out-params
// FindNearbyMemories reads per row. Uses Once so successive rows are consumed
// in order; pair each with an .On("Next").Return(true).Once().
func expectNearbyRow(mRows *mockdb.MockRows, row nearbyRowFixture) {
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args.Get(0).(*string)) = row.id
			*(args.Get(3).(*string)) = row.userId
			*(args.Get(4).(*string)) = row.memoryText
			*(args.Get(5).(**string)) = row.sessionId
			*(args.Get(6).(*pgvector.Vector)) = pgvector.NewVector(row.embedding)
			*(args.Get(7).(*string)) = row.modelId
			*(args.Get(8).(**string)) = row.targetUserId
			*(args.Get(9).(*float64)) = row.similarity
		}).Return(nil).Once()
}

// newReconcileTestCoordinator builds the minimal coordinator reconcileMemories
// needs: a resolvable "Reconcile" memory role mapped to an enabled model whose
// adapter is registered.
func newReconcileTestCoordinator(mDB *mockdb.MockDB, adapter server.AssistantAdapter) *AssistantCoordinator {
	return &AssistantCoordinator{
		srv: &server.Server{
			DB: mDB,
			Config: &config.ServerConfig{ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{AvailableModels: []model.ModelParameters{
					{ID: "rec-model", Adapter: "TestAdapter", Enabled: true},
				}},
			}},
		},
		adapters:                 map[string]server.AssistantAdapter{"TestAdapter": adapter},
		memoryAgents:             map[string]model.AgentParameters{"Reconcile": {Name: "Reconcile", Prompt: "reconcile prompt"}},
		memoryMapping:            map[string]string{"Reconcile": "rec-model@TestAdapter"},
		memoryProximityThreshold: 0.8,
	}
}

func TestAddMemory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	mem := &model.Memory{
		MemoryText: "the user prefers dark mode",
		SessionId:  "session-1",
		Embedding:  []float32{0.1, 0.2},
		ModelID:    "embed-model",
	}
	mem.UserId = "user-1"

	created := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*(args.Get(0).(*string)) = "generated-id"
		*(args.Get(1).(**time.Time)) = &created
		*(args.Get(2).(**time.Time)) = &created
	}).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		"user-1", "the user prefers dark mode", stringPtrTo("session-1"), mock.Anything, "embed-model", nilStringPtr()).
		Return(mRow)

	err := ac.AddMemory(context.Background(), mem)

	assert.NoError(t, err)
	assert.Equal(t, "generated-id", mem.Id)
	assert.Equal(t, &created, mem.CreateTime)
	assert.Equal(t, &created, mem.UpdateTime)
	mDB.AssertExpectations(t)
	mRow.AssertExpectations(t)
}

func TestAddMemoryEmptySessionId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	mem := &model.Memory{
		MemoryText: "seeded memory",
		Embedding:  []float32{0.1},
		ModelID:    "embed-model",
	}

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		mock.Anything, mock.Anything, nilStringPtr(), mock.Anything, mock.Anything, mock.Anything).
		Return(mRow)

	err := ac.AddMemory(context.Background(), mem)

	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestUpdateMemory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	mem := &model.Memory{
		MemoryText: "updated text",
		SessionId:  "session-2",
		Embedding:  []float32{0.3},
		ModelID:    "embed-model",
	}
	mem.Id = "mem-1"

	updated := time.Date(2026, 8, 6, 13, 0, 0, 0, time.UTC)

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*(args.Get(0).(**time.Time)) = &updated
	}).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains("UPDATE memories"),
		"mem-1", "updated text", stringPtrTo("session-2"), mock.Anything, "embed-model", nilStringPtr()).
		Return(mRow)

	err := ac.UpdateMemory(context.Background(), mem)

	assert.NoError(t, err)
	assert.Equal(t, &updated, mem.UpdateTime)
	mDB.AssertExpectations(t)
	mRow.AssertExpectations(t)
}

func TestUpdateMemoryEmptyId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	err := ac.UpdateMemory(context.Background(), &model.Memory{MemoryText: "no id"})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "without an id")
	mDB.AssertNotCalled(t, "QueryRow", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestUpdateMemoryScanError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	mem := &model.Memory{}
	mem.Id = "missing-id"

	scanErr := errors.New("no rows in result set")

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything).Return(scanErr)

	mDB.On("QueryRow", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mRow)

	err := ac.UpdateMemory(context.Background(), mem)

	assert.ErrorIs(t, err, scanErr)
}

func TestDeleteMemory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	mDB.On("Exec", mock.Anything, sqlContains("DELETE FROM memories"), "mem-1").Return(nil)

	err := ac.DeleteMemory(context.Background(), "mem-1")

	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestDeleteMemoryEmptyId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	err := ac.DeleteMemory(context.Background(), "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "without an id")
	mDB.AssertNotCalled(t, "Exec", mock.Anything, mock.Anything, mock.Anything)
}

func TestDeleteMemoryExecError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	execErr := errors.New("connection lost")

	mDB.On("Exec", mock.Anything, mock.Anything, mock.Anything).Return(execErr)

	err := ac.DeleteMemory(context.Background(), "mem-1")

	assert.ErrorIs(t, err, execErr)
}

func TestMemoryNoDB(t *testing.T) {
	ac := &AssistantCoordinator{srv: &server.Server{}}

	assert.ErrorIs(t, ac.AddMemory(context.Background(), &model.Memory{}), ErrNoDatabase)
	assert.ErrorIs(t, ac.UpdateMemory(context.Background(), &model.Memory{}), ErrNoDatabase)
	assert.ErrorIs(t, ac.DeleteMemory(context.Background(), "mem-1"), ErrNoDatabase)

	_, err := ac.FindNearbyMemories(context.Background(), []float32{0.1}, nil, "embed-model", 0.8, 5)
	assert.ErrorIs(t, err, ErrNoDatabase)

	_, err = ac.reconcileMemories(context.Background(), []*model.Memory{{}})
	assert.ErrorIs(t, err, ErrNoDatabase)
}

func TestApplyMemories(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	addRow := &mockdb.MockRow{}
	addRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(addRow)

	updateRow := &mockdb.MockRow{}
	updateRow.On("Scan", mock.Anything).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("UPDATE memories"),
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(updateRow)

	mDB.On("Exec", mock.Anything, sqlContains("DELETE FROM memories"), "mem-3").Return(nil)

	updateMem := &model.Memory{MemoryText: "update me"}
	updateMem.Id = "mem-2"

	deleteMem := &model.Memory{}
	deleteMem.Id = "mem-3"

	memories := []*model.ReconciledMemory{
		{Action: "add", Memory: &model.Memory{MemoryText: "new fact"}},
		{Action: "UPDATE", Memory: updateMem},
		{Action: "DELETE", Memory: deleteMem},
		{Action: "NOOP", Memory: &model.Memory{}},
		{Action: "SOMETHING_ELSE", Memory: &model.Memory{}},
	}

	created, updated, deleted, errMap := ac.applyMemories(context.Background(), memories)

	assert.Len(t, errMap, 1)
	// the failed memory has no id, so it is keyed by base64(md5(MemoryText))
	assert.Contains(t, errMap["1B2M2Y8AsgTpgAmY7PhCfg=="], "unknown memory action")
	assert.Equal(t, 1, created)
	assert.Equal(t, 1, updated)
	assert.Equal(t, 1, deleted)
	mDB.AssertExpectations(t)
	mDB.AssertNumberOfCalls(t, "QueryRow", 2)
	mDB.AssertNumberOfCalls(t, "Exec", 1)
}

func TestApplyMemoriesCollectsErrors(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	addRow := &mockdb.MockRow{}
	addRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(addRow)

	updateErr := errors.New("update failed")
	updateRow := &mockdb.MockRow{}
	updateRow.On("Scan", mock.Anything).Return(updateErr)
	mDB.On("QueryRow", mock.Anything, sqlContains("UPDATE memories"),
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(updateRow)

	mDB.On("Exec", mock.Anything, sqlContains("DELETE FROM memories"), "mem-3").Return(nil)

	updateMem := &model.Memory{MemoryText: "update me"}
	updateMem.Id = "mem-2"

	deleteMem := &model.Memory{}
	deleteMem.Id = "mem-3"

	memories := []*model.ReconciledMemory{
		{Action: "ADD", Memory: &model.Memory{MemoryText: "new fact"}},
		{Action: "UPDATE", Memory: updateMem},
		{Action: "DELETE", Memory: deleteMem},
	}

	created, updated, deleted, errMap := ac.applyMemories(context.Background(), memories)

	assert.Len(t, errMap, 1)
	assert.Contains(t, errMap["mem-2"], "update failed")
	assert.Equal(t, 1, created)
	assert.Equal(t, 0, updated)
	assert.Equal(t, 1, deleted)
	mDB.AssertNumberOfCalls(t, "Exec", 1)
}

func storedText(role string, texts ...string) *model.StoredMessage {
	blocks := make([]model.ContentBlock, 0, len(texts))
	for _, txt := range texts {
		blocks = append(blocks, model.ContentBlock{Type: "text", Text: txt})
	}

	return &model.StoredMessage{Message: &model.Message{Role: role, ContentBlocks: blocks}}
}

func TestBuildMemoryExtractTranscript(t *testing.T) {
	tests := []struct {
		name        string
		lastScanned int
		history     []*model.StoredMessage
		expected    string
	}{
		{
			name:        "empty history",
			lastScanned: 0,
			history:     []*model.StoredMessage{},
			expected:    "",
		},
		{
			name:        "index zero includes all messages",
			lastScanned: 0,
			history: []*model.StoredMessage{
				storedText("user", "hi"),
				storedText("assistant", "hello"),
			},
			expected: "user: hi\n\nassistant: hello",
		},
		{
			name:        "starts two messages before the scanned index",
			lastScanned: 5,
			history: []*model.StoredMessage{
				storedText("user", "0"),
				storedText("assistant", "1"),
				storedText("user", "2"),
				storedText("assistant", "3"),
				storedText("user", "4"),
				storedText("assistant", "5"),
			},
			expected: "assistant: 3\n\nuser: 4\n\nassistant: 5",
		},
		{
			name:        "negative index clamps to zero",
			lastScanned: -5,
			history: []*model.StoredMessage{
				storedText("user", "hi"),
			},
			expected: "user: hi",
		},
		{
			name:        "index at end of history keeps the two-message overlap",
			lastScanned: 5,
			history: []*model.StoredMessage{
				storedText("user", "0"),
				storedText("assistant", "1"),
				storedText("user", "2"),
				storedText("assistant", "3"),
				storedText("user", "4"),
			},
			expected: "assistant: 3\n\nuser: 4",
		},
		{
			name:        "index far beyond history",
			lastScanned: 10,
			history: []*model.StoredMessage{
				storedText("user", "0"),
				storedText("assistant", "1"),
				storedText("user", "2"),
			},
			expected: "",
		},
		{
			name:        "multiple text blocks concatenated",
			lastScanned: 0,
			history: []*model.StoredMessage{
				storedText("assistant", "part one, ", "part two"),
			},
			expected: "assistant: part one, part two",
		},
		{
			name:        "non-text blocks dropped, text case-insensitive",
			lastScanned: 0,
			history: []*model.StoredMessage{
				{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{
					{Type: "tool_use", Text: "ignored"},
					{Type: "Text", Text: "kept"},
				}}},
			},
			expected: "assistant: kept",
		},
		{
			name:        "message with only non-text blocks still emits its role",
			lastScanned: 0,
			history: []*model.StoredMessage{
				{Message: &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{
					{Type: "tool_use", Text: "ignored"},
				}}},
				storedText("user", "next"),
			},
			expected: "assistant: \n\nuser: next",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			details := &model.AssistantSessionDetails{
				Session: &model.AssistantSession{LastMemoryScannedIndex: tc.lastScanned},
				History: tc.history,
			}

			assert.Equal(t, tc.expected, buildMemoryExtractTranscript(details))
		})
	}
}

// opAuthorizer authorizes only the operations in allowed, and records the
// requestor id it was handed so tests can assert userId threading.
type opAuthorizer struct {
	allowed         map[string]bool
	lastRequestorId string
}

func (a *opAuthorizer) CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error {
	if id, ok := ctx.Value(web.ContextKeyRequestorId).(string); ok {
		a.lastRequestorId = id
	}

	if a.allowed[operation] {
		return nil
	}

	return model.NewUnauthorized("test-subject", operation, target)
}

func (a *opAuthorizer) CheckUserOperationAuthorized(userId string, operation string, target string) error {
	return nil
}

func TestFilterFactsByUserPerms(t *testing.T) {
	tests := []struct {
		name    string
		allowed map[string]bool
		scopes  []string
		// surviving fact texts in order; nil means the call itself returns nil
		expected []string
	}{
		{
			name:     "no write_self drops everything",
			allowed:  map[string]bool{},
			scopes:   []string{"user", "global"},
			expected: nil,
		},
		{
			name:     "write_global without write_self still drops everything",
			allowed:  map[string]bool{"write_global": true},
			scopes:   []string{"user", "global"},
			expected: nil,
		},
		{
			name:     "write_self keeps user facts and drops global",
			allowed:  map[string]bool{"write_self": true},
			scopes:   []string{"user", "global", "user"},
			expected: []string{"fact-0", "fact-2"},
		},
		{
			name:     "write_self and write_global keep everything in order",
			allowed:  map[string]bool{"write_self": true, "write_global": true},
			scopes:   []string{"user", "global"},
			expected: []string{"fact-0", "fact-1"},
		},
		{
			name:     "global scope match is case-insensitive",
			allowed:  map[string]bool{"write_self": true},
			scopes:   []string{"GLOBAL", "Global", "gLoBaL"},
			expected: []string{},
		},
		{
			name:     "unknown and empty scopes are treated as user-scoped",
			allowed:  map[string]bool{"write_self": true},
			scopes:   []string{"", "team", "USER"},
			expected: []string{"fact-0", "fact-1", "fact-2"},
		},
		{
			name:     "all global without permission returns empty not nil",
			allowed:  map[string]bool{"write_self": true},
			scopes:   []string{"global"},
			expected: []string{},
		},
		{
			name:     "empty input",
			allowed:  map[string]bool{"write_self": true},
			scopes:   []string{},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auth := &opAuthorizer{allowed: tc.allowed}
			ac := &AssistantCoordinator{srv: &server.Server{Authorizer: auth}}

			facts := make([]*model.ExtractedFact, 0, len(tc.scopes))
			for i, scope := range tc.scopes {
				facts = append(facts, &model.ExtractedFact{Fact: fmt.Sprintf("fact-%d", i), Scope: scope})
			}

			got := ac.filterFactsByUserPerms(facts, "user-1")

			if tc.expected == nil {
				assert.Nil(t, got)
			} else {
				gotTexts := make([]string, 0, len(got))
				for _, fact := range got {
					gotTexts = append(gotTexts, fact.Fact)
				}

				assert.NotNil(t, got)
				assert.Equal(t, tc.expected, gotTexts)
			}

			assert.Equal(t, "user-1", auth.lastRequestorId)
		})
	}
}

func TestFindNearbyMemoriesUserScoped(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Twice()
	mRows.On("Next").Return(false)
	expectNearbyRow(mRows, nearbyRowFixture{
		id: "mem-1", userId: "system", memoryText: "likes tea", modelId: "embed-model",
		sessionId: util.Ptr("sess-1"), targetUserId: util.Ptr("user-1"),
		embedding: []float32{0.5, 0.6}, similarity: 0.91,
	})
	expectNearbyRow(mRows, nearbyRowFixture{
		id: "mem-2", userId: "system", memoryText: "drinks coffee", modelId: "embed-model",
		similarity: 0.85,
	})
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	// the userId arg must come last, after the limit
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $5"),
		mock.Anything, "embed-model", 0.8, 5, "user-1").
		Return(mRows, nil)

	got, err := ac.FindNearbyMemories(context.Background(), []float32{0.5, 0.6}, util.Ptr("user-1"), "embed-model", 0.8, 5)

	assert.NoError(t, err)
	assert.Len(t, got, 2)

	assert.Equal(t, 0.91, got[0].Similarity)
	assert.Equal(t, "mem-1", got[0].Memory.Id)
	assert.Equal(t, "memory", got[0].Memory.Kind)
	assert.Equal(t, "likes tea", got[0].Memory.MemoryText)
	assert.Equal(t, "sess-1", got[0].Memory.SessionId)
	assert.Equal(t, []float32{0.5, 0.6}, got[0].Memory.Embedding)
	assert.Equal(t, util.Ptr("user-1"), got[0].Memory.TargetUserId)

	// NULL session_id stays empty
	assert.Equal(t, "", got[1].Memory.SessionId)
	assert.Nil(t, got[1].Memory.TargetUserId)

	mDB.AssertExpectations(t)
	mRows.AssertExpectations(t)
}

func TestFindNearbyMemoriesGlobalScopeNoLimit(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	// nil userId scopes to global rows, non-positive limit becomes LIMIT NULL
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.8, nil).
		Return(mRows, nil)

	got, err := ac.FindNearbyMemories(context.Background(), []float32{0.5}, nil, "embed-model", 0.8, -1)

	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Empty(t, got)
	mDB.AssertExpectations(t)
}

func TestFindNearbyMemoriesQueryError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	queryErr := errors.New("connection lost")

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&mockdb.MockRows{}, queryErr)

	_, err := ac.FindNearbyMemories(context.Background(), []float32{0.5}, nil, "embed-model", 0.8, 5)

	assert.ErrorIs(t, err, queryErr)
}

func TestFindNearbyMemoriesScanError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	scanErr := errors.New("bad row")

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true)
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(scanErr)
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(mRows, nil)

	_, err := ac.FindNearbyMemories(context.Background(), []float32{0.5}, nil, "embed-model", 0.8, 5)

	assert.ErrorIs(t, err, scanErr)
	mRows.AssertCalled(t, "Close")
	mRows.AssertNotCalled(t, "Err")
}

func TestFindNearbyMemoriesRowsErr(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{srv: &server.Server{DB: mDB}}

	rowsErr := errors.New("cursor failed")

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(rowsErr)
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(mRows, nil)

	_, err := ac.FindNearbyMemories(context.Background(), []float32{0.5}, nil, "embed-model", 0.8, 5)

	assert.ErrorIs(t, err, rowsErr)
}

func extractTestFixtures() (*model.AssistantSessionDetails, *model.AgentParameters, *model.ModelParameters) {
	details := &model.AssistantSessionDetails{
		Session: &model.AssistantSession{},
		History: []*model.StoredMessage{
			storedText("user", "I prefer dark mode"),
		},
	}
	memoryAgent := &model.AgentParameters{Name: "Memory", Prompt: "memory prompt"}
	memoryModel := &model.ModelParameters{ID: "mem-model", Adapter: "TestAdapter"}

	return details, memoryAgent, memoryModel
}

func TestExtractFacts(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`[{"fact":"prefers dark mode","scope":"user","category":"preference","durability":"stable","confidence":0.9}]`), nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	facts, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.NoError(t, err)
	if assert.Len(t, facts, 1) {
		assert.Equal(t, "prefers dark mode", facts[0].Fact)
		assert.Equal(t, "user", facts[0].Scope)
		assert.Equal(t, "preference", facts[0].Category)
		assert.Equal(t, "stable", facts[0].Durability)
		assert.Equal(t, 0.9, facts[0].Confidence)
	}

	if assert.NotNil(t, adapter.lastReq) {
		assert.Equal(t, "mem-model", adapter.lastReq.Model)
		assert.Equal(t, "memory prompt", adapter.lastReq.System)
		assert.Equal(t, server.SYSTEM_ID, adapter.lastReq.UserId)
		if assert.Len(t, adapter.lastReq.Messages, 1) {
			assert.Equal(t, "user", adapter.lastReq.Messages[0].Role)
			assert.Equal(t, "user: I prefer dark mode", adapter.lastReq.Messages[0].ContentBlocks[0].Text)
		}
	}
}

func TestExtractFactsLastTextBlockWins(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		msg := textResponse("not json", `[{"fact":"latest wins"}]`)
		msg.ContentBlocks = append(msg.ContentBlocks, model.ContentBlock{Type: "tool_use", Text: "ignored"})
		return msg, nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	facts, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.NoError(t, err)
	if assert.Len(t, facts, 1) {
		assert.Equal(t, "latest wins", facts[0].Fact)
	}
}

func TestExtractFactsUnknownAdapter(t *testing.T) {
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	_, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown adapter for memory model")
}

func TestExtractFactsSendError(t *testing.T) {
	sendErr := errors.New("model unavailable")
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return nil, sendErr
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	_, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.ErrorIs(t, err, sendErr)
}

func TestExtractFactsNoTextContent(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return &model.Message{ContentBlocks: []model.ContentBlock{{Type: "tool_use", Text: "ignored"}}}, nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	_, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no returned content")
}

func TestExtractFactsBadJSON(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse("not json"), nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	_, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.Error(t, err)
}

func TestExtractFactsEmptyArray(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse("[]"), nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	facts, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.NoError(t, err)
	assert.NotNil(t, facts)
	assert.Empty(t, facts)
}

// reconcileTestMem returns a fresh candidate memory per test, since
// reconcileMemories mutates the input in place.
func reconcileTestMem() *model.Memory {
	return &model.Memory{
		MemoryText: "user likes tea",
		Embedding:  []float32{0.1},
		ModelID:    "embed-model",
	}
}

// expectReconcileQuery scripts the FindNearbyMemories lookup reconcileMemories
// performs per candidate: global scope, the coordinator's proximity threshold,
// and no limit.
func expectReconcileQuery(mDB *mockdb.MockDB, mRows *mockdb.MockRows) {
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.8, nil).
		Return(mRows, nil)
}

func neighborRows(rows ...nearbyRowFixture) *mockdb.MockRows {
	mRows := &mockdb.MockRows{}
	for _, row := range rows {
		mRows.On("Next").Return(true).Once()
		expectNearbyRow(mRows, row)
	}
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	return mRows
}

func TestReconcileMemoriesInvalidAgent(t *testing.T) {
	ac := newReconcileTestCoordinator(&mockdb.MockDB{}, &scriptedAdapter{})
	delete(ac.memoryAgents, "Reconcile")

	_, err := ac.reconcileMemories(context.Background(), nil)

	assert.ErrorIs(t, err, ErrInvalidAgent)
}

func TestReconcileMemoriesUnknownAdapter(t *testing.T) {
	ac := newReconcileTestCoordinator(&mockdb.MockDB{}, &scriptedAdapter{})
	ac.adapters = map[string]server.AssistantAdapter{}

	_, err := ac.reconcileMemories(context.Background(), nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown adapter for memory model")
}

func TestReconcileMemoriesEmptyInput(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReconcileTestCoordinator(mDB, &scriptedAdapter{})

	ops, err := ac.reconcileMemories(context.Background(), nil)

	assert.NoError(t, err)
	assert.NotNil(t, ops)
	assert.Empty(t, ops)
	mDB.AssertNotCalled(t, "Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestReconcileMemoriesNoNeighborsAdds(t *testing.T) {
	mDB := &mockdb.MockDB{}
	calls := 0
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		calls++
		return textResponse("{}"), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows())

	mem := reconcileTestMem()

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	if assert.Len(t, ops, 1) {
		assert.Equal(t, "ADD", ops[0].Action)
		assert.False(t, ops[0].ReEmbed)
		assert.Same(t, mem, ops[0].Memory)
		assert.Equal(t, "user likes tea", mem.MemoryText)
	}
	// no similar memories means no LLM round trip
	assert.Equal(t, 0, calls)
	mDB.AssertExpectations(t)
}

func TestReconcileMemoriesFindNearbyError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReconcileTestCoordinator(mDB, &scriptedAdapter{})

	queryErr := errors.New("connection lost")
	mDB.On("Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&mockdb.MockRows{}, queryErr)

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.ErrorIs(t, err, queryErr)
	assert.Nil(t, ops)
}

func TestReconcileMemoriesUpdate(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"update","target_id":"n1","content":"user likes green tea"}]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user drinks tea", modelId: "embed-model", similarity: 0.95,
	}))

	mem := reconcileTestMem()

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	if assert.Len(t, ops, 1) {
		assert.Equal(t, "UPDATE", ops[0].Action)
		assert.True(t, ops[0].ReEmbed)
		assert.Same(t, mem, ops[0].Memory)
	}

	// the candidate is mutated in place and repointed at the neighbor's row
	assert.Equal(t, "user likes green tea", mem.MemoryText)
	assert.Equal(t, "n1", mem.Id)

	// the Reconcile agent request carries the candidate and its neighbors
	if assert.NotNil(t, adapter.lastReq) {
		assert.Equal(t, "rec-model", adapter.lastReq.Model)
		assert.Equal(t, "reconcile prompt", adapter.lastReq.System)
		assert.Equal(t, server.SYSTEM_ID, adapter.lastReq.UserId)

		var body model.ReconcileMemoryBody
		assert.NoError(t, json.Unmarshal([]byte(adapter.lastReq.Messages[0].ContentBlocks[0].Text), &body))
		assert.Equal(t, "user likes tea", body.Candidate.Content)
		assert.Equal(t, "global", body.Candidate.Scope)
		if assert.Len(t, body.Neighbors, 1) {
			assert.Equal(t, "n1", body.Neighbors[0].Id)
			assert.Equal(t, "user drinks tea", body.Neighbors[0].Content)
			assert.Equal(t, "global", body.Neighbors[0].Scope)
			assert.Equal(t, 0.95, body.Neighbors[0].Similarity)
		}
	}
}

func TestReconcileMemoriesUpdateSameContent(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"UPDATE","target_id":"n1","content":"user likes tea"}]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user likes tea", modelId: "embed-model", similarity: 0.99,
	}))

	mem := reconcileTestMem()

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	if assert.Len(t, ops, 1) {
		assert.Equal(t, "UPDATE", ops[0].Action)
		assert.False(t, ops[0].ReEmbed)
	}
	assert.Equal(t, "user likes tea", mem.MemoryText)
	assert.Equal(t, "n1", mem.Id)
}

func TestReconcileMemoriesAddChangedContent(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"ADD","content":"user likes tea, hot"}]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user dislikes coffee", modelId: "embed-model", similarity: 0.81,
	}))

	mem := reconcileTestMem()

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	if assert.Len(t, ops, 1) {
		assert.Equal(t, "ADD", ops[0].Action)
		assert.True(t, ops[0].ReEmbed)
		assert.Same(t, mem, ops[0].Memory)
	}
	assert.Equal(t, "user likes tea, hot", mem.MemoryText)
	assert.Empty(t, mem.Id)
}

func TestReconcileMemoriesNoop(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"NOOP"}]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user likes tea", modelId: "embed-model", similarity: 0.99,
	}))

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.NoError(t, err)
	assert.Empty(t, ops)
}

func TestReconcileMemoriesDeletesAndAdd(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[
			{"op":"DELETE","target_id":"n1"},
			{"op":"DELETE","target_id":"n2"},
			{"op":"ADD"}
		]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(
		nearbyRowFixture{id: "n1", memoryText: "stale one", modelId: "embed-model", similarity: 0.9},
		nearbyRowFixture{id: "n2", memoryText: "stale two", modelId: "embed-model", similarity: 0.85},
	))

	mem := reconcileTestMem()

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	if assert.Len(t, ops, 3) {
		assert.Equal(t, "DELETE", ops[0].Action)
		assert.Equal(t, "n1", ops[0].Memory.Id)
		assert.NotSame(t, mem, ops[0].Memory)
		assert.Empty(t, ops[0].Memory.MemoryText)

		assert.Equal(t, "DELETE", ops[1].Action)
		assert.Equal(t, "n2", ops[1].Memory.Id)

		assert.Equal(t, "ADD", ops[2].Action)
		assert.False(t, ops[2].ReEmbed)
		assert.Same(t, mem, ops[2].Memory)
	}
	assert.Equal(t, "user likes tea", mem.MemoryText)
}

func TestReconcileMemoriesUserScoped(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"NOOP"}]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)

	// a user-scoped candidate queries user-scoped rows and reports scope "user"
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $5"),
		mock.Anything, "embed-model", 0.8, nil, "user-1").
		Return(neighborRows(nearbyRowFixture{
			id: "n1", memoryText: "user likes tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.99,
		}), nil)

	mem := reconcileTestMem()
	mem.TargetUserId = util.Ptr("user-1")

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	assert.Empty(t, ops)

	var body model.ReconcileMemoryBody
	assert.NoError(t, json.Unmarshal([]byte(adapter.lastReq.Messages[0].ContentBlocks[0].Text), &body))
	assert.Equal(t, "user", body.Candidate.Scope)
	if assert.Len(t, body.Neighbors, 1) {
		assert.Equal(t, "user", body.Neighbors[0].Scope)
	}
	mDB.AssertExpectations(t)
}

func TestReconcileMemoriesValidateFails(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"ADD","target_id":"n1"}]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user likes tea", modelId: "embed-model", similarity: 0.9,
	}))

	ops, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ADD with TargetId")
	assert.Nil(t, ops)
}

func TestReconcileMemoriesSendError(t *testing.T) {
	mDB := &mockdb.MockDB{}
	sendErr := errors.New("model unavailable")
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return nil, sendErr
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user likes tea", modelId: "embed-model", similarity: 0.9,
	}))

	rec, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.Empty(t, rec)
	assert.ErrorIs(t, err, sendErr)
}

func TestReconcileMemoriesEmptyResponse(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return &model.Message{}, nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user likes tea", modelId: "embed-model", similarity: 0.9,
	}))

	rec, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.Empty(t, rec)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no returned content")
}

func TestReconcileMemoriesTextlessResponse(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return &model.Message{ContentBlocks: []model.ContentBlock{{Type: "tool_use", Text: "ignored"}}}, nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user likes tea", modelId: "embed-model", similarity: 0.9,
	}))

	rec, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.Empty(t, rec)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no returned content")
}

func TestReconcileMemoriesBadJSON(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse("not json"), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user likes tea", modelId: "embed-model", similarity: 0.9,
	}))

	rec, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.Empty(t, rec)
	assert.Error(t, err)
}
