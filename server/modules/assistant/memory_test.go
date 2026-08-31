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
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	pgvector "github.com/pgvector/pgvector-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/mock/gomock"
)

func sqlContains(substr string) any {
	return mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, substr)
	})
}

func stringPtrTo(expected string) any {
	return mock.MatchedBy(func(s *string) bool {
		return s != nil && *s == expected
	})
}

func nilStringPtr() any {
	return mock.MatchedBy(func(s *string) bool {
		return s == nil
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
	lastUsedAt                      *time.Time
	embedding                       []float32
	similarity                      float64
	userDefined                     bool
	usageCount                      int
}

// expectNearbyRow scripts one Scan call on mRows, filling the thirteen out-params
// FindNearbyMemories reads per row. Uses Once so successive rows are consumed
// in order; pair each with an .On("Next").Return(true).Once().
func expectNearbyRow(mRows *mockdb.MockRows, row nearbyRowFixture) {
	mRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*(args.Get(0).(*string)) = row.id
			*(args.Get(3).(**time.Time)) = row.lastUsedAt
			*(args.Get(4).(*string)) = row.userId
			*(args.Get(5).(*string)) = row.memoryText
			*(args.Get(6).(**string)) = row.sessionId
			*(args.Get(7).(*pgvector.Vector)) = pgvector.NewVector(row.embedding)
			*(args.Get(8).(*string)) = row.modelId
			*(args.Get(9).(**string)) = row.targetUserId
			*(args.Get(10).(*float64)) = row.similarity
			*(args.Get(11).(*bool)) = row.userDefined
			*(args.Get(12).(*int)) = row.usageCount
		}).Return(nil).Once()
}

// newTestMemoryStore wraps mDB in a real database.Store so coordinator tests
// keep scripting SQL expectations directly on the DB mock.
func newTestMemoryStore(mDB *mockdb.MockDB) *database.Store {
	mDB.On("Migrate", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	s, err := database.New(context.Background(), mDB)
	if err != nil {
		panic(err)
	}

	return s
}

// newReconcileTestCoordinator builds the minimal coordinator reconcileMemories
// needs: a resolvable "Reconcile" memory role mapped to an enabled model whose
// adapter is registered.
func newReconcileTestCoordinator(mDB *mockdb.MockDB, adapter server.AssistantAdapter) *AssistantCoordinator {
	return &AssistantCoordinator{
		store: newTestMemoryStore(mDB),
		srv: &server.Server{
			Authorizer: &opAuthorizer{allowed: map[string]bool{"write_self": true, "write_global": true}},
			Config: &config.ServerConfig{ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{AvailableModels: []model.ModelParameters{
					{ID: "rec-model", Adapter: "TestAdapter", Enabled: true},
				}},
			}},
		},
		adapters:      map[string]server.AssistantAdapter{"TestAdapter": adapter},
		memoryAgents:  map[string]model.Agent{"Reconcile": {Name: "Reconcile", Prompt: "reconcile prompt"}},
		memoryMapping: map[string]string{"Reconcile": "rec-model@TestAdapter"},
		memory: memorySettings{
			mem2mem:            0.8,
			maxUserReconcile:   20,
			maxGlobalReconcile: 20,
		},
	}
}

func TestMemoryNoDB(t *testing.T) {
	ac := &AssistantCoordinator{srv: &server.Server{}}

	_, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{{}})
	assert.ErrorIs(t, err, ErrNoDatabase)

	_, _, err = ac.fetchMemoriesForPrompt(context.Background(), "what do I like", "")
	assert.ErrorIs(t, err, ErrNoDatabase)
}

func TestApplyMemories(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := &AssistantCoordinator{store: newTestMemoryStore(mDB)}

	addRow := &mockdb.MockRow{}
	addRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(addRow)

	updateRow := &mockdb.MockRow{}
	updateRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("UPDATE memories"),
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
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
	ac := &AssistantCoordinator{store: newTestMemoryStore(mDB)}

	addRow := &mockdb.MockRow{}
	addRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(addRow)

	updateErr := errors.New("update failed")
	updateRow := &mockdb.MockRow{}
	updateRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(updateErr)
	mDB.On("QueryRow", mock.Anything, sqlContains("UPDATE memories"),
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
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

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

			got := ac.filterFactsByUserPerms(ctx, facts)

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

func extractTestFixtures() (*model.AssistantSessionDetails, *model.Agent, *model.ModelParameters) {
	details := &model.AssistantSessionDetails{
		Session: &model.AssistantSession{},
		History: []*model.StoredMessage{
			storedText("user", "I prefer dark mode"),
		},
	}
	memoryAgent := &model.Agent{Name: "Memory", Prompt: "memory prompt"}
	memoryModel := &model.ModelParameters{ID: "mem-model", Adapter: "TestAdapter"}

	return details, memoryAgent, memoryModel
}

func TestExtractFacts(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`[{"fact":"prefers dark mode","scope":"user","category":"preference","durability":"stable","confidence":0.9}]`), nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	facts, _, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

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

	facts, _, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.NoError(t, err)
	if assert.Len(t, facts, 1) {
		assert.Equal(t, "latest wins", facts[0].Fact)
	}
}

func TestExtractFactsUnknownAdapter(t *testing.T) {
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	_, _, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

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

	_, _, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.ErrorIs(t, err, sendErr)
}

func TestExtractFactsNoTextContent(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return &model.Message{ContentBlocks: []model.ContentBlock{{Type: "tool_use", Text: "ignored"}}}, nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	_, _, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no returned content")
}

func TestExtractFactsBadJSON(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse("not json"), nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	_, _, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.Error(t, err)
}

func TestExtractFactsFencedJSON(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse("```json\n[{\"fact\":\"prefers dark mode\",\"scope\":\"user\"}]\n```"), nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	facts, _, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

	assert.NoError(t, err)
	if assert.Len(t, facts, 1) {
		assert.Equal(t, "prefers dark mode", facts[0].Fact)
		assert.Equal(t, "user", facts[0].Scope)
	}
}

func TestExtractFactsEmptyArray(t *testing.T) {
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse("[]"), nil
	}}
	ac := &AssistantCoordinator{adapters: map[string]server.AssistantAdapter{"TestAdapter": adapter}}
	details, memoryAgent, memoryModel := extractTestFixtures()

	facts, _, err := ac.extractFacts(context.Background(), details, memoryAgent, memoryModel)

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

// expectReconcileQuery scripts the global-scope FindNearbyMemories lookup
// reconcileMemories performs per candidate when the session owner can write
// global memories (user-scoped candidates issue a second, user-scoped query):
// the coordinator's proximity threshold and reconcile neighbor limit.
func expectReconcileQuery(mDB *mockdb.MockDB, mRows *mockdb.MockRows) {
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.8, 20).
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

	_, _, _, err := ac.reconcileMemories(context.Background(), nil)

	assert.ErrorIs(t, err, ErrInvalidAgent)
}

func TestReconcileMemoriesUnknownAdapter(t *testing.T) {
	ac := newReconcileTestCoordinator(&mockdb.MockDB{}, &scriptedAdapter{})
	ac.adapters = map[string]server.AssistantAdapter{}

	_, _, _, err := ac.reconcileMemories(context.Background(), nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown adapter for memory model")
}

func TestReconcileMemoriesEmptyInput(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReconcileTestCoordinator(mDB, &scriptedAdapter{})

	ops, _, _, err := ac.reconcileMemories(context.Background(), nil)

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

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

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

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

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

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

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

func TestReconcileMemoriesFencedJSON(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse("```json\n{\"operations\":[{\"op\":\"update\",\"target_id\":\"n1\",\"content\":\"user likes green tea\"}]}\n```"), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user drinks tea", modelId: "embed-model", similarity: 0.95,
	}))

	mem := reconcileTestMem()

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	if assert.Len(t, ops, 1) {
		assert.Equal(t, "UPDATE", ops[0].Action)
		assert.True(t, ops[0].ReEmbed)
	}

	assert.Equal(t, "user likes green tea", mem.MemoryText)
	assert.Equal(t, "n1", mem.Id)
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

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

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

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

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

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

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

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

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

	// a user-scoped candidate issues two queries — global scope and user scope —
	// and the merged neighbors are sorted by similarity descending
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.8, 20).
		Return(neighborRows(nearbyRowFixture{
			id: "n2", memoryText: "everyone likes tea", modelId: "embed-model",
			similarity: 0.9,
		}), nil)
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.8, 20).
		Return(neighborRows(nearbyRowFixture{
			id: "n1", memoryText: "user likes tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.99,
		}), nil)

	mem := reconcileTestMem()
	mem.TargetUserId = util.Ptr("user-1")

	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	assert.Empty(t, ops)

	var body model.ReconcileMemoryBody
	assert.NoError(t, json.Unmarshal([]byte(adapter.lastReq.Messages[0].ContentBlocks[0].Text), &body))
	assert.Equal(t, "user", body.Candidate.Scope)
	if assert.Len(t, body.Neighbors, 2) {
		// the user neighbor is more similar, so it sorts ahead of the global one
		assert.Equal(t, "n1", body.Neighbors[0].Id)
		assert.Equal(t, "user", body.Neighbors[0].Scope)
		assert.Equal(t, 0.99, body.Neighbors[0].Similarity)

		assert.Equal(t, "n2", body.Neighbors[1].Id)
		assert.Equal(t, "global", body.Neighbors[1].Scope)
		assert.Equal(t, 0.9, body.Neighbors[1].Similarity)
	}
	mDB.AssertExpectations(t)
}

func TestReconcileMemoriesUpdateScopeMatchesTarget(t *testing.T) {
	tests := []struct {
		name         string
		targetId     string
		expectTarget *string
	}{
		{
			name:         "updating a global neighbor keeps the memory global",
			targetId:     "n-global",
			expectTarget: nil,
		},
		{
			name:         "updating a user neighbor keeps the memory user-scoped",
			targetId:     "n-user",
			expectTarget: util.Ptr("user-1"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mDB := &mockdb.MockDB{}
			adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
				return textResponse(fmt.Sprintf(`{"operations":[{"op":"UPDATE","target_id":"%s","content":"updated tea preference"}]}`, tc.targetId)), nil
			}}
			ac := newReconcileTestCoordinator(mDB, adapter)

			mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
				mock.Anything, "embed-model", 0.8, 20).
				Return(neighborRows(nearbyRowFixture{
					id: "n-global", memoryText: "everyone likes tea", modelId: "embed-model", similarity: 0.9,
				}), nil)
			mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
				mock.Anything, "embed-model", "user-1", 0.8, 20).
				Return(neighborRows(nearbyRowFixture{
					id: "n-user", memoryText: "user likes tea", modelId: "embed-model",
					targetUserId: util.Ptr("user-1"), similarity: 0.99,
				}), nil)

			// a user-scoped candidate, so both scope queries run and the agent
			// sees one neighbor of each scope
			mem := reconcileTestMem()
			mem.TargetUserId = util.Ptr("user-1")

			ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

			assert.NoError(t, err)
			if assert.Len(t, ops, 1) {
				assert.Equal(t, "UPDATE", ops[0].Action)
				assert.Equal(t, tc.targetId, ops[0].Memory.Id)
				if tc.expectTarget == nil {
					assert.Nil(t, ops[0].Memory.TargetUserId)
				} else if assert.NotNil(t, ops[0].Memory.TargetUserId) {
					assert.Equal(t, *tc.expectTarget, *ops[0].Memory.TargetUserId)
				}
			}
			mDB.AssertExpectations(t)
		})
	}
}

func TestReconcileMemoriesWriteSelfOnlyOmitsGlobalNeighbors(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"NOOP"}]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)

	auth := &opAuthorizer{allowed: map[string]bool{"write_self": true}}
	ac.srv.Authorizer = auth

	// without write_global, only the user-scoped query runs
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.8, 20).
		Return(neighborRows(nearbyRowFixture{
			id: "n1", memoryText: "user likes tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.99,
		}), nil)

	mem := reconcileTestMem()
	mem.TargetUserId = util.Ptr("user-1")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")

	ops, _, _, err := ac.reconcileMemories(ctx, []*model.Memory{mem})

	assert.NoError(t, err)
	assert.Empty(t, ops)
	assert.Equal(t, "user-1", auth.lastRequestorId)

	var body model.ReconcileMemoryBody
	assert.NoError(t, json.Unmarshal([]byte(adapter.lastReq.Messages[0].ContentBlocks[0].Text), &body))
	if assert.Len(t, body.Neighbors, 1) {
		assert.Equal(t, "n1", body.Neighbors[0].Id)
		assert.Equal(t, "user", body.Neighbors[0].Scope)
	}

	mDB.AssertNotCalled(t, "Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.8, 20)
	mDB.AssertExpectations(t)
}

func TestReconcileMemoriesNoWriteGlobalSkipsGlobalCandidate(t *testing.T) {
	mDB := &mockdb.MockDB{}
	calls := 0
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		calls++
		return textResponse("{}"), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	ac.srv.Authorizer = &opAuthorizer{allowed: map[string]bool{"write_self": true}}

	// a global candidate from a session owner without write_global is dropped
	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.NoError(t, err)
	assert.NotNil(t, ops)
	assert.Empty(t, ops)
	assert.Equal(t, 0, calls)
	mDB.AssertNotCalled(t, "Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestReconcileMemoriesNoWriteSelfSkipsUserCandidate(t *testing.T) {
	mDB := &mockdb.MockDB{}
	calls := 0
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		calls++
		return textResponse("{}"), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	ac.srv.Authorizer = &opAuthorizer{allowed: map[string]bool{"write_global": true}}

	mem := reconcileTestMem()
	mem.TargetUserId = util.Ptr("user-1")

	// a user-scoped candidate from a session owner without write_self is dropped
	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{mem})

	assert.NoError(t, err)
	assert.NotNil(t, ops)
	assert.Empty(t, ops)
	assert.Equal(t, 0, calls)
	mDB.AssertNotCalled(t, "Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestReconcileMemoriesInvalidOpsRemoved(t *testing.T) {
	mDB := &mockdb.MockDB{}
	adapter := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"ADD","target_id":"n1"},{"op":"DELETE","target_id":"n1"}]}`), nil
	}}
	ac := newReconcileTestCoordinator(mDB, adapter)
	expectReconcileQuery(mDB, neighborRows(nearbyRowFixture{
		id: "n1", memoryText: "user likes tea", modelId: "embed-model", similarity: 0.9,
	}))

	// the ADD is invalid (carries a TargetId) and is dropped; the DELETE still applies
	ops, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.NoError(t, err)
	assert.Len(t, ops, 1)
	assert.Equal(t, "DELETE", ops[0].Action)
	assert.Equal(t, "n1", ops[0].Memory.Id)
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

	rec, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

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

	rec, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

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

	rec, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

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

	rec, _, _, err := ac.reconcileMemories(context.Background(), []*model.Memory{reconcileTestMem()})

	assert.Empty(t, rec)
	assert.Error(t, err)
}

// embedAdapter is a captureAdapter whose Embed response is supplied by the
// test, for driving the embedding paths.
type embedAdapter struct {
	captureAdapter
	lastEmbedReq *model.EmbeddingRequest
	embedFn      func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error)
}

func (a *embedAdapter) Embed(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
	a.lastEmbedReq = req
	return a.embedFn(ctx, req)
}

// Overrides captureAdapter, which reports no embedding support.
func (a *embedAdapter) SupportsEmbeddings() bool {
	return true
}

// singleEmbedAdapter returns an embedAdapter that produces one fixed embedding
// per input, the shape most tests need.
func singleEmbedAdapter() *embedAdapter {
	return &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		embeddings := make([][]float32, 0, len(req.Input))
		for range req.Input {
			embeddings = append(embeddings, []float32{0.1})
		}

		return &model.EmbeddingResponse{Model: req.Model, Embeddings: embeddings}, nil
	}}
}

func memoryTestCtx() context.Context {
	return context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-1")
}

// newScanTestCoordinator builds the full coordinator scanForMemories needs: the
// three memory roles each mapped to an enabled model with its own adapter, a
// session store, and DB/authorizer for reconcile and apply.
func newScanTestCoordinator(store server.Assistantstore, mDB *mockdb.MockDB, extract *scriptedAdapter, embed *embedAdapter, reconcile *scriptedAdapter) *AssistantCoordinator {
	return &AssistantCoordinator{
		store: newTestMemoryStore(mDB),
		srv: &server.Server{
			Context:        context.Background(),
			DB:             mDB,
			Authorizer:     &opAuthorizer{allowed: map[string]bool{"write_self": true, "write_global": true}},
			Assistantstore: store,
			Config: &config.ServerConfig{ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{AvailableModels: []model.ModelParameters{
					{ID: "mem-model", Adapter: "ExtractAdapter", Enabled: true},
					{ID: "embed-model", Adapter: "EmbedAdapter", Enabled: true},
					{ID: "rec-model", Adapter: "ReconcileAdapter", Enabled: true},
				}},
			}},
		},
		adapters: map[string]server.AssistantAdapter{
			"ExtractAdapter":   extract,
			"EmbedAdapter":     embed,
			"ReconcileAdapter": reconcile,
		},
		memoryAgents: map[string]model.Agent{
			"Memory":    {Name: "Memory", Prompt: "memory prompt"},
			"Embed":     {Name: "Embed"},
			"Reconcile": {Name: "Reconcile", Prompt: "reconcile prompt"},
		},
		memoryMapping: map[string]string{
			"Memory":    "mem-model@ExtractAdapter",
			"Embed":     "embed-model@EmbedAdapter",
			"Reconcile": "rec-model@ReconcileAdapter",
		},
		memory: memorySettings{
			mem2mem:            0.8,
			maxUserReconcile:   20,
			maxGlobalReconcile: 20,
		},
	}
}

// allowUsageRecording permits the usage-bookkeeping store calls the scanner
// makes (see memory_usage.go) without asserting them; tests that verify the
// recording itself set explicit expectations instead.
func allowUsageRecording(store *servermock.MockAssistantstore) {
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
}

func scanTestSession(sessionId string) *model.AssistantSessionDetails {
	details := &model.AssistantSessionDetails{
		Session: &model.AssistantSession{SessionId: sessionId},
		History: []*model.StoredMessage{storedText("user", "I prefer dark mode")},
	}
	details.Session.UserId = "user-1"

	return details
}

func TestScanForMemoriesAddsExtractedFact(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return([]*model.AssistantSessionDetails{scanTestSession("sess-1")}, nil)
	store.EXPECT().UpdateSessionMemoryScanIndex(gomock.Any(), "sess-1", 1).Return(nil)

	// each agent call lands its exchange in its own new tagged session linked
	// to the scanned session
	createdByTag := map[string]*model.AssistantSession{}
	savedBySession := map[string][]*model.StoredMessage{}
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, session *model.AssistantSession) error {
		if assert.Len(t, session.Tags, 1) {
			createdByTag[session.Tags[0]] = session
		}
		return nil
	}).AnyTimes()
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, sm *model.StoredMessage) error {
		savedBySession[sm.SessionId] = append(savedBySession[sm.SessionId], sm)
		return nil
	}).AnyTimes()

	extractUsage := &model.Usage{InputTokens: 11, OutputTokens: 3}
	embedUsage := &model.Usage{InputTokens: 7}

	extract := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		msg := textResponse(`[{"fact":"prefers dark mode","scope":"user"}]`)
		msg.Usage = extractUsage
		return msg, nil
	}}
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		embeddings := make([][]float32, 0, len(req.Input))
		for range req.Input {
			embeddings = append(embeddings, []float32{0.1})
		}

		return &model.EmbeddingResponse{Model: req.Model, Embeddings: embeddings, Usage: embedUsage}, nil
	}}
	reconcile := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		t.Error("Reconcile agent should not be consulted when there are no neighbors")
		return nil, errors.New("unexpected call")
	}}

	mDB := &mockdb.MockDB{}
	// no neighbors in either scope, so the candidate becomes an ADD
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.8, 20).
		Return(neighborRows(), nil)
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.8, 20).
		Return(neighborRows(), nil)

	created := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*(args.Get(0).(*string)) = "generated-id"
		*(args.Get(1).(**time.Time)) = &created
		*(args.Get(2).(**time.Time)) = &created
	}).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		server.SYSTEM_ID, "prefers dark mode", stringPtrTo("sess-1"), mock.Anything, "embed-model", stringPtrTo("user-1"), false).
		Return(mRow)

	ac := newScanTestCoordinator(store, mDB, extract, embed, reconcile)

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))

	if assert.NotNil(t, extract.lastReq) {
		assert.Equal(t, "mem-model", extract.lastReq.Model)
	}
	if assert.NotNil(t, embed.lastEmbedReq) {
		assert.Equal(t, "embed-model", embed.lastEmbedReq.Model)
		assert.Equal(t, []string{"prefers dark mode"}, embed.lastEmbedReq.Input)
	}
	// permission filtering and reconciliation ran as the session owner
	assert.Equal(t, "user-1", ac.srv.Authorizer.(*opAuthorizer).lastRequestorId)

	// the Memory and Embed spend was recorded: one throwaway session per call,
	// holding the request and the usage-carrying response
	if assert.Contains(t, createdByTag, model.SessionTagMemory) {
		memorySession := createdByTag[model.SessionTagMemory]
		assert.Equal(t, "sess-1", memorySession.EntityId)

		if msgs := savedBySession[memorySession.SessionId]; assert.Len(t, msgs, 2) {
			assert.Equal(t, "user", msgs[0].Message.Role)
			assert.Equal(t, extractUsage, msgs[1].Message.Usage)
		}
	}
	if assert.Contains(t, createdByTag, model.SessionTagEmbed) {
		embedSession := createdByTag[model.SessionTagEmbed]
		assert.Equal(t, "sess-1", embedSession.EntityId)

		if msgs := savedBySession[embedSession.SessionId]; assert.Len(t, msgs, 2) {
			assert.Equal(t, "user", msgs[0].Message.Role)
			assert.Equal(t, embedUsage, msgs[1].Message.Usage)
		}
	}
	assert.NotContains(t, createdByTag, model.SessionTagReconcile)

	mDB.AssertExpectations(t)
}

func TestScanForMemoriesExtractErrorSkipsIndexUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// no UpdateSessionMemoryScanIndex expectation: a failed session must stay
	// pending so the next scan retries it
	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return([]*model.AssistantSessionDetails{scanTestSession("sess-1")}, nil)

	extract := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return nil, errors.New("model unavailable")
	}}

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, extract, singleEmbedAdapter(), &scriptedAdapter{})

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))
}

func TestScanForMemoriesInterrupted(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, cancel := context.WithCancelCause(context.Background())

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return([]*model.AssistantSessionDetails{
		scanTestSession("sess-1"),
		scanTestSession("sess-2"),
	}, nil)
	// settings change as sess-1 finishes; sess-2 stays pending for the next scan
	store.EXPECT().UpdateSessionMemoryScanIndex(gomock.Any(), "sess-1", 1).DoAndReturn(func(context.Context, string, int) error {
		cancel(errors.New("memory settings updated"))
		return nil
	})
	allowUsageRecording(store)

	calls := 0
	extract := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		calls++
		return textResponse("[]"), nil
	}}

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, extract, singleEmbedAdapter(), &scriptedAdapter{})

	ac.scanForMemories(ctx, log.WithField("test", t.Name()))

	assert.Equal(t, 1, calls, "an interrupted scan must not process the next session")
}

func TestScanForMemoriesContinuesAfterFailedSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return([]*model.AssistantSessionDetails{
		scanTestSession("sess-1"),
		scanTestSession("sess-2"),
	}, nil)
	// only the session that scanned cleanly advances its index
	store.EXPECT().UpdateSessionMemoryScanIndex(gomock.Any(), "sess-2", 1).Return(nil)
	allowUsageRecording(store)

	calls := 0
	extract := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("model unavailable")
		}

		return textResponse("[]"), nil
	}}

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, extract, singleEmbedAdapter(), &scriptedAdapter{})

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))

	assert.Equal(t, 2, calls)
}

func TestScanForMemoriesUpdateReembeds(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return([]*model.AssistantSessionDetails{scanTestSession("sess-1")}, nil)
	store.EXPECT().UpdateSessionMemoryScanIndex(gomock.Any(), "sess-1", 1).Return(nil)

	// collect where usage records land: extract, both embed rounds, and reconcile
	tagBySessionId := map[string]string{}
	var savedTags []string
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, session *model.AssistantSession) error {
		if assert.Len(t, session.Tags, 1) {
			tagBySessionId[session.SessionId] = session.Tags[0]
		}
		return nil
	}).AnyTimes()
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, sm *model.StoredMessage) error {
		savedTags = append(savedTags, tagBySessionId[sm.SessionId])
		return nil
	}).AnyTimes()

	extract := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`[{"fact":"prefers dark mode","scope":"user"}]`), nil
	}}
	embed := singleEmbedAdapter()
	reconcile := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`{"operations":[{"op":"UPDATE","target_id":"n1","content":"user likes green tea"}]}`), nil
	}}

	mDB := &mockdb.MockDB{}
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.8, 20).
		Return(neighborRows(), nil)
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.8, 20).
		Return(neighborRows(nearbyRowFixture{
			id: "n1", memoryText: "user drinks tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.9,
		}), nil)

	updated := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*(args.Get(0).(**time.Time)) = &updated
	}).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("UPDATE memories"),
		"n1", "user likes green tea", stringPtrTo("sess-1"), mock.Anything, "embed-model", stringPtrTo("user-1"), false).
		Return(mRow)

	ac := newScanTestCoordinator(store, mDB, extract, embed, reconcile)

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))

	// the reconciled content differs from the candidate, so it is re-embedded
	// before the UPDATE is applied
	if assert.NotNil(t, embed.lastEmbedReq) {
		assert.Equal(t, []string{"user likes green tea"}, embed.lastEmbedReq.Input)
	}

	// every agent call was recorded as its own two-message session: extract,
	// fact embed, reconcile, re-embed
	assert.Equal(t, []string{
		"memory", "memory",
		"embed", "embed",
		"reconcile", "reconcile",
		"embed", "embed",
	}, savedTags)
	assert.Len(t, tagBySessionId, 4)

	mDB.AssertExpectations(t)
}

func TestScanForMemoriesEmbedErrorSkipsSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// no UpdateSessionMemoryScanIndex expectation: the session must stay pending
	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return([]*model.AssistantSessionDetails{scanTestSession("sess-1")}, nil)
	allowUsageRecording(store)

	extract := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`[{"fact":"prefers dark mode","scope":"user"}]`), nil
	}}
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		return nil, errors.New("embedding provider down")
	}}

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, extract, embed, &scriptedAdapter{})

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))
}

func TestScanForMemoriesEmbedCountMismatchSkipsSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// no UpdateSessionMemoryScanIndex expectation: the session must stay pending
	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return([]*model.AssistantSessionDetails{scanTestSession("sess-1")}, nil)
	allowUsageRecording(store)

	extract := &scriptedAdapter{send: func(ctx context.Context, req *model.ChatRequest) (*model.Message, error) {
		return textResponse(`[{"fact":"prefers dark mode","scope":"user"}]`), nil
	}}
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		return &model.EmbeddingResponse{Model: req.Model, Embeddings: [][]float32{{0.1}, {0.2}}}, nil
	}}

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, extract, embed, &scriptedAdapter{})

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))
}

func TestScanForMemoriesStoreError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return(nil, errors.New("connection lost"))

	extract := &scriptedAdapter{}

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, extract, singleEmbedAdapter(), &scriptedAdapter{})

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))

	assert.Nil(t, extract.lastReq)
}

func TestScanForMemoriesNoMemoryAgent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// no store expectations: the scan must end before querying for sessions
	store := servermock.NewMockAssistantstore(ctrl)

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, &scriptedAdapter{}, singleEmbedAdapter(), &scriptedAdapter{})
	delete(ac.memoryAgents, "Memory")

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))
}

func TestScanForMemoriesNoEmbedAgent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// no store expectations: the scan must end before querying for sessions
	store := servermock.NewMockAssistantstore(ctrl)

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, &scriptedAdapter{}, singleEmbedAdapter(), &scriptedAdapter{})
	// an unresolvable model mapping disables the role just like a missing agent
	ac.memoryMapping["Embed"] = "missing-model"

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))
}

func TestScanForMemoriesDontScanBefore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cutoff := "2026-01-05T12:00:00.000Z"
	expected, err := time.Parse(time.RFC3339, cutoff)
	assert.NoError(t, err)

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), &expected).Return(nil, nil)

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, &scriptedAdapter{}, singleEmbedAdapter(), &scriptedAdapter{})
	ac.memory.dontScanBefore = cutoff

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))
}

func TestScanForMemoriesInvalidDontScanBefore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// no store expectations: an unparseable cutoff must end the scan before querying
	store := servermock.NewMockAssistantstore(ctrl)

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, &scriptedAdapter{}, singleEmbedAdapter(), &scriptedAdapter{})
	ac.memory.dontScanBefore = "2026-01-05"

	ac.scanForMemories(context.Background(), log.WithField("test", t.Name()))
}

func TestMemoryWorkerShutdown(t *testing.T) {
	ac := &AssistantCoordinator{memory: memorySettings{scanInterval: time.Hour}}

	ctx, cancel := context.WithCancelCause(context.Background())

	done := make(chan struct{})
	go func() {
		ac.memoryWorker(ctx, nil)
		close(done)
	}()

	cancel(errors.New("test shutdown"))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("memory worker did not shut down on context cancellation")
	}
}

func TestMemoryWorkerScansOnTick(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	scanned := make(chan struct{}, 1)
	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).DoAndReturn(func(ctx context.Context, _ *time.Time) ([]*model.AssistantSessionDetails, error) {
		select {
		case scanned <- struct{}{}:
		default:
		}

		return nil, nil
	}).MinTimes(1)

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, &scriptedAdapter{}, singleEmbedAdapter(), &scriptedAdapter{})
	ac.memory.scanInterval = 5 * time.Millisecond

	ctx, cancel := context.WithCancelCause(context.Background())

	done := make(chan struct{})
	go func() {
		ac.memoryWorker(ctx, nil)
		close(done)
	}()

	select {
	case <-scanned:
	case <-time.After(2 * time.Second):
		t.Fatal("memory worker never ran a scan")
	}

	cancel(nil)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("memory worker did not shut down on context cancellation")
	}
}

func TestStartStopMemoryWorker(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return(nil, nil).AnyTimes()

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, &scriptedAdapter{}, singleEmbedAdapter(), &scriptedAdapter{})
	ac.memory.useMemory = true
	ac.memory.useScanner = true
	ac.memory.scanInterval = time.Hour
	ac.srv.Context = context.Background()

	assert.NoError(t, ac.Start())
	assert.True(t, ac.IsRunning())
	assert.NotNil(t, ac.terminateMemory)
	// Start rebuilds the store from srv.DB, running the module's migrations
	assert.NotNil(t, ac.store)

	assert.NoError(t, ac.Stop())
	assert.False(t, ac.IsRunning())
}

// newFetchTestCoordinator builds the minimal coordinator fetchMemoriesForPrompt
// needs: a resolvable "Embed" role, its adapter, per-scope include limits, and
// an authorizer granting the given operations.
func newFetchTestCoordinator(mDB *mockdb.MockDB, embed *embedAdapter, allowed map[string]bool) *AssistantCoordinator {
	return &AssistantCoordinator{
		store: newTestMemoryStore(mDB),
		srv: &server.Server{
			Authorizer: &opAuthorizer{allowed: allowed},
			Config: &config.ServerConfig{ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{AvailableModels: []model.ModelParameters{
					{ID: "embed-model", Adapter: "EmbedAdapter", Enabled: true},
				}},
			}},
		},
		adapters:      map[string]server.AssistantAdapter{"EmbedAdapter": embed},
		memoryAgents:  map[string]model.Agent{"Embed": {Name: "Embed"}},
		memoryMapping: map[string]string{"Embed": "embed-model@EmbedAdapter"},
		memory: memorySettings{
			mem2msg:          0.7,
			maxUserInclude:   5,
			maxGlobalInclude: 5,
		},
	}
}

func TestFetchMemoriesForPromptMissingRequestor(t *testing.T) {
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter(), map[string]bool{"read_authored": true})

	_, _, err := ac.fetchMemoriesForPrompt(context.Background(), "what do I like", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing RequestorId")
}

func TestFetchMemoriesForPromptNoReadSelf(t *testing.T) {
	embed := singleEmbedAdapter()
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, embed, map[string]bool{"read_global": true})

	user, global, err := ac.fetchMemoriesForPrompt(memoryTestCtx(), "what do I like", "")

	// without read_authored the fetch is a silent no-op: no error, no embed call
	assert.NoError(t, err)
	assert.Nil(t, user)
	assert.Nil(t, global)
	assert.Nil(t, embed.lastEmbedReq)
}

func TestFetchMemoriesForPromptRecordsEmbedUsage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mDB := &mockdb.MockDB{}
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.7, 5).
		Return(neighborRows(), nil)

	embedUsage := &model.Usage{InputTokens: 4}
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		return &model.EmbeddingResponse{Model: req.Model, Embeddings: [][]float32{{0.1}}, Usage: embedUsage}, nil
	}}

	ac := newFetchTestCoordinator(mDB, embed, map[string]bool{"read_authored": true})

	// recording runs on a goroutine off the chat hot path; a failing save must
	// stay invisible to the chat
	saved := make(chan *model.StoredMessage, 2)
	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().CreateSession(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, session *model.AssistantSession) error {
		assert.Equal(t, []string{model.SessionTagEmbed}, session.Tags)
		assert.Equal(t, "chat-1", session.EntityId)

		return nil
	})
	store.EXPECT().SaveChat(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, sm *model.StoredMessage) error {
		saved <- sm
		return errors.New("save failed")
	}).Times(2)
	ac.srv.Assistantstore = store

	user, global, err := ac.fetchMemoriesForPrompt(memoryTestCtx(), "what do I like", "chat-1")

	assert.NoError(t, err)
	assert.Empty(t, user)
	assert.Empty(t, global)

	for i := 0; i < 2; i++ {
		select {
		case sm := <-saved:
			if strings.EqualFold(sm.Message.Role, "assistant") {
				assert.Equal(t, embedUsage, sm.Message.Usage)
			} else {
				if assert.Len(t, sm.Message.ContentBlocks, 1) {
					assert.Equal(t, "what do I like", sm.Message.ContentBlocks[0].Text)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatal("embed usage was never recorded")
		}
	}
}

func TestFetchMemoriesForPromptUserAndGlobal(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.7, 5).
		Return(neighborRows(nearbyRowFixture{
			id: "mem-user", memoryText: "likes tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.9,
		}), nil)
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.7, 5).
		Return(neighborRows(nearbyRowFixture{
			id: "mem-global", memoryText: "the SOC uses Zeek", modelId: "embed-model",
			similarity: 0.8,
		}), nil)

	embed := singleEmbedAdapter()
	ac := newFetchTestCoordinator(mDB, embed, map[string]bool{"read_authored": true, "read_global": true})

	user, global, err := ac.fetchMemoriesForPrompt(memoryTestCtx(), "what do I like", "")

	assert.NoError(t, err)
	if assert.Len(t, user, 1) {
		assert.Equal(t, "mem-user", user[0].Memory.Id)
	}
	if assert.Len(t, global, 1) {
		assert.Equal(t, "mem-global", global[0].Memory.Id)
	}
	if assert.NotNil(t, embed.lastEmbedReq) {
		assert.Equal(t, "embed-model", embed.lastEmbedReq.Model)
		assert.Equal(t, []string{"what do I like"}, embed.lastEmbedReq.Input)
	}
	mDB.AssertExpectations(t)
}

func TestFetchMemoriesForPromptSelfOnlySkipsGlobal(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.7, 5).
		Return(neighborRows(nearbyRowFixture{
			id: "mem-user", memoryText: "likes tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.9,
		}), nil)

	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"read_authored": true})

	user, global, err := ac.fetchMemoriesForPrompt(memoryTestCtx(), "what do I like", "")

	assert.NoError(t, err)
	assert.Len(t, user, 1)
	assert.Empty(t, global)
	mDB.AssertNotCalled(t, "Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.7, 5)
	mDB.AssertExpectations(t)
}

func TestFetchMemoriesForPromptZeroLimitsSkipQueries(t *testing.T) {
	mDB := &mockdb.MockDB{}

	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"read_authored": true, "read_global": true})
	ac.memory.maxUserInclude = 0
	ac.memory.maxGlobalInclude = 0

	user, global, err := ac.fetchMemoriesForPrompt(memoryTestCtx(), "what do I like", "")

	// a limit of zero disables that scope entirely: no LIMIT 0 round trips
	assert.NoError(t, err)
	assert.Empty(t, user)
	assert.Empty(t, global)
	mDB.AssertNotCalled(t, "Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestFetchMemoriesForPromptEmbedError(t *testing.T) {
	embedErr := errors.New("embedding provider down")
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		return nil, embedErr
	}}

	ac := newFetchTestCoordinator(&mockdb.MockDB{}, embed, map[string]bool{"read_authored": true})

	_, _, err := ac.fetchMemoriesForPrompt(memoryTestCtx(), "what do I like", "")

	assert.ErrorIs(t, err, embedErr)
}

func TestFetchMemoriesForPromptEmbedCountMismatch(t *testing.T) {
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		return &model.EmbeddingResponse{Model: req.Model, Embeddings: [][]float32{{0.1}, {0.2}}}, nil
	}}

	ac := newFetchTestCoordinator(&mockdb.MockDB{}, embed, map[string]bool{"read_authored": true})

	_, _, err := ac.fetchMemoriesForPrompt(memoryTestCtx(), "what do I like", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 1 embedding")
}

// newMemoryPromptTestCoordinator builds the coordinator prepareChatRequest
// needs to exercise memory injection: a chat model and adapter alongside the
// retrieval pieces from newFetchTestCoordinator.
func newMemoryPromptTestCoordinator(mDB *mockdb.MockDB, embed *embedAdapter) (*AssistantCoordinator, *captureAdapter) {
	chat := &captureAdapter{}

	ac := newFetchTestCoordinator(mDB, embed, map[string]bool{"read_authored": true, "read_global": true})
	ac.memory.useMemory = true
	ac.systemPromptAddendum = "base-append"
	ac.adapters["ChatAdapter"] = chat

	models := &ac.srv.Config.ClientParams.AssistantParams.AvailableModels
	*models = append(*models, model.ModelParameters{ID: "chat-model", Adapter: "ChatAdapter", Enabled: true})

	return ac, chat
}

func userTextMessage(text string) *model.Message {
	return &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{{Type: "text", Text: text}}}
}

// expectUsageCount scripts the async usage-count UPDATE and returns a channel
// closed when it runs, since prepareChatRequest fires it in a goroutine.
func expectUsageCount(mDB *mockdb.MockDB, ids []string) chan struct{} {
	counted := make(chan struct{})
	mDB.On("Exec", mock.Anything, sqlContains("usage_count"), ids, mock.AnythingOfType("time.Time")).Run(func(mock.Arguments) {
		close(counted)
	}).Return(nil)

	return counted
}

func waitForSignal(t *testing.T, ch chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestPrepareChatRequestInjectsMemories(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.7, 5).
		Return(neighborRows(nearbyRowFixture{
			id: "mem-user", memoryText: "likes tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.9,
		}), nil)
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.7, 5).
		Return(neighborRows(nearbyRowFixture{
			id: "mem-global", memoryText: "the SOC uses Zeek", modelId: "embed-model",
			similarity: 0.8,
		}), nil)
	counted := expectUsageCount(mDB, []string{"mem-user", "mem-global"})

	ac, _ := newMemoryPromptTestCoordinator(mDB, singleEmbedAdapter())

	req, _, err := ac.prepareChatRequest(memoryTestCtx(), "chat-model@ChatAdapter", []*model.Message{userTextMessage("what do I like")}, false, model.ApplyChatOpts(model.WithMemories("")))

	assert.NoError(t, err)
	assert.Equal(t,
		"base-append\n\nMemories specific to this user:\n * likes tea\n\nMemories specific to this SOC installation:\n * the SOC uses Zeek",
		req.SystemAppend)

	waitForSignal(t, counted, "usage count update")
	mDB.AssertExpectations(t)
}

func TestPrepareChatRequestUsageCountErrorLogged(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.7, 5).
		Return(neighborRows(nearbyRowFixture{
			id: "mem-user", memoryText: "likes tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.9,
		}), nil)
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.7, 5).
		Return(neighborRows(), nil)

	counted := make(chan struct{})
	mDB.On("Exec", mock.Anything, sqlContains("usage_count"), []string{"mem-user"}, mock.AnythingOfType("time.Time")).Run(func(mock.Arguments) {
		close(counted)
	}).Return(errors.New("connection lost"))

	ac, _ := newMemoryPromptTestCoordinator(mDB, singleEmbedAdapter())

	req, _, err := ac.prepareChatRequest(memoryTestCtx(), "chat-model@ChatAdapter", []*model.Message{userTextMessage("what do I like")}, false, model.ApplyChatOpts(model.WithMemories("")))

	// a failed usage-count update is telemetry only; the request still carries
	// the memories
	assert.NoError(t, err)
	assert.Contains(t, req.SystemAppend, "likes tea")
	waitForSignal(t, counted, "usage count update")
}

func TestPrepareChatRequestWithoutMemoriesOpt(t *testing.T) {
	mDB := &mockdb.MockDB{}
	embed := singleEmbedAdapter()
	ac, _ := newMemoryPromptTestCoordinator(mDB, embed)

	req, _, err := ac.prepareChatRequest(memoryTestCtx(), "chat-model@ChatAdapter", []*model.Message{userTextMessage("what do I like")}, false, model.ApplyChatOpts())

	// useMemory alone is not enough: internal turns (tool continuations,
	// delegation kickoffs) omit WithMemories and must not retrieve
	assert.NoError(t, err)
	assert.Equal(t, "base-append", req.SystemAppend)
	assert.Nil(t, embed.lastEmbedReq)
	mDB.AssertNotCalled(t, "Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestPrepareChatRequestMemoriesSkipNonUserTurn(t *testing.T) {
	mDB := &mockdb.MockDB{}
	embed := singleEmbedAdapter()
	ac, _ := newMemoryPromptTestCoordinator(mDB, embed)

	messages := []*model.Message{
		userTextMessage("what do I like"),
		{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "you like tea"}}},
	}

	req, _, err := ac.prepareChatRequest(memoryTestCtx(), "chat-model@ChatAdapter", messages, false, model.ApplyChatOpts(model.WithMemories("")))

	assert.NoError(t, err)
	assert.Equal(t, "base-append", req.SystemAppend)
	assert.Nil(t, embed.lastEmbedReq)
}

func TestPrepareChatRequestMemoriesFetchErrorSendsWithout(t *testing.T) {
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		return nil, errors.New("embedding provider down")
	}}
	ac, _ := newMemoryPromptTestCoordinator(&mockdb.MockDB{}, embed)

	req, adapter, err := ac.prepareChatRequest(memoryTestCtx(), "chat-model@ChatAdapter", []*model.Message{userTextMessage("what do I like")}, false, model.ApplyChatOpts(model.WithMemories("")))

	// retrieval failure downgrades to a memory-less request, not an error
	assert.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, "base-append", req.SystemAppend)
}

func TestPrepareChatRequestSizeCheckCountsMemories(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $3"),
		mock.Anything, "embed-model", "user-1", 0.7, 5).
		Return(neighborRows(nearbyRowFixture{
			id: "mem-user", memoryText: "likes tea", modelId: "embed-model",
			targetUserId: util.Ptr("user-1"), similarity: 0.9,
		}), nil)
	mDB.On("Query", mock.Anything, sqlContains("target_user_id IS NULL"),
		mock.Anything, "embed-model", 0.7, 5).
		Return(neighborRows(), nil)
	counted := expectUsageCount(mDB, []string{"mem-user"})

	ac, _ := newMemoryPromptTestCoordinator(mDB, singleEmbedAdapter())

	// message (14) + base-append (11) fit within maxChars = 60 * 1.0 * 1.1 = 66;
	// the injected memory section (46 chars) pushes the request over
	models := ac.srv.Config.ClientParams.AssistantParams.AvailableModels
	for i := range models {
		if models[i].ID == "chat-model" {
			models[i].CharsPerTokenEstimate = 1.0
			models[i].ContextLimitLarge = 60
		}
	}

	_, _, err := ac.prepareChatRequest(memoryTestCtx(), "chat-model@ChatAdapter", []*model.Message{userTextMessage("what do I like")}, false, model.ApplyChatOpts(model.WithMemories("")))

	assert.ErrorIs(t, err, ErrRequestTooLarge)
	waitForSignal(t, counted, "usage count update")
}

type memoryRowFixture struct {
	id, userId, memoryText, modelId string
	sessionId, targetUserId         *string
	userDefined                     bool
	usageCount                      int
	similarity                      float64
}

// expectMemoryRow scripts one Scan call over the memoryColumns projection, plus
// the similarity column when the listing is a search.
func expectMemoryRow(mRows *mockdb.MockRows, row memoryRowFixture, withSimilarity bool) {
	count := 11
	if withSimilarity {
		count = 12
	}

	args := make([]any, count)
	for i := range args {
		args[i] = mock.Anything
	}

	mRows.On("Scan", args...).Run(func(a mock.Arguments) {
		*(a.Get(0).(*string)) = row.id
		*(a.Get(4).(*string)) = row.userId
		*(a.Get(5).(*string)) = row.memoryText
		*(a.Get(6).(**string)) = row.sessionId
		*(a.Get(7).(*string)) = row.modelId
		*(a.Get(8).(**string)) = row.targetUserId
		*(a.Get(9).(*bool)) = row.userDefined
		*(a.Get(10).(*int)) = row.usageCount

		if withSimilarity {
			*(a.Get(11).(*float64)) = row.similarity
		}
	}).Return(nil).Once()
}

func expectMemoryCount(mDB *mockdb.MockDB, total int, args ...any) {
	countRow := &mockdb.MockRow{}
	countRow.On("Scan", mock.Anything).Run(func(a mock.Arguments) {
		*(a.Get(0).(*int)) = total
	}).Return(nil)

	on := append([]any{mock.Anything, sqlContains("SELECT COUNT(*) FROM memories")}, args...)
	mDB.On("QueryRow", on...).Return(countRow)
}

func memoryListRows(rows ...memoryRowFixture) *mockdb.MockRows {
	mRows := &mockdb.MockRows{}
	for _, row := range rows {
		mRows.On("Next").Return(true).Once()
		expectMemoryRow(mRows, row, row.similarity != 0)
	}

	mRows.On("Next").Return(false)
	mRows.On("Close").Return()
	mRows.On("Err").Return(nil)

	return mRows
}

func TestListMemoriesSelfScope(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"read_authored": true})

	expectMemoryCount(mDB, 3, "user-1")
	mDB.On("Query", mock.Anything, sqlContains("ORDER BY updated_at DESC"), "user-1", 25, 0).
		Return(memoryListRows(memoryRowFixture{
			id:           "mem-1",
			memoryText:   "prefers dark mode",
			targetUserId: new("user-1"),
			usageCount:   4,
		}), nil)

	results, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{Scope: model.MemoryScopeSelf})

	assert.NoError(t, err)
	assert.Equal(t, 3, results.Total)
	assert.Equal(t, 25, results.Limit)

	if assert.Len(t, results.Memories, 1) {
		assert.Equal(t, "user", results.Memories[0].Scope)
		assert.Equal(t, "user-1", results.Memories[0].TargetUserId)
		assert.Equal(t, 4, results.Memories[0].UsageCount)
		assert.Nil(t, results.Memories[0].Similarity)
	}

	mDB.AssertExpectations(t)
}

func TestListMemoriesDefaultScopeUnionsReadableScopes(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"read_authored": true, "read_global": true})

	expectMemoryCount(mDB, 1, "user-1")
	mDB.On("Query", mock.Anything, sqlContains("(target_user_id = $1 OR target_user_id IS NULL)"), "user-1", 25, 0).
		Return(memoryListRows(memoryRowFixture{id: "mem-2", memoryText: "the DMZ is 10.4.0.0/16"}), nil)

	results, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{})

	assert.NoError(t, err)

	if assert.Len(t, results.Memories, 1) {
		assert.Equal(t, "global", results.Memories[0].Scope)
		assert.Empty(t, results.Memories[0].TargetUserId)
	}

	mDB.AssertExpectations(t)
}

func TestListMemoriesReadAllSeesEveryScope(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"read_authored": true, "read_all": true})

	expectMemoryCount(mDB, 0)
	mDB.On("Query", mock.Anything, sqlContains("WHERE TRUE"), 25, 0).Return(memoryListRows(), nil)

	results, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{})

	assert.NoError(t, err)
	assert.Empty(t, results.Memories)
	mDB.AssertExpectations(t)
}

// Naming a user without a scope narrows to that user plus global, rather than
// falling through to every memory.
func TestListMemoriesReadAllHonorsTargetUser(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"read_authored": true, "read_all": true})

	expectMemoryCount(mDB, 0, "user-2")
	mDB.On("Query", mock.Anything, sqlContains("target_user_id = $1 OR target_user_id IS NULL"), "user-2", 25, 0).
		Return(memoryListRows(), nil)

	results, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{TargetUserId: "user-2"})

	assert.NoError(t, err)
	assert.Empty(t, results.Memories)
	mDB.AssertExpectations(t)
}

func TestListMemoriesGlobalScopeRequiresReadGlobal(t *testing.T) {
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter(), map[string]bool{"read_authored": true})

	_, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{Scope: model.MemoryScopeGlobal})

	assert.ErrorIs(t, err, ErrUnauthorizedMemory)
}

func TestListMemoriesOtherUserRequiresReadAll(t *testing.T) {
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter(), map[string]bool{"read_authored": true, "read_global": true})

	_, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{Scope: model.MemoryScopeSelf, TargetUserId: "user-2"})

	assert.ErrorIs(t, err, ErrUnauthorizedMemory)
}

func TestListMemoriesNoReadPermissions(t *testing.T) {
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter(), map[string]bool{})

	_, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{})

	assert.ErrorIs(t, err, ErrUnauthorizedMemory)
}

func TestListMemoriesMissingRequestor(t *testing.T) {
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter(), map[string]bool{"read_authored": true})

	_, err := ac.ListMemories(context.Background(), &model.MemoryFilter{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing RequestorId")
}

func TestListMemoriesSearchOrdersBySimilarity(t *testing.T) {
	mDB := &mockdb.MockDB{}
	embed := singleEmbedAdapter()
	ac := newFetchTestCoordinator(mDB, embed, map[string]bool{"read_authored": true})

	// the count query binds the scope and model args but never the vector
	expectMemoryCount(mDB, 1, "user-1", "embed-model")
	mDB.On("Query", mock.Anything, sqlContains("ORDER BY embedding <=> $3"), "user-1", "embed-model", mock.Anything, 25, 0).
		Return(memoryListRows(memoryRowFixture{
			id:           "mem-3",
			memoryText:   "prefers Zeek for lateral movement",
			targetUserId: new("user-1"),
			similarity:   0.82,
		}), nil)

	results, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{Scope: model.MemoryScopeSelf, Query: "which logs"})

	assert.NoError(t, err)
	assert.Equal(t, []string{"which logs"}, embed.lastEmbedReq.Input)

	if assert.Len(t, results.Memories, 1) {
		assert.NotNil(t, results.Memories[0].Similarity)
		assert.InDelta(t, 0.82, *results.Memories[0].Similarity, 0.001)
	}

	mDB.AssertExpectations(t)
}

func TestListMemoriesLimitIsCapped(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"read_authored": true})

	expectMemoryCount(mDB, 0, "user-1")
	mDB.On("Query", mock.Anything, mock.Anything, "user-1", MAX_MEMORY_PAGE_SIZE, 0).Return(memoryListRows(), nil)

	_, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{Scope: model.MemoryScopeSelf, Limit: MAX_MEMORY_PAGE_SIZE * 10})

	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func expectGetMemory(mDB *mockdb.MockDB, id string, row memoryRowFixture, found bool) {
	mRows := &mockdb.MockRows{}
	if found {
		mRows.On("Next").Return(true).Once()
		expectMemoryRow(mRows, row, false)
	}

	mRows.On("Next").Return(false)
	mRows.On("Close").Return()
	mRows.On("Err").Return(nil)

	mDB.On("Query", mock.Anything, sqlContains("FROM memories WHERE id = $1"), id).Return(mRows, nil)
}

func TestSaveMemoryCreatesPinnedMemory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	embed := singleEmbedAdapter()
	ac := newFetchTestCoordinator(mDB, embed, map[string]bool{"write_self": true})

	addRow := &mockdb.MockRow{}
	addRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO memories"),
		"user-1", "prefers dark mode", nilStringPtr(), mock.Anything, "embed-model", stringPtrTo("user-1"), true).
		Return(addRow)

	mem := &model.Memory{MemoryText: "  prefers   dark mode  ", TargetUserId: new("user-1")}

	err := ac.SaveMemory(memoryTestCtx(), mem)

	assert.NoError(t, err)
	assert.True(t, mem.UserDefined)
	assert.Equal(t, "embed-model", mem.ModelID)
	mDB.AssertExpectations(t)
}

func TestSaveMemoryRequiresText(t *testing.T) {
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter(), map[string]bool{"write_self": true})

	err := ac.SaveMemory(memoryTestCtx(), &model.Memory{MemoryText: "   ", TargetUserId: new("user-1")})

	assert.ErrorIs(t, err, ErrInvalidMemory)
}

func TestSaveMemoryGlobalRequiresWriteGlobal(t *testing.T) {
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter(), map[string]bool{"write_self": true})

	err := ac.SaveMemory(memoryTestCtx(), &model.Memory{MemoryText: "the DMZ is 10.4.0.0/16"})

	assert.ErrorIs(t, err, ErrUnauthorizedMemory)
}

func TestSaveMemoryAnotherUserRequiresWriteAll(t *testing.T) {
	ac := newFetchTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter(), map[string]bool{"write_self": true, "write_global": true})

	err := ac.SaveMemory(memoryTestCtx(), &model.Memory{MemoryText: "prefers light mode", TargetUserId: new("user-2")})

	assert.ErrorIs(t, err, ErrUnauthorizedMemory)
}

// An edit that moves a memory out of global scope still needs write_global,
// otherwise a user could pull an installation memory into their own.
func TestSaveMemoryChecksTheScopeBeingLeft(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"write_self": true})

	expectGetMemory(mDB, "mem-1", memoryRowFixture{id: "mem-1", memoryText: "the DMZ is 10.4.0.0/16"}, true)

	mem := &model.Memory{MemoryText: "the DMZ is 10.4.0.0/16", TargetUserId: new("user-1")}
	mem.Id = "mem-1"

	err := ac.SaveMemory(memoryTestCtx(), mem)

	assert.ErrorIs(t, err, ErrUnauthorizedMemory)
	mDB.AssertExpectations(t)
}

func TestSaveMemoryUpdateKeepsOriginAndAuthor(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"write_self": true})

	expectGetMemory(mDB, "mem-1", memoryRowFixture{
		id:           "mem-1",
		userId:       server.SYSTEM_ID,
		memoryText:   "prefers dark mode",
		sessionId:    new("sess-9"),
		targetUserId: new("user-1"),
	}, true)

	updateRow := &mockdb.MockRow{}
	updateRow.On("Scan", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mDB.On("QueryRow", mock.Anything, sqlContains("UPDATE memories"),
		"mem-1", "prefers light mode", stringPtrTo("sess-9"), mock.Anything, "embed-model", stringPtrTo("user-1"), true).
		Return(updateRow)

	mem := &model.Memory{MemoryText: "prefers light mode", TargetUserId: new("user-1")}
	mem.Id = "mem-1"

	err := ac.SaveMemory(memoryTestCtx(), mem)

	assert.NoError(t, err)
	assert.Equal(t, server.SYSTEM_ID, mem.UserId)
	mDB.AssertExpectations(t)
}

func TestRemoveMemoryChecksScope(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"write_self": true})

	expectGetMemory(mDB, "mem-1", memoryRowFixture{id: "mem-1", memoryText: "the DMZ is 10.4.0.0/16"}, true)

	err := ac.RemoveMemory(memoryTestCtx(), "mem-1")

	assert.ErrorIs(t, err, ErrUnauthorizedMemory)
	mDB.AssertExpectations(t)
}

func TestRemoveMemoryDeletes(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"write_self": true})

	expectGetMemory(mDB, "mem-1", memoryRowFixture{id: "mem-1", memoryText: "prefers dark mode", targetUserId: new("user-1")}, true)
	mDB.On("Exec", mock.Anything, sqlContains("DELETE FROM memories"), "mem-1").Return(nil)

	err := ac.RemoveMemory(memoryTestCtx(), "mem-1")

	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestRemoveMemoryNotFound(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newFetchTestCoordinator(mDB, singleEmbedAdapter(), map[string]bool{"write_self": true})

	expectGetMemory(mDB, "missing", memoryRowFixture{}, false)

	err := ac.RemoveMemory(memoryTestCtx(), "missing")

	assert.ErrorIs(t, err, ErrMemoryNotFound)
	mDB.AssertExpectations(t)
}

func TestMemoryManagementRequiresDatabase(t *testing.T) {
	ac := &AssistantCoordinator{srv: &server.Server{}}

	_, err := ac.ListMemories(memoryTestCtx(), &model.MemoryFilter{})
	assert.ErrorIs(t, err, ErrNoDatabase)

	assert.ErrorIs(t, ac.SaveMemory(memoryTestCtx(), &model.Memory{MemoryText: "x"}), ErrNoDatabase)
	assert.ErrorIs(t, ac.RemoveMemory(memoryTestCtx(), "mem-1"), ErrNoDatabase)
}

func memorySettingsFixture() memorySettings {
	return memorySettings{
		useMemory:          false,
		useScanner:         false,
		scanInterval:       300 * time.Second,
		mem2mem:            0.8,
		mem2msg:            0.5,
		maxUserInclude:     5,
		maxGlobalInclude:   5,
		maxUserReconcile:   20,
		maxGlobalReconcile: 20,
	}
}

func settingsByID(pairs map[string]string) map[string]*model.Setting {
	byID := map[string]*model.Setting{}
	for id, value := range pairs {
		byID[id] = &model.Setting{Id: id, Value: value}
	}

	return byID
}

func TestApplyMemorySettingsOverlaysStoredValues(t *testing.T) {
	logger := log.WithField("test", t.Name())

	applied := applyMemorySettings(logger, memorySettingsFixture(), settingsByID(map[string]string{
		ConfigSettingUseMemory:                    "true",
		ConfigSettingUseMemoryScanner:             "true",
		ConfigSettingMemoryScanInterval:           "60",
		ConfigSettingMemoryProximity:              "0.9",
		ConfigSettingMessageProximity:             "0.35",
		ConfigSettingMaxUserMemoriesToInclude:     "3",
		ConfigSettingMaxGlobalMemoriesToInclude:   "7",
		ConfigSettingMaxUserMemoriesToReconcile:   "11",
		ConfigSettingMaxGlobalMemoriesToReconcile: "13",
	}))

	assert.True(t, applied.useMemory)
	assert.True(t, applied.useScanner)
	assert.Equal(t, 60*time.Second, applied.scanInterval)
	assert.InDelta(t, 0.9, applied.mem2mem, 0.0001)
	assert.InDelta(t, 0.35, applied.mem2msg, 0.0001)
	assert.Equal(t, 3, applied.maxUserInclude)
	assert.Equal(t, 7, applied.maxGlobalInclude)
	assert.Equal(t, 11, applied.maxUserReconcile)
	assert.Equal(t, 13, applied.maxGlobalReconcile)
}

func TestApplyMemorySettingsKeepsCurrentOnMissingOrInvalid(t *testing.T) {
	logger := log.WithField("test", t.Name())
	current := memorySettingsFixture()

	applied := applyMemorySettings(logger, current, settingsByID(map[string]string{
		ConfigSettingUseMemory:                "not-a-bool",
		ConfigSettingMemoryProximity:          "high",
		ConfigSettingMaxUserMemoriesToInclude: "",
	}))

	assert.Equal(t, current, applied, "an unparseable or empty setting leaves the value alone")
}

// A zero interval would panic time.NewTicker, so it is refused rather than applied.
func TestApplyMemorySettingsRefusesNonPositiveInterval(t *testing.T) {
	logger := log.WithField("test", t.Name())

	for _, value := range []string{"0", "-30"} {
		applied := applyMemorySettings(logger, memorySettingsFixture(), settingsByID(map[string]string{
			ConfigSettingMemoryScanInterval: value,
		}))

		assert.Equal(t, 300*time.Second, applied.scanInterval, "interval %q should be refused", value)
	}
}

func newMemoryReloadTestCoordinator(store *fakeConfigstore) *AssistantCoordinator {
	return &AssistantCoordinator{
		srv: &server.Server{
			Context:     context.Background(),
			Configstore: store,
			Config: &config.ServerConfig{ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{},
			}},
		},
		memory: memorySettingsFixture(),
	}
}

func TestReloadMemoryConfigurationExposesSettings(t *testing.T) {
	store := &fakeConfigstore{settings: []*model.Setting{
		{Id: ConfigSettingUseMemory, Value: "true"},
		{Id: ConfigSettingMaxUserMemoriesToInclude, Value: "9"},
	}}

	ac := newMemoryReloadTestCoordinator(store)

	ac.reloadMemoryConfiguration(context.Background())

	params := ac.srv.Config.ClientParams.AssistantParams
	assert.True(t, params.MemoryEnabled)
	assert.True(t, params.MemoryParams.UseMemory)
	assert.False(t, params.MemoryParams.UseMemoryScanner)
	assert.Equal(t, 9, params.MemoryParams.MaxUserMemoriesToInclude)
	assert.Equal(t, 300, params.MemoryParams.ScanIntervalSeconds)
	assert.Equal(t, 9, ac.memorySnapshot().maxUserInclude)
}

func TestReloadMemoryConfigurationStartsAndStopsScanner(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sessionStore := servermock.NewMockAssistantstore(ctrl)
	sessionStore.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).Return(nil, nil).AnyTimes()

	store := &fakeConfigstore{settings: []*model.Setting{{Id: ConfigSettingUseMemoryScanner, Value: "true"}}}
	ac := newMemoryReloadTestCoordinator(store)
	ac.srv.Assistantstore = sessionStore

	ac.reloadMemoryConfiguration(context.Background())
	assert.NotNil(t, ac.terminateMemory, "enabling the scanner starts its worker")

	// A second reload with the scanner still on must not start a second worker.
	running := ac.terminateMemory
	ac.reloadMemoryConfiguration(context.Background())
	assert.Equal(t, fmt.Sprintf("%p", running), fmt.Sprintf("%p", ac.terminateMemory))

	store.settings = []*model.Setting{{Id: ConfigSettingUseMemoryScanner, Value: "false"}}

	ac.reloadMemoryConfiguration(context.Background())
	assert.Nil(t, ac.terminateMemory, "disabling the scanner stops its worker")
}

func TestReloadMemoryConfigurationInterruptsScanOnChange(t *testing.T) {
	store := &fakeConfigstore{settings: []*model.Setting{{Id: ConfigSettingMaxUserMemoriesToInclude, Value: "9"}}}
	ac := newMemoryReloadTestCoordinator(store)

	scanCtx, cancel := context.WithCancelCause(context.Background())
	ac.terminateMemoryScan = cancel

	ac.reloadMemoryConfiguration(context.Background())

	assert.EqualError(t, context.Cause(scanCtx), "memory settings updated", "a settings overwrite interrupts the running scan")

	// A reload that changes nothing leaves the scan running.
	scanCtx, cancel = context.WithCancelCause(context.Background())
	ac.terminateMemoryScan = cancel

	ac.reloadMemoryConfiguration(context.Background())

	assert.NoError(t, scanCtx.Err(), "a no-op reload must not interrupt the scan")
	cancel(nil)
}

func TestOnConfigSettingUpdatedReloadsMemoryWithoutAgentic(t *testing.T) {
	store := &fakeConfigstore{settings: []*model.Setting{{Id: ConfigSettingUseMemory, Value: "true"}}}
	ac := newMemoryReloadTestCoordinator(store)
	ac.isAgentic = false

	ac.OnConfigSettingUpdated(context.Background(), &model.Setting{Id: ConfigSettingUseMemory, Value: "true"}, false)

	assert.True(t, ac.memorySnapshot().useMemory, "memory settings reload even when agentic is off")
}

func TestMemoryWorkerRearmsOnIntervalChange(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	scanned := make(chan struct{}, 1)
	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().FindSessionsPendingMemoryScan(gomock.Any(), nil).DoAndReturn(func(ctx context.Context, _ *time.Time) ([]*model.AssistantSessionDetails, error) {
		select {
		case scanned <- struct{}{}:
		default:
		}

		return nil, nil
	}).MinTimes(1)

	ac := newScanTestCoordinator(store, &mockdb.MockDB{}, &scriptedAdapter{}, singleEmbedAdapter(), &scriptedAdapter{})
	ac.memory.scanInterval = time.Hour

	wake := make(chan struct{}, 1)
	ctx, cancel := context.WithCancelCause(context.Background())

	done := make(chan struct{})
	go func() {
		ac.memoryWorker(ctx, wake)
		close(done)
	}()

	// Shorten the interval and wake the worker; it should re-arm and scan soon.
	ac.setMemorySettings(memorySettings{scanInterval: 5 * time.Millisecond})
	wake <- struct{}{}

	select {
	case <-scanned:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not pick up the shortened scan interval")
	}

	cancel(nil)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("memory worker did not shut down")
	}
}

func TestApplyMemorySettingsOverlaysModelSelectors(t *testing.T) {
	logger := log.WithField("test", t.Name())
	current := memorySettingsFixture()
	current.memoryModel = "old@SOAI"

	applied := applyMemorySettings(logger, current, settingsByID(map[string]string{
		ConfigSettingMemoryModel:    " new@SOAI ",
		ConfigSettingEmbedModel:     "embed@SOAI",
		ConfigSettingReconcileModel: "",
	}))

	assert.Equal(t, "new@SOAI", applied.memoryModel, "surrounding whitespace is trimmed")
	assert.Equal(t, "embed@SOAI", applied.embedModel)
	assert.Empty(t, applied.reconcileModel, "an empty selector is applied, since that is how a role is disabled")
}

func newMemoryAgentTestCoordinator() *AssistantCoordinator {
	return &AssistantCoordinator{
		srv: &server.Server{
			Context: context.Background(),
			Config: &config.ServerConfig{ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{AvailableModels: []model.ModelParameters{
					{ID: "good-model", Adapter: "TestAdapter", Enabled: true},
				}},
			}},
		},
		embeddedPrompts: map[string]string{
			"prompt_agent_memory":    "memory prompt",
			"prompt_agent_reconcile": "reconcile prompt",
		},
	}
}

func TestApplyMemoryAgentsClearsRolesWhenMemoryOff(t *testing.T) {
	ac := newMemoryAgentTestCoordinator()

	ac.applyMemoryAgents(memorySettings{})

	assert.Empty(t, ac.memoryAgents)
	assert.Empty(t, ac.memoryMapping)
}

func TestApplyMemoryAgentsDisablesRoleWithUnresolvableModel(t *testing.T) {
	ac := newMemoryAgentTestCoordinator()

	ac.applyMemoryAgents(memorySettings{
		useMemory:      true,
		memoryModel:    "good-model@TestAdapter",
		embedModel:     "missing-model@TestAdapter",
		reconcileModel: "good-model@TestAdapter",
	})

	assert.Contains(t, ac.memoryAgents, "Memory")
	assert.Contains(t, ac.memoryAgents, "Reconcile")
	assert.NotContains(t, ac.memoryAgents, "Embed", "an unresolvable selector disables its role")
}

// validateMemoryMappings deletes disabled roles, so a corrected selector has to
// rebuild them; otherwise fixing the config would need a restart.
func TestApplyMemoryAgentsRestoresRoleAfterSelectorIsFixed(t *testing.T) {
	ac := newMemoryAgentTestCoordinator()

	ac.applyMemoryAgents(memorySettings{useMemory: true, embedModel: "missing-model@TestAdapter"})
	assert.NotContains(t, ac.memoryAgents, "Embed")

	ac.applyMemoryAgents(memorySettings{
		useMemory:      true,
		memoryModel:    "good-model@TestAdapter",
		embedModel:     "good-model@TestAdapter",
		reconcileModel: "good-model@TestAdapter",
	})

	assert.Contains(t, ac.memoryAgents, "Embed")
	assert.Equal(t, "memory prompt", ac.memoryAgents["Memory"].Prompt, "roles are rebuilt with their prompts")
	assert.Equal(t, "good-model@TestAdapter", ac.memoryMapping["Embed"])
}

func TestReloadMemoryConfigurationPublishesModelSelectors(t *testing.T) {
	store := &fakeConfigstore{settings: []*model.Setting{
		{Id: ConfigSettingUseMemory, Value: "true"},
		{Id: ConfigSettingEmbedModel, Value: "embed@SOAI"},
	}}

	ac := newMemoryReloadTestCoordinator(store)

	ac.reloadMemoryConfiguration(context.Background())

	assert.Equal(t, "embed@SOAI", ac.srv.Config.ClientParams.AssistantParams.MemoryParams.EmbedModel)
	assert.Equal(t, "embed@SOAI", ac.memorySnapshot().embedModel)
}

func TestApplyMemoryAgentsAppliesPersonaAddenda(t *testing.T) {
	ac := newMemoryAgentTestCoordinator()

	ac.applyMemoryAgents(memorySettings{
		useMemory:        true,
		memoryModel:      "good-model@TestAdapter",
		embedModel:       "good-model@TestAdapter",
		reconcileModel:   "good-model@TestAdapter",
		memoryPersona:    "never record IP addresses",
		reconcilePersona: "prefer keeping the older wording",
	})

	// EffectivePrompt is what setupAgent sends, so the addendum has to survive it.
	memoryRole := ac.memoryAgents["Memory"]
	reconcileRole := ac.memoryAgents["Reconcile"]

	assert.Equal(t, "memory prompt\n\nnever record IP addresses", memoryRole.EffectivePrompt())
	assert.Equal(t, "reconcile prompt\n\nprefer keeping the older wording", reconcileRole.EffectivePrompt())
	assert.Empty(t, ac.memoryAgents["Embed"].PersonaAddendum, "Embed never sees a prompt")
}

func TestApplyMemorySettingsKeepsPersonaWhitespace(t *testing.T) {
	logger := log.WithField("test", t.Name())

	applied := applyMemorySettings(logger, memorySettingsFixture(), settingsByID(map[string]string{
		ConfigSettingMemoryPersona: "line one\n  indented line",
	}))

	assert.Equal(t, "line one\n  indented line", applied.memoryPersona)
}

func TestReloadMemoryConfigurationPublishesPersonas(t *testing.T) {
	store := &fakeConfigstore{settings: []*model.Setting{
		{Id: ConfigSettingUseMemory, Value: "true"},
		{Id: ConfigSettingMemoryPersona, Value: "be terse"},
	}}

	ac := newMemoryReloadTestCoordinator(store)
	ac.embeddedPrompts = map[string]string{"prompt_agent_memory": "memory prompt"}

	ac.reloadMemoryConfiguration(context.Background())

	assert.Equal(t, "be terse", ac.srv.Config.ClientParams.AssistantParams.MemoryParams.MemoryPersona)
	assert.Equal(t, "be terse", ac.memorySnapshot().memoryPersona)
}

func newReembedTestCoordinator(mDB *mockdb.MockDB, embed *embedAdapter) *AssistantCoordinator {
	ac := newFetchTestCoordinator(mDB, embed, map[string]bool{})
	ac.srv.Context = context.Background()

	return ac
}

// expectStaleBatch scripts one batch query returning the given id/text pairs.
func expectStaleBatch(mDB *mockdb.MockDB, modelId string, pairs [][2]string) {
	mRows := &mockdb.MockRows{}
	for _, pair := range pairs {
		id, text := pair[0], pair[1]
		mRows.On("Next").Return(true).Once()
		mRows.On("Scan", mock.Anything, mock.Anything).Run(func(a mock.Arguments) {
			*(a.Get(0).(*string)) = id
			*(a.Get(1).(*string)) = text
		}).Return(nil).Once()
	}

	mRows.On("Next").Return(false)
	mRows.On("Close").Return()
	mRows.On("Err").Return(nil)

	mDB.On("Query", mock.Anything, sqlContains("WHERE model_id <> $1"), modelId, MEMORY_REEMBED_BATCH_SIZE).
		Return(mRows, nil).Once()
}

func expectStaleCount(mDB *mockdb.MockDB, modelId string, total int) {
	countRow := &mockdb.MockRow{}
	countRow.On("Scan", mock.Anything).Run(func(a mock.Arguments) {
		*(a.Get(0).(*int)) = total
	}).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains("COUNT(*) FROM memories WHERE model_id <> $1"), modelId).Return(countRow)
}

func TestReembedRewritesStaleMemories(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReembedTestCoordinator(mDB, singleEmbedAdapter())

	expectStaleCount(mDB, "embed-model", 2)
	expectStaleBatch(mDB, "embed-model", [][2]string{{"mem-1", "likes tea"}, {"mem-2", "the DMZ is 10.4.0.0/16"}})
	expectStaleBatch(mDB, "embed-model", nil)

	// Only the vector and the model change; text, counts and user_defined stand.
	mDB.On("Exec", mock.Anything, sqlContains("UPDATE memories SET embedding = $2, model_id = $3"),
		"mem-1", mock.Anything, "embed-model").Return(nil).Once()
	mDB.On("Exec", mock.Anything, sqlContains("UPDATE memories SET embedding = $2, model_id = $3"),
		"mem-2", mock.Anything, "embed-model").Return(nil).Once()

	ac.reembedStaleMemories(context.Background())

	assert.Equal(t, int64(0), ac.staleMemories.Load(), "the published count is cleared when the pass finishes")
	mDB.AssertExpectations(t)
}

// A pass books its aggregate embedding spend (probe + batches) as a single
// sessionless usage session rather than one per batch.
func TestReembedRecordsAggregateUsage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mDB := &mockdb.MockDB{}
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		embeddings := make([][]float32, 0, len(req.Input))
		for range req.Input {
			embeddings = append(embeddings, []float32{0.1})
		}

		return &model.EmbeddingResponse{Model: req.Model, Embeddings: embeddings, Usage: &model.Usage{InputTokens: 10, Credits: 1}}, nil
	}}

	ac := newReembedTestCoordinator(mDB, embed)

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

	ac.srv.Assistantstore = store

	expectStaleCount(mDB, "embed-model", 1)
	expectStaleBatch(mDB, "embed-model", [][2]string{{"mem-1", "likes tea"}})
	expectStaleBatch(mDB, "embed-model", nil)

	mDB.On("Exec", mock.Anything, sqlContains("UPDATE memories SET embedding = $2, model_id = $3"),
		"mem-1", mock.Anything, "embed-model").Return(nil).Once()

	ac.reembedStaleMemories(context.Background())

	// probe + one batch, summed into one message
	if assert.Len(t, saved, 1) {
		if assert.NotNil(t, saved[0].Message.Usage) {
			assert.Equal(t, 20, saved[0].Message.Usage.InputTokens)
			assert.Equal(t, 2, saved[0].Message.Usage.Credits)
		}

		if assert.Len(t, saved[0].Message.ContentBlocks, 1) {
			assert.Contains(t, saved[0].Message.ContentBlocks[0].Text, "Re-embedded 1 memories")
		}
	}
}

func TestReembedStopsWhenNothingIsStale(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReembedTestCoordinator(mDB, singleEmbedAdapter())

	expectStaleCount(mDB, "embed-model", 0)

	ac.reembedStaleMemories(context.Background())

	// No batch query and no updates: the count alone ends the pass.
	mDB.AssertNotCalled(t, "Query", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mDB.AssertNotCalled(t, "Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// A failed embed must leave the remaining rows alone so the next pass retries them.
func TestReembedStopsOnEmbedFailure(t *testing.T) {
	mDB := &mockdb.MockDB{}
	embed := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		// The probe succeeds; the batch embed fails.
		if len(req.Input) == 1 && req.Input[0] == "probe" {
			return &model.EmbeddingResponse{Model: req.Model, Embeddings: [][]float32{{0.1}}}, nil
		}

		return nil, errors.New("embed failed")
	}}

	ac := newReembedTestCoordinator(mDB, embed)

	expectStaleCount(mDB, "embed-model", 1)
	expectStaleBatch(mDB, "embed-model", [][2]string{{"mem-1", "likes tea"}})

	ac.reembedStaleMemories(context.Background())

	mDB.AssertNotCalled(t, "Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestReembedRequiresAnEmbedRole(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReembedTestCoordinator(mDB, singleEmbedAdapter())
	delete(ac.memoryAgents, "Embed")

	ac.reembedStaleMemories(context.Background())

	mDB.AssertNotCalled(t, "QueryRow", mock.Anything, mock.Anything, mock.Anything)
}

// The pass must survive the request that triggered it, but still be reachable by
// Stop; a cancelled request context alone must not end it.
func TestStartReembedOutlivesItsRequestButStopEndsIt(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReembedTestCoordinator(mDB, singleEmbedAdapter())
	ac.reembedBatchDelay = time.Hour

	reqCtx, cancelRequest := context.WithCancel(context.Background())

	batched := make(chan struct{})

	expectStaleCount(mDB, "embed-model", 2)
	expectStaleBatch(mDB, "embed-model", [][2]string{{"mem-1", "likes tea"}})
	mDB.On("Exec", mock.Anything, sqlContains("UPDATE memories SET embedding"), mock.Anything, mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { close(batched) }).Return(nil)

	ac.startReembed(reqCtx)

	select {
	case <-batched:
	case <-time.After(2 * time.Second):
		t.Fatal("re-embed pass never reached its first batch")
	}

	// The request is done, but the pass is parked in its inter-batch pause.
	cancelRequest()

	assert.Eventually(t, func() bool {
		ac.memoryWorkerMu.Lock()
		defer ac.memoryWorkerMu.Unlock()

		return ac.reembedding
	}, time.Second, 10*time.Millisecond, "re-embed pass ended with its request context")

	assert.NoError(t, ac.Stop())

	assert.Eventually(t, func() bool {
		ac.memoryWorkerMu.Lock()
		defer ac.memoryWorkerMu.Unlock()

		return !ac.reembedding && ac.terminateReembed == nil
	}, 2*time.Second, 10*time.Millisecond, "Stop did not end the re-embed pass")
}

// Storing a model the batch query does not filter on would re-read the same rows
// forever, so a mid-pass model change ends the pass instead.
func TestReembedStopsWhenTheModelChangesMidPass(t *testing.T) {
	mDB := &mockdb.MockDB{}

	calls := 0
	drifting := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		calls++

		embeddings := make([][]float32, 0, len(req.Input))
		for range req.Input {
			embeddings = append(embeddings, []float32{0.1})
		}

		// The probe names one model; the batch comes back from another.
		if calls == 1 {
			return &model.EmbeddingResponse{Model: req.Model, Embeddings: embeddings}, nil
		}

		return &model.EmbeddingResponse{Model: "embed-model-v2", Embeddings: embeddings}, nil
	}}

	ac := newReembedTestCoordinator(mDB, drifting)

	expectStaleCount(mDB, "embed-model", 1)
	expectStaleBatch(mDB, "embed-model", [][2]string{{"mem-1", "likes tea"}})

	ac.reembedStaleMemories(context.Background())

	// Nothing was written, so the next pass finds the same rows under the new model.
	mDB.AssertNotCalled(t, "Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	mDB.AssertNumberOfCalls(t, "Query", 1)
}

// A stalled embedding call is bounded, so it cannot strand the pass and block
// every later one.
func TestReembedTimesOutAStalledEmbedCall(t *testing.T) {
	mDB := &mockdb.MockDB{}

	stalled := &embedAdapter{embedFn: func(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}

	ac := newReembedTestCoordinator(mDB, stalled)
	ac.reembedCallTimeout = 50 * time.Millisecond

	done := make(chan struct{})
	go func() {
		ac.reembedStaleMemories(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled embedding call was never bounded")
	}

	// The probe never returned a model, so nothing was counted or read.
	mDB.AssertNotCalled(t, "QueryRow", mock.Anything, mock.Anything, mock.Anything)
}

func TestStartReembedRunsOnlyOnePassAtATime(t *testing.T) {
	ac := newReembedTestCoordinator(&mockdb.MockDB{}, singleEmbedAdapter())

	ac.memoryWorkerMu.Lock()
	ac.reembedding = true
	ac.memoryWorkerMu.Unlock()

	// Returns without touching the database because a pass is already running.
	ac.startReembed(context.Background())
}

// Without a store there is nothing to re-embed, so the pass never starts.
func TestStartReembedRequiresDatabase(t *testing.T) {
	ac := &AssistantCoordinator{srv: &server.Server{}}

	ac.startReembed(context.Background())

	ac.memoryWorkerMu.Lock()
	defer ac.memoryWorkerMu.Unlock()
	assert.False(t, ac.reembedding)
}

func TestReembedPacesBetweenBatches(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReembedTestCoordinator(mDB, singleEmbedAdapter())
	ac.reembedBatchDelay = 60 * time.Millisecond

	expectStaleCount(mDB, "embed-model", 1)
	expectStaleBatch(mDB, "embed-model", [][2]string{{"mem-1", "likes tea"}})
	expectStaleBatch(mDB, "embed-model", nil)
	mDB.On("Exec", mock.Anything, sqlContains("UPDATE memories SET embedding"), mock.Anything, mock.Anything, mock.Anything).Return(nil)

	start := time.Now()
	ac.reembedStaleMemories(context.Background())

	assert.GreaterOrEqual(t, time.Since(start), 60*time.Millisecond, "the pass yields between batches")
}

// Shutdown during the pause must not abandon work: the rows left keep their old
// model_id, so the next pass finds them again.
func TestReembedStopsWhenContextIsCancelledMidPass(t *testing.T) {
	mDB := &mockdb.MockDB{}
	ac := newReembedTestCoordinator(mDB, singleEmbedAdapter())
	ac.reembedBatchDelay = time.Hour

	ctx, cancel := context.WithCancel(context.Background())

	expectStaleCount(mDB, "embed-model", 2)
	expectStaleBatch(mDB, "embed-model", [][2]string{{"mem-1", "likes tea"}})
	mDB.On("Exec", mock.Anything, sqlContains("UPDATE memories SET embedding"), mock.Anything, mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { cancel() }).Return(nil)

	done := make(chan struct{})
	go func() {
		ac.reembedStaleMemories(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("re-embed pass did not stop on context cancellation")
	}

	// Only the first batch was requested; the second was never read.
	mDB.AssertNumberOfCalls(t, "Query", 1)
}

func TestStripMarkdownWrapper(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no fence unchanged",
			input:    `{"key": "value"}`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "json language fence",
			input:    "```json\n{\"key\": \"value\"}\n```",
			expected: `{"key": "value"}`,
		},
		{
			name:     "garbage language fence",
			input:    "```garbage\n{\"key\": \"value\"}\n```",
			expected: `{"key": "value"}`,
		},
		{
			name:     "fence without language",
			input:    "```\n{\"key\": \"value\"}\n```",
			expected: `{"key": "value"}`,
		},
		{
			name:     "trailing newline after closing fence",
			input:    "```json\n[{\"fact\": \"a\"}]\n```\n",
			expected: `[{"fact": "a"}]`,
		},
		{
			name:     "opening fence only",
			input:    "```json\n{\"key\": \"value\"}",
			expected: `{"key": "value"}`,
		},
		{
			name:     "closing fence only",
			input:    "{\"key\": \"value\"}\n```",
			expected: `{"key": "value"}`,
		},
		{
			name:     "interior backticks preserved",
			input:    "```json\n{\"key\": \"run ```ls``` now\"}\n```",
			expected: `{"key": "run ` + "```ls```" + ` now"}`,
		},
		{
			name:     "interior markdown without wrapper unchanged",
			input:    "{\"key\": \"```json\\ninner\\n```\"}",
			expected: "{\"key\": \"```json\\ninner\\n```\"}",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only a fence",
			input:    "```",
			expected: "",
		},
		{
			name:     "only fence with language",
			input:    "```json\n```",
			expected: "",
		},
		{
			name:     "single line fenced",
			input:    "```json{\"key\": \"value\"}```",
			expected: `{"key": "value"}`,
		},
		{
			name:     "whitespace only unchanged",
			input:    "  \n  ",
			expected: "  \n  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, stripMarkdownWrapper(tt.input))
		})
	}
}
