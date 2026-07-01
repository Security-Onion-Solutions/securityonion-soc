// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	detectionsmock "github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// --- sessionLocks ----------------------------------------------------------

// Without mutual exclusion this increments a non-atomic counter from many
// goroutines and the race detector / a wrong final count would flag it.
func TestSessionLocks_MutualExclusionPerKey(t *testing.T) {
	var locks sessionLocks
	const key = "session-a"
	const goroutines = 50
	const perGoroutine = 200

	counter := 0
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				locks.lock(key)
				counter++ // guarded by the per-key lock
				locks.unlock(key)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, goroutines*perGoroutine, counter)
}

func TestSessionLocks_IndependentKeysDoNotBlock(t *testing.T) {
	var locks sessionLocks

	locks.lock("session-a")
	defer locks.unlock("session-a")

	// A different key must be acquirable while session-a is held.
	acquired := make(chan struct{})
	go func() {
		locks.lock("session-b")
		locks.unlock("session-b")
		close(acquired)
	}()

	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("locking an independent key blocked on a different session's lock")
	}
}

func TestSessionLocks_PrunesUnusedEntries(t *testing.T) {
	var locks sessionLocks
	const key = "session-a"

	entryCount := func() int {
		locks.mu.Lock()
		defer locks.mu.Unlock()
		return len(locks.entries)
	}

	// Balanced lock/unlock leaves nothing behind.
	locks.lock(key)
	assert.Equal(t, 1, entryCount(), "entry exists while the lock is held")
	locks.unlock(key)
	assert.Equal(t, 0, entryCount(), "entry pruned after unlock")

	// tryLock + unlock also prunes.
	require.True(t, locks.tryLock(key))
	assert.Equal(t, 1, entryCount())
	locks.unlock(key)
	assert.Equal(t, 0, entryCount())

	// A failed tryLock drops its own reference; the holder keeps the entry.
	locks.lock(key)
	assert.False(t, locks.tryLock(key), "lock is already held")
	assert.Equal(t, 1, entryCount(), "a failed tryLock must not leave a dangling reference")
	locks.unlock(key)
	assert.Equal(t, 0, entryCount(), "entry pruned once the holder releases")

	// The entry survives while a second goroutine is blocked waiting on it, and is
	// pruned only once that waiter finishes.
	locks.lock(key)
	waiting := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(waiting)
		locks.lock(key) // blocks until the holder below releases
		close(acquired)
		locks.unlock(key)
	}()
	<-waiting
	assert.Eventually(t, func() bool { return entryCount() == 1 }, time.Second, 5*time.Millisecond,
		"entry must persist while a waiter is blocked on it")
	locks.unlock(key) // hand the lock to the waiter; must not delete the entry it holds
	<-acquired
	assert.Eventually(t, func() bool { return entryCount() == 0 }, time.Second, 5*time.Millisecond,
		"entry pruned after the waiter finishes")
}

// --- coalescing helpers ----------------------------------------------------

func TestToolResultInHistory(t *testing.T) {
	messages := []*model.Message{
		storedToolUseTurn("tu1", "tu2").Message,
		nil,
		buildToolResultMessage("tu1", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil),
	}

	assert.True(t, toolResultInHistory(messages, "tu1"))
	assert.False(t, toolResultInHistory(messages, "tu2"), "tu2 has a tool_use but no tool_result yet")
	assert.False(t, toolResultInHistory(messages, ""), "an empty tool_use id never matches")
	assert.False(t, toolResultInHistory(nil, "tu1"))
}

func TestTurnAlreadyContinued(t *testing.T) {
	toolUse := storedToolUseTurn("tu1").Message
	resultTu1 := buildToolResultMessage("tu1", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)
	assistantReply := &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "done"}}}

	// Conversation still waiting for the model: trailing tool_result.
	assert.False(t, turnAlreadyContinued([]*model.Message{toolUse, resultTu1}))
	// Model already responded: trailing assistant turn.
	assert.True(t, turnAlreadyContinued([]*model.Message{toolUse, resultTu1, assistantReply}))
	// Trailing nils are skipped.
	assert.True(t, turnAlreadyContinued([]*model.Message{toolUse, resultTu1, assistantReply, nil}))
	assert.False(t, turnAlreadyContinued(nil))
}

// --- exactly-once continuation (integration) -------------------------------

// fakeAssistantstore is a minimal, thread-safe, read-your-writes store: a saved
// message is immediately visible to a subsequent read (mirroring the elastic
// store's WithRefresh("true")). Only the methods the continuation path touches do
// real work.
type fakeAssistantstore struct {
	mu   sync.Mutex
	msgs map[string][]*model.StoredMessage
}

func newFakeAssistantstore() *fakeAssistantstore {
	return &fakeAssistantstore{msgs: map[string][]*model.StoredMessage{}}
}

func (f *fakeAssistantstore) seed(sessionId string, msg *model.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs[sessionId] = append(f.msgs[sessionId], &model.StoredMessage{SessionId: sessionId, Message: msg})
}

func (f *fakeAssistantstore) SaveChat(_ context.Context, m *model.StoredMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs[m.SessionId] = append(f.msgs[m.SessionId], m)
	return nil
}

func (f *fakeAssistantstore) GetChatMessages(_ context.Context, s *model.AssistantSession) ([]*model.StoredMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	src := f.msgs[s.SessionId]
	out := make([]*model.StoredMessage, len(src))
	copy(out, src)
	return out, nil
}

func (f *fakeAssistantstore) countToolResults(sessionId, toolUseId string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, sm := range f.msgs[sessionId] {
		if sm == nil || sm.Message == nil {
			continue
		}
		for _, cb := range sm.Message.ContentBlocks {
			if cb.ToolResult != nil && cb.ToolResult.ToolUseId == toolUseId {
				n++
			}
		}
	}
	return n
}

func (f *fakeAssistantstore) GetChatHistory(ctx context.Context, sessionId string) ([]*model.StoredMessage, error) {
	return f.GetChatMessages(ctx, &model.AssistantSession{SessionId: sessionId})
}
func (f *fakeAssistantstore) GetSessions(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
	o := &model.GetSessionsOpts{}
	for _, opt := range opts {
		opt(o)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Honor a session-id filter so loadTurnSession returns the session the caller
	// asked for (and loadSessionHistory then reads the right history).
	if id := o.SessionId(); id != "" {
		if _, ok := f.msgs[id]; ok {
			return []*model.AssistantSession{{SessionId: id}}, nil
		}
		return nil, nil
	}
	return []*model.AssistantSession{{SessionId: "default-session"}}, nil
}
func (f *fakeAssistantstore) CreateSession(_ context.Context, _ *model.AssistantSession) error {
	return nil
}
func (f *fakeAssistantstore) UpdateSessionTags(_ context.Context, _ string, _ []string) error {
	return nil
}
func (f *fakeAssistantstore) DeleteSession(_ context.Context, _ string) error { return nil }
func (f *fakeAssistantstore) GetUsage(_ context.Context, _, _ time.Time) ([]*model.UserUsage, error) {
	return nil, nil
}

// newCoordinatorWithStore builds a coordinator wired to a stateful store and a
// MakeRequest stub that counts model dispatches and returns a fresh stream each call.
func newCoordinatorWithStore(t *testing.T, ctrl *gomock.Controller, store server.Assistantstore, sends *int32) *AssistantCoordinator {
	t.Helper()

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockIO.EXPECT().MakeRequest(gomock.Any(), true).DoAndReturn(
		func(_ *http.Request, _ bool) (*http.Response, error) {
			atomic.AddInt32(sends, 1)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: [DONE]\n\n"))}, nil
		}).AnyTimes()

	srv := &server.Server{
		Assistantstore: store,
		Host:           &web.Host{Version: "1.0.0"},
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: []model.ModelParameters{{ID: "test-model", Adapter: "MyAdapter"}},
				},
			},
		},
	}

	return &AssistantCoordinator{
		srv:       srv,
		IOManager: mockIO,
		adapters: map[string]server.AssistantAdapter{
			"MyAdapter": &SOAiCloudAdapter{apiUrl: "https://api.example.com", srv: srv, IOManager: mockIO},
		},
		toolConfig: []byte(`{"tools": [], "tool_choice": {"auto": {}}}`),
	}
}

func userCtx() context.Context {
	return context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
}

// The crux: several parallel tool results for one model turn, dispatched concurrently,
// must produce exactly one model continuation and exactly one stored tool_result per
// tool_use -- no stall, no double-send, no duplicate docs. continueWithToolResult
// takes the per-session lock itself, so the goroutines call it directly.
func TestContinueWithToolResult_ExactlyOnceUnderConcurrency(t *testing.T) {
	const sessionId = "concurrent-session"
	ids := []string{"tu1", "tu2", "tu3"}

	store := newFakeAssistantstore()
	store.seed(sessionId, storedToolUseTurn(ids...).Message)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	var sends int32
	ac := newCoordinatorWithStore(t, ctrl, store, &sends)

	sess := &model.AssistantSession{SessionId: sessionId}
	turns := make([]*model.StreamedTurn, len(ids))
	errs := make([]error, len(ids))

	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			toolMsg := buildToolResultMessage(id, &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)
			// waitForLock: exercise the coalescing/serialization path (the fail-fast path
			// is covered by TestContinueWithToolResult_BusyReturnsError).
			turns[i], errs[i] = ac.continueWithToolResult(userCtx(), sess, sessionId, "test-model@MyAdapter", toolMsg, waitForLock)
		}(i, id)
	}
	wg.Wait()

	senders := 0
	for i := range ids {
		require.NoError(t, errs[i])
		require.NotNil(t, turns[i])
		if turns[i].Response != nil {
			senders++
			turns[i].Response.Body.Close()
		}
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&sends), "exactly one model continuation must be dispatched")
	assert.Equal(t, 1, senders, "exactly one request must own the continuation; the rest are persist-only")
	for _, id := range ids {
		assert.Equal(t, 1, store.countToolResults(sessionId, id), "each tool_use must have exactly one stored result")
	}
}

// A timeout-retry of the tool whose result already drove the continuation, arriving
// after that continuation has been persisted, must not dispatch a second model turn
// nor duplicate the stored result.
func TestContinueWithToolResult_RetryDoesNotDoubleSend(t *testing.T) {
	const sessionId = "retry-session"

	store := newFakeAssistantstore()
	store.seed(sessionId, storedToolUseTurn("tu1").Message)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	var sends int32
	ac := newCoordinatorWithStore(t, ctrl, store, &sends)

	sess := &model.AssistantSession{SessionId: sessionId}
	result := func() *model.Message {
		return buildToolResultMessage("tu1", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)
	}

	// First request continues the turn (the sole tool_use is now answered).
	turn, err := ac.continueWithToolResult(userCtx(), sess, sessionId, "test-model@MyAdapter", result(), failFast)
	require.NoError(t, err)
	require.NotNil(t, turn.Response)
	turn.Response.Body.Close()
	assert.Equal(t, int32(1), atomic.LoadInt32(&sends))

	// The continuation finishes: the handler runs finalize once the stream completes,
	// which persists the assistant response and releases the session lock (#1). The
	// [DONE] stream yields no message, so seed the assistant reply the model produced.
	require.NoError(t, turn.Finalize([]byte("data: [DONE]\n\n")))
	store.seed(sessionId, &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "all clear"}}})

	// Retry after completion: rejected by the durable "already continued" check.
	retry, err := ac.continueWithToolResult(userCtx(), sess, sessionId, "test-model@MyAdapter", result(), failFast)
	require.NoError(t, err)
	assert.Nil(t, retry.Response, "a retry after the continuation landed must be persist-only")
	assert.Equal(t, int32(1), atomic.LoadInt32(&sends), "no second model continuation on retry")
	assert.Equal(t, 1, store.countToolResults(sessionId, "tu1"), "a retried tool_result must not be duplicated")
}

// A fresh client tool request (failFast) whose session is already running a tool turn
// returns ErrToolTurnBusy immediately instead of blocking, so the handler can answer
// 409 and the client can retry.
func TestContinueWithToolResult_BusyReturnsError(t *testing.T) {
	const sessionId = "busy-session"

	store := newFakeAssistantstore()
	store.seed(sessionId, storedToolUseTurn("tu1").Message)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	var sends int32
	ac := newCoordinatorWithStore(t, ctrl, store, &sends)

	// Simulate another tool turn already holding the session lock.
	ac.sessionLocks.lock(sessionId)

	sess := &model.AssistantSession{SessionId: sessionId}
	toolMsg := buildToolResultMessage("tu1", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)

	turn, err := ac.continueWithToolResult(userCtx(), sess, sessionId, "test-model@MyAdapter", toolMsg, failFast)
	assert.ErrorIs(t, err, server.ErrToolTurnBusy)
	assert.Nil(t, turn)
	assert.Equal(t, int32(0), atomic.LoadInt32(&sends), "a busy request must not dispatch or persist anything")
	assert.Equal(t, 0, store.countToolResults(sessionId, "tu1"), "a busy request must not save a result")

	// Once the lock frees, the same request succeeds.
	ac.sessionLocks.unlock(sessionId)
	turn, err = ac.continueWithToolResult(userCtx(), sess, sessionId, "test-model@MyAdapter", toolMsg, failFast)
	require.NoError(t, err)
	require.NotNil(t, turn.Response)
	turn.Response.Body.Close()
}

// --- check-busy-before-execute (ToolInSession) -----------------------------

// A busy session must turn a fresh client tool request away (ErrToolTurnBusy) BEFORE
// the tool runs, so a client retry of a 409'd request never re-executes a (possibly
// non-idempotent) tool. Once the lock frees, the tool executes exactly once.
func TestToolInSession_BusyRejectsBeforeExecutingTool(t *testing.T) {
	const sessionId = "busy-exec-session"

	store := newFakeAssistantstore()
	// Two parallel tool_uses so the eventual (non-busy) continuation coalesces
	// (persist-only) instead of dispatching to the model.
	store.seed(sessionId, storedToolUseTurn("tu1", "tu2").Message)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	var sends int32
	ac := newCoordinatorWithStore(t, ctrl, store, &sends)

	var executed int32
	ac.FunctionLibrary = map[string]Tool{
		"query_events": &mockTool{
			name: "query_events",
			executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				atomic.AddInt32(&executed, 1)
				return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
			},
		},
	}

	req := &model.ToolRequest{SessionId: sessionId, ToolUseId: "tu1", Model: "test-model@MyAdapter"}

	// Simulate another tool turn already holding the session lock.
	ac.sessionLocks.lock(sessionId)
	_, err := ac.ToolInSession(userCtx(), req, "query_events")
	assert.ErrorIs(t, err, server.ErrToolTurnBusy)
	assert.Equal(t, int32(0), atomic.LoadInt32(&executed), "a busy session must reject before executing the tool")
	assert.Equal(t, 0, store.countToolResults(sessionId, "tu1"), "a busy request must not persist a result")

	// Once the lock frees, the same request executes the tool exactly once and
	// coalesces (tu2 still unresolved), persisting its result without dispatching.
	ac.sessionLocks.unlock(sessionId)
	resp, err := ac.ToolInSession(userCtx(), req, "query_events")
	require.NoError(t, err)
	assert.Empty(t, resp)
	assert.Equal(t, int32(1), atomic.LoadInt32(&executed), "the tool must execute exactly once")
	assert.Equal(t, 1, store.countToolResults(sessionId, "tu1"))
	assert.Equal(t, int32(0), atomic.LoadInt32(&sends), "a coalesced continuation must not dispatch")
}

// A retried tool request (the UI resends a POST whose long-running tool timed out)
// that lands on the non-streaming path AFTER the continuation was persisted must not
// panic: the turn is already continued, so ToolInSession returns an empty result
// rather than indexing an empty slice, and neither dispatches nor duplicates.
func TestToolInSession_RetryAfterContinuationDoesNotPanic(t *testing.T) {
	const sessionId = "retry-panic-session"

	store := newFakeAssistantstore()
	store.seed(sessionId, storedToolUseTurn("tu1").Message)
	store.seed(sessionId, buildToolResultMessage("tu1", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil))
	store.seed(sessionId, &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "all clear"}}})

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	var sends int32
	ac := newCoordinatorWithStore(t, ctrl, store, &sends)
	ac.FunctionLibrary = map[string]Tool{
		"query_events": &mockTool{
			name: "query_events",
			executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
			},
		},
	}

	req := &model.ToolRequest{SessionId: sessionId, ToolUseId: "tu1", Model: "test-model@MyAdapter"}
	resp, err := ac.ToolInSession(userCtx(), req, "query_events")

	require.NoError(t, err)
	assert.Empty(t, resp, "an already-continued retry has nothing to chain")
	assert.Equal(t, int32(0), atomic.LoadInt32(&sends), "no second model dispatch on a retry")
	assert.Equal(t, 1, store.countToolResults(sessionId, "tu1"), "a retried tool_result must not be duplicated")
}

// --- acquireTurnLock -------------------------------------------------------

func TestAcquireTurnLock_FailFastBusyReturnsError(t *testing.T) {
	ac := &AssistantCoordinator{}
	ac.sessionLocks.lock("s")
	defer ac.sessionLocks.unlock("s")

	release, err := ac.acquireTurnLock("s", failFast)
	assert.ErrorIs(t, err, server.ErrToolTurnBusy)
	release() // the busy path's release must be a safe no-op
	assert.False(t, ac.sessionLocks.tryLock("s"), "a busy failFast must not have taken the lock")
}

func TestAcquireTurnLock_WaitForLockAcquiresAndReleases(t *testing.T) {
	ac := &AssistantCoordinator{}

	release, err := ac.acquireTurnLock("s", waitForLock)
	require.NoError(t, err)
	assert.False(t, ac.sessionLocks.tryLock("s"), "lock must be held after waitForLock")

	release()
	require.True(t, ac.sessionLocks.tryLock("s"), "release must free the lock")
	ac.sessionLocks.unlock("s")
}

func TestAcquireTurnLock_LockHeldReleaseIsNoop(t *testing.T) {
	ac := &AssistantCoordinator{}
	ac.sessionLocks.lock("s")
	defer ac.sessionLocks.unlock("s")

	release, err := ac.acquireTurnLock("s", lockHeld)
	require.NoError(t, err)
	release() // must not touch the caller's lock
	assert.False(t, ac.sessionLocks.tryLock("s"), "lockHeld release must leave the caller's lock held")
}

func TestAcquireTurnLock_ReleaseIsIdempotent(t *testing.T) {
	ac := &AssistantCoordinator{}

	release, err := ac.acquireTurnLock("s", waitForLock)
	require.NoError(t, err)
	release()
	release() // second call must be a no-op, not an unlock of an already-free lock

	require.True(t, ac.sessionLocks.tryLock("s"))
	ac.sessionLocks.unlock("s")
}

// --- shouldPersistOnly -----------------------------------------------------

func TestShouldPersistOnly(t *testing.T) {
	toolUse := storedToolUseTurn("tu1").Message
	twoUses := storedToolUseTurn("tu1", "tu2").Message
	resultTu1 := buildToolResultMessage("tu1", &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil)
	assistantReply := &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Type: "text", Text: "done"}}}

	// The tool_use turn hasn't landed yet -> wait.
	assert.True(t, shouldPersistOnly(false, []*model.Message{toolUse, resultTu1}))
	// A sibling tool_use is still unresolved -> wait.
	assert.True(t, shouldPersistOnly(true, []*model.Message{twoUses, resultTu1}))
	// The model already answered this batch (a post-continuation retry) -> don't dispatch again.
	assert.True(t, shouldPersistOnly(true, []*model.Message{toolUse, resultTu1, assistantReply}))
	// Turn present, all tool_uses answered, not yet continued -> dispatch.
	assert.False(t, shouldPersistOnly(true, []*model.Message{toolUse, resultTu1}))
}

// --- lock held through finalize (#1) ---------------------------------------

func newStreamLockCoordinator(t *testing.T, ctrl *gomock.Controller, store server.Assistantstore, sends *int32) *AssistantCoordinator {
	ac := newCoordinatorWithStore(t, ctrl, store, sends)
	ac.FunctionLibrary = map[string]Tool{
		"query_events": &mockTool{
			name: "query_events",
			executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
			},
		},
	}
	return ac
}

// A dispatched streaming turn must keep the session lock held until the handler runs
// finalize (which persists the assistant turn), so a retry racing the in-flight stream
// is turned away rather than dispatching a second continuation.
func TestToolStreamInSession_HoldsLockUntilFinalize(t *testing.T) {
	const sessionId = "stream-lock-session"

	store := newFakeAssistantstore()
	store.seed(sessionId, storedToolUseTurn("tu1").Message) // sole tool_use -> dispatches

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	var sends int32
	ac := newStreamLockCoordinator(t, ctrl, store, &sends)

	req := &model.ToolRequest{SessionId: sessionId, ToolUseId: "tu1", Model: "test-model@MyAdapter"}
	turn, err := ac.ToolStreamInSession(userCtx(), req, "query_events")
	require.NoError(t, err)
	require.NotNil(t, turn.Response, "the turn must dispatch")
	turn.Response.Body.Close()
	assert.Equal(t, int32(1), atomic.LoadInt32(&sends))

	// Lock is held: a fresh client request fails fast instead of double-dispatching.
	assert.False(t, ac.sessionLocks.tryLock(sessionId), "lock must stay held until finalize runs")

	// The handler runs finalize once the stream completes; that releases the lock.
	require.NoError(t, turn.Finalize([]byte("data: [DONE]\n\n")))
	require.True(t, ac.sessionLocks.tryLock(sessionId), "finalize must release the lock")
	ac.sessionLocks.unlock(sessionId)
}

// A persist-only streaming turn (a sibling tool_use is still unresolved) has no
// finalize to run, so it must release the lock on return.
func TestToolStreamInSession_PersistOnlyReleasesLock(t *testing.T) {
	const sessionId = "stream-persistonly-session"

	store := newFakeAssistantstore()
	store.seed(sessionId, storedToolUseTurn("tu1", "tu2").Message) // sibling unresolved -> persist-only

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	var sends int32
	ac := newStreamLockCoordinator(t, ctrl, store, &sends)

	req := &model.ToolRequest{SessionId: sessionId, ToolUseId: "tu1", Model: "test-model@MyAdapter"}
	turn, err := ac.ToolStreamInSession(userCtx(), req, "query_events")
	require.NoError(t, err)
	assert.Nil(t, turn.Response, "a sibling tool_use is unresolved -> persist-only")
	assert.Equal(t, int32(0), atomic.LoadInt32(&sends), "a coalesced turn must not dispatch")

	require.True(t, ac.sessionLocks.tryLock(sessionId), "persist-only must release the lock on return")
	ac.sessionLocks.unlock(sessionId)
}
