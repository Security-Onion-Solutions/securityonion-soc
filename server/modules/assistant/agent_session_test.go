// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	detectionsmock "github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// --- SSE fixtures -----------------------------------------------------------

func sseBody(build func(w *sseEventWriter)) string {
	var buf bytes.Buffer
	w := newSSEEventWriter(log.Log, &buf)
	w.writeMessageStart("test-model")
	build(w)
	w.writeMessageStop()
	w.writeDone()
	return buf.String()
}

func sseText(text string) string {
	return sseBody(func(w *sseEventWriter) {
		w.writeContentBlockDelta(0, "text_delta", text)
		w.writeContentBlockStop(0)
		w.writeStopReason("end_turn")
		w.writeUsage(10, 5)
	})
}

type sseToolCall struct{ id, name, input string }

func sseToolUses(calls ...sseToolCall) string {
	return sseBody(func(w *sseEventWriter) {
		for i, call := range calls {
			w.writeContentBlockStart(i, map[string]any{"type": "tool_use", "id": call.id, "name": call.name, "input": map[string]any{}})
			if call.input != "" {
				w.writeInputJsonDelta(i, call.input)
			}
			w.writeContentBlockStop(i)
		}
		w.writeStopReason("tool_use")
		w.writeUsage(10, 5)
	})
}

func sseError(message string) string {
	var buf bytes.Buffer
	w := newSSEEventWriter(log.Log, &buf)
	w.writeMessageStart("test-model")
	w.writeContentBlockDelta(0, "text_delta", "partial")
	w.writeError(message)
	w.writeDone()
	return buf.String()
}

// eventReader hands out one SSE event per Read so a turn flushes several times.
type eventReader struct{ events []string }

func (r *eventReader) Read(p []byte) (int, error) {
	if len(r.events) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.events[0])
	r.events[0] = r.events[0][n:]
	if r.events[0] == "" {
		r.events = r.events[1:]
	}
	return n, nil
}

// blockingBody never yields; it fails only once the request is cancelled.
type blockingBody struct{ ctx context.Context }

func (b *blockingBody) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *blockingBody) Close() error { return nil }

// --- coordinator fixture ---------------------------------------------------

// headlessScript answers each model call with the next body and keeps what the
// model was sent.
type headlessScript struct {
	mu       sync.Mutex
	bodies   []string
	chunked  bool
	calls    int32
	requests []*model.ChatRequest
	respond  func(n int, req *http.Request) (io.ReadCloser, error)
}

func (s *headlessScript) makeRequest(req *http.Request, _ bool) (*http.Response, error) {
	n := int(atomic.AddInt32(&s.calls, 1))

	var chat model.ChatRequest
	if err := json.NewDecoder(req.Body).Decode(&chat); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.requests = append(s.requests, &chat)
	s.mu.Unlock()

	var body io.ReadCloser
	if s.respond != nil {
		var err error
		if body, err = s.respond(n, req); err != nil {
			return nil, err
		}
	} else {
		if n > len(s.bodies) {
			return nil, fmt.Errorf("unexpected model call %d", n)
		}
		if s.chunked {
			body = io.NopCloser(&eventReader{events: strings.SplitAfter(s.bodies[n-1], "\n\n")})
		} else {
			body = io.NopCloser(strings.NewReader(s.bodies[n-1]))
		}
	}

	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: body}, nil
}

func (s *headlessScript) count() int { return int(atomic.LoadInt32(&s.calls)) }

func (s *headlessScript) request(i int) *model.ChatRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[i]
}

type headlessFixture struct {
	ac     *AssistantCoordinator
	store  *fakeAssistantstore
	script *headlessScript
	tool   *mockTool
	// tool_use ids query_events was executed for, in order.
	executed []string
	mu       sync.Mutex
}

func newHeadlessFixture(t *testing.T, ctrl *gomock.Controller, bodies ...string) *headlessFixture {
	t.Helper()
	return newHeadlessFixtureWithStore(t, ctrl, newFakeAssistantstore(), bodies...)
}

func newHeadlessFixtureWithStore(t *testing.T, ctrl *gomock.Controller, store server.Assistantstore, bodies ...string) *headlessFixture {
	t.Helper()

	f := &headlessFixture{script: &headlessScript{bodies: bodies}}
	if fake, ok := store.(*fakeAssistantstore); ok {
		f.store = fake
	}

	f.tool = &mockTool{name: "query_events", executeFunc: func(_ context.Context, _ *server.Server, req *model.ToolRequest) (*model.ToolResponse, error) {
		f.mu.Lock()
		f.executed = append(f.executed, req.ToolUseId)
		f.mu.Unlock()
		return &model.ToolResponse{ToolName: "query_events", Result: "events for " + req.ToolUseId}, nil
	}}

	mockIO := detectionsmock.NewMockIOManager(ctrl)
	mockIO.EXPECT().MakeRequest(gomock.Any(), true).DoAndReturn(f.script.makeRequest).AnyTimes()

	srv := &server.Server{
		Assistantstore: store,
		Host:           &web.Host{Version: "1.0.0"},
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: []model.ModelParameters{{ID: "test-model", Adapter: "MyAdapter", Enabled: true}},
				},
			},
		},
	}

	f.ac = &AssistantCoordinator{
		srv:       srv,
		IOManager: mockIO,
		adapters: map[string]server.AssistantAdapter{
			"MyAdapter": &SOAiCloudAdapter{apiUrl: "https://api.example.com", srv: srv, IOManager: mockIO},
		},
		isAgentic: true,
		agents: map[string]model.Agent{
			"Hunter":  {Name: "Hunter", Enabled: true, AllowedSkills: []string{"Hunt"}},
			"Analyst": {Name: "Analyst", Enabled: true, AllowedSkills: []string{"Hunt"}},
		},
		agentMapping:    map[string]string{"Hunter": "test-model@MyAdapter", "Analyst": "test-model@MyAdapter"},
		SkillLibrary:    map[string]model.Skill{"Hunt": {Name: "Hunt", Tools: []string{"query_events"}, Enabled: true}},
		FunctionLibrary: map[string]Tool{"query_events": f.tool},
		DelegationLibrary: map[string]Tool{
			"delegate_to_Analyst": &mockTool{name: "delegate_to_Analyst", executeFunc: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return &model.ToolResponse{
					ToolName: "delegate_to_Analyst",
					Result:   model.DelegationKickoff{ChildSessionId: "child-1", ChildModel: "Analyst", Objective: "child objective", AgentName: "Analyst"},
				}, nil
			}},
		},
		agentSessionMaxTurns: 20,
		toolUseTurnAttempts:  DEFAULT_TOOL_USE_TURN_ATTEMPTS,
	}

	return f
}

func (f *headlessFixture) executedIds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.executed...)
}

func baseRequest() *model.AgentSessionRequest {
	return &model.AgentSessionRequest{Objective: "investigate alert 42", Agent: "Hunter", OwnerId: "user-1"}
}

func assertUnlocked(t *testing.T, ac *AssistantCoordinator, sessionId string) {
	t.Helper()
	require.True(t, ac.sessionLocks.tryLock(sessionId), "session lock leaked for %s", sessionId)
	ac.sessionLocks.unlock(sessionId)
}

func toolResults(msgs []*model.StoredMessage) []*model.ToolResult {
	var out []*model.ToolResult
	for _, sm := range msgs {
		for _, cb := range sm.Message.ContentBlocks {
			if cb.ToolResult != nil {
				out = append(out, cb.ToolResult)
			}
		}
	}
	return out
}

// --- tests -----------------------------------------------------------------

// A turn that errors mid-stream leaves its partial behind, keeps the session id on
// the result, and releases everything it held.
func TestRunAgentSession_ErrorPathReleasesLock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl, sseError("upstream exploded"))
	f.script.chunked = true

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.Error(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.SessionId)
	assert.Equal(t, 1, res.Turns)
	assertUnlocked(t, f.ac, res.SessionId)
	assert.Empty(t, f.ac.AgentSessionPhases())

	msgs := f.store.messages(res.SessionId)
	require.Len(t, msgs, 2)
	assert.True(t, msgs[1].IsPartial())
	assert.Equal(t, "partial", msgs[1].Message.ContentBlocks[0].Text)
}

func TestRunAgentSession_ParallelToolUsesBothRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl,
		sseToolUses(sseToolCall{"t1", "query_events", `{"q":"a"}`}, sseToolCall{"t2", "query_events", `{"q":"b"}`}),
		sseText("done"))

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)
	assert.Equal(t, "done", res.FinalText)
	assert.Equal(t, 2, res.Turns)
	assert.False(t, res.Truncated)
	assert.Equal(t, []string{"t1", "t2"}, f.executedIds())
	assert.Equal(t, 2, f.script.count())

	// Both results reach the model in one user turn.
	second := f.script.request(1)
	last := second.Messages[len(second.Messages)-1]
	assert.Equal(t, "user", last.Role)
	require.Len(t, last.ContentBlocks, 2)
	assert.Equal(t, "t1", last.ContentBlocks[0].ToolResult.ToolUseId)
	assert.Equal(t, "t2", last.ContentBlocks[1].ToolResult.ToolUseId)

	msgs := f.store.messages(res.SessionId)
	require.Len(t, msgs, 5)
	assert.Equal(t, []string{"tool_result"}, msgs[2].Tags)
	assert.Equal(t, []string{"tool_result"}, msgs[3].Tags)
	assert.False(t, msgs[4].IsPartial())
	assert.NotEmpty(t, msgs[4].Message.Id)
	assertUnlocked(t, f.ac, res.SessionId)
}

func TestRunAgentSession_MaxTurnsTruncates(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl, sseToolUses(sseToolCall{"t1", "query_events", `{}`}))

	req := baseRequest()
	req.MaxTurns = 1

	res, err := f.ac.RunAgentSession(userCtx(), req)
	require.NoError(t, err)
	assert.True(t, res.Truncated)
	assert.Equal(t, 1, res.Turns)
	assert.Empty(t, res.FinalText)
	assert.Empty(t, f.executedIds(), "the last permitted turn's tools must not run")
	assert.Equal(t, 1, f.script.count())
	assertUnlocked(t, f.ac, res.SessionId)
}

func TestRunAgentSession_UnresolvableAgentFailsBeforeAnything(t *testing.T) {
	for _, agent := range []string{"", "Nobody"} {
		t.Run("agent="+agent, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := newHeadlessFixture(t, ctrl, sseText("never"))
			req := baseRequest()
			req.Agent = agent

			res, err := f.ac.RunAgentSession(userCtx(), req)
			assert.ErrorIs(t, err, ErrInvalidAgent)
			require.NotNil(t, res)
			assert.NotEmpty(t, res.SessionId)
			assert.Equal(t, 0, f.script.count())
			assert.Nil(t, f.store.session(res.SessionId))
			assertUnlocked(t, f.ac, res.SessionId)
		})
	}
}

type failingCreateStore struct{ server.Assistantstore }

func (failingCreateStore) CreateSession(context.Context, *model.AssistantSession) error {
	return errors.New("es down")
}

func TestValidateAgentSessionRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl)

	assert.Error(t, f.ac.ValidateAgentSessionRequest(nil))
	assert.ErrorIs(t, f.ac.ValidateAgentSessionRequest(&model.AgentSessionRequest{Agent: "Hunter", OwnerId: "u"}), ErrAgentSessionObjectiveRequired)
	assert.ErrorIs(t, f.ac.ValidateAgentSessionRequest(&model.AgentSessionRequest{Agent: "Hunter", Objective: "o"}), ErrAgentSessionOwnerRequired)
	assert.Error(t, f.ac.ValidateAgentSessionRequest(&model.AgentSessionRequest{Agent: "Nobody", Objective: "o", OwnerId: "u"}))
	assert.NoError(t, f.ac.ValidateAgentSessionRequest(baseRequest()))
}

func TestRunAgentSession_SessionIdOnCreateFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixtureWithStore(t, ctrl, failingCreateStore{newFakeAssistantstore()}, sseText("never"))

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.EqualError(t, err, "es down")
	require.NotNil(t, res)
	assert.NotEmpty(t, res.SessionId)
	assert.Equal(t, 0, f.script.count())
	assertUnlocked(t, f.ac, res.SessionId)
}

func TestRunAgentSession_SessionIdOnModelFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl)
	f.script.respond = func(int, *http.Request) (io.ReadCloser, error) { return nil, errors.New("gateway refused") }

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.Error(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.SessionId)
	assert.Equal(t, 0, res.Turns, "a turn that never started costs no budget")
	assertUnlocked(t, f.ac, res.SessionId)
}

func TestRunAgentSession_MintsSessionIdAndStampsTags(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl, sseText("done"))
	req := baseRequest()
	req.Tags = []string{"run:abc", "shared", ""}

	res, err := f.ac.RunAgentSession(userCtx(), req)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.SessionId)

	sess := f.store.session(res.SessionId)
	require.NotNil(t, sess)
	assert.Equal(t, []string{"automation", "shared", "run:abc"}, sess.Tags)
	assert.Equal(t, "Hunter", sess.Model)
	assert.Equal(t, "investigate alert 42", sess.Title)
}

func TestRunAgentSession_BusyChildResolvesAsErrorResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl,
		sseToolUses(sseToolCall{"d1", "delegate_to_Analyst", `{}`}),
		sseText("final"))
	f.ac.sessionLocks.lock("child-1")
	defer f.ac.sessionLocks.unlock("child-1")

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)
	assert.Equal(t, "final", res.FinalText)
	assert.Equal(t, 2, f.script.count(), "the locked child never reaches the model")
	assert.Nil(t, f.store.session("child-1"))

	results := toolResults(f.store.messages(res.SessionId))
	require.Len(t, results, 1)
	assert.True(t, results[0].IsError)
	assert.Contains(t, results[0].Content[0].Text, ErrAgentSessionBusy.Error())
	assertUnlocked(t, f.ac, res.SessionId)
}

func TestRunAgentSession_DelegationRunsChildHeadlessly(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl,
		sseToolUses(sseToolCall{"d1", "delegate_to_Analyst", `{"objective":"x"}`}),
		sseText("child answer"),
		sseText("final"))

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)
	assert.Equal(t, "final", res.FinalText)
	assert.Equal(t, 3, res.Turns, "the child's turn spends the shared budget")
	assert.False(t, res.Truncated)

	child := f.store.session("child-1")
	require.NotNil(t, child)
	assert.Equal(t, res.SessionId, child.ParentSessionId)
	assert.Equal(t, "d1", child.ParentToolUseId)
	assert.Equal(t, "Hunter", child.ParentModel)
	assert.Equal(t, "Analyst", child.Model)
	assert.Equal(t, 1, child.Depth)
	assert.Equal(t, []string{"automation", "shared"}, child.Tags)

	// The child's answer resolves the parent's delegate tool_use.
	third := f.script.request(2)
	last := third.Messages[len(third.Messages)-1]
	require.Len(t, last.ContentBlocks, 1)
	assert.Equal(t, "d1", last.ContentBlocks[0].ToolResult.ToolUseId)
	assert.Contains(t, fmt.Sprint(last.ContentBlocks[0].ToolResult.Content[0].Json), "child answer")

	assertUnlocked(t, f.ac, res.SessionId)
	assertUnlocked(t, f.ac, "child-1")
	assert.Empty(t, f.ac.AgentSessionPhases())
}

func TestRunAgentSession_TruncatedChildResolvesAsNoResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl,
		sseToolUses(sseToolCall{"d1", "delegate_to_Analyst", `{}`}),
		sseToolUses(sseToolCall{"t1", "query_events", `{}`}))

	req := baseRequest()
	req.MaxTurns = 2

	res, err := f.ac.RunAgentSession(userCtx(), req)
	require.NoError(t, err)
	assert.True(t, res.Truncated)
	assert.Equal(t, 2, res.Turns)
	assert.Empty(t, f.executedIds())

	results := toolResults(f.store.messages(res.SessionId))
	require.Len(t, results, 1)
	assert.True(t, results[0].IsError)
	assert.Contains(t, results[0].Content[0].Text, "ERROR_DELEGATION_NO_RESULT")
	assertUnlocked(t, f.ac, "child-1")
}

func TestRunAgentSession_DelegationDepthRefused(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl,
		sseToolUses(sseToolCall{"d1", "delegate_to_Analyst", `{}`}),
		sseToolUses(sseToolCall{"d2", "delegate_to_Analyst", `{}`}),
		sseText("child done"),
		sseText("final"))
	f.ac.maxDelegationDepth.Store(1)

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)
	assert.Equal(t, "final", res.FinalText)
	assert.Equal(t, 4, res.Turns)

	results := toolResults(f.store.messages("child-1"))
	require.Len(t, results, 1)
	assert.Equal(t, "d2", results[0].ToolUseId)
	assert.Contains(t, fmt.Sprint(results[0].Content[0].Json), "Delegation was refused")
	assert.Len(t, f.store.sessions, 2, "the refused delegation creates no session")
}

func TestRunAgentSession_SubSessionBudgetHaltsChild(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// The SSE fixtures report 5 output tokens, so one child turn spends the budget.
	f := newHeadlessFixture(t, ctrl,
		sseToolUses(sseToolCall{"d1", "delegate_to_Analyst", `{}`}),
		sseToolUses(sseToolCall{"t1", "query_events", `{}`}),
		sseText("final"))
	f.ac.maxSubSessionTokens.Store(5)

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)
	assert.Equal(t, "final", res.FinalText)
	assert.False(t, res.Truncated)
	assert.Equal(t, 3, res.Turns)
	assert.Equal(t, []string{"t1"}, f.executedIds(), "the tool the last affordable turn asked for still runs")

	assert.Equal(t, 5, f.script.request(1).MaxTokens, "the child's turn is capped at the remaining budget")
	assert.Equal(t, 0, f.script.request(0).MaxTokens)

	childMsgs := f.store.messages("child-1")
	halted := childMsgs[len(childMsgs)-1]
	assert.Equal(t, []string{"subsession_halted"}, halted.Tags)
	assert.Equal(t, subSessionBudgetNotice(5), halted.Message.ContentBlocks[0].Text)

	third := f.script.request(2)
	last := third.Messages[len(third.Messages)-1]
	require.Len(t, last.ContentBlocks, 1)
	assert.Equal(t, "d1", last.ContentBlocks[0].ToolResult.ToolUseId)
	assert.Contains(t, fmt.Sprint(last.ContentBlocks[0].ToolResult.Content[0].Json), subSessionBudgetNotice(5))
	assertUnlocked(t, f.ac, res.SessionId)
	assertUnlocked(t, f.ac, "child-1")
}

// A tool that fails or returns nothing resolves its tool_use with an error result the
// model reacts to; the session goes on.
func TestRunAgentSession_ToolFailureResolvesAsErrorResult(t *testing.T) {
	tests := []struct {
		name    string
		execute func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error)
		want    string
	}{
		{
			name: "error",
			execute: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return nil, errors.New("boom")
			},
			want: "boom",
		},
		{
			name: "no result",
			execute: func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
				return nil, nil
			},
			want: "tool returned no result",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := newHeadlessFixture(t, ctrl, sseToolUses(sseToolCall{"t1", "query_events", `{}`}), sseText("done"))
			f.tool.executeFunc = tc.execute

			res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
			require.NoError(t, err)
			assert.Equal(t, "done", res.FinalText)
			assert.Equal(t, 2, res.Turns)

			results := toolResults(f.store.messages(res.SessionId))
			require.Len(t, results, 1)
			assert.Equal(t, "t1", results[0].ToolUseId)
			assert.True(t, results[0].IsError)
			assert.Equal(t, tc.want, results[0].Content[0].Text)

			second := f.script.request(1)
			last := second.Messages[len(second.Messages)-1]
			require.Len(t, last.ContentBlocks, 1)
			assert.Equal(t, "t1", last.ContentBlocks[0].ToolResult.ToolUseId)
			assert.True(t, last.ContentBlocks[0].ToolResult.IsError)
			assertUnlocked(t, f.ac, res.SessionId)
		})
	}
}

// A child that fails resolves the parent's delegate tool_use with the error; only a
// cancelled run stops the parent.
func TestRunAgentSession_FailedChildResolvesAsErrorResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl,
		sseToolUses(sseToolCall{"d1", "delegate_to_Analyst", `{}`}),
		sseError("child exploded"),
		sseText("final"))
	f.script.chunked = true

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)
	assert.Equal(t, "final", res.FinalText)
	assert.False(t, res.Truncated)
	assert.Equal(t, 3, res.Turns, "the failed child turn reached the model, so it costs budget")

	results := toolResults(f.store.messages(res.SessionId))
	require.Len(t, results, 1)
	assert.Equal(t, "d1", results[0].ToolUseId)
	assert.True(t, results[0].IsError)
	assert.Contains(t, results[0].Content[0].Text, "the delegated sub-agent could not complete")
	assert.Contains(t, results[0].Content[0].Text, "child exploded")

	childMsgs := f.store.messages("child-1")
	require.Len(t, childMsgs, 2)
	assert.True(t, childMsgs[1].IsPartial(), "the child's abandoned turn is left as a partial")

	assertUnlocked(t, f.ac, res.SessionId)
	assertUnlocked(t, f.ac, "child-1")
	assert.Empty(t, f.ac.AgentSessionPhases())
}

// countingStore records every partial flush as it was stored.
type countingStore struct {
	*fakeAssistantstore
	mu       sync.Mutex
	partials []*model.Message
}

func (c *countingStore) SavePartialChat(ctx context.Context, m *model.StoredMessage) error {
	snap := *m.Message
	c.mu.Lock()
	c.partials = append(c.partials, &snap)
	c.mu.Unlock()
	return c.fakeAssistantstore.SavePartialChat(ctx, m)
}

func TestStreamAgentTurn_PartialFlushesShareOneMessage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	body := sseBody(func(w *sseEventWriter) {
		w.writeContentBlockDelta(0, "text_delta", "hello ")
		w.writeContentBlockDelta(0, "text_delta", "world")
		w.writeContentBlockStop(0)
		w.writeStopReason("end_turn")
	})

	store := &countingStore{fakeAssistantstore: newFakeAssistantstore()}
	f := newHeadlessFixtureWithStore(t, ctrl, store, body)
	f.script.chunked = true

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)
	assert.Equal(t, "hello world", res.FinalText)

	msgs := store.messages(res.SessionId)
	require.Len(t, msgs, 2, "every flush rewrites the one assistant message")
	final := msgs[1]
	assert.False(t, final.IsPartial())
	assert.Equal(t, "hello world", final.Message.ContentBlocks[0].Text)

	require.GreaterOrEqual(t, len(store.partials), 2)
	assert.Equal(t, "hello ", store.partials[0].ContentBlocks[0].Text, "a message_start alone is not flushed; the first flush carries text")
	assert.Equal(t, "text", store.partials[0].ContentBlocks[0].Type)
	for _, p := range store.partials {
		assert.Equal(t, final.Message.Id, p.Id)
	}
}

// SSE events may end in CRLF pairs; a partial is still flushed at their boundary.
func TestStreamAgentTurn_CRLFEventsFlush(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	body := strings.ReplaceAll(sseText("hello"), "\n", "\r\n")
	store := &countingStore{fakeAssistantstore: newFakeAssistantstore()}
	f := newHeadlessFixtureWithStore(t, ctrl, store)
	f.script.respond = func(int, *http.Request) (io.ReadCloser, error) {
		return io.NopCloser(&eventReader{events: strings.SplitAfter(body, "\r\n\r\n")}), nil
	}

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)
	assert.Equal(t, "hello", res.FinalText)
	require.NotEmpty(t, store.partials, "a CRLF-delimited stream flushes before it ends")
	assert.Equal(t, "hello", store.partials[0].ContentBlocks[0].Text)
}

func TestLastEventEnd(t *testing.T) {
	assert.Equal(t, -1, lastEventEnd([]byte("data: x")))
	assert.Equal(t, 9, lastEventEnd([]byte("data: x\n\ndata: y")))
	assert.Equal(t, 11, lastEventEnd([]byte("data: x\r\n\r\ndata: y")))
}

func TestWithoutThoughtSignatures(t *testing.T) {
	msg := &model.Message{ContentBlocks: []model.ContentBlock{{Type: "tool_use", Id: "t1", ThoughtSignature: []byte("sig")}}}

	out := withoutThoughtSignatures(msg)
	assert.Nil(t, out.ContentBlocks[0].ThoughtSignature)
	assert.Equal(t, []byte("sig"), msg.ContentBlocks[0].ThoughtSignature, "the history copy keeps what the model needs")
	assert.Nil(t, withoutThoughtSignatures(nil))
}

func TestBroadcastAgentStream_WithoutHost(t *testing.T) {
	ac := &AssistantCoordinator{srv: &server.Server{}}
	assert.NotPanics(t, func() {
		ac.broadcastAgentStream(model.AgentStreamEvent{SessionId: "s", MessageId: "m", Seq: 1, Message: &model.Message{Role: "assistant"}})
	})
}

// A viewer that is not reading holds the broadcast, not the turn: publish returns at
// once, intermediate events are replaced, and the last one still goes out.
func TestAgentStreamPublisher_LatestWinsWithoutBlocking(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})

	var mu sync.Mutex
	var sent []int
	broadcast := func(event model.AgentStreamEvent) {
		if event.Seq == 1 {
			close(started)
			<-release
		}
		mu.Lock()
		sent = append(sent, event.Seq)
		mu.Unlock()
	}

	p := newAgentStreamPublisher(broadcast)
	msg := &model.Message{ContentBlocks: []model.ContentBlock{{Type: "tool_use", Id: "t1", ThoughtSignature: []byte("sig")}}}

	p.publish(model.AgentStreamEvent{Seq: 1, Message: msg})
	<-started
	p.publish(model.AgentStreamEvent{Seq: 2, Message: msg})
	p.publish(model.AgentStreamEvent{Seq: 3, Message: msg, Done: true})
	close(release)
	p.close()
	<-p.done

	assert.Equal(t, []int{1, 3}, sent)
	assert.Equal(t, []byte("sig"), msg.ContentBlocks[0].ThoughtSignature, "the run's copy keeps its signatures")
}

func TestRunAgentSession_PhaseRegistry(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl, sseToolUses(sseToolCall{"t1", "query_events", `{}`}), sseText("done"))

	var seen []model.AgentSessionPhase
	f.tool.executeFunc = func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
		seen = f.ac.AgentSessionPhases()
		return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
	}

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.NoError(t, err)

	require.Len(t, seen, 1)
	assert.Equal(t, res.SessionId, seen[0].SessionId)
	assert.Equal(t, res.SessionId, seen[0].RootSessionId)
	assert.Equal(t, "Hunter", seen[0].Agent)
	assert.Equal(t, "invoking_tool:query_events", seen[0].Phase)
	assert.False(t, seen[0].Since.IsZero())
	assert.Empty(t, f.ac.AgentSessionPhases())
}

// cancelCheckingStore refuses writes on a cancelled context, as the elastic client does.
type cancelCheckingStore struct{ *fakeAssistantstore }

func (s *cancelCheckingStore) SaveChat(ctx context.Context, m *model.StoredMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.fakeAssistantstore.SaveChat(ctx, m)
}

// A tool that ran has its result recorded even though the run was cancelled meanwhile.
func TestRunAgentSession_CancelledInsideToolReportsCause(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := &cancelCheckingStore{fakeAssistantstore: newFakeAssistantstore()}
	f := newHeadlessFixtureWithStore(t, ctrl, store, sseToolUses(sseToolCall{"t1", "query_events", `{}`}), sseText("never"))

	ctx, cancel := context.WithCancelCause(userCtx())
	defer cancel(nil)
	f.tool.executeFunc = func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
		cancel(ErrAutomationParamsChanged)
		return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
	}

	res, err := f.ac.RunAgentSession(ctx, baseRequest())
	assert.ErrorIs(t, err, ErrAutomationParamsChanged)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.SessionId)
	assert.Equal(t, 1, f.script.count(), "no turn starts on a cancelled run")

	results := toolResults(store.messages(res.SessionId))
	require.Len(t, results, 1, "the tool ran, so its result is stored")
	assert.Equal(t, "t1", results[0].ToolUseId)
	assertUnlocked(t, f.ac, res.SessionId)
}

// A tool that never returns is abandoned on the idle timeout, like a stalled stream.
// The idle tests run on synctest's clock, so the windows are life-sized yet instant.
func TestRunAgentSession_HungToolIsAbandoned(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		f := newHeadlessFixture(t, ctrl, sseToolUses(sseToolCall{"t1", "query_events", `{}`}), sseText("never"))
		f.ac.agentStreamIdleTimeout = time.Minute
		f.tool.executeFunc = func(ctx context.Context, _ *server.Server, _ *model.ToolRequest) (*model.ToolResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}

		res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
		assert.ErrorIs(t, err, ErrAgentTurnStalled)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.SessionId)
		assert.Equal(t, 1, f.script.count())
		assertUnlocked(t, f.ac, res.SessionId)
		assert.Empty(t, f.ac.AgentSessionPhases())
	})
}

// The tool and the model turn after it each get the whole idle window.
func TestRunAgentSession_ToolAndTurnHaveSeparateIdleWindows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		const idle = time.Minute
		f := newHeadlessFixture(t, ctrl, sseToolUses(sseToolCall{"t1", "query_events", `{}`}), sseText("done"))
		f.ac.agentStreamIdleTimeout = idle
		f.tool.executeFunc = func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
			time.Sleep(idle - time.Nanosecond)
			return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
		}
		bodies := f.script.bodies
		f.script.respond = func(n int, _ *http.Request) (io.ReadCloser, error) {
			if n == 2 {
				time.Sleep(idle - time.Nanosecond)
			}
			return io.NopCloser(strings.NewReader(bodies[n-1])), nil
		}

		res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
		require.NoError(t, err)
		assert.Equal(t, "done", res.FinalText)
	})
}

// The idle watchdog cancels the turn's request context, which is how a stalled
// upstream is abandoned.
func TestRunAgentSession_StalledStreamIsAbandoned(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		f := newHeadlessFixture(t, ctrl)
		f.ac.agentStreamIdleTimeout = time.Minute
		f.script.respond = func(_ int, req *http.Request) (io.ReadCloser, error) {
			return &blockingBody{ctx: req.Context()}, nil
		}

		res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
		assert.ErrorIs(t, err, ErrAgentTurnStalled)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.SessionId)
		assert.Equal(t, 1, res.Turns)
		assertUnlocked(t, f.ac, res.SessionId)
	})
}

// cancelledStreamAdapter streams one text delta, waits for ctx to be cancelled and
// ends the stream the way finish says.
type cancelledStreamAdapter struct {
	started chan struct{}
	finish  func(w *sseEventWriter, cause error)
}

func (a *cancelledStreamAdapter) Protocol() string { return "fake" }
func (a *cancelledStreamAdapter) SendMessage(context.Context, *model.ChatRequest) (*model.Message, error) {
	return nil, nil
}
func (a *cancelledStreamAdapter) GetBalance(context.Context) (*model.BalanceResponse, error) {
	return nil, nil
}
func (a *cancelledStreamAdapter) GetHealth(context.Context) (*model.HealthResponse, error) {
	return nil, nil
}
func (a *cancelledStreamAdapter) Embed(context.Context, *model.EmbeddingRequest) (*model.EmbeddingResponse, error) {
	return nil, nil
}
func (a *cancelledStreamAdapter) SupportsEmbeddings() bool { return false }

func (a *cancelledStreamAdapter) SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, *model.AuxMessageData, error) {
	response, body := fabricateResponse(http.StatusOK)
	w := newSSEEventWriter(log.Log, body)
	go func() {
		defer body.Close()
		w.writeMessageStart(req.Model)
		w.writeContentBlockDelta(0, "text_delta", "thinking")
		close(a.started)
		<-ctx.Done()
		a.finish(w, context.Cause(ctx))
	}()
	return response, nil, nil
}

// The SDK adapters report a cancelled context as an SSE error event; an adapter may
// instead end its stream cleanly. The cause must surface either way.
var streamEndings = map[string]func(w *sseEventWriter, cause error){
	"sse error event": func(w *sseEventWriter, cause error) { w.writeError(cause.Error()); w.writeDone() },
	"clean close":     func(w *sseEventWriter, _ error) { w.writeMessageStop(); w.writeDone() },
}

func TestRunAgentSession_CancelReachesStreamingAdapters(t *testing.T) {
	triggers := []struct {
		name string
		run  func(f *headlessFixture, cancel context.CancelCauseFunc, started <-chan struct{})
		want error
	}{
		{
			name: "idle watchdog",
			run: func(f *headlessFixture, _ context.CancelCauseFunc, _ <-chan struct{}) {
				f.ac.agentStreamIdleTimeout = time.Minute
			},
			want: ErrAgentTurnStalled,
		},
		{
			name: "params change",
			run: func(_ *headlessFixture, cancel context.CancelCauseFunc, started <-chan struct{}) {
				go func() {
					<-started
					cancel(ErrAutomationParamsChanged)
				}()
			},
			want: ErrAutomationParamsChanged,
		},
	}

	for ending, finish := range streamEndings {
		for _, tc := range triggers {
			t.Run(ending+"/"+tc.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctrl := gomock.NewController(t)
					defer ctrl.Finish()

					f := newHeadlessFixture(t, ctrl)
					adapter := &cancelledStreamAdapter{started: make(chan struct{}), finish: finish}
					f.ac.adapters["MyAdapter"] = adapter

					ctx, cancel := context.WithCancelCause(userCtx())
					defer cancel(nil)
					tc.run(f, cancel, adapter.started)

					res, err := f.ac.RunAgentSession(ctx, baseRequest())
					assert.ErrorIs(t, err, tc.want)
					require.NotNil(t, res)
					assert.NotEmpty(t, res.SessionId)
					assert.Equal(t, 1, res.Turns)
					assertUnlocked(t, f.ac, res.SessionId)

					msgs := f.store.messages(res.SessionId)
					require.Len(t, msgs, 2)
					assert.True(t, msgs[1].IsPartial(), "an abandoned turn is never finished")
					assert.Equal(t, "thinking", msgs[1].Message.ContentBlocks[0].Text)
				})
			})
		}
	}
}

func TestRunAgentSession_PanicIsRecoveredWithSessionId(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl, sseToolUses(sseToolCall{"t1", "query_events", `{}`}))
	f.tool.executeFunc = func(context.Context, *server.Server, *model.ToolRequest) (*model.ToolResponse, error) {
		panic("tool exploded")
	}

	res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tool exploded")
	require.NotNil(t, res)
	assert.NotEmpty(t, res.SessionId)
	assert.Equal(t, 1, res.Turns)
	assertUnlocked(t, f.ac, res.SessionId)
	assert.Empty(t, f.ac.AgentSessionPhases())
}

func TestRunAgentSession_ConcurrentSessionsDoNotInterfere(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	f := newHeadlessFixture(t, ctrl, sseText("done"), sseText("done"))

	var mu sync.Mutex
	var ids []string
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := f.ac.RunAgentSession(userCtx(), baseRequest())
			assert.NoError(t, err)
			assert.Equal(t, "done", res.FinalText)
			mu.Lock()
			ids = append(ids, res.SessionId)
			mu.Unlock()
		}()
	}
	wg.Wait()

	assert.Empty(t, f.ac.AgentSessionPhases())
	require.Len(t, ids, 2)
	assert.NotEqual(t, ids[0], ids[1])
	for _, id := range ids {
		assert.NotEmpty(t, id)
		assert.Len(t, f.store.messages(id), 2)
	}
}

func TestPartialSnapshot(t *testing.T) {
	stop := "end_turn"

	tests := []struct {
		name   string
		msg    *model.Message
		wantOk bool
		check  func(t *testing.T, snap *model.Message)
	}{
		{name: "nil", msg: nil, wantOk: false},
		{name: "message_start only", msg: &model.Message{Role: "assistant"}, wantOk: false},
		{
			name:   "open text block",
			msg:    &model.Message{Role: "assistant", ContentBlocks: []model.ContentBlock{{Content: "abc"}}},
			wantOk: true,
			check: func(t *testing.T, snap *model.Message) {
				assert.Equal(t, "text", snap.ContentBlocks[0].Type)
				assert.Equal(t, "abc", snap.ContentBlocks[0].Text)
				assert.Nil(t, snap.ContentBlocks[0].Content)
			},
		},
		{
			name:   "half-streamed tool input is dropped",
			msg:    &model.Message{ContentBlocks: []model.ContentBlock{{Type: "tool_use", Id: "t1", Name: "x", Input: json.RawMessage(`{"q":`)}}},
			wantOk: true,
			check: func(t *testing.T, snap *model.Message) {
				assert.Nil(t, snap.ContentBlocks[0].Input)
				_, err := json.Marshal(snap)
				assert.NoError(t, err)
			},
		},
		{
			name:   "empty tool input is kept",
			msg:    &model.Message{ContentBlocks: []model.ContentBlock{{Type: "tool_use", Id: "t1", Name: "x"}}},
			wantOk: true,
		},
		{
			name:   "closed text block is left alone",
			msg:    &model.Message{StopReason: &stop, ContentBlocks: []model.ContentBlock{{Type: "text", Text: "done"}}},
			wantOk: true,
			check: func(t *testing.T, snap *model.Message) {
				assert.Equal(t, "done", snap.ContentBlocks[0].Text)
				assert.Equal(t, &stop, snap.StopReason)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap, ok := partialSnapshot(tc.msg)
			assert.Equal(t, tc.wantOk, ok)
			if tc.check != nil {
				tc.check(t, snap)
			}
			if tc.msg != nil && len(tc.msg.ContentBlocks) > 0 {
				assert.NotSame(t, &tc.msg.ContentBlocks[0], &snap.ContentBlocks[0], "the parser's message is never mutated")
			}
		})
	}
}

func TestAssistantCoordinator_Init_AgentSessionConfig(t *testing.T) {
	newAC := func() *AssistantCoordinator {
		return NewAssistantCoordinator(&server.Server{
			Context: context.Background(),
			Config:  &config.ServerConfig{ClientParams: model.ClientParameters{AssistantParams: model.AssistantParameters{}}},
		})
	}

	ac := newAC()
	require.NoError(t, ac.Init(module.ModuleConfig{}))
	assert.Equal(t, DEFAULT_AGENT_SESSION_MAX_TURNS, ac.agentSessionMaxTurns)
	assert.Equal(t, DEFAULT_AGENT_STREAM_FLUSH_INTERVAL_MS*time.Millisecond, ac.agentStreamFlushInterval)
	assert.Equal(t, DEFAULT_AGENT_STREAM_IDLE_TIMEOUT_SECONDS*time.Second, ac.agentStreamIdleTimeout)

	ac = newAC()
	require.NoError(t, ac.Init(module.ModuleConfig{
		"agentSessionMaxTurns":          float64(3),
		"agentStreamFlushIntervalMs":    float64(50),
		"agentStreamIdleTimeoutSeconds": float64(0),
	}))
	assert.Equal(t, 3, ac.agentSessionMaxTurns)
	assert.Equal(t, 50*time.Millisecond, ac.agentStreamFlushInterval)
	assert.Equal(t, time.Duration(0), ac.agentStreamIdleTimeout)
}

// A headless run's request id names the automation, replacing any web request id.
func TestRunAgentSession_StampsAutomationRequestId(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no request id":  userCtx(),
		"web request id": context.WithValue(userCtx(), web.ContextKeyRequestId, "0d5a7c1e-6f0b-4c1c-9b3e-2a4f8d9e1b22"),
	} {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			f := newHeadlessFixture(t, ctrl, sseToolUses(sseToolCall{"t1", "query_events", `{}`}), sseText("done"))
			var seen any
			f.tool.executeFunc = func(ctx context.Context, _ *server.Server, _ *model.ToolRequest) (*model.ToolResponse, error) {
				seen = ctx.Value(web.ContextKeyRequestId)
				return &model.ToolResponse{ToolName: "query_events", Result: "ok"}, nil
			}

			res, err := f.ac.RunAgentSession(ctx, baseRequest())
			require.NoError(t, err)
			assert.Equal(t, automationRequestId(res.SessionId), seen)
		})
	}
}

// --- AutomationRun wrapper --------------------------------------------------

// fakeAutomationStore records the one call the wrapper makes; the package's gomock
// store cannot be imported here without a cycle.
type fakeAutomationStore struct {
	AutomationStore
	itemId, sessionId string
	err               error
}

func (f *fakeAutomationStore) EnsureAutomationWorkItemSession(_ context.Context, itemId, sessionId string) error {
	f.itemId, f.sessionId = itemId, sessionId
	return f.err
}

func TestAutomationRunRunAgentSession_RecordsSessionOnItem(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := &fakeAutomationStore{}
	manager := servermock.NewMockAssistantManager(ctrl)
	want := &model.AgentSessionResult{SessionId: "session-9", FinalText: "report"}

	manager.EXPECT().ValidateAgentSessionRequest(gomock.Any()).Return(nil)
	manager.EXPECT().RunAgentSession(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req *model.AgentSessionRequest) (*model.AgentSessionResult, error) {
			assert.Equal(t, "user-1", req.OwnerId)
			assert.Equal(t, []string{"run:run-7"}, req.Tags)
			return want, nil
		})

	run := &AutomationRun{
		Srv:   &server.Server{AssistantManager: manager},
		Task:  &model.Automation{Auditable: model.Auditable{Id: "automation-1", UserId: "user-1"}},
		RunId: "run-7",
		Store: store,
	}

	got, err := run.RunAgentSession(context.Background(), "item-1", &model.AgentSessionRequest{Objective: "o", Agent: "Hunter", Tags: []string{"run:run-7"}})
	require.NoError(t, err)
	assert.Same(t, want, got)
	assert.Equal(t, "item-1", store.itemId)
	assert.Equal(t, "session-9", store.sessionId)
}

func TestAutomationRunRunAgentSession_FailedRunStillRecordsSession(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := &fakeAutomationStore{}
	manager := servermock.NewMockAssistantManager(ctrl)
	manager.EXPECT().ValidateAgentSessionRequest(gomock.Any()).Return(nil)
	manager.EXPECT().RunAgentSession(gomock.Any(), gomock.Any()).Return(&model.AgentSessionResult{SessionId: "session-9"}, ErrAgentSessionBusy)

	run := &AutomationRun{
		Srv:   &server.Server{AssistantManager: manager},
		Task:  &model.Automation{},
		Store: store,
	}

	got, err := run.RunAgentSession(context.Background(), "item-1", &model.AgentSessionRequest{OwnerId: "user-1"})
	assert.ErrorIs(t, err, ErrAgentSessionBusy)
	assert.Equal(t, "session-9", got.SessionId)
	assert.Equal(t, "session-9", store.sessionId)
}

func TestAutomationRunRunAgentSession_StoreErrorIsReported(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := &fakeAutomationStore{err: errors.New("pg down")}
	manager := servermock.NewMockAssistantManager(ctrl)
	manager.EXPECT().ValidateAgentSessionRequest(gomock.Any()).Return(nil)
	manager.EXPECT().RunAgentSession(gomock.Any(), gomock.Any()).Return(&model.AgentSessionResult{SessionId: "session-9"}, nil)

	run := &AutomationRun{
		Srv:   &server.Server{AssistantManager: manager},
		Task:  &model.Automation{},
		Store: store,
	}

	got, err := run.RunAgentSession(context.Background(), "item-1", &model.AgentSessionRequest{OwnerId: "user-1"})
	require.EqualError(t, err, "pg down")
	assert.Equal(t, "session-9", got.SessionId)
}

func TestAutomationRunRunAgentSession_InvalidRequestRecordsNothing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := &fakeAutomationStore{}
	manager := servermock.NewMockAssistantManager(ctrl)
	manager.EXPECT().ValidateAgentSessionRequest(gomock.Any()).Return(ErrInvalidAgent)

	run := &AutomationRun{
		Srv:   &server.Server{AssistantManager: manager},
		Task:  &model.Automation{},
		Store: store,
	}

	_, err := run.RunAgentSession(context.Background(), "item-1", &model.AgentSessionRequest{Objective: "o", Agent: "Nobody", OwnerId: "user-1"})
	assert.ErrorIs(t, err, ErrInvalidAgent)
	assert.Empty(t, store.sessionId, "a request that cannot run is not recorded on the item")
}
