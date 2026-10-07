// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	historyRunId      = "3f1a7c0e-9b21-4d8a-bc55-2e77a1f0c934"
	historyOtherRunId = "6d2b9e10-4c7f-4a3e-9b8d-1f0e2c3a4b5c"
)

var _ automationHistoryStore = (*database.Store)(nil)

// fakeHistoryStore answers the run history's reads from fixtures and records what was asked.
type fakeHistoryStore struct {
	run    *model.AutomationRunRecord
	runErr error
	runs   []*model.AutomationRunRecord
	items  []*model.AutomationWorkItem
	open   map[model.AutomationWorkItemState]int
	counts map[string]map[model.AutomationWorkItemState]int

	listQuery  database.AutomationRunQuery
	listedRun  string
	countedIds []string
}

func (f *fakeHistoryStore) GetAutomationRun(context.Context, string) (*model.AutomationRunRecord, error) {
	return f.run, f.runErr
}

func (f *fakeHistoryStore) ListAutomationRuns(_ context.Context, query database.AutomationRunQuery) ([]*model.AutomationRunRecord, error) {
	f.listQuery = query

	runs := f.runs
	if query.Offset < len(runs) {
		runs = runs[query.Offset:]
	} else {
		runs = nil
	}

	if query.Limit > 0 && len(runs) > query.Limit {
		runs = runs[:query.Limit]
	}

	return runs, nil
}

func (f *fakeHistoryStore) ListAutomationWorkItems(_ context.Context, runId string) ([]*model.AutomationWorkItem, error) {
	f.listedRun = runId

	return f.items, nil
}

func (f *fakeHistoryStore) CountOpenAutomationWorkItems(context.Context, string) (map[model.AutomationWorkItemState]int, error) {
	return f.open, nil
}

func (f *fakeHistoryStore) CountAutomationWorkItemsByRun(_ context.Context, runIds []string) (map[string]map[model.AutomationWorkItemState]int, error) {
	f.countedIds = runIds

	return f.counts, nil
}

// historySessionstore is the session half of the assistant store: which sessions exist,
// their transcripts, and what was asked for them.
type historySessionstore struct {
	server.Assistantstore

	sessions  []*model.AssistantSession
	histories map[string][]*model.StoredMessage

	sessionOpts  *model.GetSessionsOpts
	sessionCalls int
	historyIds   []string
	historyCalls int
}

func (s *historySessionstore) GetSessions(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
	s.sessionCalls++
	s.sessionOpts = &model.GetSessionsOpts{}
	for _, opt := range opts {
		opt(s.sessionOpts)
	}

	return s.sessions, nil
}

func (s *historySessionstore) GetChatHistoryOutlines(_ context.Context, sessions []*model.AssistantSession) ([][]*model.StoredMessage, error) {
	s.historyCalls++
	out := make([][]*model.StoredMessage, len(sessions))
	for i, session := range sessions {
		s.historyIds = append(s.historyIds, session.SessionId)
		out[i] = s.histories[session.SessionId]
	}

	return out, nil
}

// historyAssistantstore adds the ledger, so the alert reads happen.
type historyAssistantstore struct {
	historySessionstore
}

func (s *historyAssistantstore) AlertTriageUpdate(context.Context, *model.AlertTriageUpdate) (*model.EventUpdateResults, error) {
	return nil, errors.New("not under test")
}

func (s *historyAssistantstore) AlertTriageSchemaPrefix() string { return "so_" }

type historyFixture struct {
	ac     *AssistantCoordinator
	cfg    *automationConfigstore
	store  *fakeHistoryStore
	chats  *historyAssistantstore
	events *server.FakeEventstore
}

func newHistoryFixture(t *testing.T) *historyFixture {
	t.Helper()

	f := &historyFixture{
		cfg:    &automationConfigstore{},
		store:  &fakeHistoryStore{},
		chats:  &historyAssistantstore{historySessionstore{histories: map[string][]*model.StoredMessage{}}},
		events: server.NewFakeEventstore(),
	}
	f.cfg.settings = []*model.Setting{automationsSetting(t, historyAutomation(automationTestId, "Nightly", `{"groupBy":["rule.name"],"maxFailures":2}`))}
	f.ac = automationCoordinator(f.cfg)
	f.ac.srv.Assistantstore = f.chats
	f.ac.srv.Eventstore = f.events

	return f
}

func historyAutomation(id, displayName, params string) *model.Automation {
	return &model.Automation{
		Auditable:       model.Auditable{Id: id, UserId: "user-1"},
		DisplayName:     displayName,
		AutomationKind:  alertTriageKindName,
		Agent:           automationTestAgent,
		IntervalSeconds: 300,
		Params:          json.RawMessage(params),
	}
}

func historyRun(id string, state model.AutomationRunState) *model.AutomationRunRecord {
	started := time.Date(2026, 9, 15, 16, 0, 2, 0, time.UTC)
	run := &model.AutomationRunRecord{Id: id, AutomationId: automationTestId, State: state, StartTime: &started}
	if state.IsTerminal() {
		ended := started.Add(3 * time.Minute)
		run.EndTime = &ended
	}

	return run
}

func historyItem(id string, state model.AutomationWorkItemState, sessionIds ...string) *model.AutomationWorkItem {
	return &model.AutomationWorkItem{Id: id, AutomationId: automationTestId, RunId: historyRunId, State: state, SessionIds: sessionIds}
}

func historyItemWithFloor(t *testing.T, item *model.AutomationWorkItem, floor time.Time) *model.AutomationWorkItem {
	t.Helper()

	payload, err := json.Marshal(alertTriagePayload{GroupFilter: `rule.name:"Foo"`, Floor: floor, Ceiling: floor.Add(time.Hour), Count: 1})
	require.NoError(t, err)

	item.Payload = payload

	return item
}

func TestAutomationRunHistoryRequiresAStoreAndAnId(t *testing.T) {
	f := newHistoryFixture(t)

	_, err := f.ac.GetAutomationRunHistory(context.Background(), automationTestId, 0, 0)
	assert.ErrorIs(t, err, ErrNoDatabase)

	_, err = f.ac.GetAutomationRunDetails(context.Background(), automationTestId, historyRunId, 0)
	assert.ErrorIs(t, err, ErrNoDatabase)

	// A strict mock with no expectations: any statement fails the test.
	f.ac.store = automationTestStore(&mockdb.MockDB{})

	_, err = f.ac.GetAutomationRunHistory(context.Background(), "not-a-uuid", 0, 0)
	assert.ErrorIs(t, err, ErrAutomationNotFound)

	_, err = f.ac.GetAutomationRunDetails(context.Background(), "not-a-uuid", historyRunId, 0)
	assert.ErrorIs(t, err, ErrAutomationNotFound)

	_, err = f.ac.GetAutomationRunDetails(context.Background(), automationTestId, "not-a-uuid", 0)
	assert.ErrorIs(t, err, ErrAutomationRunNotFound)
}

// A strict mock with no expectations: the refusal comes before any statement.
func TestAutomationHistoryAndActivityRequireAutomationsRead(t *testing.T) {
	ac := automationCoordinatorAs(&automationConfigstore{}, false)
	ac.store = automationTestStore(&mockdb.MockDB{})

	_, historyErr := ac.GetAutomationRunHistory(context.Background(), automationTestId, 0, 0)
	_, detailsErr := ac.GetAutomationRunDetails(context.Background(), automationTestId, historyRunId, 0)
	_, activityErr := ac.GetAutomationActivity(context.Background())

	for _, err := range []error{historyErr, detailsErr, activityErr} {
		var unauthorized *model.Unauthorized
		require.ErrorAs(t, err, &unauthorized)
		assert.Equal(t, "read", unauthorized.Operation)
		assert.Equal(t, "automations", unauthorized.Target)
	}
}

func TestAutomationRunHistoryCountsBacklogAndItems(t *testing.T) {
	f := newHistoryFixture(t)
	f.store.runs = []*model.AutomationRunRecord{historyRun(historyRunId, model.AutomationRunSucceeded), historyRun(historyOtherRunId, model.AutomationRunRunning)}
	f.store.counts = map[string]map[model.AutomationWorkItemState]int{historyRunId: {model.AutomationWorkItemDone: 4, model.AutomationWorkItemFailed: 1}}
	f.store.open = map[model.AutomationWorkItemState]int{
		model.AutomationWorkItemPending:  2,
		model.AutomationWorkItemRunning:  1,
		model.AutomationWorkItemApplying: 1,
	}

	history, err := f.ac.automationRunHistory(context.Background(), f.store, automationTestId, 0, 0)
	require.NoError(t, err)

	assert.Equal(t, automationTestId, history.AutomationId)
	assert.Equal(t, "Nightly", history.DisplayName)
	assert.False(t, history.AutomationDeleted)
	assert.Equal(t, model.AutomationBacklog{Pending: 2, Running: 1, Applying: 1}, history.Backlog)
	assert.False(t, history.HasMore)
	assert.Equal(t, []string{historyRunId, historyOtherRunId}, f.store.countedIds)

	require.Len(t, history.Runs, 2)
	assert.Equal(t, historyRunId, history.Runs[0].Id)
	assert.Equal(t, model.AutomationRunSucceeded, history.Runs[0].State)
	assert.Equal(t, map[model.AutomationWorkItemState]int{model.AutomationWorkItemDone: 4, model.AutomationWorkItemFailed: 1}, history.Runs[0].ItemCounts)
	assert.NotNil(t, history.Runs[1].ItemCounts)
	assert.Empty(t, history.Runs[1].ItemCounts)
}

func TestAutomationRunHistoryPagesWithHasMore(t *testing.T) {
	f := newHistoryFixture(t)
	for _, id := range []string{"a", "b", "c"} {
		f.store.runs = append(f.store.runs, historyRun(id, model.AutomationRunSucceeded))
	}

	history, err := f.ac.automationRunHistory(context.Background(), f.store, automationTestId, 2, 0)
	require.NoError(t, err)

	assert.True(t, history.HasMore)
	assert.Len(t, history.Runs, 2)
	assert.Equal(t, database.AutomationRunQuery{AutomationId: automationTestId, Limit: 3}, f.store.listQuery)

	history, err = f.ac.automationRunHistory(context.Background(), f.store, automationTestId, 2, 2)
	require.NoError(t, err)

	assert.False(t, history.HasMore)
	assert.Len(t, history.Runs, 1)
	assert.Equal(t, 2, f.store.listQuery.Offset)

	_, err = f.ac.automationRunHistory(context.Background(), f.store, automationTestId, -1, -5)
	require.NoError(t, err)
	assert.Equal(t, defaultAutomationRunPageSize+1, f.store.listQuery.Limit)
	assert.Equal(t, 0, f.store.listQuery.Offset)

	_, err = f.ac.automationRunHistory(context.Background(), f.store, automationTestId, 99999, 0)
	require.NoError(t, err)
	assert.Equal(t, maxAutomationRunPageSize+1, f.store.listQuery.Limit)
}

// A deleted automation keeps its history; only its name is gone.
func TestAutomationRunHistoryDeletedAutomationRendersFromId(t *testing.T) {
	f := newHistoryFixture(t)
	f.cfg.settings = nil
	f.store.runs = []*model.AutomationRunRecord{historyRun(historyRunId, model.AutomationRunSucceeded)}
	f.store.run = f.store.runs[0]

	history, err := f.ac.automationRunHistory(context.Background(), f.store, automationTestId, 0, 0)
	require.NoError(t, err)

	assert.Equal(t, automationTestId, history.AutomationId)
	assert.Empty(t, history.DisplayName)
	assert.True(t, history.AutomationDeleted)
	assert.Len(t, history.Runs, 1)

	details, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
	require.NoError(t, err)

	assert.True(t, details.AutomationDeleted)
	assert.Empty(t, details.DisplayName)
	assert.Equal(t, 0, details.MaxFailures)
	assert.Equal(t, 0, details.GivenUpAlerts)
	// The cap is unknown, so there is no given-up query.
	assert.Len(t, f.events.InputSearchCriterias, 1)
}

func TestAutomationRunHistoryDeletedWithNoRunsIsNotFound(t *testing.T) {
	f := newHistoryFixture(t)
	f.cfg.settings = nil

	_, err := f.ac.automationRunHistory(context.Background(), f.store, automationTestId, 0, 0)
	assert.ErrorIs(t, err, ErrAutomationNotFound)

	// Past the end of a real history is an empty page, not a missing automation.
	f.store.runs = []*model.AutomationRunRecord{historyRun(historyRunId, model.AutomationRunSucceeded)}

	history, err := f.ac.automationRunHistory(context.Background(), f.store, automationTestId, 0, 5)
	require.NoError(t, err)
	assert.Empty(t, history.Runs)
}

func TestAutomationRunDetailsRejectsARunOfAnotherAutomation(t *testing.T) {
	f := newHistoryFixture(t)
	f.store.run = historyRun(historyRunId, model.AutomationRunSucceeded)

	_, err := f.ac.automationRunDetails(context.Background(), f.store, otherAutomationTestId, historyRunId, 0)
	assert.ErrorIs(t, err, ErrAutomationRunNotFound)

	f.store.run = nil
	f.store.runErr = database.ErrAutomationRunNotFound

	_, err = f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
	assert.ErrorIs(t, err, ErrAutomationRunNotFound)
}

// Every attempt is listed, in item then attempt order. Only the newest attempt of an item can
// be the report, and only a live one is running.
func TestAutomationRunDetailsFlattensSessionsIncludingFailedAttempts(t *testing.T) {
	f := newHistoryFixture(t)
	f.store.run = historyRun(historyRunId, model.AutomationRunRunning)
	f.store.items = []*model.AutomationWorkItem{
		{Id: "done", AutomationId: automationTestId, RunId: historyRunId, State: model.AutomationWorkItemDone, SessionIds: []string{"s1", "s2"}, FailedRunIds: []string{historyOtherRunId}},
		historyItem("running", model.AutomationWorkItemRunning, "s3"),
		historyItem("pending", model.AutomationWorkItemPending, "s4"),
		historyItem("failed", model.AutomationWorkItemFailed, "s5"),
		historyItem("applying", model.AutomationWorkItemApplying, "s6"),
		historyItem("queued", model.AutomationWorkItemPending),
		// Claimed again and waiting for a slot; its newest session is the failed attempt before.
		historyItem("waiting", model.AutomationWorkItemRunning, "s7"),
	}
	f.ac.setAgentPhase("s3", "s3", automationTestAgent, model.AgentPhaseWaitingLLM)
	f.ac.setAgentPhase("s3-child", "s3", automationTestAgent, model.AgentPhaseWaitingLLM)

	created := time.Date(2026, 9, 15, 16, 0, 5, 0, time.UTC)
	for _, id := range []string{"s1", "s2", "s3", "s5", "s6"} {
		f.chats.sessions = append(f.chats.sessions, &model.AssistantSession{
			Auditable:    model.Auditable{CreateTime: &created},
			SessionId:    id,
			Model:        automationTestAgent,
			MessageCount: 3,
		})
	}
	answered := created.Add(2 * time.Minute)
	f.chats.histories["s2"] = []*model.StoredMessage{
		{Auditable: model.Auditable{CreateTime: &created}, Message: &model.Message{Role: "user", ContentStr: "go"}},
		{Auditable: model.Auditable{CreateTime: &answered}, Message: &model.Message{Role: "assistant", Thoughts: "looking"}},
	}

	details, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
	require.NoError(t, err)

	assert.Equal(t, historyRunId, f.store.listedRun)
	assert.Equal(t, f.store.items, details.Items)

	var got []string
	for _, session := range details.Sessions {
		got = append(got, session.SessionId+":"+session.ItemId+":"+session.Outcome)
	}
	assert.Equal(t, []string{
		"s1:done:failed", "s2:done:report",
		"s3:running:running",
		"s4:pending:failed",
		"s5:failed:failed",
		"s6:applying:report",
		"s7:waiting:failed",
	}, got)

	assert.Equal(t, historyOtherRunId, details.Sessions[0].RunId)
	assert.Equal(t, historyRunId, details.Sessions[1].RunId)
	assert.Equal(t, historyRunId, details.Sessions[2].RunId)

	assert.Equal(t, 1, f.chats.sessionCalls)
	assert.Equal(t, []string{"s1", "s2", "s3", "s4", "s5", "s6", "s7"}, f.chats.sessionOpts.SessionIds())
	assert.True(t, f.chats.sessionOpts.IncludeDeleted())
	assert.True(t, f.chats.sessionOpts.IncludeAutomationSessions())
	assert.False(t, f.chats.sessionOpts.MessageMeta())
	assert.Equal(t, 1, f.chats.historyCalls)
	assert.Equal(t, []string{"s1", "s2", "s3", "s5", "s6"}, f.chats.historyIds)

	s2 := details.Sessions[1]
	assert.Equal(t, automationTestAgent, s2.Agent)
	assert.Equal(t, &created, s2.CreateTime)
	assert.Equal(t, &answered, s2.UpdateTime)
	assert.Equal(t, 3, s2.MessageCount)
	assert.False(t, s2.Missing)
	assert.Equal(t, []model.AutomationRunStep{{Kind: model.AutomationRunStepThought, Text: "looking"}}, s2.Steps)

	s4 := details.Sessions[3]
	assert.True(t, s4.Missing)
	assert.Empty(t, s4.Agent)
	assert.NotNil(t, s4.Steps)
	assert.Empty(t, s4.Steps)
}

func TestAutomationRunDetailsWithNoSessionsAsksForNone(t *testing.T) {
	f := newHistoryFixture(t)
	f.store.run = historyRun(historyRunId, model.AutomationRunSucceeded)
	f.store.items = []*model.AutomationWorkItem{historyItem("queued", model.AutomationWorkItemPending)}

	details, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
	require.NoError(t, err)

	assert.NotNil(t, details.Sessions)
	assert.Empty(t, details.Sessions)
	assert.Zero(t, f.chats.sessionCalls)
	assert.Zero(t, f.chats.historyCalls)
}

func TestAutomationRunStepsInterleaveThoughtsAndTools(t *testing.T) {
	long := strings.Repeat("ü", automationThoughtPreviewRunes+10)

	history := []*model.StoredMessage{
		{Message: &model.Message{Role: "user", ContentStr: "go"}},
		{Message: &model.Message{Role: "assistant", Thoughts: long, ContentBlocks: []model.ContentBlock{
			{Type: "tool_use", Id: "t1", Name: "query_events"},
			{Type: "tool_use", Id: "t1", Name: "query_events", Input: json.RawMessage(`{"q":1}`)},
			{Type: "tool_use", Id: "t2", Name: "lookup_ip"},
			{Type: "tool_use", Id: "t3", Name: "delegate"},
		}}},
		{Message: &model.Message{Role: "user", ContentBlocks: []model.ContentBlock{
			{ToolResult: &model.ToolResult{ToolUseId: "t1"}},
			{ToolResult: &model.ToolResult{ToolUseId: "t2", IsError: true}},
			{ToolResult: &model.ToolResult{ToolUseId: "t3", Status: "rejected", IsError: true}},
		}}},
		{Message: &model.Message{Role: "assistant", Thoughts: "  short  ", ContentBlocks: []model.ContentBlock{
			{Type: "text", Text: "report"},
			{Type: "tool_use", Id: "t4", Name: "send_notification"},
		}}},
		{Message: nil},
	}

	steps := automationRunSteps(history)

	require.Len(t, steps, 6)
	assert.Equal(t, model.AutomationRunStepThought, steps[0].Kind)
	assert.True(t, steps[0].Truncated)
	assert.Equal(t, automationThoughtPreviewRunes, len([]rune(steps[0].Text)))
	assert.Equal(t, model.AutomationRunStep{Kind: model.AutomationRunStepTool, Name: "query_events", Status: model.AutomationToolStatusOk}, steps[1])
	assert.Equal(t, model.AutomationRunStep{Kind: model.AutomationRunStepTool, Name: "lookup_ip", Status: model.AutomationToolStatusError}, steps[2])
	assert.Equal(t, model.AutomationRunStep{Kind: model.AutomationRunStepTool, Name: "delegate", Status: model.AutomationToolStatusRejected}, steps[3])
	assert.Equal(t, model.AutomationRunStep{Kind: model.AutomationRunStepThought, Text: "  short  "}, steps[4])
	assert.Equal(t, model.AutomationRunStep{Kind: model.AutomationRunStepTool, Name: "send_notification", Status: model.AutomationToolStatusPending}, steps[5])

	assert.NotNil(t, automationRunSteps(nil))
	assert.Empty(t, automationRunSteps(nil))
}

// The failed runs own the earlier attempts in order; whatever is left belongs to the run holding the item.
func TestAutomationAttemptRun(t *testing.T) {
	item := &model.AutomationWorkItem{RunId: historyRunId, FailedRunIds: []string{"f1", "f2"}}

	assert.Equal(t, "f1", automationAttemptRun(item, 0))
	assert.Equal(t, "f2", automationAttemptRun(item, 1))
	assert.Equal(t, historyRunId, automationAttemptRun(item, 2))
	assert.Equal(t, historyRunId, automationAttemptRun(item, 3))
}

func TestPayloadIntReadsEveryNumberShape(t *testing.T) {
	cases := map[string]any{"float": float64(3), "int": 3, "int64": int64(3), "number": json.Number("3")}

	for name, value := range cases {
		assert.Equal(t, 3, payloadInt(map[string]any{"n": value}, "n"), name)
	}

	assert.Equal(t, 0, payloadInt(map[string]any{"n": "3"}, "n"))
	assert.Equal(t, 0, payloadInt(map[string]any{}, "n"))
}

func TestTruncateRunesTrimsOnlyTheCut(t *testing.T) {
	text, truncated := truncateRunes(" ab cd", 4)

	assert.Equal(t, " ab", text)
	assert.True(t, truncated)
}

func TestAutomationRunDetailsAlertsComeFromTheLedger(t *testing.T) {
	f := newHistoryFixture(t)
	epoch := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	f.ac.alertTriageEpoch.Store(epoch.UnixNano())
	f.store.run = historyRun(historyRunId, model.AutomationRunSucceeded)
	f.store.items = []*model.AutomationWorkItem{
		historyItemWithFloor(t, historyItem("a", model.AutomationWorkItemDone, "s1"), time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)),
		historyItemWithFloor(t, historyItem("b", model.AutomationWorkItemDone, "s2"), time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)),
		{Id: "c", State: model.AutomationWorkItemFailed, Payload: json.RawMessage(`nonsense`)},
	}

	listed := model.NewEventSearchResults()
	listed.TotalEvents = 120
	listed.Events = []*model.EventRecord{{
		Id:        "alert-1",
		Timestamp: "2026-09-15T15:58:41.000Z",
		Payload: map[string]any{
			"rule.name":                               "Suspicious PowerShell",
			"event.severity_label":                    "high",
			"event.so_alerttriage.session_id":         "s1",
			"event.so_alerttriage.assessment":         "likely_benign",
			"event.so_alerttriage.failed_session_ids": []any{"s0", 7},
			"event.so_alerttriage.failed_run_ids":     []string{historyOtherRunId},
			"event.so_alerttriage.failed_count":       float64(1),
			"event.so_alerttriage.automation_run_id":  historyRunId,
			"event.so_alerttriage.automation_run_ids": []any{historyOtherRunId, historyRunId},
			"event.so_alerttriage.timestamp":          "2026-09-15T16:02:41Z",
		},
	}, {Id: "alert-2", Payload: map[string]any{}}}

	counted := model.NewEventSearchResults()
	counted.TotalEvents = 12

	f.events.SearchResults = []*model.EventSearchResults{listed, counted}

	details, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 25)
	require.NoError(t, err)

	require.Len(t, f.events.InputSearchCriterias, 2)

	first := f.events.InputSearchCriterias[0]
	assert.Equal(t, model.BuildAlertTriageQuery("so_", historyRunId), first.RawQuery)
	assert.Equal(t, 25, first.EventLimit)
	assert.Equal(t, 0, first.MetricLimit)
	assert.Equal(t, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), first.BeginTime.UTC())
	assert.WithinDuration(t, time.Now(), first.EndTime, time.Minute)
	require.Len(t, first.SortFields, 1)
	assert.Equal(t, "@timestamp", first.SortFields[0].Field)
	assert.Equal(t, "desc", first.SortFields[0].Order)

	second := f.events.InputSearchCriterias[1]
	assert.Equal(t, `event.so_alerttriage.automation_run_ids:"`+historyRunId+`" AND event.so_alerttriage.failed_count:>=2`, second.RawQuery)
	assert.Equal(t, 0, second.EventLimit)
	assert.Equal(t, first.BeginTime, second.BeginTime)

	assert.Equal(t, 2, details.MaxFailures)
	assert.Equal(t, 120, details.AlertTotal)
	assert.Equal(t, 12, details.GivenUpAlerts)
	assert.False(t, details.AlertsExpired)

	require.Len(t, details.Alerts, 2)
	assert.Equal(t, &model.AlertTriageAlert{
		Id:               "alert-1",
		Timestamp:        "2026-09-15T15:58:41.000Z",
		RuleName:         "Suspicious PowerShell",
		Severity:         "high",
		SessionId:        "s1",
		Assessment:       "likely_benign",
		FailedSessionIds: []string{"s0"},
		FailedRunIds:     []string{historyOtherRunId},
		FailedCount:      1,
		LatestRunId:      historyRunId,
		TriageTime:       "2026-09-15T16:02:41Z",
	}, details.Alerts[0])
	assert.Equal(t, &model.AlertTriageAlert{Id: "alert-2", FailedSessionIds: []string{}, FailedRunIds: []string{}}, details.Alerts[1])
}

// A run with no alerts left has none given up either.
func TestAutomationRunDetailsSkipsTheGivenUpCountWithoutAlerts(t *testing.T) {
	f := newHistoryFixture(t)
	f.store.run = historyRun(historyRunId, model.AutomationRunSucceeded)

	details, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
	require.NoError(t, err)

	assert.Len(t, f.events.InputSearchCriterias, 1)
	assert.Equal(t, 2, details.MaxFailures)
	assert.Zero(t, details.GivenUpAlerts)
}

// The epoch bounds the query when the items carry nothing older, and an unset epoch is not a
// bound at all.
func TestAutomationAlertFloor(t *testing.T) {
	epoch := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	older := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)

	assert.Equal(t, epoch, automationAlertFloor(epoch, nil))
	assert.Equal(t, epoch, automationAlertFloor(epoch, []*model.AutomationWorkItem{historyItemWithFloor(t, historyItem("a", model.AutomationWorkItemDone), newer)}))
	assert.Equal(t, older, automationAlertFloor(epoch, []*model.AutomationWorkItem{historyItemWithFloor(t, historyItem("a", model.AutomationWorkItemDone), older)}))
	assert.Equal(t, newer, automationAlertFloor(time.Unix(0, 0).UTC(), []*model.AutomationWorkItem{historyItemWithFloor(t, historyItem("a", model.AutomationWorkItemDone), newer)}))
	assert.Equal(t, time.Unix(0, 0).UTC(), automationAlertFloor(time.Time{}, nil))
}

func TestAutomationRunDetailsAlertLimitIsClamped(t *testing.T) {
	f := newHistoryFixture(t)
	f.store.run = historyRun(historyRunId, model.AutomationRunSucceeded)

	for _, c := range []struct{ asked, want int }{{0, defaultAutomationAlertLimit}, {-3, defaultAutomationAlertLimit}, {40, 40}, {50000, maxAutomationAlertLimit}} {
		f.events.InputSearchCriterias = nil

		_, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, c.asked)
		require.NoError(t, err)
		require.NotEmpty(t, f.events.InputSearchCriterias)
		assert.Equal(t, c.want, f.events.InputSearchCriterias[0].EventLimit, "asked %d", c.asked)
	}
}

func TestAutomationRunDetailsAlertsExpired(t *testing.T) {
	cases := []struct {
		name  string
		state model.AutomationRunState
		items []*model.AutomationWorkItem
		total int
		want  bool
	}{
		{name: "recorded and gone", state: model.AutomationRunSucceeded, items: []*model.AutomationWorkItem{historyItem("a", model.AutomationWorkItemDone, "s1")}, want: true},
		{name: "still present", state: model.AutomationRunSucceeded, items: []*model.AutomationWorkItem{historyItem("a", model.AutomationWorkItemDone, "s1")}, total: 3},
		{name: "nothing recorded", state: model.AutomationRunSucceeded, items: []*model.AutomationWorkItem{historyItem("a", model.AutomationWorkItemPending)}},
		// Reconcile charges an interrupted run the same way without writing alerts, so it is flagged too.
		{name: "failed by this run", state: model.AutomationRunFailed, items: []*model.AutomationWorkItem{{Id: "a", RunId: historyRunId, State: model.AutomationWorkItemPending, SessionIds: []string{"s1"}, FailedRunIds: []string{historyRunId}}}, want: true},
		{name: "failed, then done by a later run", state: model.AutomationRunFailed, items: []*model.AutomationWorkItem{{Id: "a", RunId: historyOtherRunId, State: model.AutomationWorkItemDone, SessionIds: []string{"s1", "s2"}, FailedRunIds: []string{historyRunId}}}, want: true},
		{name: "done by another run", state: model.AutomationRunSucceeded, items: []*model.AutomationWorkItem{{Id: "a", RunId: historyOtherRunId, State: model.AutomationWorkItemDone, SessionIds: []string{"s1"}}}},
		{name: "still running", state: model.AutomationRunRunning, items: []*model.AutomationWorkItem{historyItem("a", model.AutomationWorkItemDone, "s1")}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newHistoryFixture(t)
			f.store.run = historyRun(historyRunId, c.state)
			f.store.items = c.items
			f.events.SearchResults[0].TotalEvents = c.total

			details, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
			require.NoError(t, err)

			assert.Equal(t, c.want, details.AlertsExpired)
		})
	}
}

// A store with no ledger has recorded nothing, so nothing is searched.
func TestAutomationRunDetailsWithoutALedgerSkipsAlerts(t *testing.T) {
	f := newHistoryFixture(t)
	f.ac.srv.Assistantstore = &f.chats.historySessionstore
	f.store.run = historyRun(historyRunId, model.AutomationRunSucceeded)
	f.store.items = []*model.AutomationWorkItem{historyItem("a", model.AutomationWorkItemDone, "s1")}

	details, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
	require.NoError(t, err)

	assert.Empty(t, f.events.InputSearchCriterias)
	assert.NotNil(t, details.Alerts)
	assert.Empty(t, details.Alerts)
	assert.Equal(t, 0, details.AlertTotal)
	assert.False(t, details.AlertsExpired)
	assert.Equal(t, 2, details.MaxFailures)
	assert.Equal(t, 0, details.GivenUpAlerts)
}

func TestAutomationRunDetailsSurfacesSearchErrors(t *testing.T) {
	f := newHistoryFixture(t)
	f.store.run = historyRun(historyRunId, model.AutomationRunSucceeded)

	f.events.Err = errors.New("elastic is down")

	_, err := f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
	assert.ErrorContains(t, err, "elastic is down")

	f.events.Err = nil
	f.events.SearchResults[0].Errors = []string{"shard failed"}

	_, err = f.ac.automationRunDetails(context.Background(), f.store, automationTestId, historyRunId, 0)
	assert.ErrorContains(t, err, "shard failed")
}
