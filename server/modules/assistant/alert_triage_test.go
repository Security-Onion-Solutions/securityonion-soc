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
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const triageTestParams = `{"filter":"event.module:suricata","groupBy":["rule.name","source.ip"],"maxGroupsPerScan":10}`

// triageAssistantstore is the half of the assistant store a kind needs: the ledger's prefix and
// the alert updates, which it logs into the work store's events so their order is visible.
type triageAssistantstore struct {
	server.Assistantstore
	prefix string
	work   *triageWorkStore

	updateErr error
	// Fails only the successful updates, so a failure can still be recorded.
	applyErr error
	updates  []*model.AlertTriageUpdate
}

func (s *triageAssistantstore) AlertTriageUpdate(_ context.Context, update *model.AlertTriageUpdate) (*model.EventUpdateResults, error) {
	s.work.mu.Lock()
	defer s.work.mu.Unlock()

	s.updates = append(s.updates, update)

	err := s.updateErr
	if err == nil && !update.Failed {
		err = s.applyErr
	}

	switch {
	case err != nil:
		s.work.events = append(s.work.events, "alerts:error")

		return nil, err
	case update.Failed:
		s.work.events = append(s.work.events, "alerts:"+strings.Join(update.FailedRunIds, ","))
	default:
		s.work.events = append(s.work.events, "alerts:ok:"+update.SessionId)
	}

	return model.NewEventUpdateResults(), nil
}

func (s *triageAssistantstore) AlertTriageSchemaPrefix() string { return s.prefix }

func (s *triageAssistantstore) recorded() []*model.AlertTriageUpdate {
	s.work.mu.Lock()
	defer s.work.mu.Unlock()

	return slices.Clone(s.updates)
}

// triageAssistantManager plays the session driver: every request is kept, the hook sees the
// job's context, and the configured result comes back.
type triageAssistantManager struct {
	server.AssistantManager

	mu         sync.Mutex
	result     *model.AgentSessionResult
	err        error
	onRun      func(ctx context.Context)
	requests   []*model.AgentSessionRequest
	requestors []any
}

func (m *triageAssistantManager) RunAgentSession(ctx context.Context, req *model.AgentSessionRequest) (*model.AgentSessionResult, error) {
	m.mu.Lock()
	m.requests = append(m.requests, req)
	m.requestors = append(m.requestors, ctx.Value(web.ContextKeyRequestorId))
	m.mu.Unlock()

	if m.onRun != nil {
		m.onRun(ctx)
	}

	if m.result == nil {
		return nil, m.err
	}

	result := *m.result
	result.SessionId = req.SessionId

	return &result, m.err
}

func (m *triageAssistantManager) ValidateAgentSessionRequest(*model.AgentSessionRequest) error {
	return nil
}

func (m *triageAssistantManager) FilterEvents(events []*model.EventRecord, _ ...string) []map[string]any {
	filtered := make([]map[string]any, 0, len(events))

	for _, event := range events {
		fields := map[string]any{"_id": event.Id}
		maps.Copy(fields, event.Payload)
		filtered = append(filtered, map[string]any{"payload": fields})
	}

	return filtered
}

func (m *triageAssistantManager) sessions() []*model.AgentSessionRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	return slices.Clone(m.requests)
}

// lockedEventstore serialises the fake's bookkeeping, since jobs search concurrently, and answers
// each pinned-alert lookup from alerts by id, so every job finds its own.
type lockedEventstore struct {
	*server.FakeEventstore
	mu     sync.Mutex
	alerts map[string]*model.EventRecord
}

func (es *lockedEventstore) Search(ctx context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	id, ok := pinnedAlertLookup(criteria.RawQuery)
	if !ok {
		return es.FakeEventstore.Search(ctx, criteria)
	}

	es.InputSearchCriterias = append(es.InputSearchCriterias, criteria)

	results := model.NewEventSearchResults()
	if alert := es.alerts[id]; alert != nil {
		results.TotalEvents = 1
		results.Events = []*model.EventRecord{alert}
	}

	return results, es.Err
}

// pinnedAlertLookup is the id a server.FindEventBySocId query names.
func pinnedAlertLookup(query string) (string, bool) {
	id, found := strings.CutPrefix(query, `log.id.uid:"`)
	if !found {
		return "", false
	}

	id, _, found = strings.Cut(id, `"`)

	return id, found
}

func (es *lockedEventstore) MSearch(ctx context.Context, criteria []*model.EventMSearchCriteria) (*model.EventMSearchResults, error) {
	es.mu.Lock()
	defer es.mu.Unlock()

	return es.FakeEventstore.MSearch(ctx, criteria)
}

// cancelled marks an event written under a cancelled context, so a test can tell a detached
// write from one on the run's own context.
func cancelled(ctx context.Context, event string) string {
	if ctx.Err() != nil {
		return event + ":cancelled"
	}

	return event
}

// triageWorkStore plays the work-item table: ensured rows become pending, claims hand them out
// oldest first, and every call is logged in order.
type triageWorkStore struct {
	AutomationStore

	mu           sync.Mutex
	next         int
	pending      []*model.AutomationWorkItem
	claimErr     error
	requeueErr   error
	failRunErr   error
	failErr      error
	failApplyErr error
	applyingErr  error
	completeErr  error
	repinErr     error
	sessionErr   error
	// Runs before a transition answers, the way a params change cancels the run first.
	sweep    func()
	running  map[string]*model.AutomationWorkItem
	applying map[string]*model.AutomationWorkItem
	// Chooses which ensured rows count as inserted; nil inserts them all.
	insert  func(items []*model.AutomationWorkItem) []*model.AutomationWorkItem
	ensured [][]*model.AutomationWorkItem
	events  []string
}

func (s *triageWorkStore) EnsureAutomationWorkItems(_ context.Context, runId string, items []*model.AutomationWorkItem) ([]*model.AutomationWorkItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensured = append(s.ensured, items)
	s.events = append(s.events, "ensure")

	inserted := items
	if s.insert != nil {
		inserted = s.insert(items)
	}

	for _, item := range inserted {
		s.next++
		item.Id = fmt.Sprintf("item-%d", s.next)
		item.RunId = runId
		item.State = model.AutomationWorkItemPending
	}

	s.pending = append(s.pending, inserted...)

	return inserted, nil
}

func (s *triageWorkStore) ClaimNextAutomationWorkItem(_ context.Context, _, runId string, maxFailures int) (*model.AutomationWorkItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.claimErr != nil {
		return nil, s.claimErr
	}

	i := slices.IndexFunc(s.pending, func(item *model.AutomationWorkItem) bool {
		return !slices.Contains(item.FailedRunIds, runId) && len(item.FailedRunIds) < maxFailures
	})
	if i < 0 {
		s.events = append(s.events, "claim:none")

		return nil, nil
	}

	item := s.pending[i]
	s.pending = slices.Delete(s.pending, i, i+1)

	if s.running == nil {
		s.running = map[string]*model.AutomationWorkItem{}
	}

	s.running[item.Id] = item
	item.State = model.AutomationWorkItemRunning
	item.RunId = runId
	item.Attempts++

	s.events = append(s.events, "claim:"+item.Id)

	return item, nil
}

func (s *triageWorkStore) EnsureAutomationWorkItemSession(ctx context.Context, itemId, sessionId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, cancelled(ctx, "session:"+itemId))

	// The real store refuses a cancelled context.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if s.sessionErr != nil {
		return s.sessionErr
	}

	if item := s.running[itemId]; item != nil {
		item.SessionIds = append(item.SessionIds, sessionId)
	}

	return nil
}

func (s *triageWorkStore) UpdateAutomationWorkItemPayload(ctx context.Context, itemId string, payload json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, cancelled(ctx, "repin:"+itemId))

	if s.repinErr != nil {
		return s.repinErr
	}

	item, ok := s.running[itemId]
	if !ok {
		return database.ErrAutomationWorkItemNotFound
	}

	item.Payload = payload

	return nil
}

func (s *triageWorkStore) MarkAutomationWorkItemApplying(ctx context.Context, itemId string, result json.RawMessage) error {
	if s.sweep != nil {
		s.sweep()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, cancelled(ctx, "applying:"+itemId))

	if s.applyingErr != nil {
		return s.applyingErr
	}

	item, ok := s.running[itemId]
	if !ok {
		return database.ErrAutomationWorkItemNotFound
	}

	delete(s.running, itemId)

	if s.applying == nil {
		s.applying = map[string]*model.AutomationWorkItem{}
	}

	s.applying[itemId] = item
	item.State = model.AutomationWorkItemApplying
	item.Result = result

	return nil
}

func (s *triageWorkStore) CompleteAutomationWorkItem(ctx context.Context, itemId string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, cancelled(ctx, "complete:"+itemId))

	if s.completeErr != nil {
		return s.completeErr
	}

	if item, ok := s.applying[itemId]; ok {
		delete(s.applying, itemId)
		item.State = model.AutomationWorkItemDone
	}

	return nil
}

func (s *triageWorkStore) RequeueAutomationWorkItem(ctx context.Context, itemId, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, cancelled(ctx, "requeue:"+itemId))

	return s.requeueErr
}

func (s *triageWorkStore) FailAutomationWorkItemRun(_ context.Context, itemId, cause string) (*model.AutomationWorkItem, error) {
	if s.sweep != nil {
		s.sweep()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, "failrun:"+itemId)

	if s.failRunErr != nil {
		return nil, s.failRunErr
	}

	item, ok := s.running[itemId]
	if !ok {
		return nil, database.ErrAutomationWorkItemNotFound
	}

	delete(s.running, itemId)

	if !slices.Contains(item.FailedRunIds, item.RunId) {
		item.FailedRunIds = append(item.FailedRunIds, item.RunId)
	}

	item.State = model.AutomationWorkItemPending
	item.Error = cause
	s.pending = append(s.pending, item)

	return item, nil
}

func (s *triageWorkStore) FailAutomationWorkItemApply(ctx context.Context, itemId, runId, cause string) (*model.AutomationWorkItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, cancelled(ctx, "failapply:"+itemId))

	if s.failApplyErr != nil {
		return nil, s.failApplyErr
	}

	item, ok := s.applying[itemId]
	if !ok {
		return nil, database.ErrAutomationWorkItemNotFound
	}

	if !slices.Contains(item.FailedRunIds, runId) {
		item.FailedRunIds = append(item.FailedRunIds, runId)
	}

	item.Error = cause

	return item, nil
}

func (s *triageWorkStore) FailAutomationWorkItem(_ context.Context, itemId, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, "fail:"+itemId)

	if s.failErr != nil {
		return s.failErr
	}

	s.pending = slices.DeleteFunc(s.pending, func(item *model.AutomationWorkItem) bool { return item.Id == itemId })

	return nil
}

func (s *triageWorkStore) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.events)
}

type triageFixture struct {
	es      *server.FakeEventstore
	store   *triageWorkStore
	alerts  *triageAssistantstore
	manager *triageAssistantManager
	run     *AutomationRun
	kind    *AlertTriageKind
	// Pinned alerts the lookups can find, by id.
	pinned map[string]*model.EventRecord
	// Ends with nothing to record: an unreadable item, or a group with no alerts left.
	allowUnrecordedEnd bool

	mu   sync.Mutex
	keys []string
}

// Deliberately not DEFAULT_ALERT_TRIAGE_EPOCH, so a test can tell the run's epoch is the one used.
var triageTestEpoch = time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

func newTriageFixture(t *testing.T, params string, open ...*model.AutomationWorkItem) *triageFixture {
	t.Helper()

	f := &triageFixture{es: server.NewFakeEventstore(), store: &triageWorkStore{}, kind: &AlertTriageKind{}, pinned: map[string]*model.EventRecord{}}
	f.alerts = &triageAssistantstore{prefix: "so_", work: f.store}
	f.manager = &triageAssistantManager{result: &model.AgentSessionResult{FinalText: "report"}}
	f.es.MSearchResults = []*model.EventMSearchResults{model.NewEventMSearchResults()}

	// An item ends only after its alerts carry the outcome.
	t.Cleanup(func() {
		if f.allowUnrecordedEnd {
			return
		}

		events := f.store.log()
		for i, event := range events {
			if !strings.HasPrefix(event, "complete:") && !strings.HasPrefix(event, "fail:") {
				continue
			}

			update := ""
			for j := i - 1; j >= 0 && update == ""; j-- {
				if strings.HasPrefix(events[j], "alerts:") {
					update = events[j]
				}
			}

			assert.True(t, update != "" && !strings.HasPrefix(update, "alerts:error"), "%s without a clean alert update before it: %v", event, events)
		}
	})

	pool := execpool.New(context.Background(), execpool.Config{Name: "test", KeyLimitFunc: func(key string) int {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.keys = append(f.keys, key)

		return 0
	}})
	t.Cleanup(func() { _ = pool.Shutdown(context.Background()) })

	f.run = &AutomationRun{
		Srv: &server.Server{Eventstore: &lockedEventstore{FakeEventstore: f.es, alerts: f.pinned}, Assistantstore: f.alerts, AssistantManager: f.manager},
		Task: &model.Automation{
			Auditable:      model.Auditable{Id: automationTestId, UserId: "user-1"},
			AutomationKind: alertTriageKindName,
			Agent:          automationTestAgent,
			Params:         json.RawMessage(params),
		},
		RunId:            "run-1",
		Store:            f.store,
		Pool:             pool,
		AlertTriageEpoch: triageTestEpoch,
		OpenItems:        open,
	}

	return f
}

// withGroups answers the groupby with buckets under the compound-key aggregation.
func (f *triageFixture) withGroups(fields string, buckets ...*model.EventMetric) {
	results := model.NewEventSearchResults()
	results.Metrics["groupby_0|"+fields] = buckets
	f.es.SearchResults = []*model.EventSearchResults{results}
}

// withLatest answers the MSearch with one hit per id; an empty id is a slot with no hit.
func (f *triageFixture) withLatest(ids ...string) *model.EventMSearchResults {
	results := model.NewEventMSearchResults()

	for _, id := range ids {
		response := model.NewEventSearchResults()
		if id != "" {
			response.Events = append(response.Events, &model.EventRecord{Id: id, Timestamp: "2026-09-26T10:00:00.000Z"})
		}

		results.Responses = append(results.Responses, response)
	}

	f.es.MSearchResults = []*model.EventMSearchResults{results}

	return results
}

// withAlert makes a pinned alert findable, carrying fields.
func (f *triageFixture) withAlert(id string, fields map[string]any) {
	f.pinned[id] = &model.EventRecord{Id: id, Timestamp: "2026-09-26T10:00:00.000Z", Payload: fields}
}

// withNewest answers the group's own latest-alert query, run once its pinned alert is gone; no
// ids is a group with nothing left.
func (f *triageFixture) withNewest(ids ...string) {
	results := model.NewEventSearchResults()
	for _, id := range ids {
		results.Events = append(results.Events, &model.EventRecord{Id: id, Timestamp: "2026-09-26T11:00:00.000Z", Payload: map[string]any{"rule": map[string]any{"name": "A"}}})
	}

	results.TotalEvents = len(results.Events)
	f.es.SearchResults = []*model.EventSearchResults{results}
}

func (f *triageFixture) submittedKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.keys)
}

// sessionId is the id the fixture's one session was started with.
func (f *triageFixture) sessionId(t *testing.T) string {
	t.Helper()

	requests := f.manager.sessions()
	require.Len(t, requests, 1)

	return requests[0].SessionId
}

func bucket(count float64, keys ...any) *model.EventMetric {
	return &model.EventMetric{Keys: keys, Value: count}
}

func TestAlertTriageRegistered(t *testing.T) {
	kind, ok := knownAutomationKinds[alertTriageKindName]
	require.True(t, ok)
	assert.Equal(t, alertTriageKindName, kind.GetName())
	assert.NotEmpty(t, kind.GetDisplayName())
	assert.NotEmpty(t, kind.GetDescription())

	schema := kind.GetParamSchema()
	require.NotNil(t, schema.Json)
	assert.Equal(t, []string{"groupBy"}, schema.Json.Required)

	for _, name := range []string{"filter", "groupBy", "maxGroupsPerScan", "maxFailures", "floor"} {
		assert.Contains(t, schema.Json.Properties, name)
	}
}

func TestAlertTriageValidateParams(t *testing.T) {
	kind := &AlertTriageKind{}

	tests := []struct {
		name    string
		params  string
		wantErr string
	}{
		{"empty", ``, "groupBy"},
		{"null", `null`, "groupBy"},
		{"no groupBy", `{"filter":"tags:alert"}`, "groupBy"},
		{"empty groupBy", `{"groupBy":[]}`, "groupBy"},
		{"blank field", `{"groupBy":[" "]}`, "not a field name"},
		{"pipe in field", `{"groupBy":["a|b"]}`, "not a field name"},
		{"option as field", `{"groupBy":["-pie"]}`, "not a field name"},
		{"bare wildcard", `{"groupBy":["*"]}`, "not a field name"},
		{"unknown key", `{"groupBy":["rule.name"],"flor":"2026-09-25T00:00:00Z"}`, "flor"},
		{"bad floor", `{"groupBy":["rule.name"],"floor":"yesterday"}`, "floor"},
		{"negative cap", `{"groupBy":["rule.name"],"maxGroupsPerScan":-1}`, "maxGroupsPerScan"},
		{"negative failures", `{"groupBy":["rule.name"],"maxFailures":-1}`, "maxFailures"},
		{"filter with groupby", `{"groupBy":["rule.name"],"filter":"tags:alert | groupby rule.name"}`, "search-only"},
		{"unparseable filter", `{"groupBy":["rule.name"],"filter":"rule.name:\"Foo"}`, "filter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := kind.ValidateParams(json.RawMessage(tt.params))
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidAutomationParams)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}

	assert.NoError(t, kind.ValidateParams(json.RawMessage(`{"groupBy":["rule.name"]}`)))

	params, err := parseAlertTriageParams(json.RawMessage(`{"groupBy":[" rule.name ","event.module*"],"filter":" event.module:suricata ","floor":"2026-09-26T00:00:00Z"}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"rule.name", "event.module*"}, params.GroupBy)
	assert.Equal(t, "event.module:suricata", params.Filter)
	assert.Equal(t, alertTriageDefaultGroupCap, params.MaxGroupsPerScan)
	assert.Equal(t, model.DefaultAlertTriageMaxFailures, params.MaxFailures)
	assert.True(t, params.floor.Equal(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)))
}

// A blank floor is the epoch, so an automation created for alerts already on hand reaches them.
func TestAlertTriageFloorResolution(t *testing.T) {
	params, err := parseAlertTriageParams(json.RawMessage(`{"groupBy":["rule.name"]}`))
	require.NoError(t, err)
	assert.True(t, alertTriageFloor(params, triageTestEpoch).Equal(triageTestEpoch))

	later := triageTestEpoch.Add(25 * time.Hour)
	params, err = parseAlertTriageParams(json.RawMessage(`{"groupBy":["rule.name"],"floor":"` + later.Format(time.RFC3339) + `"}`))
	require.NoError(t, err)
	assert.True(t, alertTriageFloor(params, triageTestEpoch).Equal(later))

	params, err = parseAlertTriageParams(json.RawMessage(`{"groupBy":["rule.name"],"floor":"2020-01-01T00:00:00Z"}`))
	require.NoError(t, err)
	assert.True(t, alertTriageFloor(params, triageTestEpoch).Equal(triageTestEpoch))
}

func TestAlertTriageMetricName(t *testing.T) {
	assert.Equal(t, "groupby_0|rule.name", alertTriageMetricName([]string{"rule.name"}))
	assert.Equal(t, "groupby_0|rule.name|event.module", alertTriageMetricName([]string{"rule.name", "event.module*"}))
}

func TestAlertTriageScanCarriesPredicateAndBounds(t *testing.T) {
	f := newTriageFixture(t, `{"filter":"event.module:suricata","groupBy":["rule.name","source.ip"],"maxGroupsPerScan":10,"maxFailures":5,"floor":"2026-09-26T00:00:00Z"}`)

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	require.Len(t, f.es.InputSearchCriterias, 1)
	criteria := f.es.InputSearchCriterias[0]
	assert.Equal(t, "(tags:alert AND NOT event.acknowledged:true AND NOT _exists_:event.so_alerttriage.session_id"+
		" AND NOT event.so_alerttriage.failed_count:>=5) AND (event.module:suricata) | groupby rule.name source.ip", criteria.RawQuery)
	assert.True(t, criteria.BeginTime.Equal(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)))
	assert.WithinDuration(t, time.Now(), criteria.EndTime, time.Minute)
	assert.True(t, criteria.EndTime.Equal(criteria.EndTime.Truncate(time.Second)))
	assert.Equal(t, 10, criteria.MetricLimit)
	assert.Equal(t, 0, criteria.EventLimit)

	// No groups, so nothing to look up, nothing to enqueue and nothing to claim.
	assert.Empty(t, f.es.InputMSearchCriterias)
	assert.Empty(t, f.store.ensured)
	assert.Equal(t, []string{"claim:none"}, f.store.log())
}

func TestAlertTriageEnqueuesOneItemPerGroup(t *testing.T) {
	f := newTriageFixture(t, triageTestParams)
	f.withGroups("rule.name|source.ip", bucket(7, "ET SCAN", "1.2.3.4"), bucket(2, "ET POLICY", "5.6.7.8"))
	f.withLatest("alert-a", "alert-b")
	f.withAlert("alert-a", nil)
	f.withAlert("alert-b", nil)

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	scan := f.es.InputSearchCriterias[0]

	// One MSearch, one slot per group: newest unprocessed alert inside the scan's bounds.
	require.Len(t, f.es.InputMSearchCriterias, 1)
	slots := f.es.InputMSearchCriterias[0]
	require.Len(t, slots, 2)

	for _, slot := range slots {
		assert.Equal(t, 1, slot.EventLimit)
		assert.Equal(t, 0, slot.MetricLimit)
		require.Len(t, slot.SortFields, 1)
		assert.Equal(t, "@timestamp", slot.SortFields[0].Field)
		assert.Equal(t, "desc", slot.SortFields[0].Order)
		assert.True(t, slot.BeginTime.Equal(scan.BeginTime))
		assert.True(t, slot.EndTime.Equal(scan.EndTime))
		assert.Contains(t, slot.RawQuery, "NOT _exists_:event.so_alerttriage.session_id")
		assert.Contains(t, slot.RawQuery, "failed_count:>=3")
	}

	// Each slot is the scan's own predicate narrowed to one group, nothing repeated.
	base := strings.TrimSuffix(scan.RawQuery, " | groupby rule.name source.ip")
	assert.Equal(t, base+` AND rule.name:"ET SCAN" AND source.ip:"1.2.3.4"`, slots[0].RawQuery)
	assert.Equal(t, base+` AND rule.name:"ET POLICY" AND source.ip:"5.6.7.8"`, slots[1].RawQuery)

	require.Len(t, f.store.ensured, 1)
	items := f.store.ensured[0]
	require.Len(t, items, 2)
	assert.Equal(t, automationTestId, items[0].AutomationId)
	assert.Equal(t, `rule.name:"ET SCAN" AND source.ip:"1.2.3.4"`, items[0].GroupKey)
	assert.Equal(t, `rule.name:"ET POLICY" AND source.ip:"5.6.7.8"`, items[1].GroupKey)

	var payload alertTriagePayload
	require.NoError(t, json.Unmarshal(items[0].Payload, &payload))
	assert.Equal(t, slots[0].RawQuery, payload.GroupFilter)
	assert.True(t, payload.Floor.Equal(scan.BeginTime))
	assert.True(t, payload.Ceiling.Equal(scan.EndTime))
	assert.Equal(t, "alert-a", payload.LatestAlertId)
	assert.Equal(t, "2026-09-26T10:00:00.000Z", payload.LatestAlertTimestamp)
	assert.Equal(t, 7, payload.Count)

	// Rows before jobs: both items are ensured, then claimed in order, and each job ran its
	// session, checkpointed it, and finished after recording it.
	events := f.store.log()
	require.Len(t, events, 12)
	assert.Equal(t, "ensure", events[0])
	assert.Less(t, slices.Index(events, "claim:item-1"), slices.Index(events, "claim:item-2"))

	for _, id := range []string{"item-1", "item-2"} {
		assert.Less(t, slices.Index(events, "claim:"+id), slices.Index(events, "session:"+id))
		assert.Less(t, slices.Index(events, "session:"+id), slices.Index(events, "applying:"+id))
		assert.Less(t, slices.Index(events, "applying:"+id), slices.Index(events, "complete:"+id))
	}

	assert.NotContains(t, events, "fail:item-1")
	assert.Len(t, f.manager.sessions(), 2)

	assert.Equal(t, []string{automationTestAgent, automationTestAgent}, f.submittedKeys())
}

func TestAlertTriageSubmitsOnlyInsertedRows(t *testing.T) {
	f := newTriageFixture(t, triageTestParams)
	f.withGroups("rule.name|source.ip", bucket(7, "ET SCAN", "1.2.3.4"), bucket(2, "ET POLICY", "5.6.7.8"))
	f.withLatest("alert-a", "alert-b")
	f.withAlert("alert-b", nil)
	f.store.insert = func(items []*model.AutomationWorkItem) []*model.AutomationWorkItem { return items[1:] }

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	assert.ElementsMatch(t, []string{"ensure", "claim:item-1", "claim:none", "session:item-1", "applying:item-1", "alerts:ok:" + f.sessionId(t), "complete:item-1"}, f.store.log())
	assert.Equal(t, `rule.name:"ET POLICY" AND source.ip:"5.6.7.8"`, f.store.ensured[0][1].GroupKey)
}

func TestAlertTriageReclaimsPendingWithoutRescanning(t *testing.T) {
	old := &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemPending, GroupKey: `rule.name:"ET SCAN" AND source.ip:"1.2.3.4"`, Payload: triageTestPayload(t)}

	f := newTriageFixture(t, triageTestParams, old)
	f.store.pending = []*model.AutomationWorkItem{old}
	f.withGroups("rule.name|source.ip", bucket(7, "ET SCAN", "1.2.3.4"), bucket(2, "ET POLICY", "5.6.7.8"))
	f.withLatest("alert-b")
	f.withAlert("alert-1", nil)
	f.withAlert("alert-b", nil)

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	// The resumed item is older than anything the scan enqueued, so it is claimed first.
	events := f.store.log()
	assert.Equal(t, "ensure", events[0])
	assert.Equal(t, "claim:item-old", events[1])
	assert.Less(t, slices.Index(events, "claim:item-old"), slices.Index(events, "claim:item-1"))
	assert.Contains(t, events, "complete:item-old")

	// The open group still comes back from the aggregation, so the scan asks for one more bucket
	// and skips it; only the new group is looked up and enqueued.
	assert.Equal(t, 11, f.es.InputSearchCriterias[0].MetricLimit)
	require.Len(t, f.es.InputMSearchCriterias[0], 1)
	assert.Contains(t, f.es.InputMSearchCriterias[0][0].RawQuery, `rule.name:"ET POLICY"`)
	require.Len(t, f.store.ensured[0], 1)
	assert.Equal(t, `rule.name:"ET POLICY" AND source.ip:"5.6.7.8"`, f.store.ensured[0][0].GroupKey)
}

func TestAlertTriagePerScanCapHolds(t *testing.T) {
	held := &model.AutomationWorkItem{Id: "item-held", State: model.AutomationWorkItemRunning, GroupKey: `rule.name:"A"`}

	f := newTriageFixture(t, `{"groupBy":["rule.name"],"maxGroupsPerScan":2}`, held)
	f.withGroups("rule.name", bucket(9, "A"), bucket(8, "B"), bucket(7, "C"), bucket(6, "D"), bucket(5, "E"))
	f.withLatest("alert-b", "alert-c")
	f.withAlert("alert-b", nil)
	f.withAlert("alert-c", nil)

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	assert.Equal(t, 3, f.es.InputSearchCriterias[0].MetricLimit)
	require.Len(t, f.es.InputMSearchCriterias[0], 2)
	require.Len(t, f.store.ensured[0], 2)
	assert.Equal(t, `rule.name:"B"`, f.store.ensured[0][0].GroupKey)
	assert.Equal(t, `rule.name:"C"`, f.store.ensured[0][1].GroupKey)

	// A job still holds the running item, so it is neither claimed nor touched.
	assert.NotContains(t, f.store.log(), "requeue:item-held")
	assert.Equal(t, "ensure", f.store.log()[0])
}

func TestAlertTriageSkipsGroupsWithoutAHit(t *testing.T) {
	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`)
	f.withGroups("rule.name", bucket(3, "A"), bucket(2, "B"), bucket(1, "C"))
	results := f.withLatest("alert-a", "", "alert-c")
	results.Responses[2].Errors = []string{"shard failure"}
	f.withAlert("alert-a", nil)

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	require.Len(t, f.store.ensured, 1)
	require.Len(t, f.store.ensured[0], 1)
	assert.Equal(t, `rule.name:"A"`, f.store.ensured[0][0].GroupKey)
}

func TestAlertTriageScanErrorsStopTheScan(t *testing.T) {
	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`)
	f.withGroups("rule.name", bucket(3, "A"))
	f.es.SearchResults[0].Errors = []string{"shard failure"}

	err := f.kind.Execute(context.Background(), f.run)
	assert.ErrorContains(t, err, "shard failure")
	assert.Empty(t, f.es.InputMSearchCriterias)
	assert.Empty(t, f.store.ensured)
}

func TestAlertTriageStoreUnsupported(t *testing.T) {
	f := newTriageFixture(t, triageTestParams)
	f.run.Srv.Assistantstore = nil

	assert.ErrorIs(t, f.kind.Execute(context.Background(), f.run), ErrAlertTriageStoreUnsupported)
	assert.Empty(t, f.es.InputSearchCriterias)
}

func TestAlertTriageRejectsBadStoredParams(t *testing.T) {
	f := newTriageFixture(t, `{"groupBy":["rule.name"],"flor":"x"}`)

	assert.ErrorIs(t, f.kind.Execute(context.Background(), f.run), ErrInvalidAutomationParams)
	assert.Empty(t, f.es.InputSearchCriterias)
}

func TestAlertTriageCancelledRunScansNothing(t *testing.T) {
	f := newTriageFixture(t, triageTestParams)
	f.withGroups("rule.name|source.ip", bucket(7, "ET SCAN", "1.2.3.4"))

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrAutomationParamsChanged)

	assert.ErrorIs(t, f.kind.Execute(ctx, f.run), ErrAutomationParamsChanged)
	assert.Empty(t, f.es.InputSearchCriterias)
	assert.Empty(t, f.store.log())
}

func triageTestPayload(t *testing.T) json.RawMessage {
	t.Helper()

	payload, err := json.Marshal(alertTriagePayload{
		GroupFilter:          `tags:alert AND rule.name:"A"`,
		Floor:                triageTestEpoch,
		Ceiling:              triageTestEpoch.Add(time.Hour),
		LatestAlertId:        "alert-1",
		LatestAlertTimestamp: "2026-09-26T10:00:00.000Z",
		Count:                4,
	})
	require.NoError(t, err)

	return payload
}

// claimed puts an item in the fake's hands as if this run had just claimed it.
func (f *triageFixture) claimed(t *testing.T, failedRunIds ...string) *model.AutomationWorkItem {
	t.Helper()

	item := &model.AutomationWorkItem{Id: "item-1", RunId: f.run.RunId, State: model.AutomationWorkItemRunning, Payload: triageTestPayload(t), FailedRunIds: failedRunIds}
	f.store.running = map[string]*model.AutomationWorkItem{item.Id: item}

	return item
}

// newTriageJob builds what a job body runs under, with the pinned alert findable.
func newTriageJob(t *testing.T) (*triageFixture, *alertTriageRun) {
	t.Helper()

	f := newTriageFixture(t, triageTestParams)
	f.withAlert("alert-1", map[string]any{"rule": map[string]any{"name": "A"}, "source": map[string]any{"ip": "1.2.3.4"}})

	params, err := parseAlertTriageParams(f.run.Task.Params)
	require.NoError(t, err)

	return f, &alertTriageRun{run: f.run, params: params, updater: f.alerts}
}

func TestAlertTriageWorkItemRecordsReport(t *testing.T) {
	f, r := newTriageJob(t)
	item := f.claimed(t)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)
	require.NoError(t, r.workItem(ctx, item))
	assert.Equal(t, []string{"session:item-1", "applying:item-1", "alerts:ok:" + f.sessionId(t), "complete:item-1"}, f.store.log())

	// The lookup names the pinned alert and searches around its timestamp.
	require.Len(t, f.es.InputSearchCriterias, 1)
	lookup := f.es.InputSearchCriterias[0]
	pinned := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	assert.Contains(t, lookup.RawQuery, `_id:"alert-1"`)
	assert.True(t, lookup.BeginTime.Equal(pinned.Add(-24*time.Hour)))
	assert.True(t, lookup.EndTime.Equal(pinned.Add(24*time.Hour)))

	// The automation's agent, under the run's server context, is handed the projected
	// alert and its group.
	requests := f.manager.sessions()
	require.Len(t, requests, 1)
	assert.Equal(t, automationTestAgent, requests[0].Agent)
	assert.Empty(t, requests[0].OwnerId)
	assert.Equal(t, []any{server.SYSTEM_ID}, f.manager.requestors)
	assert.Contains(t, requests[0].Objective, "4 unprocessed alerts")
	assert.Contains(t, requests[0].Objective, `tags:alert AND rule.name:"A"`)
	assert.Contains(t, requests[0].Objective, `"_id": "alert-1"`)
	assert.Contains(t, requests[0].Objective, `"ip": "1.2.3.4"`)

	// The item, its result and its alerts all hold the id the session was started with.
	sessionId := requests[0].SessionId
	assert.NotEmpty(t, sessionId)
	assert.Equal(t, model.AutomationWorkItemDone, item.State)
	assert.Equal(t, []string{sessionId}, item.SessionIds)
	assert.JSONEq(t, `{"sessionId":"`+sessionId+`"}`, string(item.Result))

	updates := f.alerts.recorded()
	require.Len(t, updates, 1)
	assert.False(t, updates[0].Failed)
	assert.Equal(t, sessionId, updates[0].SessionId)
	assert.Equal(t, "run-1", updates[0].RunId)
	assert.Equal(t, `tags:alert AND rule.name:"A"`, updates[0].Query)
	assert.True(t, updates[0].Floor.Equal(triageTestEpoch))
	assert.True(t, updates[0].Ceiling.Equal(triageTestEpoch.Add(time.Hour)))
	assert.Equal(t, 4, updates[0].Count)
	assert.Empty(t, updates[0].FailedRunIds)
}

func TestAlertTriageWorkItemNoReport(t *testing.T) {
	tests := []struct {
		name    string
		result  *model.AgentSessionResult
		err     error
		wantErr string
	}{
		{"session error", &model.AgentSessionResult{}, errors.New("model is down"), "model is down"},
		{"truncated", &model.AgentSessionResult{FinalText: "half", Truncated: true}, nil, ErrAlertTriageNoReport.Error()},
		{"empty report", &model.AgentSessionResult{FinalText: " \n"}, nil, ErrAlertTriageNoReport.Error()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, r := newTriageJob(t)
			f.manager.result, f.manager.err = tt.result, tt.err
			item := f.claimed(t, "run-0")

			// Below the cap the item waits for the next run, its failed session on the alerts.
			require.NoError(t, r.workItem(context.Background(), item))
			assert.Equal(t, []string{"session:item-1", "failrun:item-1", "alerts:run-0,run-1"}, f.store.log())
			assert.Equal(t, model.AutomationWorkItemPending, item.State)
			assert.Equal(t, tt.wantErr, item.Error)

			updates := f.alerts.recorded()
			require.Len(t, updates, 1)
			assert.True(t, updates[0].Failed)
			assert.Equal(t, f.sessionId(t), updates[0].SessionId)
			assert.Equal(t, "run-1", updates[0].RunId)
			assert.Equal(t, []string{"run-0", "run-1"}, updates[0].FailedRunIds)
		})
	}

	t.Run("reaching the cap updates the alerts then gives up", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.manager.result = &model.AgentSessionResult{Truncated: true}
		item := f.claimed(t, "run-a", "run-b")

		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"session:item-1", "failrun:item-1", "alerts:run-a,run-b,run-1", "fail:item-1"}, f.store.log())
	})

	t.Run("a session that cannot be linked never starts", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.store.sessionErr = errors.New("pg down")
		item := f.claimed(t)

		require.NoError(t, r.workItem(context.Background(), item))
		assert.Empty(t, f.manager.sessions())
		assert.Equal(t, []string{"session:item-1", "failrun:item-1", "alerts:run-1"}, f.store.log())
		assert.Empty(t, item.SessionIds)
		assert.Equal(t, "pg down", item.Error)
		assert.Empty(t, f.alerts.recorded()[0].SessionId)
	})

	t.Run("alerts that cannot be updated keep the item", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.manager.result = &model.AgentSessionResult{Truncated: true}
		f.alerts.updateErr = errors.New("elasticsearch is down")
		item := f.claimed(t, "run-a", "run-b")

		assert.ErrorContains(t, r.workItem(context.Background(), item), "elasticsearch is down")
		assert.NotContains(t, f.store.log(), "fail:item-1")
	})

	t.Run("swept while it ran", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.manager.result = &model.AgentSessionResult{Truncated: true}

		ctx, cancel := context.WithCancelCause(context.Background())
		f.store.sweep = func() { cancel(ErrAutomationParamsChanged) }
		f.store.failRunErr = database.ErrAutomationWorkItemNotFound

		assert.NoError(t, r.workItem(ctx, f.claimed(t)))
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("vanished on a live run", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.manager.result = &model.AgentSessionResult{Truncated: true}
		f.store.failRunErr = database.ErrAutomationWorkItemNotFound

		assert.ErrorIs(t, r.workItem(context.Background(), f.claimed(t)), database.ErrAutomationWorkItemNotFound)
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("store failure", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.manager.result = &model.AgentSessionResult{Truncated: true}
		f.store.failRunErr = errors.New("postgres is down")

		assert.ErrorContains(t, r.workItem(context.Background(), f.claimed(t)), "postgres is down")
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("cancelled before it ran", func(t *testing.T) {
		f, r := newTriageJob(t)

		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(ErrAutomationParamsChanged)

		assert.ErrorIs(t, r.workItem(ctx, f.claimed(t)), ErrAutomationParamsChanged)
		assert.Empty(t, f.store.log())
		assert.Empty(t, f.manager.sessions())
	})
}

func TestAlertTriageWorkItemAlertLookup(t *testing.T) {
	t.Run("search error spends a retry", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.es.Err = errors.New("elasticsearch is down")
		item := f.claimed(t)

		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"failrun:item-1", "alerts:run-1"}, f.store.log())
		assert.Empty(t, f.manager.sessions())
		assert.Contains(t, item.Error, "elasticsearch is down")
	})

	t.Run("pinned alert gone falls back to the group's newest", func(t *testing.T) {
		f, r := newTriageJob(t)
		delete(f.pinned, "alert-1")
		f.withNewest("alert-2")
		item := f.claimed(t)

		// The item is re-pinned to the alert actually investigated before its session opens.
		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"repin:item-1", "session:item-1", "applying:item-1", "alerts:ok:" + f.sessionId(t), "complete:item-1"}, f.store.log())

		// Both id lookups miss, then the group's own query runs over the payload's window.
		require.Len(t, f.es.InputSearchCriterias, 3)
		requery := f.es.InputSearchCriterias[2]
		assert.Equal(t, `tags:alert AND rule.name:"A"`, requery.RawQuery)
		assert.True(t, requery.BeginTime.Equal(triageTestEpoch))
		assert.True(t, requery.EndTime.Equal(triageTestEpoch.Add(time.Hour)))
		assert.Equal(t, []*model.SortCriteria{{Field: "@timestamp", Order: "desc"}}, requery.SortFields)
		assert.Equal(t, 1, requery.EventLimit)

		requests := f.manager.sessions()
		require.Len(t, requests, 1)
		assert.Contains(t, requests[0].Objective, `"_id": "alert-2"`)

		payload, err := decodeAlertTriagePayload(item)
		require.NoError(t, err)
		assert.Equal(t, "alert-2", payload.LatestAlertId)
		assert.Equal(t, "2026-09-26T11:00:00.000Z", payload.LatestAlertTimestamp)
		assert.Equal(t, `tags:alert AND rule.name:"A"`, payload.GroupFilter)
		assert.Equal(t, 4, payload.Count)
	})

	t.Run("re-pin store error leaves the item running", func(t *testing.T) {
		f, r := newTriageJob(t)
		delete(f.pinned, "alert-1")
		f.withNewest("alert-2")
		f.store.repinErr = errors.New("postgres is down")
		item := f.claimed(t)

		assert.ErrorContains(t, r.workItem(context.Background(), item), "postgres is down")
		assert.Equal(t, []string{"repin:item-1"}, f.store.log())
		assert.Empty(t, f.manager.sessions())
		assert.Equal(t, model.AutomationWorkItemRunning, item.State)
		assert.JSONEq(t, string(triageTestPayload(t)), string(item.Payload))
	})

	t.Run("re-pin on a vanished item", func(t *testing.T) {
		f, r := newTriageJob(t)
		delete(f.pinned, "alert-1")
		f.withNewest("alert-2")
		f.store.repinErr = database.ErrAutomationWorkItemNotFound

		assert.ErrorIs(t, r.workItem(context.Background(), f.claimed(t)), database.ErrAutomationWorkItemNotFound)
		assert.Empty(t, f.manager.sessions())
	})

	t.Run("unreadable pinned timestamp widens the lookup", func(t *testing.T) {
		f, r := newTriageJob(t)
		item := f.claimed(t)

		payload, err := decodeAlertTriagePayload(item)
		require.NoError(t, err)
		payload.LatestAlertTimestamp = "yesterday"
		item.Payload, err = json.Marshal(payload)
		require.NoError(t, err)

		// Still found, so still pinned: one all-time id lookup and no re-pin.
		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"session:item-1", "applying:item-1", "alerts:ok:" + f.sessionId(t), "complete:item-1"}, f.store.log())

		require.Len(t, f.es.InputSearchCriterias, 1)
		assert.Contains(t, f.es.InputSearchCriterias[0].RawQuery, `_id:"alert-1"`)
		assert.True(t, f.es.InputSearchCriterias[0].BeginTime.Equal(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)))
	})

	t.Run("nothing left in the group ends the item", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.allowUnrecordedEnd = true
		delete(f.pinned, "alert-1")
		f.withNewest()
		item := f.claimed(t)

		// A retry would find the group just as empty, so no retry is spent.
		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"fail:item-1"}, f.store.log())
		assert.Empty(t, f.manager.sessions())
		assert.Empty(t, f.alerts.recorded())
		assert.Len(t, f.es.InputSearchCriterias, 3)
	})

	t.Run("group query failure spends a retry", func(t *testing.T) {
		f, r := newTriageJob(t)
		delete(f.pinned, "alert-1")
		failed := model.NewEventSearchResults()
		failed.Errors = []string{"shard failure"}
		f.es.SearchResults = []*model.EventSearchResults{failed}
		item := f.claimed(t)

		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"failrun:item-1", "alerts:run-1"}, f.store.log())
		assert.Empty(t, f.manager.sessions())
		assert.Contains(t, item.Error, "shard failure")
	})

	t.Run("payload names no alert", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.withNewest("alert-2")
		item := f.claimed(t)

		payload, err := json.Marshal(alertTriagePayload{GroupFilter: `tags:alert AND rule.name:"A"`, Floor: triageTestEpoch, Ceiling: triageTestEpoch.Add(time.Hour), Count: 4})
		require.NoError(t, err)
		item.Payload = payload

		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"repin:item-1", "session:item-1", "applying:item-1", "alerts:ok:" + f.sessionId(t), "complete:item-1"}, f.store.log())

		// Straight to the group's own query, and the item now names what it found.
		require.Len(t, f.es.InputSearchCriterias, 1)
		assert.Equal(t, `tags:alert AND rule.name:"A"`, f.es.InputSearchCriterias[0].RawQuery)
		assert.Len(t, f.manager.sessions(), 1)

		repinned, err := decodeAlertTriagePayload(item)
		require.NoError(t, err)
		assert.Equal(t, "alert-2", repinned.LatestAlertId)
	})

	t.Run("unreadable payload ends the item", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.allowUnrecordedEnd = true
		item := f.claimed(t)
		item.Payload = json.RawMessage(`{`)

		// No retry can read it, so no retry is spent.
		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"fail:item-1"}, f.store.log())
		assert.Empty(t, f.manager.sessions())
	})
}

func TestAlertTriageCheckpointFailures(t *testing.T) {
	t.Run("store error leaves the item running", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.store.applyingErr = errors.New("postgres is down")
		item := f.claimed(t)

		assert.ErrorContains(t, r.workItem(context.Background(), item), "postgres is down")
		assert.Equal(t, []string{"session:item-1", "applying:item-1"}, f.store.log())
		assert.Equal(t, model.AutomationWorkItemRunning, item.State)
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("swept by a params change", func(t *testing.T) {
		f, r := newTriageJob(t)

		ctx, cancel := context.WithCancelCause(context.Background())
		f.store.sweep = func() { cancel(ErrAutomationParamsChanged) }
		f.store.applyingErr = database.ErrAutomationWorkItemNotFound

		require.NoError(t, r.workItem(ctx, f.claimed(t)))
		assert.Equal(t, []string{"session:item-1", "applying:item-1:cancelled"}, f.store.log())
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("vanished on a live run", func(t *testing.T) {
		f, r := newTriageJob(t)
		f.store.applyingErr = database.ErrAutomationWorkItemNotFound

		assert.ErrorIs(t, r.workItem(context.Background(), f.claimed(t)), database.ErrAutomationWorkItemNotFound)
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("shutdown during the checkpoint stays on the run's context", func(t *testing.T) {
		f, r := newTriageJob(t)

		ctx, cancel := context.WithCancelCause(context.Background())
		f.store.sweep = func() { cancel(ErrAutomationSchedulerStopped) }

		assert.ErrorIs(t, r.workItem(ctx, f.claimed(t)), ErrAutomationSchedulerStopped)
		assert.Equal(t, []string{"session:item-1", "applying:item-1:cancelled"}, f.store.log())
		assert.Empty(t, f.alerts.recorded())
	})
}

func TestAlertTriageUpdateErrorSpendsARetry(t *testing.T) {
	f, r := newTriageJob(t)
	f.alerts.updateErr = errors.New("elasticsearch is down")
	item := f.claimed(t)

	assert.ErrorContains(t, r.workItem(context.Background(), item), "elasticsearch is down")
	assert.Equal(t, []string{"session:item-1", "applying:item-1", "alerts:error", "failapply:item-1", "alerts:error"}, f.store.log())

	// The checkpoint survives with this run charged against it, so the next run replays only
	// the update.
	assert.Equal(t, model.AutomationWorkItemApplying, item.State)
	assert.JSONEq(t, `{"sessionId":"`+f.sessionId(t)+`"}`, string(item.Result))
	assert.Equal(t, []string{"run-1"}, item.FailedRunIds)
}

func TestAlertTriageCompleteErrorKeepsApplying(t *testing.T) {
	f, r := newTriageJob(t)
	f.store.completeErr = errors.New("postgres is down")
	item := f.claimed(t)

	assert.ErrorContains(t, r.workItem(context.Background(), item), "postgres is down")
	assert.Equal(t, []string{"session:item-1", "applying:item-1", "alerts:ok:" + f.sessionId(t), "complete:item-1"}, f.store.log())
	assert.Equal(t, model.AutomationWorkItemApplying, item.State)
	assert.Len(t, f.alerts.recorded(), 1)
}

func TestAlertTriageInterruptedSessionWritesNothing(t *testing.T) {
	tests := []struct {
		name   string
		cause  error
		events []string
	}{
		// The session is linked to the item before it starts, and nothing is written after.
		{"params changed", ErrAutomationParamsChanged, []string{"session:item-1"}},
		{"shutdown", ErrAutomationSchedulerStopped, []string{"session:item-1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, r := newTriageJob(t)

			ctx, cancel := context.WithCancelCause(context.Background())
			f.manager.onRun = func(context.Context) { cancel(tt.cause) }
			f.manager.result, f.manager.err = &model.AgentSessionResult{}, tt.cause

			assert.ErrorIs(t, r.workItem(ctx, f.claimed(t)), tt.cause)
			assert.Equal(t, tt.events, f.store.log())
			assert.Empty(t, f.alerts.recorded())
		})
	}
}

func TestAlertTriageReportAfterParamsChangeIsRecorded(t *testing.T) {
	t.Run("item still held", func(t *testing.T) {
		f, r := newTriageJob(t)

		ctx, cancel := context.WithCancelCause(context.Background())
		f.manager.onRun = func(context.Context) { cancel(ErrAutomationParamsChanged) }
		item := f.claimed(t)

		// Every write after the cancel runs detached from it.
		require.NoError(t, r.workItem(ctx, item))
		assert.Equal(t, []string{"session:item-1", "applying:item-1", "alerts:ok:" + f.sessionId(t), "complete:item-1"}, f.store.log())
		assert.Equal(t, model.AutomationWorkItemDone, item.State)
	})

	t.Run("item already swept", func(t *testing.T) {
		f, r := newTriageJob(t)

		ctx, cancel := context.WithCancelCause(context.Background())
		f.manager.onRun = func(context.Context) { cancel(ErrAutomationParamsChanged) }
		f.store.applyingErr = database.ErrAutomationWorkItemNotFound

		require.NoError(t, r.workItem(ctx, f.claimed(t)))
		assert.Equal(t, []string{"session:item-1", "applying:item-1"}, f.store.log())
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("shutdown records nothing", func(t *testing.T) {
		f, r := newTriageJob(t)

		ctx, cancel := context.WithCancelCause(context.Background())
		f.manager.onRun = func(context.Context) { cancel(ErrAutomationSchedulerStopped) }

		assert.ErrorIs(t, r.workItem(ctx, f.claimed(t)), ErrAutomationSchedulerStopped)
		assert.Equal(t, []string{"session:item-1"}, f.store.log(), "only the link made before the session started")
		assert.Empty(t, f.alerts.recorded())
	})
}

func TestAlertTriageReclaimGivesUpExhaustedItems(t *testing.T) {
	exhausted := &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemPending, GroupKey: `rule.name:"A"`,
		Payload: triageTestPayload(t), FailedRunIds: []string{"run-a", "run-b", "run-c"}}

	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, exhausted)
	f.store.pending = []*model.AutomationWorkItem{exhausted}

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	// Given up before anything is claimed, and its group is no longer held open.
	assert.Equal(t, []string{"alerts:run-a,run-b,run-c", "fail:item-old", "claim:none"}, f.store.log())
	assert.Equal(t, alertTriageDefaultGroupCap, f.es.InputSearchCriterias[0].MetricLimit)
}

func TestAlertTriageReclaimKeepsExhaustedItemsItCannotRecord(t *testing.T) {
	exhausted := &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemPending, GroupKey: `rule.name:"A"`,
		Payload: triageTestPayload(t), FailedRunIds: []string{"run-a", "run-b", "run-c"}}

	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, exhausted)
	f.store.pending = []*model.AutomationWorkItem{exhausted}
	f.alerts.updateErr = errors.New("elasticsearch is down")

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	// Still open, so the scan leaves its group alone, and never claimed.
	assert.Equal(t, []string{"alerts:error", "claim:none"}, f.store.log())
	assert.Equal(t, alertTriageDefaultGroupCap+1, f.es.InputSearchCriterias[0].MetricLimit)
}

func TestAlertTriageClaimErrorsAreReported(t *testing.T) {
	old := &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemPending}

	f := newTriageFixture(t, triageTestParams, old)
	f.store.claimErr = errors.New("postgres is down")

	err := f.kind.Execute(context.Background(), f.run)
	assert.ErrorContains(t, err, "postgres is down")
	// The scan still ran; a stuck claim must not hide new work.
	assert.Len(t, f.es.InputSearchCriterias, 1)
}

func TestAlertTriageObjective(t *testing.T) {
	objective := alertTriageObjective(map[string]any{"rule.name": "ET SCAN", "source.ip": "1.2.3.4"}, 7, `rule.name:"ET SCAN"`)

	assert.Contains(t, objective, "7 unprocessed alerts")
	assert.Contains(t, objective, `rule.name:"ET SCAN"`)
	assert.Contains(t, objective, `"source.ip": "1.2.3.4"`)
	assert.Contains(t, objective, "report for the analyst")
}

func TestAlertTriageReclaimAppliesCheckpointedItems(t *testing.T) {
	checkpointed := &model.AutomationWorkItem{Id: "item-old", RunId: "run-0", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`,
		Payload: triageTestPayload(t), Result: json.RawMessage(`{"sessionId":"sess-old"}`)}

	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, checkpointed)

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	// Recorded under the run that produced the report, without a new session, before the scan;
	// its group is no longer held open.
	assert.Equal(t, []string{"alerts:ok:sess-old", "complete:item-old", "claim:none"}, f.store.log())
	assert.Empty(t, f.manager.sessions())
	assert.Equal(t, alertTriageDefaultGroupCap, f.es.InputSearchCriterias[0].MetricLimit)

	updates := f.alerts.recorded()
	require.Len(t, updates, 1)
	assert.False(t, updates[0].Failed)
	assert.Equal(t, "run-0", updates[0].RunId)
	assert.Equal(t, "sess-old", updates[0].SessionId)
	assert.Equal(t, `tags:alert AND rule.name:"A"`, updates[0].Query)
}

func TestAlertTriageReclaimKeepsApplyingItemsItCannotRecord(t *testing.T) {
	checkpointed := &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`,
		Payload: triageTestPayload(t), Result: json.RawMessage(`{"sessionId":"sess-old"}`)}

	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, checkpointed)
	f.store.applying = map[string]*model.AutomationWorkItem{checkpointed.Id: checkpointed}
	f.alerts.updateErr = errors.New("elasticsearch is down")

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	// Still applying with its checkpoint and this run charged against it, so the scan leaves
	// its group alone.
	assert.Equal(t, []string{"alerts:error", "failapply:item-old", "alerts:error", "claim:none"}, f.store.log())
	assert.Equal(t, []string{"run-1"}, checkpointed.FailedRunIds)
	assert.Equal(t, alertTriageDefaultGroupCap+1, f.es.InputSearchCriterias[0].MetricLimit)
}

func TestAlertTriageApplyOutOfRetriesGivesUp(t *testing.T) {
	checkpointed := &model.AutomationWorkItem{Id: "item-old", RunId: "run-0", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`,
		Payload: triageTestPayload(t), Result: json.RawMessage(`{"sessionId":"sess-old"}`), FailedRunIds: []string{"run-a", "run-b"}}

	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, checkpointed)
	f.store.applying = map[string]*model.AutomationWorkItem{checkpointed.Id: checkpointed}
	f.alerts.applyErr = errors.New("elasticsearch rejected the update")

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	// This failure reaches the cap: the alerts take every failed run, the item ends, and its
	// group is no longer held open.
	assert.Equal(t, []string{"alerts:error", "failapply:item-old", "alerts:run-a,run-b,run-1", "fail:item-old", "claim:none"}, f.store.log())
	assert.Equal(t, alertTriageDefaultGroupCap, f.es.InputSearchCriterias[0].MetricLimit)

	updates := f.alerts.recorded()
	require.Len(t, updates, 2)
	assert.True(t, updates[1].Failed)
	assert.Empty(t, updates[1].SessionId, "the session produced the report; only the write failed")
	assert.Equal(t, "run-1", updates[1].RunId)
	assert.Equal(t, []string{"run-a", "run-b", "run-1"}, updates[1].FailedRunIds)
}

func TestAlertTriageApplyAtTheCapStillRecordsAReport(t *testing.T) {
	checkpointed := &model.AutomationWorkItem{Id: "item-old", RunId: "run-0", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`,
		Payload: triageTestPayload(t), Result: json.RawMessage(`{"sessionId":"sess-old"}`), FailedRunIds: []string{"run-a", "run-b", "run-c"}}

	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, checkpointed)
	f.store.applying = map[string]*model.AutomationWorkItem{checkpointed.Id: checkpointed}

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	// The report is paid for; the budget only decides when a failing update stops being retried.
	assert.Equal(t, []string{"alerts:ok:sess-old", "complete:item-old", "claim:none"}, f.store.log())
	assert.Equal(t, model.AutomationWorkItemDone, checkpointed.State)
}

// An item already out of retries is charged nothing more for a failed apply; its alerts take
// the failures it has and it ends.
func TestAlertTriageApplyFailurePastTheCapChargesNoRun(t *testing.T) {
	checkpointed := &model.AutomationWorkItem{Id: "item-old", RunId: "run-0", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`,
		Payload: triageTestPayload(t), Result: json.RawMessage(`{"sessionId":"sess-old"}`), FailedRunIds: []string{"run-a", "run-b", "run-c"}}

	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, checkpointed)
	f.store.applying = map[string]*model.AutomationWorkItem{checkpointed.Id: checkpointed}
	f.alerts.applyErr = errors.New("elasticsearch rejected the update")

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	assert.Equal(t, []string{"alerts:error", "alerts:run-a,run-b,run-c", "fail:item-old", "claim:none"}, f.store.log())
	assert.Equal(t, []string{"run-a", "run-b", "run-c"}, checkpointed.FailedRunIds)
}

// An item out of retries whose alerts cannot be updated at all stays applying, and does not
// gain a run for every run that tries it.
func TestAlertTriageStuckApplyPastTheCapDoesNotGrow(t *testing.T) {
	checkpointed := &model.AutomationWorkItem{Id: "item-old", RunId: "run-0", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`,
		Payload: triageTestPayload(t), Result: json.RawMessage(`{"sessionId":"sess-old"}`), FailedRunIds: []string{"run-a", "run-b", "run-c"}}

	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, checkpointed)
	f.store.applying = map[string]*model.AutomationWorkItem{checkpointed.Id: checkpointed}
	f.alerts.updateErr = errors.New("elasticsearch is down")

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	assert.Equal(t, []string{"alerts:error", "alerts:error", "claim:none"}, f.store.log())
	assert.Equal(t, model.AutomationWorkItemApplying, checkpointed.State)
	assert.Equal(t, []string{"run-a", "run-b", "run-c"}, checkpointed.FailedRunIds)
	assert.Equal(t, alertTriageDefaultGroupCap+1, f.es.InputSearchCriterias[0].MetricLimit)
}

func TestAlertTriageReclaimEndsUnusableCheckpoints(t *testing.T) {
	tests := []struct {
		name string
		item *model.AutomationWorkItem
	}{
		{"no session", &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`, Payload: triageTestPayload(t), Result: json.RawMessage(`{}`)}},
		{"unreadable result", &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`, Payload: triageTestPayload(t), Result: json.RawMessage(`{`)}},
		{"unreadable payload", &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`, Payload: json.RawMessage(`{`), Result: json.RawMessage(`{"sessionId":"sess-old"}`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newTriageFixture(t, `{"groupBy":["rule.name"]}`, tt.item)
			f.allowUnrecordedEnd = true

			require.NoError(t, f.kind.Execute(context.Background(), f.run))

			// Nothing to record, so the item ends and the next scan re-derives its group.
			assert.Equal(t, []string{"fail:item-old", "claim:none"}, f.store.log())
			assert.Empty(t, f.alerts.recorded())
			assert.Equal(t, alertTriageDefaultGroupCap, f.es.InputSearchCriterias[0].MetricLimit)
		})
	}
}

// The fixed params go through the same strict validation as any save, so a typo in the
// definition would make the builtin unsaveable.
func TestBuiltinAlertTriageDefinitionIsValid(t *testing.T) {
	ac := &AssistantCoordinator{}
	ac.automationTickInterval.Store(int64(time.Minute))
	builtin := seedBuiltinAutomation(ac)

	require.NoError(t, validateAutomation(builtin))
	require.NoError(t, (&AlertTriageKind{}).ValidateParams(builtin.Params))
	assert.Equal(t, alertTriageKindName, builtin.AutomationKind)

	params, err := parseAlertTriageParams(builtin.Params)
	require.NoError(t, err)
	assert.Equal(t, []string{"source.ip", "rule.uuid", "destination.ip"}, params.GroupBy)
	assert.Equal(t, "groupby_0|source.ip|rule.uuid|destination.ip", alertTriageMetricName(params.GroupBy))
}
