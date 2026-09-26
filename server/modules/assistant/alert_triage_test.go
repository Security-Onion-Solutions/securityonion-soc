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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"

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
	updates   []*model.AlertTriageUpdate
}

func (s *triageAssistantstore) AlertTriageUpdate(_ context.Context, update *model.AlertTriageUpdate) (*model.EventUpdateResults, error) {
	s.work.mu.Lock()
	defer s.work.mu.Unlock()

	s.updates = append(s.updates, update)
	s.work.events = append(s.work.events, "alerts:"+strings.Join(update.FailedRunIds, ","))

	if s.updateErr != nil {
		return nil, s.updateErr
	}

	return model.NewEventUpdateResults(), nil
}

func (s *triageAssistantstore) AlertTriageSchemaPrefix() string { return s.prefix }

func (s *triageAssistantstore) recorded() []*model.AlertTriageUpdate {
	s.work.mu.Lock()
	defer s.work.mu.Unlock()

	return slices.Clone(s.updates)
}

// triageWorkStore plays the work-item table: ensured rows become pending, claims hand them out
// oldest first, and every call is logged in order.
type triageWorkStore struct {
	AutomationStore

	mu         sync.Mutex
	next       int
	pending    []*model.AutomationWorkItem
	claimErr   error
	requeueErr error
	failRunErr error
	failErr    error
	running    map[string]*model.AutomationWorkItem
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

func (s *triageWorkStore) RequeueAutomationWorkItem(_ context.Context, itemId, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, "requeue:"+itemId)

	return s.requeueErr
}

func (s *triageWorkStore) FailAutomationWorkItemRun(_ context.Context, itemId, cause string) (*model.AutomationWorkItem, error) {
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
	es     *server.FakeEventstore
	store  *triageWorkStore
	alerts *triageAssistantstore
	run    *AutomationRun
	kind   *AlertTriageKind

	mu   sync.Mutex
	keys []string
}

// Deliberately not DEFAULT_ALERT_TRIAGE_EPOCH, so a test can tell the run's epoch is the one used.
var triageTestEpoch = time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

func newTriageFixture(t *testing.T, params string, open ...*model.AutomationWorkItem) *triageFixture {
	t.Helper()

	f := &triageFixture{es: server.NewFakeEventstore(), store: &triageWorkStore{}, kind: &AlertTriageKind{}}
	f.alerts = &triageAssistantstore{prefix: "so_", work: f.store}
	f.es.MSearchResults = []*model.EventMSearchResults{model.NewEventMSearchResults()}

	pool := execpool.New(context.Background(), execpool.Config{Name: "test", KeyLimitFunc: func(key string) int {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.keys = append(f.keys, key)

		return 0
	}})
	t.Cleanup(func() { _ = pool.Shutdown(context.Background()) })

	created := triageTestEpoch.Add(48 * time.Hour)

	f.run = &AutomationRun{
		Srv: &server.Server{Eventstore: f.es, Assistantstore: f.alerts},
		Task: &model.Automation{
			Auditable:      model.Auditable{Id: automationTestId, UserId: "user-1", CreateTime: &created},
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

func (f *triageFixture) submittedKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.keys)
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

func TestAlertTriageFloorResolution(t *testing.T) {
	created := triageTestEpoch.Add(24 * time.Hour)
	task := &model.Automation{Auditable: model.Auditable{CreateTime: &created}}

	params, err := parseAlertTriageParams(json.RawMessage(`{"groupBy":["rule.name"]}`))
	require.NoError(t, err)
	assert.True(t, alertTriageFloor(params, task, triageTestEpoch).Equal(created))
	assert.True(t, alertTriageFloor(params, &model.Automation{}, triageTestEpoch).Equal(triageTestEpoch))

	later := created.Add(time.Hour)
	params, err = parseAlertTriageParams(json.RawMessage(`{"groupBy":["rule.name"],"floor":"` + later.Format(time.RFC3339) + `"}`))
	require.NoError(t, err)
	assert.True(t, alertTriageFloor(params, task, triageTestEpoch).Equal(later))

	params, err = parseAlertTriageParams(json.RawMessage(`{"groupBy":["rule.name"],"floor":"2020-01-01T00:00:00Z"}`))
	require.NoError(t, err)
	assert.True(t, alertTriageFloor(params, task, triageTestEpoch).Equal(triageTestEpoch))
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

	// Rows before jobs: both items are ensured, then claimed in order, and each job ran. Neither
	// is claimed again by the run that failed it.
	events := f.store.log()
	require.Len(t, events, 8)
	assert.Equal(t, "ensure", events[0])
	assert.Less(t, slices.Index(events, "claim:item-1"), slices.Index(events, "claim:item-2"))
	assert.Less(t, slices.Index(events, "claim:item-1"), slices.Index(events, "failrun:item-1"))
	assert.Less(t, slices.Index(events, "claim:item-2"), slices.Index(events, "failrun:item-2"))
	assert.NotContains(t, events, "fail:item-1")

	assert.Equal(t, []string{automationTestAgent, automationTestAgent}, f.submittedKeys())
}

func TestAlertTriageSubmitsOnlyInsertedRows(t *testing.T) {
	f := newTriageFixture(t, triageTestParams)
	f.withGroups("rule.name|source.ip", bucket(7, "ET SCAN", "1.2.3.4"), bucket(2, "ET POLICY", "5.6.7.8"))
	f.withLatest("alert-a", "alert-b")
	f.store.insert = func(items []*model.AutomationWorkItem) []*model.AutomationWorkItem { return items[1:] }

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	assert.ElementsMatch(t, []string{"ensure", "claim:item-1", "claim:none", "failrun:item-1", "alerts:run-1"}, f.store.log())
	assert.Equal(t, `rule.name:"ET POLICY" AND source.ip:"5.6.7.8"`, f.store.ensured[0][1].GroupKey)
}

func TestAlertTriageReclaimsPendingWithoutRescanning(t *testing.T) {
	old := &model.AutomationWorkItem{Id: "item-old", State: model.AutomationWorkItemPending, GroupKey: `rule.name:"ET SCAN" AND source.ip:"1.2.3.4"`, Payload: json.RawMessage(`{}`)}

	f := newTriageFixture(t, triageTestParams, old)
	f.store.pending = []*model.AutomationWorkItem{old}
	f.withGroups("rule.name|source.ip", bucket(7, "ET SCAN", "1.2.3.4"), bucket(2, "ET POLICY", "5.6.7.8"))
	f.withLatest("alert-b")

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	// The resumed item is older than anything the scan enqueued, so it is claimed first.
	events := f.store.log()
	assert.Equal(t, "ensure", events[0])
	assert.Equal(t, "claim:item-old", events[1])
	assert.Less(t, slices.Index(events, "claim:item-old"), slices.Index(events, "claim:item-1"))
	assert.Contains(t, events, "failrun:item-old")

	// The open group still comes back from the aggregation, so the scan asks for one more bucket
	// and skips it; only the new group is looked up and enqueued.
	assert.Equal(t, 11, f.es.InputSearchCriterias[0].MetricLimit)
	require.Len(t, f.es.InputMSearchCriterias[0], 1)
	assert.Contains(t, f.es.InputMSearchCriterias[0][0].RawQuery, `rule.name:"ET POLICY"`)
	require.Len(t, f.store.ensured[0], 1)
	assert.Equal(t, `rule.name:"ET POLICY" AND source.ip:"5.6.7.8"`, f.store.ensured[0][0].GroupKey)
}

func TestAlertTriagePerScanCapHolds(t *testing.T) {
	applying := &model.AutomationWorkItem{Id: "item-applying", State: model.AutomationWorkItemApplying, GroupKey: `rule.name:"A"`, Result: json.RawMessage(`{}`)}

	f := newTriageFixture(t, `{"groupBy":["rule.name"],"maxGroupsPerScan":2}`, applying)
	f.withGroups("rule.name", bucket(9, "A"), bucket(8, "B"), bucket(7, "C"), bucket(6, "D"), bucket(5, "E"))
	f.withLatest("alert-b", "alert-c")

	require.NoError(t, f.kind.Execute(context.Background(), f.run))

	assert.Equal(t, 3, f.es.InputSearchCriterias[0].MetricLimit)
	require.Len(t, f.es.InputMSearchCriterias[0], 2)
	require.Len(t, f.store.ensured[0], 2)
	assert.Equal(t, `rule.name:"B"`, f.store.ensured[0][0].GroupKey)
	assert.Equal(t, `rule.name:"C"`, f.store.ensured[0][1].GroupKey)

	// The applying item is neither claimed nor touched; its update is a later step.
	assert.NotContains(t, f.store.log(), "requeue:item-applying")
	assert.Equal(t, "ensure", f.store.log()[0])
}

func TestAlertTriageSkipsGroupsWithoutAHit(t *testing.T) {
	f := newTriageFixture(t, `{"groupBy":["rule.name"]}`)
	f.withGroups("rule.name", bucket(3, "A"), bucket(2, "B"), bucket(1, "C"))
	results := f.withLatest("alert-a", "", "alert-c")
	results.Responses[2].Errors = []string{"shard failure"}

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
		GroupFilter: `tags:alert AND rule.name:"A"`,
		Floor:       triageTestEpoch,
		Ceiling:     triageTestEpoch.Add(time.Hour),
		Count:       4,
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

func newTriageFailureRun(t *testing.T) (*triageFixture, *alertTriageRun) {
	t.Helper()

	f := newTriageFixture(t, triageTestParams)
	params, err := parseAlertTriageParams(f.run.Task.Params)
	require.NoError(t, err)

	return f, &alertTriageRun{run: f.run, params: params, updater: f.alerts}
}

func TestAlertTriageWorkItemFailure(t *testing.T) {
	t.Run("below the cap the item waits for the next run", func(t *testing.T) {
		f, r := newTriageFailureRun(t)
		item := f.claimed(t, "run-0")

		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"failrun:item-1", "alerts:run-0,run-1"}, f.store.log())

		updates := f.alerts.recorded()
		require.Len(t, updates, 1)
		assert.True(t, updates[0].Failed)
		assert.Equal(t, `tags:alert AND rule.name:"A"`, updates[0].Query)
		assert.True(t, updates[0].Floor.Equal(triageTestEpoch))
		assert.True(t, updates[0].Ceiling.Equal(triageTestEpoch.Add(time.Hour)))
		assert.Equal(t, 4, updates[0].Count)
		assert.Equal(t, "run-1", updates[0].RunId)
		assert.Empty(t, updates[0].SessionId)
		assert.Equal(t, model.AutomationWorkItemPending, item.State)
		assert.Equal(t, ErrAlertTriageUpdateNotImplemented.Error(), item.Error)
	})

	t.Run("reaching the cap updates the alerts then gives up", func(t *testing.T) {
		f, r := newTriageFailureRun(t)
		item := f.claimed(t, "run-a", "run-b")

		require.NoError(t, r.workItem(context.Background(), item))
		assert.Equal(t, []string{"failrun:item-1", "alerts:run-a,run-b,run-1", "fail:item-1"}, f.store.log())
	})

	t.Run("alerts that cannot be updated keep the item", func(t *testing.T) {
		f, r := newTriageFailureRun(t)
		f.alerts.updateErr = errors.New("elasticsearch is down")
		item := f.claimed(t, "run-a", "run-b")

		assert.ErrorContains(t, r.workItem(context.Background(), item), "elasticsearch is down")
		assert.NotContains(t, f.store.log(), "fail:item-1")
	})

	t.Run("swept while it ran", func(t *testing.T) {
		f, r := newTriageFailureRun(t)
		f.store.failRunErr = database.ErrAutomationWorkItemNotFound

		assert.NoError(t, r.workItem(context.Background(), f.claimed(t)))
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("store failure", func(t *testing.T) {
		f, r := newTriageFailureRun(t)
		f.store.failRunErr = errors.New("postgres is down")

		assert.ErrorContains(t, r.workItem(context.Background(), f.claimed(t)), "postgres is down")
		assert.Empty(t, f.alerts.recorded())
	})

	t.Run("cancelled before it ran", func(t *testing.T) {
		f, r := newTriageFailureRun(t)

		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(ErrAutomationParamsChanged)

		assert.ErrorIs(t, r.workItem(ctx, f.claimed(t)), ErrAutomationParamsChanged)
		assert.Empty(t, f.store.log())
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
	assert.Equal(t, []string{"alerts:run-a,run-b,run-c", "claim:none"}, f.store.log())
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
	assert.Contains(t, objective, "human analyst")
	assert.Contains(t, objective, "Do not acknowledge")
	assert.Contains(t, objective, "no software will parse it")
}
