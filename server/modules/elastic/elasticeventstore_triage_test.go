// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	modmock "github.com/security-onion-solutions/securityonion-soc/server/modules/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func newTriageTestStore(t *testing.T, srv *server.Server) (*ElasticEventstore, *modmock.MockTransport) {
	client, transport := modmock.NewMockClient(t)
	store := &ElasticEventstore{
		server:         srv,
		esClient:       client,
		esAllClients:   []*elasticsearch.Client{client},
		hostUrls:       []string{"http://localhost:9200"},
		cacheTime:      time.Now().Add(time.Hour),
		fieldDefs:      make(map[string]*FieldDefinition),
		index:          "myIndex",
		maxLogLength:   math.MaxInt,
		asyncThreshold: 10,
	}
	return store, transport
}

func esResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func triageUpdate() *model.AlertTriageUpdate {
	return &model.AlertTriageUpdate{
		Query:     `rule.name:"Foo"`,
		Floor:     time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Ceiling:   time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC),
		Count:     3,
		RunId:     "run-1",
		SessionId: "session-1",
	}
}

func requestBody(t *testing.T, req *http.Request) string {
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	return string(body)
}

func TestAddAlertTriageScript(t *testing.T) {
	store := &ElasticEventstore{}
	timeNow := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

	criteria := model.NewEventUpdateCriteria()
	store.addAlertTriageScript(criteria, timeNow, triageUpdate())
	require.Len(t, criteria.UpdateScripts, 1)
	script := criteria.UpdateScripts[0]
	assert.Contains(t, script, "if (triage_rec.session_id == null) {")
	assert.Contains(t, script, "triage_rec.session_id = params.triageSessionId;")
	assert.Contains(t, script, "triage_rec.automation_run_ids.add(params.triageRunId);")
	assert.Contains(t, script, "triage_rec.timestamp = triage_date;")
	assert.NotContains(t, script, "failed_session_ids")
	assert.Equal(t, int64(1257894000000), criteria.Params["triageNowMillis"])
	assert.Equal(t, "run-1", criteria.Params["triageRunId"])
	assert.Equal(t, "session-1", criteria.Params["triageSessionId"])
	assert.Len(t, criteria.Params, 3)

	// Locals must not collide with the other update scripts.
	for _, local := range []string{"now_instant", "now_date", "track_timing"} {
		assert.NotContains(t, script, local)
	}

	criteria = model.NewEventUpdateCriteria()
	update := triageUpdate()
	update.Failed = true
	store.addAlertTriageScript(criteria, timeNow, update)
	require.Len(t, criteria.UpdateScripts, 1)
	script = criteria.UpdateScripts[0]
	assert.Contains(t, script, "triage_rec.failed_session_ids.add(params.triageSessionId);")
	assert.Contains(t, script, "triage_rec.failed_count = triage_rec.failed_session_ids.size();")
	assert.Contains(t, script, "triage_rec.automation_run_ids.add(params.triageRunId);")
	assert.NotContains(t, script, "triage_rec.session_id")
}

func TestAddAlertTriageScript_InjectionAttack(t *testing.T) {
	store := &ElasticEventstore{}
	criteria := model.NewEventUpdateCriteria()

	update := triageUpdate()
	update.RunId = `run'; ctx._source.other = 'leaked`
	update.SessionId = `session'; ctx._source.more = 'leaked`
	store.addAlertTriageScript(criteria, time.Now(), update)

	assert.NotContains(t, criteria.UpdateScripts[0], "leaked")
	assert.Equal(t, update.RunId, criteria.Params["triageRunId"])
	assert.Equal(t, update.SessionId, criteria.Params["triageSessionId"])
}

func TestAlertTriageUpdateSuccess(t *testing.T) {
	store, transport := newTriageTestStore(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(`{"took":5,"timed_out":false,"total":3,"updated":3,"noops":0,"failures":[]}`), nil)

	results, err := store.AlertTriageUpdate(context.Background(), triageUpdate())
	require.NoError(t, err)
	assert.Equal(t, 3, results.UpdatedCount)
	assert.Empty(t, results.TaskIds)
	assert.Empty(t, results.Errors)

	reqs := transport.GetRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/myIndex/_update_by_query", reqs[0].URL.Path)
	assert.Equal(t, "true", reqs[0].URL.Query().Get("wait_for_completion"))

	body := requestBody(t, reqs[0])
	assert.Equal(t, `(NOT _exists_:event.triage.session_id) AND (rule.name:"Foo")`, gjson.Get(body, "query.bool.must.0.query_string.query").String())
	assert.Equal(t, "2026-09-01T00:00:00Z", gjson.Get(body, `query.bool.must.1.range.@timestamp.gte`).String())
	assert.Equal(t, "2026-09-22T12:00:00Z", gjson.Get(body, `query.bool.must.1.range.@timestamp.lte`).String())

	source := gjson.Get(body, "script.source").String()
	assert.Contains(t, source, "triage_rec.session_id = params.triageSessionId;")
	assert.NotContains(t, source, "acknowledged")
	assert.False(t, gjson.Get(body, "script.params.userId").Exists())
	assert.Equal(t, "session-1", gjson.Get(body, "script.params.triageSessionId").String())
}

func TestAlertTriageUpdateFailure(t *testing.T) {
	store, transport := newTriageTestStore(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(`{"took":5,"timed_out":false,"total":1,"updated":1,"noops":0,"failures":[]}`), nil)

	update := triageUpdate()
	update.Query = `_id:"abc"`
	update.Failed = true
	results, err := store.AlertTriageUpdate(context.Background(), update)
	require.NoError(t, err)
	assert.Equal(t, 1, results.UpdatedCount)

	body := requestBody(t, transport.GetRequests()[0])
	assert.Equal(t, `_id: "abc"`, gjson.Get(body, "query.bool.must.0.query_string.query").String())
	assert.Contains(t, gjson.Get(body, "script.source").String(), "triage_rec.failed_count = triage_rec.failed_session_ids.size();")
}

func TestAlertTriageUpdateZeroFloor(t *testing.T) {
	store, transport := newTriageTestStore(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(`{"took":5,"timed_out":false,"total":0,"updated":0,"noops":0,"failures":[]}`), nil)

	update := triageUpdate()
	update.Floor = time.Time{}
	results, err := store.AlertTriageUpdate(context.Background(), update)
	require.NoError(t, err)
	assert.Equal(t, 0, results.UpdatedCount)

	body := requestBody(t, transport.GetRequests()[0])
	assert.Equal(t, "1970-01-01T00:00:00Z", gjson.Get(body, `query.bool.must.1.range.@timestamp.gte`).String())
}

func TestAlertTriageUpdateSyncHostFailure(t *testing.T) {
	store, transport := newTriageTestStore(t, server.NewFakeAuthorizedServer(nil))
	second, secondTransport := modmock.NewMockClient(t)
	store.esAllClients = append(store.esAllClients, second)
	store.hostUrls = append(store.hostUrls, "http://localhost:9201")
	transport.AddResponse(esResponse(`{"took":5,"timed_out":false,"total":3,"updated":3,"noops":0,"failures":[]}`), nil)
	secondTransport.AddResponse(&http.Response{
		StatusCode: 500,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":{"type":"exception","reason":"boom"}}`)),
	}, nil)

	results, err := store.AlertTriageUpdate(context.Background(), triageUpdate())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
	assert.Equal(t, 3, results.UpdatedCount)
	require.Len(t, results.Errors, 1)
	assert.Contains(t, results.Errors[0], "boom")
}

func TestAlertTriageUpdateAsync(t *testing.T) {
	store, transport := newTriageTestStore(t, server.NewFakeAuthorizedServer(nil))
	// Any broadcast would dereference a nil host; the triage path must never broadcast.
	store.server.Host = nil
	transport.AddResponse(esResponse(`{"task":"node-1:1"}`), nil)
	transport.AddResponse(esResponse(`{"completed":true,"response":{"updated":5,"version_conflicts":0,"timed_out":false,"failures":[]}}`), nil)

	update := triageUpdate()
	update.Count = 11

	var results *model.EventUpdateResults
	var err error
	assert.NotPanics(t, func() {
		results, err = store.AlertTriageUpdate(context.Background(), update)
	})
	require.NoError(t, err)
	assert.Equal(t, 5, results.UpdatedCount)
	assert.Equal(t, []string{"node-1:1"}, results.TaskIds)
	assert.Empty(t, results.Errors)

	reqs := transport.GetRequests()
	require.Len(t, reqs, 2)
	assert.Equal(t, "false", reqs[0].URL.Query().Get("wait_for_completion"))
	assert.Equal(t, "/_tasks/node-1:1", reqs[1].URL.Path)
}

func TestAlertTriageUpdateAsyncFailure(t *testing.T) {
	store, transport := newTriageTestStore(t, server.NewFakeAuthorizedServer(nil))
	store.server.Host = nil
	transport.AddResponse(esResponse(`{"task":"node-1:1"}`), nil)
	transport.AddResponse(esResponse(`{"completed":true,"response":{"updated":2,"version_conflicts":0,"timed_out":false,"failures":[{"cause":{"type":"mapper_parsing_exception","reason":"boom"}}]}}`), nil)

	update := triageUpdate()
	update.Count = 11
	results, err := store.AlertTriageUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
	assert.Equal(t, []string{"boom"}, results.Errors)
}

func TestAlertTriageUpdateUnauthorized(t *testing.T) {
	store, transport := newTriageTestStore(t, server.NewFakeUnauthorizedServer())

	_, err := store.AlertTriageUpdate(context.Background(), triageUpdate())
	assert.Error(t, err)
	assert.Empty(t, transport.GetRequests())
}

func TestAlertTriageUpdateInvalid(t *testing.T) {
	store, transport := newTriageTestStore(t, server.NewFakeAuthorizedServer(nil))

	update := triageUpdate()
	update.SessionId = ""
	results, err := store.AlertTriageUpdate(context.Background(), update)
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Empty(t, transport.GetRequests())
}
