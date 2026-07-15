// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/server"
	modmock "github.com/security-onion-solutions/securityonion-soc/server/modules/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func esResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func newEsHealthHandler(t *testing.T, srv *server.Server) (*EsHealthHandler, *modmock.MockTransport) {
	client, transport := modmock.NewMockClient(t)
	store := NewElasticEventstore(srv)
	store.esClient = client
	return &EsHealthHandler{server: srv, store: store}, transport
}

func getEsHealth(h *EsHealthHandler) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/eshealth/", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.getEsHealth(w, req)
	return w
}

func TestGetEsHealthUnauthorized(t *testing.T) {
	h, _ := newEsHealthHandler(t, server.NewFakeUnauthorizedServer())

	w := getEsHealth(h)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGetEsHealthGreen(t *testing.T) {
	h, transport := newEsHealthHandler(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(200, `{"status":"green","indicators":{"shards_availability":{"status":"green"}}}`), nil)
	transport.AddResponse(esResponse(200, `{"persistent":{},"transient":{}}`), nil)
	transport.AddResponse(esResponse(200, `[{"name":"node-1","heap.percent":"42"}]`), nil)

	w := getEsHealth(h)

	assert.Equal(t, http.StatusOK, w.Code)

	var health EsHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	assert.Equal(t, "green", gjson.GetBytes(health.HealthReport, "status").String())
	assert.Equal(t, `{"persistent":{},"transient":{}}`, string(health.ClusterSettings))
	assert.Equal(t, "node-1", gjson.GetBytes(health.CatNodes, "0.name").String())
	assert.Nil(t, health.UnassignedShards)

	requests := transport.GetRequests()
	assert.Len(t, requests, 3)
	assert.Equal(t, "/_health_report", requests[0].URL.Path)
	assert.Equal(t, "/_cluster/settings", requests[1].URL.Path)
	assert.Equal(t, "/_cat/nodes", requests[2].URL.Path)

	// Every ES call is bounded by the endpoint's fail-fast deadline
	for _, request := range requests {
		deadline, ok := request.Context().Deadline()
		if assert.True(t, ok) {
			assert.LessOrEqual(t, time.Until(deadline), ESHEALTH_TIMEOUT)
		}
	}
}

func TestGetEsHealthUnassignedShards(t *testing.T) {
	h, transport := newEsHealthHandler(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(200, `{"status":"red","indicators":{"shards_availability":{"status":"red","symptom":"This cluster has 2 unavailable primary shards."}}}`), nil)
	transport.AddResponse(esResponse(200, `{"persistent":{},"transient":{}}`), nil)
	transport.AddResponse(esResponse(200, `[{"name":"node-1"}]`), nil)
	transport.AddResponse(esResponse(200, `[
		{"index":"so-logs","shard":"0","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"so-logs","shard":"1","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"so-case","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"INDEX_CREATED"},
		{"index":"so-detection","shard":"0","prirep":"p","state":"STARTED","unassigned.reason":""}
	]`), nil)
	transport.AddResponse(esResponse(200, `{"index":"so-logs","shard":0,"primary":true,"unassigned_info":{"reason":"NODE_LEFT"},"can_allocate":"no_valid_shard_copy"}`), nil)
	transport.AddResponse(esResponse(200, `{"index":"so-case","shard":0,"primary":false,"unassigned_info":{"reason":"INDEX_CREATED"},"can_allocate":"no","node_allocation_decisions":[
		{"node_name":"node-1","node_decision":"no","deciders":[
			{"decider":"same_shard","decision":"NO","explanation":"a copy of this shard is already allocated to this node [[so-case][0], node[abc], [P], s[STARTED]]"},
			{"decider":"disk_threshold","decision":"NO","explanation":"the node is above the low watermark cluster setting"}
		]},
		{"node_name":"node-2","node_decision":"no","deciders":[
			{"decider":"disk_threshold","decision":"NO","explanation":"the node is above the low watermark cluster setting"},
			{"decider":"throttling","decision":"YES","explanation":"below shard recovery limit"}
		]},
		{"node_name":"node-3","node_decision":"no","deciders":[
			{"decider":"disk_threshold","decision":"NO","explanation":"the node is above the flood stage watermark cluster setting"}
		]}
	]}`), nil)

	w := getEsHealth(h)

	assert.Equal(t, http.StatusOK, w.Code)

	var health EsHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	if assert.NotNil(t, health.UnassignedShards) {
		assert.Equal(t, 3, health.UnassignedShards.Total)
		assert.Equal(t, 2, health.UnassignedShards.Primaries)
		assert.Equal(t, 1, health.UnassignedShards.Replicas)
		if assert.Len(t, health.UnassignedShards.Groups, 2) {
			// Primaries sort ahead of replicas
			assert.Equal(t, "NODE_LEFT", health.UnassignedShards.Groups[0].Reason)
			assert.True(t, health.UnassignedShards.Groups[0].Primary)
			assert.Equal(t, 2, health.UnassignedShards.Groups[0].Count)
			assert.Equal(t, "NODE_LEFT", gjson.GetBytes(health.UnassignedShards.Groups[0].Explanation, "unassigned_info.reason").String())
			// Lost primary: allocation verdict digested, no deciders to report
			assert.Equal(t, "no_valid_shard_copy", health.UnassignedShards.Groups[0].CanAllocate)
			assert.Empty(t, health.UnassignedShards.Groups[0].Deciders)

			assert.Equal(t, "INDEX_CREATED", health.UnassignedShards.Groups[1].Reason)
			assert.False(t, health.UnassignedShards.Groups[1].Primary)
			assert.Equal(t, 1, health.UnassignedShards.Groups[1].Count)
			assert.Equal(t, "INDEX_CREATED", gjson.GetBytes(health.UnassignedShards.Groups[1].Explanation, "unassigned_info.reason").String())
			// Identical NO deciders dedupe across nodes; YES decisions are excluded;
			// node-specific explanations stay separate (node-3's flood stage)
			assert.Equal(t, "no", health.UnassignedShards.Groups[1].CanAllocate)
			if assert.Len(t, health.UnassignedShards.Groups[1].Deciders, 3) {
				assert.Equal(t, "same_shard", health.UnassignedShards.Groups[1].Deciders[0].Name)
				assert.Equal(t, "a copy of this shard is already allocated to this node [[so-case][0], node[abc], [P], s[STARTED]]", health.UnassignedShards.Groups[1].Deciders[0].Explanation)
				assert.Equal(t, []string{"node-1"}, health.UnassignedShards.Groups[1].Deciders[0].Nodes)
				assert.Equal(t, "disk_threshold", health.UnassignedShards.Groups[1].Deciders[1].Name)
				assert.Equal(t, "the node is above the low watermark cluster setting", health.UnassignedShards.Groups[1].Deciders[1].Explanation)
				assert.Equal(t, []string{"node-1", "node-2"}, health.UnassignedShards.Groups[1].Deciders[1].Nodes)
				assert.Equal(t, "disk_threshold", health.UnassignedShards.Groups[1].Deciders[2].Name)
				assert.Equal(t, "the node is above the flood stage watermark cluster setting", health.UnassignedShards.Groups[1].Deciders[2].Explanation)
				assert.Equal(t, []string{"node-3"}, health.UnassignedShards.Groups[1].Deciders[2].Nodes)
			}
		}
	}

	requests := transport.GetRequests()
	assert.Len(t, requests, 6)
	assert.Equal(t, "/_cat/shards", requests[3].URL.Path)
	assert.Equal(t, "/_cluster/allocation/explain", requests[4].URL.Path)
	assert.Equal(t, "/_cluster/allocation/explain", requests[5].URL.Path)

	// Each sampled explain targets the group's sample shard
	body, _ := io.ReadAll(requests[4].Body)
	assert.Equal(t, `{"index":"so-logs","shard":0,"primary":true}`, string(body))
	body, _ = io.ReadAll(requests[5].Body)
	assert.Equal(t, `{"index":"so-case","shard":0,"primary":false}`, string(body))
}

func TestGetEsHealthExplainCapAndPartialFailure(t *testing.T) {
	// 6 unassigned shard groups: only MAX_ALLOCATION_EXPLAINS are explained, and
	// one failing explain doesn't abort the remaining groups.
	h, transport := newEsHealthHandler(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(200, `{"status":"red","indicators":{"shards_availability":{"status":"red"}}}`), nil)
	transport.AddResponse(esResponse(200, `{"persistent":{},"transient":{}}`), nil)
	transport.AddResponse(esResponse(200, `[{"name":"node-1"}]`), nil)
	transport.AddResponse(esResponse(200, `[
		{"index":"idx-p-nl","shard":"0","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"idx-p-cr","shard":"0","prirep":"p","state":"UNASSIGNED","unassigned.reason":"CLUSTER_RECOVERED"},
		{"index":"idx-p-ic","shard":"0","prirep":"p","state":"UNASSIGNED","unassigned.reason":"INDEX_CREATED"},
		{"index":"idx-r-nl","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"idx-r-cr","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"CLUSTER_RECOVERED"},
		{"index":"idx-r-ic","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"INDEX_CREATED"},
		{"index":"idx-p-nl","shard":"1","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"idx-p-nl","shard":"2","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"idx-p-cr","shard":"1","prirep":"p","state":"UNASSIGNED","unassigned.reason":"CLUSTER_RECOVERED"},
		{"index":"idx-r-nl","shard":"1","prirep":"r","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"idx-r-nl","shard":"2","prirep":"r","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"idx-r-cr","shard":"1","prirep":"r","state":"UNASSIGNED","unassigned.reason":"CLUSTER_RECOVERED"}
	]`), nil)
	transport.AddResponse(esResponse(200, `{"index":"idx-p-nl","shard":0,"primary":true}`), nil)
	transport.AddResponse(esResponse(500, `{"error":{"type":"exception","reason":"explain failed"}}`), nil)
	transport.AddResponse(esResponse(200, `{"index":"idx-p-ic","shard":0,"primary":true}`), nil)
	transport.AddResponse(esResponse(200, `{"index":"idx-r-nl","shard":0,"primary":false}`), nil)
	transport.AddResponse(esResponse(200, `{"index":"idx-r-cr","shard":0,"primary":false}`), nil)

	w := getEsHealth(h)

	assert.Equal(t, http.StatusOK, w.Code)

	var health EsHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	if assert.NotNil(t, health.UnassignedShards) {
		assert.Equal(t, 12, health.UnassignedShards.Total)
		assert.Equal(t, 6, health.UnassignedShards.Primaries)
		assert.Equal(t, 6, health.UnassignedShards.Replicas)
		if assert.Len(t, health.UnassignedShards.Groups, 6) {
			// Primaries before replicas, largest groups first
			groups := []string{}
			for _, group := range health.UnassignedShards.Groups {
				groups = append(groups, fmt.Sprintf("%t/%s/%d", group.Primary, group.Reason, group.Count))
			}
			assert.Equal(t, []string{
				"true/NODE_LEFT/3", "true/CLUSTER_RECOVERED/2", "true/INDEX_CREATED/1",
				"false/NODE_LEFT/3", "false/CLUSTER_RECOVERED/2", "false/INDEX_CREATED/1",
			}, groups)
			assert.NotNil(t, health.UnassignedShards.Groups[0].Explanation)
			// Second explain failed; the remaining groups are still explained
			assert.Nil(t, health.UnassignedShards.Groups[1].Explanation)
			assert.NotNil(t, health.UnassignedShards.Groups[2].Explanation)
			assert.NotNil(t, health.UnassignedShards.Groups[3].Explanation)
			assert.NotNil(t, health.UnassignedShards.Groups[4].Explanation)
			// Sixth group exceeds MAX_ALLOCATION_EXPLAINS
			assert.Nil(t, health.UnassignedShards.Groups[5].Explanation)
		}
	}

	assert.Len(t, transport.GetRequests(), 4+MAX_ALLOCATION_EXPLAINS)
}

func TestGetEsHealthCatShardsFailureTolerated(t *testing.T) {
	h, transport := newEsHealthHandler(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(200, `{"status":"red","indicators":{"shards_availability":{"status":"red"}}}`), nil)
	transport.AddResponse(esResponse(200, `{"persistent":{},"transient":{}}`), nil)
	transport.AddResponse(esResponse(200, `[{"name":"node-1"}]`), nil)
	transport.AddResponse(esResponse(403, `{"error":{"type":"security_exception","reason":"denied"}}`), nil)

	w := getEsHealth(h)

	assert.Equal(t, http.StatusOK, w.Code)

	var health EsHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	assert.Nil(t, health.UnassignedShards)

	requests := transport.GetRequests()
	assert.Len(t, requests, 4)
	assert.Equal(t, "/_cat/shards", requests[3].URL.Path)
}

func TestGetEsHealthSupplementalFailuresTolerated(t *testing.T) {
	h, transport := newEsHealthHandler(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(200, `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`), nil)
	transport.AddResponse(esResponse(403, `{"error":{"type":"security_exception","reason":"denied"}}`), nil)
	transport.AddResponse(esResponse(403, `{"error":{"type":"security_exception","reason":"denied"}}`), nil)
	transport.AddResponse(esResponse(403, `{"error":{"type":"security_exception","reason":"denied"}}`), nil)

	w := getEsHealth(h)

	assert.Equal(t, http.StatusOK, w.Code)

	var health EsHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	assert.Equal(t, "yellow", gjson.GetBytes(health.HealthReport, "status").String())
	assert.Nil(t, health.ClusterSettings)
	assert.Nil(t, health.CatNodes)
	assert.Nil(t, health.UnassignedShards)
}

func TestGetEsHealthUnknownShardStatusSkipsInventory(t *testing.T) {
	// "unknown" means no stable master; the shard listing would block on master
	// discovery, so the inventory is skipped entirely.
	h, transport := newEsHealthHandler(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(200, `{"status":"red","indicators":{"shards_availability":{"status":"unknown"}}}`), nil)
	transport.AddResponse(esResponse(200, `{"persistent":{},"transient":{}}`), nil)
	transport.AddResponse(esResponse(200, `[{"name":"node-1"}]`), nil)

	w := getEsHealth(h)

	assert.Equal(t, http.StatusOK, w.Code)

	var health EsHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	assert.Nil(t, health.UnassignedShards)
	assert.Len(t, transport.GetRequests(), 3)
}

func TestGetEsHealthNoUnassignedShardsFound(t *testing.T) {
	// Shards recovered between the report and the listing; the inventory is omitted.
	h, transport := newEsHealthHandler(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(200, `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`), nil)
	transport.AddResponse(esResponse(200, `{"persistent":{},"transient":{}}`), nil)
	transport.AddResponse(esResponse(200, `[{"name":"node-1"}]`), nil)
	transport.AddResponse(esResponse(200, `[{"index":"so-logs","shard":"0","prirep":"p","state":"STARTED","unassigned.reason":""}]`), nil)

	w := getEsHealth(h)

	assert.Equal(t, http.StatusOK, w.Code)

	var health EsHealth
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &health))
	assert.Nil(t, health.UnassignedShards)

	requests := transport.GetRequests()
	assert.Len(t, requests, 4)
}

func TestGetEsHealthReportError(t *testing.T) {
	h, transport := newEsHealthHandler(t, server.NewFakeAuthorizedServer(nil))
	transport.AddResponse(esResponse(500, `{"error":{"type":"master_not_discovered_exception","reason":"no master"}}`), nil)

	w := getEsHealth(h)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
