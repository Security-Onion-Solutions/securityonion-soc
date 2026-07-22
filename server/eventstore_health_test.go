// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func TestGetEventstoreHealthGreen(t *testing.T) {
	store := NewFakeEventstore()
	store.HealthReportJson = `{"status":"green","indicators":{"shards_availability":{"status":"green"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1","heap.percent":"42"}]`

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Equal(t, "green", gjson.GetBytes(health.HealthReport, "status").String())
	assert.Equal(t, `{"persistent":{},"transient":{}}`, string(health.ClusterSettings))
	assert.Equal(t, "node-1", gjson.GetBytes(health.CatNodes, "0.name").String())
	assert.Nil(t, health.UnassignedShards)

	// report + settings + nodes; no shard listing on green
	assert.Len(t, store.InputContexts, 3)
}

func TestGetEventstoreHealthUnassignedShards(t *testing.T) {
	store := NewFakeEventstore()
	store.HealthReportJson = `{"status":"red","indicators":{"shards_availability":{"status":"red","symptom":"This cluster has 2 unavailable primary shards."}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[
		{"index":"so-logs","shard":"0","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"so-logs","shard":"1","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"so-case","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"INDEX_CREATED"},
		{"index":"so-detection","shard":"0","prirep":"p","state":"STARTED","unassigned.reason":""}
	]`
	store.ExplainResults = []FakeExplainResult{
		{Json: `{"index":"so-logs","shard":0,"primary":true,"unassigned_info":{"reason":"NODE_LEFT"},"can_allocate":"no_valid_shard_copy"}`},
		{Json: `{"index":"so-case","shard":0,"primary":false,"unassigned_info":{"reason":"INDEX_CREATED"},"can_allocate":"no","node_allocation_decisions":[
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
		]}`},
	}

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.NoError(t, err)
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

	// Each sampled explain targets the group's sample shard
	assert.Equal(t, []string{"so-logs", "so-case"}, store.InputExplainIndexes)
	assert.Equal(t, []int64{0, 0}, store.InputExplainShards)
	assert.Equal(t, []bool{true, false}, store.InputExplainPrimaries)
}

func TestGetEventstoreHealthExplainCapAndPartialFailure(t *testing.T) {
	// 6 unassigned shard groups: only MAX_ALLOCATION_EXPLAINS are explained, and
	// one failing explain doesn't abort the remaining groups.
	store := NewFakeEventstore()
	store.HealthReportJson = `{"status":"red","indicators":{"shards_availability":{"status":"red"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[
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
	]`
	store.ExplainResults = []FakeExplainResult{
		{Json: `{"index":"idx-p-nl","shard":0,"primary":true}`},
		{Err: errors.New("explain failed")},
		{Json: `{"index":"idx-p-ic","shard":0,"primary":true}`},
		{Json: `{"index":"idx-r-nl","shard":0,"primary":false}`},
		{Json: `{"index":"idx-r-cr","shard":0,"primary":false}`},
	}

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.NoError(t, err)
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

	assert.Len(t, store.InputExplainIndexes, MAX_ALLOCATION_EXPLAINS)
}

func TestGetEventstoreHealthShardListingFailureTolerated(t *testing.T) {
	store := NewFakeEventstore()
	store.HealthReportJson = `{"status":"red","indicators":{"shards_availability":{"status":"red"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsErr = errors.New("denied")

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.UnassignedShards)

	// report + settings + nodes + shard listing
	assert.Len(t, store.InputContexts, 4)
	assert.Empty(t, store.InputExplainIndexes)
}

func TestGetEventstoreHealthSupplementalFailuresTolerated(t *testing.T) {
	store := NewFakeEventstore()
	store.HealthReportJson = `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`
	store.ClusterSettingsErr = errors.New("denied")
	store.NodesErr = errors.New("denied")
	store.ShardsErr = errors.New("denied")

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Equal(t, "yellow", gjson.GetBytes(health.HealthReport, "status").String())
	assert.Nil(t, health.ClusterSettings)
	assert.Nil(t, health.CatNodes)
	assert.Nil(t, health.UnassignedShards)
}

func TestGetEventstoreHealthUnknownShardStatusSkipsInventory(t *testing.T) {
	// "unknown" means no stable master; the shard listing would block on master
	// discovery, so the inventory is skipped entirely.
	store := NewFakeEventstore()
	store.HealthReportJson = `{"status":"red","indicators":{"shards_availability":{"status":"unknown"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.UnassignedShards)

	// report + settings + nodes only; no shard listing
	assert.Len(t, store.InputContexts, 3)
}

func TestGetEventstoreHealthNoUnassignedShardsFound(t *testing.T) {
	// Shards recovered between the report and the listing; the inventory is omitted.
	store := NewFakeEventstore()
	store.HealthReportJson = `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[{"index":"so-logs","shard":"0","prirep":"p","state":"STARTED","unassigned.reason":""}]`

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.UnassignedShards)

	// report + settings + nodes + shard listing
	assert.Len(t, store.InputContexts, 4)
}

func TestGetEventstoreHealthEmptyReport(t *testing.T) {
	store := NewFakeEventstore()

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.Error(t, err)
	assert.Nil(t, health)
}

func TestGetEventstoreHealthReportError(t *testing.T) {
	store := NewFakeEventstore()
	store.HealthReportErr = errors.New("no master")

	health, err := GetEventstoreHealth(context.Background(), store)

	assert.Error(t, err)
	assert.Nil(t, health)
}
