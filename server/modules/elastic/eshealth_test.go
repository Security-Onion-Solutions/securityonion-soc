// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
)

func TestGetEventsHealthGreen(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"green","indicators":{"shards_availability":{"status":"green","symptom":"This cluster has all shards available."}}}`
	store.ClusterSettingsJson = `{"persistent":{"cluster.routing.allocation.enable":"all"},"transient":{}}`
	store.NodesJson = `[{"name":"node-1","ip":"10.0.0.5","node.role":"dhimrt","master":"*","version":"8.14.3",
		"heap.percent":"42","ram.percent":"88","cpu":"12","load_1m":"1.42",
		"disk.total":"1.5tb","disk.used_percent":"80.6","uptime":"42d"}]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Equal(t, "green", health.Status)
	if assert.Len(t, health.Indicators, 1) {
		assert.Equal(t, "shards_availability", health.Indicators[0].Id)
		assert.Equal(t, "green", health.Indicators[0].Status)
		assert.Equal(t, "This cluster has all shards available.", health.Indicators[0].Symptom)
		assert.Empty(t, health.Indicators[0].Causes)
	}
	if assert.Len(t, health.Nodes, 1) {
		assert.Equal(t, model.EventsHealthNode{
			Name: "node-1", Ip: "10.0.0.5", Roles: "dhimrt", Master: "*", Version: "8.14.3",
			HeapPercent: "42", RamPercent: "88", Cpu: "12", Load1m: "1.42",
			DiskTotal: "1.5tb", DiskUsedPercent: "80.6", Uptime: "42d",
		}, health.Nodes[0])
	}
	if assert.NotNil(t, health.Settings) {
		assert.Equal(t, map[string]interface{}{"cluster.routing.allocation.enable": "all"}, health.Settings.Persistent)
		assert.Empty(t, health.Settings.Transient)
	}
	assert.Nil(t, health.UnassignedShards)
	assert.Nil(t, health.Errors)

	// report + settings + nodes; no shard listing on green
	assert.Len(t, store.InputContexts, 3)
}

func TestGetEventsHealthIndicatorCauses(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"red","indicators":{
		"shards_availability":{"status":"green"},
		"disk":{"status":"red","symptom":"1 node is out of disk space.",
			"details":{"indices_with_readonly_block":3},
			"diagnosis":[
				{"cause":"Disk usage exceeds the flood-stage watermark.",
					"affected_resources":{"nodes":[{"id":"abc","name":"node-1"}],"indices":["so-logs"]}},
				{"cause":"No affected resources reported."},
				{"action":"no cause on this entry"}
			]}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Equal(t, "red", health.Status)
	if assert.Len(t, health.Indicators, 2) {
		// Red sorts ahead of green regardless of the order the datastore reported
		disk := health.Indicators[0]
		assert.Equal(t, "disk", disk.Id)
		if assert.Len(t, disk.Findings, 1) {
			assert.Equal(t, FINDING_INDICES_READONLY, disk.Findings[0].Condition)
			assert.Equal(t, model.FINDING_SEVERITY_CRITICAL, disk.Findings[0].Severity)
			assert.Equal(t, 3, disk.Findings[0].Count)
		}
		// Diagnosis entries without a cause are skipped
		if assert.Len(t, disk.Causes, 2) {
			assert.Equal(t, "Disk usage exceeds the flood-stage watermark.", disk.Causes[0].Cause)
			assert.Equal(t, []string{"node-1"}, disk.Causes[0].Nodes)
			assert.Equal(t, []string{"so-logs"}, disk.Causes[0].Indices)
			// Missing affected resources marshal as empty arrays, not null
			assert.Equal(t, []string{}, disk.Causes[1].Nodes)
			assert.Equal(t, []string{}, disk.Causes[1].Indices)
		}
	}
}

func TestGetEventsHealthMissingStatusIsUnknown(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"indicators":{}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Equal(t, "unknown", health.Status)
	assert.Empty(t, health.Indicators)
}

func TestGetEventsHealthUnassignedShards(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"red","indicators":{"shards_availability":{"status":"red","symptom":"This cluster has 2 unavailable primary shards."}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[
		{"index":"so-logs","shard":"0","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"so-logs","shard":"1","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"so-case","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"INDEX_CREATED"},
		{"index":"so-detection","shard":"0","prirep":"p","state":"STARTED","unassigned.reason":""}
	]`
	store.ExplainResults = []fakeExplainResult{
		{Json: `{"index":"so-logs","shard":0,"primary":true,
			"unassigned_info":{"reason":"NODE_LEFT","at":"2026-07-21T20:48:02.943Z","details":"node_left [abc]"},
			"can_allocate":"no_valid_shard_copy"}`},
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

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.Errors)
	if assert.NotNil(t, health.UnassignedShards) {
		assert.Equal(t, 3, health.UnassignedShards.Total)
		assert.Equal(t, 2, health.UnassignedShards.Primaries)
		assert.Equal(t, 1, health.UnassignedShards.Replicas)
		if assert.Len(t, health.UnassignedShards.Groups, 2) {
			group := health.UnassignedShards.Groups[0]
			assert.Equal(t, "NODE_LEFT", group.Reason)
			assert.True(t, group.Primary)
			assert.Equal(t, 2, group.Count)
			assert.Equal(t, model.SAMPLE_STATUS_EXPLAINED, group.SampleStatus)
			assert.Equal(t, "so-logs", group.SampleIndex)
			assert.Equal(t, int64(0), group.SampleShard)
			assert.Equal(t, "2026-07-21T20:48:02.943Z", group.Since)
			assert.Equal(t, "node_left [abc]", group.FailureDetails)
			// Lost primary: allocation verdict digested, no deciders to report
			assert.Equal(t, "no_valid_shard_copy", group.CanAllocate)
			assert.Empty(t, group.Deciders)

			group = health.UnassignedShards.Groups[1]
			assert.Equal(t, "INDEX_CREATED", group.Reason)
			assert.False(t, group.Primary)
			assert.Equal(t, 1, group.Count)
			assert.Equal(t, "so-case", group.SampleIndex)
			// Identical NO deciders dedupe across nodes; YES decisions are excluded;
			// node-specific explanations stay separate (node-3's flood stage)
			assert.Equal(t, "no", group.CanAllocate)
			if assert.Len(t, group.Deciders, 3) {
				assert.Equal(t, "same_shard", group.Deciders[0].Name)
				assert.Equal(t, "a copy of this shard is already allocated to this node [[so-case][0], node[abc], [P], s[STARTED]]", group.Deciders[0].Explanation)
				assert.Equal(t, []string{"node-1"}, group.Deciders[0].Nodes)
				assert.Equal(t, "disk_threshold", group.Deciders[1].Name)
				assert.Equal(t, "the node is above the low watermark cluster setting", group.Deciders[1].Explanation)
				assert.Equal(t, []string{"node-1", "node-2"}, group.Deciders[1].Nodes)
				assert.Equal(t, "disk_threshold", group.Deciders[2].Name)
				assert.Equal(t, "the node is above the flood stage watermark cluster setting", group.Deciders[2].Explanation)
				assert.Equal(t, []string{"node-3"}, group.Deciders[2].Nodes)
			}
		}
	}

	// Each sampled explain targets the group's sample shard
	assert.Equal(t, []string{"so-logs", "so-case"}, store.InputExplainIndexes)
	assert.Equal(t, []int64{0, 0}, store.InputExplainShards)
	assert.Equal(t, []bool{true, false}, store.InputExplainPrimaries)
}

func TestGetEventsHealthShardFindingsRanked(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"red","indicators":{
		"shards_availability":{"status":"red"},
		"disk":{"status":"green"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[
		{"index":"so-logs","shard":"0","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"so-logs","shard":"1","prirep":"p","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"},
		{"index":"so-case","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"INDEX_CREATED"}
	]`
	store.ExplainResults = []fakeExplainResult{
		{Json: `{"can_allocate":"no_valid_shard_copy"}`},
		{Json: `{"can_allocate":"no","node_allocation_decisions":[
			{"node_name":"node-1","deciders":[
				{"decider":"same_shard","decision":"NO","explanation":"a copy is already allocated to this node"},
				{"decider":"disk_threshold","decision":"NO","explanation":"the node is above the low watermark cluster setting"},
				{"decider":"awaiting_info","decision":"NO","explanation":"an unrecognized decider"}
			]}
		]}`},
	}

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)

	// Findings hang off the indicator whose symptom they explain
	shards := health.Indicators[0]
	assert.Equal(t, HEALTH_INDICATOR_SHARDS, shards.Id)
	assert.Empty(t, health.Indicators[1].Findings)

	if assert.Len(t, shards.Findings, 4) {
		// Ranked most severe first: lost primary, then blocking deciders,
		// then the expected single-node replica placement
		assert.Equal(t, FINDING_NO_VALID_SHARD_COPY, shards.Findings[0].Condition)
		assert.Equal(t, model.FINDING_SEVERITY_CRITICAL, shards.Findings[0].Severity)
		assert.Equal(t, &model.FindingScope{Reason: "NODE_LEFT", Count: 2, Primary: true}, shards.Findings[0].Scope)

		assert.Equal(t, FINDING_DISK_THRESHOLD, shards.Findings[1].Condition)
		assert.Equal(t, model.FINDING_SEVERITY_WARNING, shards.Findings[1].Severity)
		assert.Equal(t, "the node is above the low watermark cluster setting", shards.Findings[1].Detail)
		assert.Equal(t, []string{"node-1"}, shards.Findings[1].Nodes)

		// Unrecognized deciders are warnings and carry the datastore's own prose
		assert.Equal(t, "awaiting_info", shards.Findings[2].Condition)
		assert.Equal(t, model.FINDING_SEVERITY_WARNING, shards.Findings[2].Severity)
		assert.Equal(t, "an unrecognized decider", shards.Findings[2].Detail)

		assert.Equal(t, FINDING_SAME_SHARD, shards.Findings[3].Condition)
		assert.Equal(t, model.FINDING_SEVERITY_INFO, shards.Findings[3].Severity)
	}
}

func TestGetEventsHealthUnexplainedGroupStillReported(t *testing.T) {
	// A group whose explanation has no NO/THROTTLE deciders must still surface
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[{"index":"so-logs","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"}]`
	store.ExplainResults = []fakeExplainResult{
		{Json: `{"can_allocate":"throttled","node_allocation_decisions":[
			{"node_name":"node-1","deciders":[{"decider":"throttling","decision":"YES","explanation":"below limit"}]}
		]}`},
	}

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	if assert.Len(t, health.Indicators[0].Findings, 1) {
		finding := health.Indicators[0].Findings[0]
		assert.Equal(t, model.FINDING_UNEXPLAINED, finding.Condition)
		assert.Equal(t, model.FINDING_SEVERITY_INFO, finding.Severity)
		assert.Equal(t, "throttled", finding.Detail)
		assert.Equal(t, &model.FindingScope{Reason: "NODE_LEFT", Count: 1, Primary: false}, finding.Scope)
	}
}

func TestGetEventsHealthThrottledGroupAttributed(t *testing.T) {
	// Throttled recoveries return THROTTLE decisions, never NO; they must keep
	// their per-node attribution instead of falling back to unexplained.
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[{"index":"so-logs","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"}]`
	store.ExplainResults = []fakeExplainResult{
		{Json: `{"can_allocate":"throttled","node_allocation_decisions":[
			{"node_name":"node-1","deciders":[{"decider":"throttling","decision":"THROTTLE","explanation":"reached the limit of concurrent incoming shard recoveries"}]}
		]}`},
	}

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	if assert.Len(t, health.Indicators[0].Findings, 1) {
		finding := health.Indicators[0].Findings[0]
		assert.Equal(t, FINDING_THROTTLING, finding.Condition)
		assert.Equal(t, model.FINDING_SEVERITY_INFO, finding.Severity)
		assert.Equal(t, "reached the limit of concurrent incoming shard recoveries", finding.Detail)
		assert.Equal(t, []string{"node-1"}, finding.Nodes)
	}
}

func TestGetEventsHealthUnknownDeciderDetailFallback(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[{"index":"so-logs","shard":"0","prirep":"r","state":"UNASSIGNED","unassigned.reason":"NODE_LEFT"}]`
	store.ExplainResults = []fakeExplainResult{
		{Json: `{"can_allocate":"no","node_allocation_decisions":[
			{"node_name":"node-1","deciders":[{"decider":"awareness","decision":"NO"}]}
		]}`},
	}

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	if assert.Len(t, health.Indicators[0].Findings, 1) {
		finding := health.Indicators[0].Findings[0]
		assert.Equal(t, "awareness", finding.Condition)
		assert.Equal(t, model.FINDING_SEVERITY_WARNING, finding.Severity)
		assert.Equal(t, "no explanation provided by the datastore", finding.Detail)
	}
}

func TestGetEventsHealthDiskFindingOnlyWhenDegraded(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"green","indicators":{"disk":{"status":"green","details":{"indices_with_readonly_block":3}}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Empty(t, health.Indicators[0].Findings)
}

func TestGetEventsHealthIndicatorsSortedBySeverity(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"red","indicators":{
		"master_is_stable":{"status":"green"},
		"repository_integrity":{"status":"unknown"},
		"disk":{"status":"red"},
		"ilm":{"status":"yellow"},
		"slm":{"status":"bogus"},
		"data_stream_lifecycle":{"status":"green"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	ids := []string{}
	for _, indicator := range health.Indicators {
		ids = append(ids, indicator.Id)
	}
	// Red, yellow, then unknown (an unrecognized status ranks as unknown, and
	// ties break on id), then green
	assert.Equal(t, []string{
		"disk", "ilm", "repository_integrity", "slm", "data_stream_lifecycle", "master_is_stable",
	}, ids)
}

func TestGetEventsHealthExplainCapAndPartialFailure(t *testing.T) {
	// Only MAX_ALLOCATION_EXPLAINS groups are explained; one failing explain
	// doesn't abort the rest.
	store := newFakeHealthFetcher()
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
	store.ExplainResults = []fakeExplainResult{
		{Json: `{"index":"idx-p-nl","shard":0,"primary":true,"can_allocate":"no"}`},
		{Err: errors.New("explain failed")},
		{Json: `{"index":"idx-p-ic","shard":0,"primary":true,"can_allocate":"no"}`},
		{Json: `{"index":"idx-r-nl","shard":0,"primary":false,"can_allocate":"no"}`},
		{Json: `{"index":"idx-r-cr","shard":0,"primary":false,"can_allocate":"no"}`},
	}

	health, err := getEventsHealth(context.Background(), store)

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
			assert.Equal(t, "idx-p-nl", health.UnassignedShards.Groups[0].SampleIndex)
			// Second explain failed; the remaining groups are still explained
			assert.Empty(t, health.UnassignedShards.Groups[1].SampleIndex)
			assert.Equal(t, "idx-p-ic", health.UnassignedShards.Groups[2].SampleIndex)
			assert.Equal(t, "idx-r-nl", health.UnassignedShards.Groups[3].SampleIndex)
			assert.Equal(t, "idx-r-cr", health.UnassignedShards.Groups[4].SampleIndex)
			// Sixth group exceeds MAX_ALLOCATION_EXPLAINS
			assert.Empty(t, health.UnassignedShards.Groups[5].SampleIndex)

			// An unsampled group distinguishes a failed explain from the cap
			statuses := []string{}
			for _, group := range health.UnassignedShards.Groups {
				statuses = append(statuses, group.SampleStatus)
			}
			assert.Equal(t, []string{
				model.SAMPLE_STATUS_EXPLAINED, model.SAMPLE_STATUS_FAILED, model.SAMPLE_STATUS_EXPLAINED,
				model.SAMPLE_STATUS_EXPLAINED, model.SAMPLE_STATUS_EXPLAINED, model.SAMPLE_STATUS_CAPPED,
			}, statuses)
		}
	}

	assert.Len(t, store.InputExplainIndexes, MAX_ALLOCATION_EXPLAINS)
}

func TestGetEventsHealthShardListingFailureReported(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"red","indicators":{"shards_availability":{"status":"red"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsErr = errors.New("denied")

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.UnassignedShards)
	// The failure reason is reported, not merely that the section is missing
	assert.Equal(t, map[string]string{"unassignedShards": "denied"}, health.Errors)

	// report + settings + nodes + shard listing
	assert.Len(t, store.InputContexts, 4)
	assert.Empty(t, store.InputExplainIndexes)
}

func TestGetEventsHealthSupplementalFailuresReported(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`
	store.ClusterSettingsErr = errors.New("denied")
	store.NodesErr = errors.New("denied")
	store.ShardsErr = errors.New("denied")

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Equal(t, "yellow", health.Status)
	assert.Nil(t, health.Settings)
	assert.Nil(t, health.Nodes)
	assert.Nil(t, health.UnassignedShards)
	assert.Equal(t, map[string]string{
		"settings":         "denied",
		"nodes":            "denied",
		"unassignedShards": "denied",
	}, health.Errors)
}

func TestGetEventsHealthUnknownShardStatusSkipsInventory(t *testing.T) {
	// "unknown" means no stable master; the shard inventory is skipped.
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"red","indicators":{"shards_availability":{"status":"unknown"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.UnassignedShards)
	assert.Nil(t, health.Errors)

	// report + settings + nodes only; no shard listing
	assert.Len(t, store.InputContexts, 3)
}

func TestGetEventsHealthMissingShardIndicatorReported(t *testing.T) {
	// An omitted indicator must not read as "no unassigned shards"
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"red","indicators":{"disk":{"status":"red"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.UnassignedShards)
	if assert.Contains(t, health.Errors, model.HEALTH_SECTION_UNASSIGNED_SHARDS) {
		assert.Contains(t, health.Errors[model.HEALTH_SECTION_UNASSIGNED_SHARDS], HEALTH_INDICATOR_SHARDS)
	}

	// report + settings + nodes only; the shard listing is not attempted
	assert.Len(t, store.InputContexts, 3)
}

func TestGetEventsHealthGreenShardIndicatorIsNotAnError(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"green","indicators":{"shards_availability":{"status":"green"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.UnassignedShards)
	assert.Nil(t, health.Errors)
}

func TestGetEventsHealthNoIndicatorsStillSucceeds(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"yellow","indicators":{}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Equal(t, "yellow", health.Status)
	assert.Empty(t, health.Indicators)
	if assert.Contains(t, health.Errors, model.HEALTH_SECTION_UNASSIGNED_SHARDS) {
		assert.Contains(t, health.Errors[model.HEALTH_SECTION_UNASSIGNED_SHARDS], HEALTH_INDICATOR_SHARDS)
	}
}

func TestGetEventsHealthNoUnassignedShardsFound(t *testing.T) {
	// Shards recovered between report and listing; omitted, not a failure.
	store := newFakeHealthFetcher()
	store.HealthReportJson = `{"status":"yellow","indicators":{"shards_availability":{"status":"yellow"}}}`
	store.ClusterSettingsJson = `{"persistent":{},"transient":{}}`
	store.NodesJson = `[{"name":"node-1"}]`
	store.ShardsJson = `[{"index":"so-logs","shard":"0","prirep":"p","state":"STARTED","unassigned.reason":""}]`

	health, err := getEventsHealth(context.Background(), store)

	assert.NoError(t, err)
	assert.Nil(t, health.UnassignedShards)
	assert.Nil(t, health.Errors)

	// report + settings + nodes + shard listing
	assert.Len(t, store.InputContexts, 4)
}

func TestGetEventsHealthEmptyReport(t *testing.T) {
	store := newFakeHealthFetcher()

	health, err := getEventsHealth(context.Background(), store)

	assert.Error(t, err)
	assert.Nil(t, health)
}

func TestGetEventsHealthReportError(t *testing.T) {
	store := newFakeHealthFetcher()
	store.HealthReportErr = errors.New("no master")

	health, err := getEventsHealth(context.Background(), store)

	assert.Error(t, err)
	assert.Nil(t, health)
}

func TestGetEventsHealthEndToEnd(t *testing.T) {
	store, transport := newHealthTestStore(t)
	transport.AddResponse(healthResponse(200, `{"status":"green","indicators":{"shards_availability":{"status":"green"}}}`), nil)
	transport.AddResponse(healthResponse(200, `{"persistent":{},"transient":{}}`), nil)
	transport.AddResponse(healthResponse(200, `[{"name":"node-1"}]`), nil)

	health, err := store.GetEventsHealth(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, "green", health.Status)
	if assert.Len(t, health.Indicators, 1) {
		assert.Equal(t, "shards_availability", health.Indicators[0].Id)
	}
	if assert.Len(t, health.Nodes, 1) {
		assert.Equal(t, "node-1", health.Nodes[0].Name)
	}
}

// fakeHealthFetcher feeds canned diagnostic JSON to the digestion logic.
type fakeHealthFetcher struct {
	InputContexts         []context.Context
	InputExplainIndexes   []string
	InputExplainShards    []int64
	InputExplainPrimaries []bool
	HealthReportJson      string
	HealthReportErr       error
	ClusterSettingsJson   string
	ClusterSettingsErr    error
	NodesJson             string
	NodesErr              error
	ShardsJson            string
	ShardsErr             error
	ExplainResults        []fakeExplainResult
	explainCount          int
}

// One explainAllocation outcome; calls beyond the configured results return
// the zero value.
type fakeExplainResult struct {
	Json string
	Err  error
}

func newFakeHealthFetcher() *fakeHealthFetcher {
	return &fakeHealthFetcher{}
}

func (store *fakeHealthFetcher) clusterHealthReport(ctx context.Context) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	return store.HealthReportJson, store.HealthReportErr
}

func (store *fakeHealthFetcher) clusterSettings(ctx context.Context) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	return store.ClusterSettingsJson, store.ClusterSettingsErr
}

func (store *fakeHealthFetcher) listNodes(ctx context.Context) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	return store.NodesJson, store.NodesErr
}

func (store *fakeHealthFetcher) listShards(ctx context.Context) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	return store.ShardsJson, store.ShardsErr
}

func (store *fakeHealthFetcher) explainAllocation(ctx context.Context, index string, shard int64, primary bool) (string, error) {
	store.InputContexts = append(store.InputContexts, ctx)
	store.InputExplainIndexes = append(store.InputExplainIndexes, index)
	store.InputExplainShards = append(store.InputExplainShards, shard)
	store.InputExplainPrimaries = append(store.InputExplainPrimaries, primary)
	var result fakeExplainResult
	if store.explainCount < len(store.ExplainResults) {
		result = store.ExplainResults[store.explainCount]
	}
	store.explainCount += 1
	return result.Json, result.Err
}
