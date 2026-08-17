// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/tidwall/gjson"
)

// Seam letting digestion tests run on canned JSON
type esHealthFetcher interface {
	clusterHealthReport(ctx context.Context) (string, error)
	clusterSettings(ctx context.Context) (string, error)
	listNodes(ctx context.Context) (string, error)
	listShards(ctx context.Context) (string, error)
	explainAllocation(ctx context.Context, index string, shard int64, primary bool) (string, error)
}

func (store *ElasticEventstore) GetEventsHealth(ctx context.Context) (*model.EventsHealth, error) {
	return getEventsHealth(ctx, store)
}

// Wraps an esapi call, draining the response into its JSON body
func readJsonFromCall(res *esapi.Response, err error) (string, error) {
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	return readJsonFromResponse(res)
}

func (store *ElasticEventstore) clusterHealthReport(ctx context.Context) (string, error) {
	return readJsonFromCall(store.esClient.HealthReport(
		store.esClient.HealthReport.WithContext(ctx),
		store.esClient.HealthReport.WithVerbose(true),
	))
}

func (store *ElasticEventstore) clusterSettings(ctx context.Context) (string, error) {
	return readJsonFromCall(store.esClient.Cluster.GetSettings(
		store.esClient.Cluster.GetSettings.WithContext(ctx),
		store.esClient.Cluster.GetSettings.WithFlatSettings(true),
	))
}

func (store *ElasticEventstore) listNodes(ctx context.Context) (string, error) {
	return readJsonFromCall(store.esClient.Cat.Nodes(
		store.esClient.Cat.Nodes.WithContext(ctx),
		store.esClient.Cat.Nodes.WithFormat("json"),
		store.esClient.Cat.Nodes.WithH("name", "ip", "node.role", "master", "version",
			"heap.percent", "ram.percent", "cpu", "load_1m", "disk.total", "disk.used_percent", "uptime"),
	))
}

func (store *ElasticEventstore) listShards(ctx context.Context) (string, error) {
	return readJsonFromCall(store.esClient.Cat.Shards(
		store.esClient.Cat.Shards.WithContext(ctx),
		store.esClient.Cat.Shards.WithFormat("json"),
		store.esClient.Cat.Shards.WithH("index", "shard", "prirep", "state", "unassigned.reason"),
	))
}

func (store *ElasticEventstore) explainAllocation(ctx context.Context, index string, shard int64, primary bool) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"index":   index,
		"shard":   shard,
		"primary": primary,
	})
	return readJsonFromCall(store.esClient.Cluster.AllocationExplain(
		store.esClient.Cluster.AllocationExplain.WithContext(ctx),
		store.esClient.Cluster.AllocationExplain.WithBody(bytes.NewReader(body)),
	))
}

// Shards typically fail in groups for the same reason, so only one shard is
// explained per group, capped at this many backend calls.
const MAX_ALLOCATION_EXPLAINS = 5

// Health report indicators SOC diagnoses beyond reporting their status.
const (
	HEALTH_INDICATOR_DISK   = "disk"
	HEALTH_INDICATOR_SHARDS = "shards_availability"
)

var healthStatusRank = map[string]int{"red": 0, "yellow": 1, "unknown": 2, "green": 3}

// Orders findings most severe first.
var findingSeverityRank = map[string]int{
	model.FINDING_SEVERITY_CRITICAL: 0,
	model.FINDING_SEVERITY_WARNING:  1,
	model.FINDING_SEVERITY_INFO:     2,
}

// Deciders are an open set; unrecognized ones are treated as warnings.
var shardDeciderSeverity = map[string]string{
	model.FINDING_DISK_THRESHOLD: model.FINDING_SEVERITY_WARNING,
	model.FINDING_SAME_SHARD:     model.FINDING_SEVERITY_INFO,
	model.FINDING_THROTTLING:     model.FINDING_SEVERITY_INFO,
}

// Verdicts conclusive on their own, with no decider having rejected a node.
var canAllocateSeverity = map[string]string{
	model.FINDING_NO_VALID_SHARD_COPY: model.FINDING_SEVERITY_CRITICAL,
}

// getEventsHealth aggregates live event datastore diagnostics. The health
// report is required; remaining sections are best-effort, failures recorded
// in Errors.
func getEventsHealth(ctx context.Context, store esHealthFetcher) (*model.EventsHealth, error) {
	logger := log.FromContext(ctx)

	report, err := store.clusterHealthReport(ctx)
	if err != nil {
		return nil, err
	}
	if report == "" {
		return nil, errors.New("eventstore returned an empty health report")
	}

	health := &model.EventsHealth{
		Status:     gjson.Get(report, "status").String(),
		Indicators: convertHealthIndicators(report),
	}
	if health.Status == "" {
		health.Status = "unknown"
	}
	sectionErrors := make(map[string]string)

	if settings, err := store.clusterSettings(ctx); err == nil {
		health.Settings = convertHealthSettings(settings)
	} else {
		logger.WithError(err).Warn("unable to retrieve eventstore cluster settings")
		sectionErrors[model.HEALTH_SECTION_SETTINGS] = err.Error()
	}

	if nodes, err := store.listNodes(ctx); err == nil {
		health.Nodes = convertHealthNodes(nodes)
	} else {
		logger.WithError(err).Warn("unable to retrieve eventstore node listing")
		sectionErrors[model.HEALTH_SECTION_NODES] = err.Error()
	}

	// Only yellow/red: during master elections the status is "unknown" and the
	// shard listing would block on master discovery.
	shardStatus := gjson.Get(report, "indicators."+HEALTH_INDICATOR_SHARDS+".status").String()
	if shardStatus == "yellow" || shardStatus == "red" {
		unassigned, err := buildUnassignedShards(ctx, store)
		if err != nil {
			logger.WithError(err).Warn("unable to retrieve eventstore shard listing")
			sectionErrors[model.HEALTH_SECTION_UNASSIGNED_SHARDS] = err.Error()
		} else {
			health.UnassignedShards = unassigned
		}
	}

	attachShardFindings(health)
	sortHealthIndicators(health.Indicators)

	if len(sectionErrors) > 0 {
		health.Errors = sectionErrors
	}

	return health, nil
}

// Ties break on id so the ordering is stable across collections.
func sortHealthIndicators(indicators []model.HealthIndicator) {
	rank := func(status string) int {
		if rank, known := healthStatusRank[status]; known {
			return rank
		}
		return healthStatusRank["unknown"]
	}
	sort.SliceStable(indicators, func(i, j int) bool {
		a, b := rank(indicators[i].Status), rank(indicators[j].Status)
		if a != b {
			return a < b
		}
		return indicators[i].Id < indicators[j].Id
	})
}

// The allocation diagnosis hangs off the indicator reporting the symptom it explains.
func attachShardFindings(health *model.EventsHealth) {
	findings := buildShardFindings(health.UnassignedShards)
	if len(findings) == 0 {
		return
	}

	for i := range health.Indicators {
		if health.Indicators[i].Id == HEALTH_INDICATOR_SHARDS {
			health.Indicators[i].Findings = append(health.Indicators[i].Findings, findings...)
			return
		}
	}
}

// One finding per conclusive verdict and per blocking decider.
func buildShardFindings(unassigned *model.UnassignedShards) []model.HealthFinding {
	findings := make([]model.HealthFinding, 0)
	if unassigned == nil {
		return findings
	}

	for _, group := range unassigned.Groups {
		scope := &model.FindingScope{
			Reason:  group.Reason,
			Count:   group.Count,
			Primary: group.Primary,
		}
		before := len(findings)

		if severity, known := canAllocateSeverity[group.CanAllocate]; known {
			findings = append(findings, model.HealthFinding{
				Severity:  severity,
				Condition: group.CanAllocate,
				Scope:     scope,
			})
		}

		for _, decider := range group.Deciders {
			severity, known := shardDeciderSeverity[decider.Name]
			if !known {
				severity = model.FINDING_SEVERITY_WARNING
			}
			detail := decider.Explanation
			// Unknown conditions promise Detail as the client's fallback text
			if !known && detail == "" {
				detail = "no explanation provided by the datastore"
			}
			findings = append(findings, model.HealthFinding{
				Severity:  severity,
				Condition: decider.Name,
				Scope:     scope,
				Detail:    detail,
				Nodes:     decider.Nodes,
			})
		}

		// Transient outcomes (allocation_delayed, awaiting_info...) report no
		// deciders; every explained group still gets a finding.
		if len(findings) == before && group.CanAllocate != "" {
			findings = append(findings, model.HealthFinding{
				Severity:  model.FINDING_SEVERITY_INFO,
				Condition: model.FINDING_UNEXPLAINED,
				Scope:     scope,
				Detail:    group.CanAllocate,
			})
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return findingSeverityRank[findings[i].Severity] < findingSeverityRank[findings[j].Severity]
	})

	return findings
}

// Problems visible in the indicator itself; shard findings need the shard
// inventory and are attached later.
func buildIndicatorFindings(converted model.HealthIndicator, indicator gjson.Result) []model.HealthFinding {
	findings := make([]model.HealthFinding, 0)

	// A read-only block rejects writes, outranking the watermark warning that caused it.
	if converted.Id == HEALTH_INDICATOR_DISK && converted.Status != "green" {
		if readonly := int(indicator.Get("details.indices_with_readonly_block").Int()); readonly > 0 {
			findings = append(findings, model.HealthFinding{
				Severity:  model.FINDING_SEVERITY_CRITICAL,
				Condition: model.FINDING_INDICES_READONLY,
				Count:     readonly,
			})
		}
	}

	return findings
}

func convertHealthIndicators(report string) []model.HealthIndicator {
	indicators := make([]model.HealthIndicator, 0)
	gjson.Get(report, "indicators").ForEach(func(id, indicator gjson.Result) bool {
		converted := model.HealthIndicator{
			Id:      id.String(),
			Status:  indicator.Get("status").String(),
			Symptom: indicator.Get("symptom").String(),
		}
		indicator.Get("diagnosis").ForEach(func(_, diagnosis gjson.Result) bool {
			if diagnosis.Get("cause").String() == "" {
				return true
			}
			cause := model.HealthIndicatorCause{
				Cause:   diagnosis.Get("cause").String(),
				Nodes:   make([]string, 0),
				Indices: make([]string, 0),
			}
			diagnosis.Get("affected_resources.nodes").ForEach(func(_, node gjson.Result) bool {
				cause.Nodes = append(cause.Nodes, node.Get("name").String())
				return true
			})
			diagnosis.Get("affected_resources.indices").ForEach(func(_, index gjson.Result) bool {
				cause.Indices = append(cause.Indices, index.String())
				return true
			})
			converted.Causes = append(converted.Causes, cause)
			return true
		})
		converted.Findings = buildIndicatorFindings(converted, indicator)
		indicators = append(indicators, converted)
		return true
	})
	return indicators
}

func convertHealthNodes(nodesJson string) []model.EventsHealthNode {
	nodes := make([]model.EventsHealthNode, 0)
	gjson.Parse(nodesJson).ForEach(func(_, node gjson.Result) bool {
		nodes = append(nodes, model.EventsHealthNode{
			Name:            node.Get("name").String(),
			Ip:              node.Get("ip").String(),
			Roles:           node.Get(`node\.role`).String(),
			Master:          node.Get("master").String(),
			Version:         node.Get("version").String(),
			HeapPercent:     node.Get(`heap\.percent`).String(),
			RamPercent:      node.Get(`ram\.percent`).String(),
			Cpu:             node.Get("cpu").String(),
			Load1m:          node.Get("load_1m").String(),
			DiskTotal:       node.Get(`disk\.total`).String(),
			DiskUsedPercent: node.Get(`disk\.used_percent`).String(),
			Uptime:          node.Get("uptime").String(),
		})
		return true
	})
	return nodes
}

func convertHealthSettings(settingsJson string) *model.EventsHealthSettings {
	settings := &model.EventsHealthSettings{
		Persistent: make(map[string]interface{}),
		Transient:  make(map[string]interface{}),
	}
	if scope, ok := gjson.Get(settingsJson, "persistent").Value().(map[string]interface{}); ok {
		settings.Persistent = scope
	}
	if scope, ok := gjson.Get(settingsJson, "transient").Value().(map[string]interface{}); ok {
		settings.Transient = scope
	}
	return settings
}

type shardSample struct {
	index string
	shard int64
}

type unassignedGroup struct {
	group  model.UnassignedShardGroup
	sample shardSample
}

// buildUnassignedShards inventories unassigned shards; a nil result with no
// error means none were found.
func buildUnassignedShards(ctx context.Context, store esHealthFetcher) (*model.UnassignedShards, error) {
	logger := log.FromContext(ctx)

	shardsJson, err := store.listShards(ctx)
	if err != nil {
		return nil, err
	}

	unassigned := &model.UnassignedShards{}
	groups := make([]unassignedGroup, 0)
	indexByKey := make(map[string]int)
	gjson.Parse(shardsJson).ForEach(func(_, shard gjson.Result) bool {
		if shard.Get("state").String() != "UNASSIGNED" {
			return true
		}
		unassigned.Total++
		primary := shard.Get("prirep").String() == "p"
		if primary {
			unassigned.Primaries++
		} else {
			unassigned.Replicas++
		}
		reason := shard.Get(`unassigned\.reason`).String()
		key := fmt.Sprintf("%t|%s", primary, reason)
		i, exists := indexByKey[key]
		if !exists {
			i = len(groups)
			indexByKey[key] = i
			groups = append(groups, unassignedGroup{
				group: model.UnassignedShardGroup{
					Reason:  reason,
					Primary: primary,
				},
				sample: shardSample{
					index: shard.Get("index").String(),
					shard: shard.Get("shard").Int(),
				},
			})
		}
		groups[i].group.Count++
		return true
	})

	if unassigned.Total == 0 {
		return nil, nil
	}

	// Explain the largest groups first, primaries before replicas.
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i].group, groups[j].group
		if a.Primary != b.Primary {
			return a.Primary
		}
		return a.Count > b.Count
	})

	unassigned.Groups = make([]model.UnassignedShardGroup, len(groups))
	for i, entry := range groups {
		group := entry.group
		if i >= MAX_ALLOCATION_EXPLAINS {
			group.SampleStatus = model.SAMPLE_STATUS_CAPPED
		} else if explain, err := store.explainAllocation(ctx, entry.sample.index, entry.sample.shard, group.Primary); err == nil {
			group.SampleStatus = model.SAMPLE_STATUS_EXPLAINED
			group.SampleIndex = entry.sample.index
			group.SampleShard = entry.sample.shard
			digestExplanation(&group, explain)
		} else {
			group.SampleStatus = model.SAMPLE_STATUS_FAILED
			logger.WithError(err).WithFields(log.Fields{
				"index": entry.sample.index,
				"shard": entry.sample.shard,
			}).Warn("unable to retrieve allocation explanation for sampled shard")
		}
		unassigned.Groups[i] = group
	}

	return unassigned, nil
}

// digestExplanation extracts the sampled shard's allocation verdict and its
// distinct blocking (NO) and throttling (THROTTLE) deciders. Same-named
// deciders with different explanations stay separate so no node is attributed
// another node's details.
func digestExplanation(group *model.UnassignedShardGroup, explain string) {
	group.CanAllocate = gjson.Get(explain, "can_allocate").String()
	group.Since = gjson.Get(explain, "unassigned_info.at").String()
	group.FailureDetails = gjson.Get(explain, "unassigned_info.details").String()

	deciders := make([]model.AllocationDecider, 0)
	indexByKey := make(map[string]int)
	gjson.Get(explain, "node_allocation_decisions").ForEach(func(_, node gjson.Result) bool {
		nodeName := node.Get("node_name").String()
		node.Get("deciders").ForEach(func(_, result gjson.Result) bool {
			decision := result.Get("decision").String()
			if decision != "NO" && decision != "THROTTLE" {
				return true
			}
			name := result.Get("decider").String()
			explanation := result.Get("explanation").String()
			key := name + "|" + explanation
			i, exists := indexByKey[key]
			if !exists {
				i = len(deciders)
				indexByKey[key] = i
				deciders = append(deciders, model.AllocationDecider{
					Name:        name,
					Explanation: explanation,
					Nodes:       make([]string, 0),
				})
			}
			if nodeName != "" && !slices.Contains(deciders[i].Nodes, nodeName) {
				deciders[i].Nodes = append(deciders[i].Nodes, nodeName)
			}
			return true
		})
		return true
	})

	group.Deciders = deciders
}
