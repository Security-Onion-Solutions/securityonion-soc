// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/tidwall/gjson"
)

// FindEventBySocId finds the event matching the given SOC id (log.id.uid,
// event.id, or _id), or nil if none matched. A non-zero ts bounds the search
// to +/-24h around it before falling back to an unbounded search.
func FindEventBySocId(ctx context.Context, store Eventstore, id string, ts time.Time) (*model.EventRecord, error) {
	if !ts.IsZero() {
		dateRange := ts.Add(-24*time.Hour).Format(time.RFC3339) + " - " + ts.Add(24*time.Hour).Format(time.RFC3339)

		event, err := findEventBySocId(ctx, store, id, dateRange)
		if err != nil || event != nil {
			return event, err
		}
	}

	dateRange := "1970-01-01T00:00:00Z - " + time.Now().Format(time.RFC3339)

	return findEventBySocId(ctx, store, id, dateRange)
}

func findEventBySocId(ctx context.Context, store Eventstore, id string, dateRange string) (*model.EventRecord, error) {
	query := fmt.Sprintf(`log.id.uid:"%[1]s" OR event.id:"%[1]s" OR _id:"%[1]s"`, id)
	criteria := model.NewEventSearchCriteria()

	err := criteria.Populate(query, dateRange, time.RFC3339, "", "0", "1")
	if err != nil {
		return nil, fmt.Errorf("failed to populate event search criteria: %w", err)
	}

	events, err := store.Search(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search for alert: %w", err)
	}
	if events.TotalEvents == 0 || len(events.Events) == 0 {
		return nil, nil
	}

	return events.Events[0], nil
}

type Eventstore interface {
	Search(context context.Context, criteria *model.EventSearchCriteria) (*model.EventSearchResults, error)
	MSearch(context context.Context, criteria []*model.EventMSearchCriteria) (*model.EventMSearchResults, error)
	Scroll(context context.Context, criteria *model.EventScrollCriteria, indexes []string) (*model.EventScrollResults, error)
	Index(ctx context.Context, index string, document map[string]interface{}, id string) (*model.EventIndexResults, error)
	Update(context context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error)
	Delete(context context.Context, index string, id string) error
	Acknowledge(context context.Context, criteria *model.EventAckCriteria) (*model.EventUpdateResults, error)
	GetActiveQueries(context context.Context, filter bool) ([]*model.QueryTask, error)
	CancelQuery(context context.Context, queryId string) error

	// Health diagnostics, returned as raw JSON from the backend's
	// Elasticsearch-compatible diagnostic APIs. ClusterHealthReport must
	// include indicators.shards_availability.status.
	ClusterHealthReport(ctx context.Context) (string, error)
	ClusterSettings(ctx context.Context) (string, error)
	ListNodes(ctx context.Context) (string, error)
	ListShards(ctx context.Context) (string, error)
	ExplainAllocation(ctx context.Context, index string, shard int64, primary bool) (string, error)
}

// Shards typically fail in groups for the same reason, so only one shard is
// explained per group, capped at this many backend calls.
const MAX_ALLOCATION_EXPLAINS = 5

// GetEventstoreHealth aggregates live eventstore diagnostics. The health
// report is required; the remaining diagnostics are best-effort.
func GetEventstoreHealth(ctx context.Context, store Eventstore) (*model.EventstoreHealth, error) {
	logger := log.FromContext(ctx)

	report, err := store.ClusterHealthReport(ctx)
	if err != nil {
		return nil, err
	}
	// An empty RawMessage fails JSON marshaling of the response
	if report == "" {
		return nil, errors.New("eventstore returned an empty health report")
	}

	health := &model.EventstoreHealth{
		HealthReport: json.RawMessage(report),
	}

	if settings, err := store.ClusterSettings(ctx); err == nil {
		health.ClusterSettings = json.RawMessage(settings)
	} else {
		logger.WithError(err).Warn("unable to retrieve eventstore cluster settings")
	}

	if nodes, err := store.ListNodes(ctx); err == nil {
		health.CatNodes = json.RawMessage(nodes)
	} else {
		logger.WithError(err).Warn("unable to retrieve eventstore node listing")
	}

	// Only yellow/red: during master elections the status is "unknown" and the
	// shard listing would block on master discovery.
	shardStatus := gjson.Get(report, "indicators.shards_availability.status").String()
	if shardStatus == "yellow" || shardStatus == "red" {
		health.UnassignedShards = buildUnassignedShards(ctx, store)
	}

	return health, nil
}

type shardSample struct {
	index string
	shard int64
}

func buildUnassignedShards(ctx context.Context, store Eventstore) *model.UnassignedShards {
	logger := log.FromContext(ctx)

	shardsJson, err := store.ListShards(ctx)
	if err != nil {
		logger.WithError(err).Warn("unable to retrieve eventstore shard listing")
		return nil
	}

	unassigned := &model.UnassignedShards{
		Groups: make([]*model.UnassignedShardGroup, 0),
	}
	groupsByKey := make(map[string]*model.UnassignedShardGroup)
	samples := make(map[*model.UnassignedShardGroup]shardSample)
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
		group, exists := groupsByKey[key]
		if !exists {
			group = &model.UnassignedShardGroup{
				Reason:  reason,
				Primary: primary,
			}
			groupsByKey[key] = group
			samples[group] = shardSample{
				index: shard.Get("index").String(),
				shard: shard.Get("shard").Int(),
			}
			unassigned.Groups = append(unassigned.Groups, group)
		}
		group.Count++
		return true
	})

	if unassigned.Total == 0 {
		return nil
	}

	// Explain the largest groups first, primaries before replicas.
	sort.SliceStable(unassigned.Groups, func(i, j int) bool {
		a, b := unassigned.Groups[i], unassigned.Groups[j]
		if a.Primary != b.Primary {
			return a.Primary
		}
		return a.Count > b.Count
	})

	for i, group := range unassigned.Groups {
		if i >= MAX_ALLOCATION_EXPLAINS {
			break
		}
		sample := samples[group]
		if explain, err := store.ExplainAllocation(ctx, sample.index, sample.shard, group.Primary); err == nil {
			group.Explanation = json.RawMessage(explain)
			digestExplanation(group, explain)
		} else {
			logger.WithError(err).WithFields(log.Fields{
				"index": sample.index,
				"shard": sample.shard,
			}).Warn("unable to retrieve allocation explanation for sampled shard")
		}
	}

	return unassigned
}

// digestExplanation extracts the allocation verdict and distinct NO deciders.
// Same-named deciders with different explanations (e.g. per-node disk
// watermarks) stay separate so no node is attributed another node's details.
func digestExplanation(group *model.UnassignedShardGroup, explain string) {
	group.CanAllocate = gjson.Get(explain, "can_allocate").String()

	decidersByKey := make(map[string]*model.AllocationDecider)
	gjson.Get(explain, "node_allocation_decisions").ForEach(func(_, node gjson.Result) bool {
		nodeName := node.Get("node_name").String()
		node.Get("deciders").ForEach(func(_, result gjson.Result) bool {
			if result.Get("decision").String() != "NO" {
				return true
			}
			name := result.Get("decider").String()
			explanation := result.Get("explanation").String()
			decider, exists := decidersByKey[name+"|"+explanation]
			if !exists {
				decider = &model.AllocationDecider{
					Name:        name,
					Explanation: explanation,
					Nodes:       make([]string, 0),
				}
				decidersByKey[name+"|"+explanation] = decider
				group.Deciders = append(group.Deciders, decider)
			}
			if nodeName != "" && !slices.Contains(decider.Nodes, nodeName) {
				decider.Nodes = append(decider.Nodes, nodeName)
			}
			return true
		})
		return true
	})
}
