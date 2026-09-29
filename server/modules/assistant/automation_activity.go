// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"maps"
	"slices"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"
)

// automationActivityStore is what the activity view reads; *database.Store satisfies it.
type automationActivityStore interface {
	ListAutomationRuns(ctx context.Context, query database.AutomationRunQuery) ([]*model.AutomationRunRecord, error)
	ListOpenAutomationWorkItems(ctx context.Context, automationId string) ([]*model.AutomationWorkItem, error)
	CountAutomationWorkItemsByRun(ctx context.Context, runIds []string) (map[string]map[model.AutomationWorkItemState]int, error)
}

func (ac *AssistantCoordinator) GetAutomationActivity(ctx context.Context) (*model.AutomationActivity, error) {
	// A nil *database.Store is a non-nil interface.
	if ac.store == nil {
		return ac.automationActivity(ctx, nil)
	}

	return ac.automationActivity(ctx, ac.store)
}

// automationActivity joins the runs in flight to their open items, and each item to its live
// session. Without a store no run can exist, so only the scheduler and the pool are reported.
func (ac *AssistantCoordinator) automationActivity(ctx context.Context, store automationActivityStore) (*model.AutomationActivity, error) {
	// Read before the items: a session is on its item before its first phase is set.
	phases := automationPhasesByRoot(ac.AgentSessionPhases())
	status := ac.getAutomationEngineStatus()

	activity := &model.AutomationActivity{
		SchedulerRunning: status.Running,
		Pool:             ac.agentPoolActivity(status.Pool),
		Runs:             []*model.AutomationRunActivity{},
	}

	if store == nil {
		return activity, nil
	}

	runs, err := store.ListAutomationRuns(ctx, database.AutomationRunQuery{InFlight: true})
	if err != nil {
		return nil, err
	}

	runIds := make([]string, len(runs))
	for i, run := range runs {
		runIds[i] = run.Id
	}

	counts, err := store.CountAutomationWorkItemsByRun(ctx, runIds)
	if err != nil {
		return nil, err
	}

	var queued map[string]bool
	if ac.execPool != nil {
		queued = ac.execPool.QueuedDedupeKeys()
	}

	for _, run := range runs {
		desc, err := ac.describeAutomation(ctx, run.AutomationId)
		if err != nil {
			return nil, err
		}

		items, err := store.ListOpenAutomationWorkItems(ctx, run.AutomationId)
		if err != nil {
			return nil, err
		}

		itemCounts := counts[run.Id]
		if itemCounts == nil {
			itemCounts = map[model.AutomationWorkItemState]int{}
		}

		runActivity := &model.AutomationRunActivity{
			AutomationRunSummary: model.AutomationRunSummary{AutomationRunRecord: *run, ItemCounts: itemCounts},
			DisplayName:          desc.DisplayName,
			AutomationDeleted:    desc.Deleted,
			Items:                make([]*model.AutomationWorkItemActivity, 0, len(items)),
		}

		for _, item := range items {
			itemActivity := &model.AutomationWorkItemActivity{
				AutomationWorkItem: *item,
				Queued:             queued[item.Id],
				Phases:             []model.AgentSessionPhase{},
			}

			if n := len(item.SessionIds); n > 0 {
				if live, ok := phases[item.SessionIds[n-1]]; ok {
					itemActivity.Phases = live
				}
			}

			runActivity.Items = append(runActivity.Items, itemActivity)
		}

		activity.Runs = append(activity.Runs, runActivity)
	}

	return activity, nil
}

// automationPhasesByRoot groups phases under the session a work item records, that session first.
func automationPhasesByRoot(phases []model.AgentSessionPhase) map[string][]model.AgentSessionPhase {
	byRoot := map[string][]model.AgentSessionPhase{}

	for _, phase := range phases {
		if phase.SessionId == phase.RootSessionId {
			byRoot[phase.RootSessionId] = slices.Insert(byRoot[phase.RootSessionId], 0, phase)
		} else {
			byRoot[phase.RootSessionId] = append(byRoot[phase.RootSessionId], phase)
		}
	}

	return byRoot
}

func (ac *AssistantCoordinator) agentPoolActivity(stats execpool.Stats) model.AgentPoolActivity {
	pool := model.AgentPoolActivity{
		Queued:        stats.Queued,
		Running:       stats.Running,
		MaxConcurrent: ac.automationMaxConcurrentItems,
		MaxQueueDepth: ac.automationMaxQueuedItems,
		PeakQueued:    stats.PeakQueued,
		PeakRunning:   stats.PeakRunning,
		Rejected:      stats.Rejected,
		Deduped:       stats.Deduped,
		Busy:          stats.Busy,
		Agents:        make([]*model.AgentPoolLoad, 0, len(stats.Keys)),
	}

	for _, name := range slices.Sorted(maps.Keys(stats.Keys)) {
		load := stats.Keys[name]

		pool.Agents = append(pool.Agents, &model.AgentPoolLoad{
			Name:                   name,
			Queued:                 load.Queued,
			Running:                load.Running,
			MaxConcurrentInstances: ac.agentConcurrencyLimit(name),
		})
	}

	return pool
}
