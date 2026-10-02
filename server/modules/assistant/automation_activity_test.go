// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/assistant/database"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const activityDeletedAutomationId = "7a1c2e3f-4b5d-4c6e-8f90-a1b2c3d4e5f6"

var _ automationActivityStore = (*database.Store)(nil)

// fakeActivityStore answers the activity's reads from fixtures and records what was asked.
type fakeActivityStore struct {
	runs   []*model.AutomationRunRecord
	items  map[string][]*model.AutomationWorkItem
	counts map[string]map[model.AutomationWorkItemState]int

	listErr, openErr, countErr error

	query   database.AutomationRunQuery
	counted []string
}

func (f *fakeActivityStore) ListAutomationRuns(_ context.Context, query database.AutomationRunQuery) ([]*model.AutomationRunRecord, error) {
	f.query = query

	return f.runs, f.listErr
}

func (f *fakeActivityStore) ListOpenAutomationWorkItems(_ context.Context, automationId string) ([]*model.AutomationWorkItem, error) {
	return f.items[automationId], f.openErr
}

func (f *fakeActivityStore) CountAutomationWorkItemsByRun(_ context.Context, runIds []string) (map[string]map[model.AutomationWorkItemState]int, error) {
	f.counted = runIds

	return f.counts, f.countErr
}

func newActivityCoordinator(t *testing.T) *AssistantCoordinator {
	t.Helper()

	cfg := &automationConfigstore{}
	cfg.settings = []*model.Setting{automationsSetting(t, historyAutomation(automationTestId, "Nightly", `{"groupBy":["rule.name"]}`))}

	return automationCoordinator(cfg)
}

func activityItems(run *model.AutomationRunActivity) map[string]*model.AutomationWorkItemActivity {
	items := map[string]*model.AutomationWorkItemActivity{}
	for _, item := range run.Items {
		items[item.Id] = item
	}

	return items
}

func TestAutomationActivityJoinsRunsItemsAndLiveSessions(t *testing.T) {
	ac := newActivityCoordinator(t)
	ac.automationScheduler = &automationScheduler{}

	// Sorted by session id, the child comes first; the item's own session still leads.
	ac.setAgentPhase("s1", "s1", automationTestAgent, model.AgentPhaseInvokingToolPrefix+"delegate")
	ac.setAgentPhase("a-child", "s1", "Log Analyst", model.AgentPhaseWaitingLLM)
	ac.setAgentPhase("stray", "stray", automationTestAgent, model.AgentPhaseWaitingLLM)

	store := &fakeActivityStore{
		runs: []*model.AutomationRunRecord{
			historyRun(historyRunId, model.AutomationRunRunning),
			{Id: historyOtherRunId, AutomationId: activityDeletedAutomationId, State: model.AutomationRunQueued},
		},
		items: map[string][]*model.AutomationWorkItem{
			automationTestId: {
				historyItem("live", model.AutomationWorkItemRunning, "s0", "s1"),
				// Its newest session is an earlier attempt; the next has not started.
				historyItem("retry", model.AutomationWorkItemRunning, "s1-old"),
				historyItem("pending", model.AutomationWorkItemPending),
			},
		},
		counts: map[string]map[model.AutomationWorkItemState]int{
			historyRunId: {model.AutomationWorkItemDone: 2, model.AutomationWorkItemRunning: 2},
		},
	}

	activity, err := ac.automationActivity(context.Background(), store)
	require.NoError(t, err)

	assert.True(t, activity.SchedulerRunning)
	assert.True(t, store.query.InFlight)
	assert.Equal(t, []string{historyRunId, historyOtherRunId}, store.counted)
	require.Len(t, activity.Runs, 2)

	run := activity.Runs[0]
	assert.Equal(t, historyRunId, run.Id)
	assert.Equal(t, model.AutomationRunRunning, run.State)
	assert.Equal(t, "Nightly", run.DisplayName)
	assert.False(t, run.AutomationDeleted)
	assert.Equal(t, 2, run.ItemCounts[model.AutomationWorkItemDone])
	require.Len(t, run.Items, 3)

	items := activityItems(run)
	live := items["live"].Phases
	require.Len(t, live, 2)
	assert.Equal(t, "s1", live[0].SessionId)
	assert.Equal(t, model.AgentPhaseInvokingToolPrefix+"delegate", live[0].Phase)
	assert.Equal(t, "a-child", live[1].SessionId)
	assert.Equal(t, "Log Analyst", live[1].Agent)

	assert.Empty(t, items["retry"].Phases)
	assert.NotNil(t, items["retry"].Phases)
	assert.Empty(t, items["pending"].Phases)
	assert.False(t, items["live"].Queued, "no pool to wait in")

	// A run finishing for a deleted automation keeps its own state and has no open work.
	deleted := activity.Runs[1]
	assert.Equal(t, model.AutomationRunQueued, deleted.State)
	assert.True(t, deleted.AutomationDeleted)
	assert.Empty(t, deleted.DisplayName)
	assert.NotNil(t, deleted.ItemCounts)
	assert.NotNil(t, deleted.Items)

	for _, run := range activity.Runs {
		for _, item := range run.Items {
			for _, phase := range item.Phases {
				assert.NotEqual(t, "stray", phase.RootSessionId, "a session no item holds is not shown")
			}
		}
	}
}

func TestAutomationActivityReadsThePool(t *testing.T) {
	ac := newActivityCoordinator(t)
	ac.automationMaxConcurrentItems = 4
	ac.automationMaxQueuedItems = 10
	agent := ac.agents[automationTestAgent]
	agent.MaxConcurrentInstances = 1
	ac.agents[automationTestAgent] = agent

	ac.execPool = ac.newExecPool()
	release := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		_ = ac.execPool.Shutdown(context.Background())
	})

	hold := func(ctx context.Context) error {
		select {
		case <-release:
		case <-ctx.Done():
		}

		return nil
	}

	for _, job := range []execpool.Job{
		{Key: automationTestAgent, DedupeKey: "working", Run: hold},
		{Key: automationTestAgent, DedupeKey: "waiting", Run: hold},
		{Key: "chat-model@MyAdapter", DedupeKey: "chat-session", Run: hold},
	} {
		_, err := ac.execPool.Submit(job)
		require.NoError(t, err)
	}

	store := &fakeActivityStore{
		runs: []*model.AutomationRunRecord{historyRun(historyRunId, model.AutomationRunRunning)},
		items: map[string][]*model.AutomationWorkItem{
			automationTestId: {
				historyItem("working", model.AutomationWorkItemRunning),
				historyItem("waiting", model.AutomationWorkItemRunning),
			},
		},
	}

	activity, err := ac.automationActivity(context.Background(), store)
	require.NoError(t, err)

	items := activityItems(activity.Runs[0])
	assert.False(t, items["working"].Queued)
	assert.True(t, items["waiting"].Queued, "held back by the agent's limit")

	pool := activity.Pool
	assert.Equal(t, 2, pool.Running)
	assert.Equal(t, 1, pool.Queued)
	assert.Equal(t, 4, pool.MaxConcurrent)
	assert.Equal(t, 10, pool.MaxQueueDepth)
	assert.Equal(t, []*model.AgentPoolLoad{
		{Name: automationTestAgent, Queued: 1, Running: 1, MaxConcurrentInstances: 1},
		{Name: "chat-model@MyAdapter", Running: 1},
	}, pool.Agents)
}

// No run opens without a database, so the answer is the scheduler and the pool.
func TestAutomationActivityWithoutADatabase(t *testing.T) {
	ac := newActivityCoordinator(t)

	activity, err := ac.GetAutomationActivity(context.Background())
	require.NoError(t, err)

	assert.False(t, activity.SchedulerRunning)
	assert.Empty(t, activity.Runs)

	raw, err := json.Marshal(activity)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"runs":[]`)
	assert.Contains(t, string(raw), `"agents":[]`)
}

func TestAutomationActivityReportsStoreErrors(t *testing.T) {
	failure := errors.New("postgres is down")

	for name, store := range map[string]*fakeActivityStore{
		"runs":   {listErr: failure},
		"counts": {runs: []*model.AutomationRunRecord{historyRun(historyRunId, model.AutomationRunRunning)}, countErr: failure},
		"items":  {runs: []*model.AutomationRunRecord{historyRun(historyRunId, model.AutomationRunRunning)}, openErr: failure},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newActivityCoordinator(t).automationActivity(context.Background(), store)
			assert.ErrorIs(t, err, failure)
		})
	}
}
