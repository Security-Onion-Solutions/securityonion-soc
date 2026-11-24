// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"fmt"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Named only here: the work-item insert infers this index from its predicate rather than
// by name, so nothing in the store refers to it.
const idxWorkItemsOpenPerKey = "idx_automation_work_items_one_open_per_group"

// The migration is otherwise unread by the test suite, so a change to it surfaces on a
// customer's first upgrade. These tests pin the parts the Go code silently depends on.
func automationMigration(t *testing.T) string {
	t.Helper()

	sql, err := migrationFS.ReadFile("migrations/2_automations.sql")
	require.NoError(t, err)

	return string(sql)
}

// Without the WHERE clause this is a plain unique index, and an automation could run
// exactly once, ever. With no index at all, two runs race.
func TestMigrationDedupesRunsWithAPartialIndex(t *testing.T) {
	sql := automationMigration(t)

	assert.Contains(t, sql, "CREATE UNIQUE INDEX IF NOT EXISTS "+idxRunsOneInFlight)
	assert.Contains(t, sql, "WHERE state IN "+inFlightRunStates)
}

// ON CONFLICT infers a partial index only from an identical predicate, and a mismatch is
// a runtime 42P10 no mock can see, so both sides are tied to one constant.
func TestMigrationOpenWorkItemPredicateMatchesTheConstant(t *testing.T) {
	sql := automationMigration(t)

	assert.Contains(t, sql, "CREATE UNIQUE INDEX IF NOT EXISTS "+idxWorkItemsOpenPerKey)
	assert.Contains(t, sql, "WHERE state IN "+openWorkItemStates)
}

// A state the Go code can write but the CHECK rejects is an insert that fails in
// production and nowhere else.
func TestMigrationChecksAcceptEveryState(t *testing.T) {
	sql := automationMigration(t)

	runStates := []model.AutomationRunState{
		model.AutomationRunQueued,
		model.AutomationRunRunning,
		model.AutomationRunSucceeded,
		model.AutomationRunFailed,
	}

	for _, state := range runStates {
		assert.Contains(t, sql, fmt.Sprintf("'%s'", state),
			"automation_runs CHECK must accept %q", state)
	}

	itemStates := []model.AutomationWorkItemState{
		model.AutomationWorkItemPending,
		model.AutomationWorkItemRunning,
		model.AutomationWorkItemApplying,
		model.AutomationWorkItemDone,
		model.AutomationWorkItemFailed,
	}

	for _, state := range itemStates {
		assert.Contains(t, sql, fmt.Sprintf("'%s'", state),
			"automation_work_items CHECK must accept %q", state)
	}
}

// Work items outlive the run that created them: a pending item is re-submitted by a
// later run, so cascading from runs would delete recoverable work.
func TestMigrationDoesNotCascadeWorkItemsFromRuns(t *testing.T) {
	sql := automationMigration(t)

	assert.Contains(t, sql, "REFERENCES automation_runs (id) ON DELETE SET NULL")
}

// Postgres holds runtime state only: an automations table reappearing would mean config
// drifted back out of Salt.
func TestMigrationHoldsOnlyRuntimeState(t *testing.T) {
	sql := automationMigration(t)

	// Automations live in Salt pillar now, so this migration must not recreate them.
	assert.NotContains(t, sql, "CREATE TABLE IF NOT EXISTS automations")
	assert.NotContains(t, sql, "automation_run_sessions")
	assert.NotContains(t, sql, "automation_run_result_audit")

	// One root session per attempt, so a retry cannot orphan the previous transcript.
	// Matched loosely: the column's alignment is formatting, not schema.
	assert.Regexp(t, `session_ids\s+text\[\]\s+NOT NULL DEFAULT '\{\}'`, sql)
}

// Runs and work items must key on the immutable id, never on anything renameable.
func TestMigrationRunsAndItemsKeyOnAutomationId(t *testing.T) {
	sql := automationMigration(t)

	assert.NotContains(t, sql, "automation_name")
	assert.Contains(t, sql, "ON automation_runs (automation_id)")
	assert.Contains(t, sql, "ON automation_work_items (automation_id, created_at)")
	assert.Contains(t, sql, "ON automation_work_items (automation_id, group_key)")
}

// Run history reads by run_id and failed_run_ids, neither of which the open-item
// indexes cover.
func TestMigrationIndexesWorkItemsByRun(t *testing.T) {
	sql := automationMigration(t)

	assert.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_automation_work_items_run_id")
	assert.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_automation_work_items_failed_run_ids")
	assert.Contains(t, sql, "USING GIN (failed_run_ids)")
}

// Listing runs across automations orders by started_at alone, which the per-automation index
// can't serve.
func TestMigrationIndexesRunsByStartTime(t *testing.T) {
	sql, err := migrationFS.ReadFile("migrations/3_automation_runs_started_at.sql")
	require.NoError(t, err)

	assert.Contains(t, string(sql), "CREATE INDEX IF NOT EXISTS idx_automation_runs_started_at")
	assert.Contains(t, string(sql), "ON automation_runs (started_at DESC, id)")
}

func runStopMigration(t *testing.T) string {
	t.Helper()

	sql, err := migrationFS.ReadFile("migrations/4_automation_run_stop.sql")
	require.NoError(t, err)

	return string(sql)
}

// The CHECK is replaced by name; a name that doesn't match migration 2's inline constraint
// would leave both in place, and the old one would still refuse stopped.
func TestRunStopMigrationReplacesTheStateCheck(t *testing.T) {
	sql := runStopMigration(t)

	assert.Contains(t, sql, "DROP CONSTRAINT IF EXISTS automation_runs_state_check")
	assert.Equal(t, 1, strings.Count(sql, "ADD CONSTRAINT automation_runs_state_check"))

	runStates := []model.AutomationRunState{
		model.AutomationRunQueued,
		model.AutomationRunRunning,
		model.AutomationRunSucceeded,
		model.AutomationRunFailed,
		model.AutomationRunStopped,
	}

	for _, state := range runStates {
		assert.Contains(t, sql, fmt.Sprintf("'%s'", state), "automation_runs CHECK must accept %q", state)
	}
}

// stopped is terminal, so the in-flight index must be left exactly as migration 2 built it.
func TestRunStopMigrationLeavesTheInFlightIndexAlone(t *testing.T) {
	sql := runStopMigration(t)

	assert.NotContains(t, sql, "INDEX IF NOT EXISTS "+idxRunsOneInFlight)
	assert.NotContains(t, sql, "DROP INDEX")
	assert.True(t, model.AutomationRunStopped.IsTerminal())
}

// Rows from 3.4.0 must read as scheduled and not stopped, so every new column is nullable or
// defaults to empty.
func TestRunStopMigrationAddsNullableColumns(t *testing.T) {
	sql := runStopMigration(t)

	assert.Contains(t, sql, "ADD COLUMN IF NOT EXISTS started_by text;")
	assert.Contains(t, sql, "ADD COLUMN IF NOT EXISTS stopped_by text;")
	assert.Contains(t, sql, "ADD COLUMN IF NOT EXISTS stopped_at timestamptz;")
	assert.Regexp(t, `session_run_ids\s+text\[\]\s+NOT NULL DEFAULT '\{\}'`, sql)
}

func TestRunStopMigrationIndexesSessionRuns(t *testing.T) {
	sql := runStopMigration(t)

	assert.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_automation_work_items_session_run_ids")
	assert.Contains(t, sql, "USING GIN (session_run_ids)")
}
