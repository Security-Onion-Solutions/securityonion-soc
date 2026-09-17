// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"fmt"
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
	assert.Contains(t, sql, "WHERE state IN ('queued', 'running')")
}

// ON CONFLICT infers a partial unique index only from a predicate identical to the
// index's. A mismatch raises 42P10 at runtime, which no mock can see, so the statement
// and the index are tied to one constant and checked against the migration here.
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
