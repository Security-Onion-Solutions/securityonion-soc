// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"

	"github.com/security-onion-solutions/securityonion-soc/db"
)

// AutomationRunReconcileResult counts what a reconcile pass recovered, so the caller can
// say whether a restart interrupted anything.
type AutomationRunReconcileResult struct {
	// Runs a previous process left in flight, now failed so their automations can run
	// again.
	FailedRuns int
	// Items a previous process was running, now back in the queue to be redone.
	ResetItems int
}

// ReconcileAutomationRuns closes out runs that started but never finished themselves,
// and returns the work those runs had in flight to the queue. A run left open blocks its
// automation forever, because the in-flight index cannot tell an abandoned run from a
// live one.
//
// Correct only while nothing is running: it assumes every open row belongs to a process
// that is gone. Call it once, from Start, before anything schedules.
func (s *Store) ReconcileAutomationRuns(ctx context.Context) (*AutomationRunReconcileResult, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("database: begin transaction: %w", err)
	}

	defer tx.Rollback(ctx)

	// An open run belongs to a process that is gone; this one has opened none yet.
	failedRuns, err := countAffected(ctx, tx, `
		UPDATE automation_runs
		SET state = 'failed', ended_at = now(),
		    error = COALESCE(NULLIF(error, ''), 'ERROR_AUTOMATION_RUN_INTERRUPTED')
		WHERE ended_at IS NULL
		RETURNING id`)
	if err != nil {
		return nil, err
	}

	// A running item's session is half-finished and cannot be continued, so the item
	// goes back in the queue and is redone from the beginning. attempts is deliberately
	// not incremented: the claim that died already counted itself, and counting again
	// would halve the retry budget.
	resetItems, err := countAffected(ctx, tx, `
		UPDATE automation_work_items
		SET state = 'pending', session_id = NULL, result = NULL,
		    error = 'ERROR_AUTOMATION_WORK_ITEM_INTERRUPTED', updated_at = now()
		WHERE state = 'running'
		RETURNING id`)
	if err != nil {
		return nil, err
	}

	// Items left applying are deliberately untouched. Their result is already stored, so
	// the next run resumes at the apply step rather than paying for the session twice.

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &AutomationRunReconcileResult{FailedRuns: failedRuns, ResetItems: resetItems}, nil
}

// countAffected runs a statement that returns one row per row it changed, because
// db.Tx.Exec discards the rows-affected count.
func countAffected(ctx context.Context, tx db.Tx, stmt string) (int, error) {
	rows, err := tx.Query(ctx, stmt)
	if err != nil {
		return 0, err
	}

	defer rows.Close()

	count := 0

	for rows.Next() {
		count++
	}

	return count, rows.Err()
}
