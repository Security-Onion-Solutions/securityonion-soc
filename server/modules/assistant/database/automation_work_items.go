// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// Must match the open-item indexes' predicate exactly: ON CONFLICT infers a partial
// unique index only from an identical one, and a mismatch is a runtime 42P10.
const openWorkItemStates = `('pending', 'running', 'applying')`

// The states a claimed item can still be transitioned from; pulling one back out of a
// terminal state is how a completed group gets worked a second time.
const claimedWorkItemStates = `('running', 'applying')`

// The states whose payload came from the automation's params, and which are therefore
// stale when those params change. applying is excluded: its conclusion is already reached
// and its alerts still need stamping.
const staleWorkItemStates = `('pending', 'running')`

// Work a deleted automation had queued but never started. running and applying are excluded:
// a run already under way is allowed to finish.
const pendingWorkItemStates = `('pending')`

const automationWorkItemColumns = `id, automation_id, run_id, group_key, payload, state, attempts, session_ids, failed_run_ids, result, error, created_at, updated_at`

func scanAutomationWorkItemRow(row db.Row) (*model.AutomationWorkItem, error) {
	item := &model.AutomationWorkItem{}

	var state string
	var runId, failure *string
	var payload, result []byte

	err := row.Scan(&item.Id, &item.AutomationId, &runId, &item.GroupKey, &payload, &state,
		&item.Attempts, &item.SessionIds, &item.FailedRunIds, &result, &failure, &item.CreateTime, &item.UpdateTime)
	if err != nil {
		return nil, err
	}

	item.State = model.AutomationWorkItemState(state)
	item.Payload = json.RawMessage(payload)

	if len(result) > 0 {
		item.Result = json.RawMessage(result)
	}

	if runId != nil {
		item.RunId = *runId
	}

	if failure != nil {
		item.Error = *failure
	}

	return item, nil
}

// EnsureAutomationWorkItems enqueues a batch, skipping any group that already has an item
// in flight, so a kind that died partway through enqueueing can simply enqueue again. It
// returns only what it inserted: anything skipped is already being worked elsewhere.
func (s *Store) EnsureAutomationWorkItems(ctx context.Context, runId string, items []*model.AutomationWorkItem) ([]*model.AutomationWorkItem, error) {
	if len(items) == 0 {
		return nil, nil
	}

	automationId := items[0].AutomationId
	if automationId == "" {
		return nil, fmt.Errorf("cannot enqueue work items without an automation id")
	}

	groupKeys := make([]string, 0, len(items))
	payloads := make([]string, 0, len(items))

	for _, item := range items {
		if item.AutomationId != automationId {
			return nil, fmt.Errorf("cannot enqueue work items for more than one automation at a time")
		}

		groupKeys = append(groupKeys, item.GroupKey)
		payloads = append(payloads, jsonbOrEmpty(item.Payload))
	}

	// The ON CONFLICT predicate must match idx_automation_work_items_one_open_per_group
	// verbatim or Postgres cannot infer the index and raises 42P10.
	rows, err := s.db.Query(ctx, `
		INSERT INTO automation_work_items (automation_id, run_id, group_key, payload)
		SELECT $1, NULLIF($2, '')::uuid, w.group_key, w.payload::jsonb
		FROM unnest($3::text[], $4::text[]) AS w(group_key, payload)
		ON CONFLICT (automation_id, group_key) WHERE state IN `+openWorkItemStates+`
		DO NOTHING
		RETURNING `+automationWorkItemColumns,
		automationId, runId, groupKeys, payloads)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	return collectWorkItems(rows)
}

// ClaimNextAutomationWorkItem takes the oldest pending item for one automation and counts
// the attempt, returning nil when there is nothing to claim. It skips items this run already
// failed, so retries wait for the next run, and items with maxFailures failed runs, which the
// kind gives up once their alerts carry those failures.
//
// run_id moves to the claiming run, so an item a later run resumes is credited to that
// run rather than to the dead one that enqueued it.
func (s *Store) ClaimNextAutomationWorkItem(ctx context.Context, automationId, runId string, maxFailures int) (*model.AutomationWorkItem, error) {
	if runId == "" {
		return nil, fmt.Errorf("cannot claim a work item without a run id")
	}

	rows, err := s.db.Query(ctx, `
		UPDATE automation_work_items
		SET state = 'running', run_id = $2, attempts = attempts + 1,
		    result = NULL, error = NULL, updated_at = now()
		WHERE id = (
			SELECT id FROM automation_work_items
			WHERE automation_id = $1 AND state = 'pending'
			  AND NOT ($2::text = ANY(failed_run_ids))
			  AND cardinality(failed_run_ids) < $3
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+automationWorkItemColumns,
		automationId, runId, maxFailures)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if !rows.Next() {
		return nil, rows.Err()
	}

	return scanAutomationWorkItemRow(rows)
}

// EnsureAutomationWorkItemSession appends the session analyzing a claimed item rather than
// overwriting, so each attempt's root stays reachable. Idempotent, so a replayed write does
// not double-add.
func (s *Store) EnsureAutomationWorkItemSession(ctx context.Context, itemId, sessionId string) error {
	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET session_ids = CASE WHEN $2 = ANY(session_ids)
		                       THEN session_ids
		                       ELSE array_append(session_ids, $2) END,
		    updated_at = now()
		WHERE id = $1 AND state IN `+openWorkItemStates+`
		RETURNING id`, itemId, sessionId)
}

// MarkAutomationWorkItemApplying stores the kind's conclusion and moves the item to
// applying in one statement. Reconciliation leaves applying items alone because everything
// past this point replays from the stored result, so an empty result is refused: it would
// park the item in the one state nothing recovers.
func (s *Store) MarkAutomationWorkItemApplying(ctx context.Context, itemId string, result json.RawMessage) error {
	if len(result) == 0 {
		return fmt.Errorf("cannot move a work item to applying without a result")
	}

	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET state = 'applying', result = $2::jsonb, updated_at = now()
		WHERE id = $1 AND state IN `+claimedWorkItemStates+`
		RETURNING id`, itemId, string(result))
}

func (s *Store) CompleteAutomationWorkItem(ctx context.Context, itemId string) error {
	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET state = 'done', error = NULL, updated_at = now()
		WHERE id = $1 AND state IN `+claimedWorkItemStates+`
		RETURNING id`, itemId)
}

// RequeueAutomationWorkItem returns a running item to the queue after a failure it may
// recover from. An applying item keeps its state and result, so only its update replays.
// attempts is deliberately left alone: the claim already counted this try.
func (s *Store) RequeueAutomationWorkItem(ctx context.Context, itemId, cause string) error {
	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET state = CASE WHEN state = 'applying' THEN state ELSE 'pending' END,
		    result = CASE WHEN state = 'applying' THEN result ELSE NULL END,
		    error = NULLIF($2, ''), updated_at = now()
		WHERE id = $1 AND state IN `+claimedWorkItemStates+`
		RETURNING id`, itemId, cause)
}

// FailAutomationWorkItemRun records that the claiming run failed a running item and returns
// it to the queue with that run added to failed_run_ids. It never ends the item: the kind
// does that once the item's alerts carry every failure.
func (s *Store) FailAutomationWorkItemRun(ctx context.Context, itemId, cause string) (*model.AutomationWorkItem, error) {
	if itemId == "" {
		return nil, fmt.Errorf("cannot update a work item without an id")
	}

	rows, err := s.db.Query(ctx, `
		UPDATE automation_work_items
		SET failed_run_ids = CASE WHEN run_id IS NULL OR run_id::text = ANY(failed_run_ids)
		                          THEN failed_run_ids
		                          ELSE array_append(failed_run_ids, run_id::text) END,
		    state = 'pending', result = NULL, error = NULLIF($2, ''), updated_at = now()
		WHERE id = $1 AND state = 'running'
		RETURNING `+automationWorkItemColumns, itemId, cause)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}

		return nil, ErrAutomationWorkItemNotFound
	}

	return scanAutomationWorkItemRow(rows)
}

// FailAutomationWorkItem ends an item for good; a retryable failure goes through
// FailAutomationWorkItemRun instead. The caller must have recorded the failures on this
// item's alerts first, or the next scan re-enqueues them as a fresh item with no failed runs.
func (s *Store) FailAutomationWorkItem(ctx context.Context, itemId, cause string) error {
	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET state = 'failed', error = NULLIF($2, ''), updated_at = now()
		WHERE id = $1 AND state IN `+openWorkItemStates+`
		RETURNING id`, itemId, cause)
}

// failWorkItems terminalizes every item an automation holds in one of states, which is a
// SQL literal list from this file rather than anything a caller composes.
func (s *Store) failWorkItems(ctx context.Context, automationId, cause, states string) (int, error) {
	if automationId == "" {
		return 0, fmt.Errorf("cannot fail work items without an automation id")
	}

	return countAffected(ctx, s.db, `
		UPDATE automation_work_items
		SET state = 'failed', error = NULLIF($2, ''), updated_at = now()
		WHERE automation_id = $1 AND state IN `+states+`
		RETURNING id`, automationId, cause)
}

// FailStaleAutomationWorkItems terminalizes work whose payload was derived from params that
// have since changed. The next scan re-derives their alerts under the new params as fresh items
// with no failed runs -- the old budget belonged to a definition that no longer exists.
func (s *Store) FailStaleAutomationWorkItems(ctx context.Context, automationId, cause string) (int, error) {
	return s.failWorkItems(ctx, automationId, cause, staleWorkItemStates)
}

// FailPendingAutomationWorkItems terminalizes work that will never be claimed, because the
// automation that would have claimed it is gone.
func (s *Store) FailPendingAutomationWorkItems(ctx context.Context, automationId, cause string) (int, error) {
	return s.failWorkItems(ctx, automationId, cause, pendingWorkItemStates)
}

// FailOrphanedAutomationWorkItems terminalizes open work whose automation is no longer
// defined. Unlike the per-automation sweeps this includes applying: an orphaned item has no
// run left to resume its apply step. An empty liveIds means no automation is defined at all,
// so everything open is orphaned.
func (s *Store) FailOrphanedAutomationWorkItems(ctx context.Context, liveIds []string, cause string) (int, error) {
	return s.failOrphanedWorkItems(ctx, liveIds, cause, openWorkItemStates)
}

// FailOrphanedPendingAutomationWorkItems terminalizes only the unclaimed work of automations
// no longer defined, so a run still under way for one of them is allowed to finish.
func (s *Store) FailOrphanedPendingAutomationWorkItems(ctx context.Context, liveIds []string, cause string) (int, error) {
	return s.failOrphanedWorkItems(ctx, liveIds, cause, pendingWorkItemStates)
}

func (s *Store) failOrphanedWorkItems(ctx context.Context, liveIds []string, cause, states string) (int, error) {
	// pgx sends []string as text[]; automation_id is uuid.
	return countAffected(ctx, s.db, `
		UPDATE automation_work_items
		SET state = 'failed', error = NULLIF($2, ''), updated_at = now()
		WHERE state IN `+states+`
		  AND NOT (automation_id = ANY($1::uuid[]))
		RETURNING id`, liveIds, cause)
}

// transitionWorkItem runs a statement that returns the id it changed, because db.DB.Exec
// discards the rows-affected count and RETURNING is the only way to tell a write against a
// vanished item from a silent no-op. Every transition also guards the state it is legal
// from, so an item that has already gone terminal collapses into the same error.
func (s *Store) transitionWorkItem(ctx context.Context, stmt, itemId string, args ...any) error {
	if itemId == "" {
		return fmt.Errorf("cannot update a work item without an id")
	}

	rows, err := s.db.Query(ctx, stmt, append([]any{itemId}, args...)...)
	if err != nil {
		return err
	}

	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}

		return ErrAutomationWorkItemNotFound
	}

	return nil
}

// ListOpenAutomationWorkItems returns every unfinished item for one automation, oldest
// first: what an earlier process left behind plus anything the current run enqueued.
func (s *Store) ListOpenAutomationWorkItems(ctx context.Context, automationId string) ([]*model.AutomationWorkItem, error) {
	if automationId == "" {
		return nil, fmt.Errorf("cannot list open work items without an automation id")
	}

	rows, err := s.db.Query(ctx, `
		SELECT `+automationWorkItemColumns+`
		FROM automation_work_items
		WHERE automation_id = $1 AND state IN `+openWorkItemStates+`
		ORDER BY created_at`, automationId)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	return collectWorkItems(rows)
}

// ListAutomationWorkItems returns the items one run worked, for the run detail view.
func (s *Store) ListAutomationWorkItems(ctx context.Context, runId string) ([]*model.AutomationWorkItem, error) {
	if runId == "" {
		return nil, fmt.Errorf("cannot list work items without a run id")
	}

	rows, err := s.db.Query(ctx, `
		SELECT `+automationWorkItemColumns+`
		FROM automation_work_items
		WHERE run_id = $1
		ORDER BY created_at`, runId)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	return collectWorkItems(rows)
}

func collectWorkItems(rows db.Rows) ([]*model.AutomationWorkItem, error) {
	items := []*model.AutomationWorkItem{}

	for rows.Next() {
		item, err := scanAutomationWorkItemRow(rows)
		if err != nil {
			return nil, err
		}

		items = append(items, item)
	}

	return items, rows.Err()
}
