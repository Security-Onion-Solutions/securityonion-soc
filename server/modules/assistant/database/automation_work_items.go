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

const automationWorkItemColumns = `id, automation_id, run_id, group_key, payload, state, attempts, session_id, result, error, created_at, updated_at`

func scanAutomationWorkItemRow(rows db.Rows) (*model.AutomationWorkItem, error) {
	item := &model.AutomationWorkItem{}

	var state string
	var runId, sessionId, failure *string
	var payload, result []byte

	err := rows.Scan(&item.Id, &item.AutomationId, &runId, &item.GroupKey, &payload, &state,
		&item.Attempts, &sessionId, &result, &failure, &item.CreateTime, &item.UpdateTime)
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

	if sessionId != nil {
		item.SessionId = *sessionId
	}

	if failure != nil {
		item.Error = *failure
	}

	return item, nil
}

// EnsureAutomationWorkItems enqueues a batch, skipping any group that already has an item
// in flight, so a kind that died partway through enqueueing can simply enqueue again.
//
// It returns the items it inserted, not every item for the given groups: the caller wants
// the work that is newly its own to submit, and anything skipped is already queued or
// running somewhere.
func (s *Store) EnsureAutomationWorkItems(ctx context.Context, runId string, items []*model.AutomationWorkItem) ([]*model.AutomationWorkItem, error) {
	if len(items) == 0 {
		return nil, nil
	}

	automationId := items[0].AutomationId
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
// the attempt. It returns nil when there is nothing to claim.
//
// It deliberately does not filter on attempts. Retry policy belongs to the kind, and an
// item the store refused to hand out would sit pending forever: unclaimable, yet still in
// the open set blocking its group from being enqueued again. Claiming unconditionally means
// every item can always be driven to a terminal state, so the caller checks Attempts on
// what it receives and either runs the work or gives up on it.
func (s *Store) ClaimNextAutomationWorkItem(ctx context.Context, automationId string) (*model.AutomationWorkItem, error) {
	rows, err := s.db.Query(ctx, `
		UPDATE automation_work_items
		SET state = 'running', attempts = attempts + 1,
		    session_id = NULL, result = NULL, error = NULL, updated_at = now()
		WHERE id = (
			SELECT id FROM automation_work_items
			WHERE automation_id = $1 AND state = 'pending'
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+automationWorkItemColumns,
		automationId)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if !rows.Next() {
		return nil, rows.Err()
	}

	return scanAutomationWorkItemRow(rows)
}

// SetAutomationWorkItemSession records the session analyzing a claimed item, so work
// interrupted mid-flight can still be traced to its transcript.
func (s *Store) SetAutomationWorkItemSession(ctx context.Context, itemId, sessionId string) error {
	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET session_id = $2, updated_at = now()
		WHERE id = $1
		RETURNING id`, itemId, sessionId)
}

// MarkAutomationWorkItemApplying stores the kind's conclusion and moves the item to
// applying in one statement. Everything past this point is replayable from the stored
// result, which is why reconciliation leaves applying items alone.
func (s *Store) MarkAutomationWorkItemApplying(ctx context.Context, itemId string, result json.RawMessage) error {
	var stored any
	if len(result) > 0 {
		stored = string(result)
	}

	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET state = 'applying', result = $2::jsonb, updated_at = now()
		WHERE id = $1
		RETURNING id`, itemId, stored)
}

func (s *Store) CompleteAutomationWorkItem(ctx context.Context, itemId string) error {
	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET state = 'done', error = NULL, updated_at = now()
		WHERE id = $1
		RETURNING id`, itemId)
}

// RequeueAutomationWorkItem returns a claimed item to the queue after a failure it may
// recover from. attempts is deliberately left alone: the claim already counted this try.
func (s *Store) RequeueAutomationWorkItem(ctx context.Context, itemId, cause string) error {
	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET state = 'pending', session_id = NULL, result = NULL,
		    error = NULLIF($2, ''), updated_at = now()
		WHERE id = $1
		RETURNING id`, itemId, cause)
}

// FailAutomationWorkItem ends an item for good. Reserved for a failure retrying cannot
// fix, and for the caller giving up after too many attempts; a retryable failure goes
// through RequeueAutomationWorkItem instead.
//
// The caller must have stamped this item's alerts before calling: an item that goes
// terminal with its alerts unstamped is re-found by the next scan, enqueued as a fresh
// item with attempts back at zero, and retried forever.
func (s *Store) FailAutomationWorkItem(ctx context.Context, itemId, cause string) error {
	return s.transitionWorkItem(ctx, `
		UPDATE automation_work_items
		SET state = 'failed', error = NULLIF($2, ''), updated_at = now()
		WHERE id = $1
		RETURNING id`, itemId, cause)
}

// transitionWorkItem runs a statement that returns the id it changed, so a write against
// a vanished item is an error rather than a silent no-op -- db.DB.Exec discards the
// rows-affected count, so RETURNING is the only way to tell.
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

		return ErrAutomationWorkItemGone
	}

	return nil
}

// ListOpenAutomationWorkItems returns every unfinished item for one automation, oldest
// first: what an earlier process left behind plus anything the current run enqueued.
func (s *Store) ListOpenAutomationWorkItems(ctx context.Context, automationId string) ([]*model.AutomationWorkItem, error) {
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

// ListAutomationWorkItems returns the items one run created, for the run detail view.
func (s *Store) ListAutomationWorkItems(ctx context.Context, runId string) ([]*model.AutomationWorkItem, error) {
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
