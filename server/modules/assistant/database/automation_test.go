// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Identity is a UUID, matching the column type these ids are bound into.
const (
	testAutomationId  = "5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90"
	otherAutomationId = "1d7e3a44-88b6-4c0f-9a21-70f5e9c3b812"
	testRunId         = "3f1a7c0e-9b21-4d8a-bc55-2e77a1f0c934"
)

// assertNoStatements fails when a guard let a call through.
func assertNoStatements(t *testing.T, mDB *mockdb.MockDB) {
	t.Helper()

	assert.Empty(t, mDB.Calls, "the guard must return before touching the database")
}

// erroringRow returns a Row whose Scan fails, for the pg error-mapping tests.
func erroringRow(err error) *mockdb.MockRow {
	mRow := &mockdb.MockRow{}
	mRow.On("Scan", anyArgs(9)...).Return(err)

	return mRow
}

// emptyRows returns a Rows that yields nothing, which is how every conditional write
// reports "no row matched".
func emptyRows() *mockdb.MockRows {
	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	return mRows
}

func TestOpenAutomationRunInFlight(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO automation_runs"), testAutomationId, "").
		Return(erroringRow(&pgconn.PgError{Code: "23505", ConstraintName: idxRunsOneInFlight}))

	run, err := s.OpenAutomationRun(context.Background(), testAutomationId, "")

	assert.Nil(t, run)
	assert.ErrorIs(t, err, ErrAutomationRunInFlight)
	mDB.AssertExpectations(t)
}

// A foreign-key or any other pg failure must not be reported as "already running";
// only the in-flight index means that.
func TestOpenAutomationRunPassesOtherErrorsThrough(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	fkViolation := &pgconn.PgError{Code: "23503"}
	mDB.On("QueryRow", mock.Anything, mock.Anything, testAutomationId, "").Return(erroringRow(fkViolation))

	_, err := s.OpenAutomationRun(context.Background(), testAutomationId, "")

	assert.NotErrorIs(t, err, ErrAutomationRunInFlight)
	assert.ErrorIs(t, err, fkViolation)
}

// Two unique indexes can fire on one statement, so the constraint name is what makes
// the mapping specific rather than the 23505 alone.
func TestOpenAutomationRunIgnoresOtherUniqueViolations(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, testAutomationId, "").
		Return(erroringRow(&pgconn.PgError{Code: "23505", ConstraintName: "some_other_index"}))

	_, err := s.OpenAutomationRun(context.Background(), testAutomationId, "")

	assert.NotErrorIs(t, err, ErrAutomationRunInFlight)
}

func TestOpenAutomationRunRequiresAnAutomationId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.OpenAutomationRun(context.Background(), "", "")

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

func TestCloseAutomationRunTwiceReports(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "run-1", "failed", "boom").Return(emptyRows(), nil)

	err := s.CloseAutomationRun(context.Background(), "run-1", model.AutomationRunFailed, "boom")

	assert.ErrorIs(t, err, ErrAutomationRunNotOpen)
}

func TestCloseAutomationRunRejectsNonTerminalState(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	err := s.CloseAutomationRun(context.Background(), "run-1", model.AutomationRunRunning, "")

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

func TestClaimNextAutomationWorkItemUsesSkipLocked(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	// SKIP LOCKED is what keeps two pool goroutines inside one run from claiming the
	// same item.
	claim := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "FOR UPDATE SKIP LOCKED") &&
			strings.Contains(sql, "attempts = attempts + 1") &&
			strings.Contains(sql, "ORDER BY created_at")
	})

	mDB.On("Query", mock.Anything, claim, testAutomationId, testRunId, 3).Return(emptyRows(), nil)

	item, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId, 3)

	assert.Nil(t, item)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

// A run never retries what it failed, and nothing retries an item out of failed runs.
func TestClaimNextAutomationWorkItemSkipsFailedRuns(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	claim := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "AND NOT ($2::text = ANY(failed_run_ids))") &&
			strings.Contains(sql, "AND cardinality(failed_run_ids) < $3")
	})

	mDB.On("Query", mock.Anything, claim, testAutomationId, testRunId, 5).Return(emptyRows(), nil)

	_, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId, 5)
	require.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestFailAutomationWorkItemRunRecordsTheRun(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	// Appending only when absent keeps a replayed write from spending a second retry.
	fail := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "WHEN run_id IS NULL OR run_id::text = ANY(failed_run_ids)") &&
			strings.Contains(sql, "ELSE array_append(failed_run_ids, run_id::text) END") &&
			strings.Contains(sql, "state = 'pending', result = NULL") &&
			strings.Contains(sql, "WHERE id = $1 AND state = 'running'") &&
			!strings.Contains(sql, "attempts =")
	})

	mRows := automationWorkItemRows(automationWorkItemRow{
		id:           "item-1",
		payload:      []byte(`{}`),
		state:        string(model.AutomationWorkItemPending),
		failedRunIds: []string{testRunId},
	})

	mDB.On("Query", mock.Anything, fail, "item-1", "boom").Return(mRows, nil)

	item, err := s.FailAutomationWorkItemRun(context.Background(), "item-1", "boom")
	require.NoError(t, err)
	assert.Equal(t, model.AutomationWorkItemPending, item.State)
	assert.Equal(t, []string{testRunId}, item.FailedRunIds)
	mDB.AssertExpectations(t)
}

func TestFailAutomationWorkItemRunOnVanishedItem(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "item-1", "boom").Return(emptyRows(), nil)

	_, err := s.FailAutomationWorkItemRun(context.Background(), "item-1", "boom")
	assert.ErrorIs(t, err, ErrAutomationWorkItemNotFound)
}

func TestFailAutomationWorkItemRunRequiresAnId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.FailAutomationWorkItemRun(context.Background(), "", "boom")
	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

// A failed apply charges the run that tried it, not the row's run_id, which is the run that
// produced the checkpoint; the checkpoint itself stays for the next run to replay.
func TestFailAutomationWorkItemApplyRecordsTheRun(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	fail := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "WHEN $2 = ANY(failed_run_ids)") &&
			strings.Contains(sql, "ELSE array_append(failed_run_ids, $2) END") &&
			strings.Contains(sql, "WHERE id = $1 AND state = 'applying'") &&
			!strings.Contains(sql, "SET state") &&
			!strings.Contains(sql, "result =") &&
			!strings.Contains(sql, "attempts =")
	})

	mRows := automationWorkItemRows(automationWorkItemRow{
		id:           "item-1",
		payload:      []byte(`{}`),
		state:        string(model.AutomationWorkItemApplying),
		failedRunIds: []string{"run-0", testRunId},
	})

	mDB.On("Query", mock.Anything, fail, "item-1", testRunId, "boom").Return(mRows, nil)

	item, err := s.FailAutomationWorkItemApply(context.Background(), "item-1", testRunId, "boom")
	require.NoError(t, err)
	assert.Equal(t, model.AutomationWorkItemApplying, item.State)
	assert.Equal(t, []string{"run-0", testRunId}, item.FailedRunIds)
	mDB.AssertExpectations(t)
}

func TestFailAutomationWorkItemApplyOnVanishedItem(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "item-1", testRunId, "boom").Return(emptyRows(), nil)

	_, err := s.FailAutomationWorkItemApply(context.Background(), "item-1", testRunId, "boom")
	assert.ErrorIs(t, err, ErrAutomationWorkItemNotFound)
}

func TestFailAutomationWorkItemApplyRequiresIds(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.FailAutomationWorkItemApply(context.Background(), "", testRunId, "boom")
	assert.Error(t, err)

	_, err = s.FailAutomationWorkItemApply(context.Background(), "item-1", "", "boom")
	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

// Requeueing must preserve attempts and failures: a requeue is not a failure, and must not
// forgive one either.
func TestRequeueAutomationWorkItemKeepsAttempts(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	requeue := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "ELSE 'pending' END") &&
			strings.Contains(sql, "ELSE NULL END")
	})

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Once()
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, requeue, "item-1", "truncated").Return(mRows, nil)

	require.NoError(t, s.RequeueAutomationWorkItem(context.Background(), "item-1", "truncated"))

	// session_ids is what keeps a failed try's transcript reachable.
	resets := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "attempts") || strings.Contains(sql, "session_ids") ||
			strings.Contains(sql, "failed_run_ids")
	})
	mDB.AssertNotCalled(t, "Query", mock.Anything, resets, mock.Anything, mock.Anything)
}

// An applying item's result is its checkpoint; requeueing it would forfeit the session it
// already paid for. It stays applying so the next run replays only the update.
func TestRequeueAutomationWorkItemLeavesApplyingInPlace(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	keepsApplying := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "state = CASE WHEN state = 'applying' THEN state") &&
			strings.Contains(sql, "result = CASE WHEN state = 'applying' THEN result")
	})

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Once()
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, keepsApplying, "item-1", "update failed").Return(mRows, nil)

	require.NoError(t, s.RequeueAutomationWorkItem(context.Background(), "item-1", "update failed"))
	mDB.AssertExpectations(t)
}

func TestRequeueAutomationWorkItemOnVanishedItem(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "item-1", "boom").Return(emptyRows(), nil)

	err := s.RequeueAutomationWorkItem(context.Background(), "item-1", "boom")

	assert.ErrorIs(t, err, ErrAutomationWorkItemNotFound)
}

func TestEnsureAutomationWorkItemsEmptyBatchTouchesNothing(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	items, err := s.EnsureAutomationWorkItems(context.Background(), "run-1", nil)

	assert.Nil(t, items)
	assert.NoError(t, err)
	assertNoStatements(t, mDB)
}

// ON CONFLICT infers a partial unique index only from an identical predicate, so the
// statement builds its clause from the same constant the migration is checked against.
func TestEnsureAutomationWorkItemsIsIdempotent(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	upsert := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "ON CONFLICT (automation_id, group_key) WHERE state IN "+openWorkItemStates) &&
			strings.Contains(sql, "DO NOTHING")
	})

	mDB.On("Query", mock.Anything, upsert, testAutomationId, "run-1",
		[]string{"group-a"}, []string{`{"ids":["1"]}`}).Return(emptyRows(), nil)

	items, err := s.EnsureAutomationWorkItems(context.Background(), "run-1", []*model.AutomationWorkItem{
		{AutomationId: testAutomationId, GroupKey: "group-a", Payload: json.RawMessage(`{"ids":["1"]}`)},
	})

	require.NoError(t, err)
	assert.Empty(t, items)
	mDB.AssertExpectations(t)
}

// A nil payload cannot bind as an empty string: jsonb rejects it.
func TestEnsureAutomationWorkItemsDefaultsNilPayload(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, testAutomationId, "run-1",
		[]string{"group-a"}, []string{"{}"}).Return(emptyRows(), nil)

	_, err := s.EnsureAutomationWorkItems(context.Background(), "run-1",
		[]*model.AutomationWorkItem{{AutomationId: testAutomationId, GroupKey: "group-a"}})

	require.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestEnsureAutomationWorkItemsRejectsMixedAutomations(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.EnsureAutomationWorkItems(context.Background(), "run-1", []*model.AutomationWorkItem{
		{AutomationId: testAutomationId, GroupKey: "a"},
		{AutomationId: otherAutomationId, GroupKey: "b"},
	})

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

// The conclusion must be stored byte-for-byte: it is the kind's own structured output
// and the apply step parses it back.
func TestMarkAutomationWorkItemApplyingStoresResultVerbatim(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	result := json.RawMessage(`{"recommendation":"acknowledge","reason":"benign"}`)

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Once()
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, sqlContains("state = 'applying'"), "item-1", string(result)).
		Return(mRows, nil)

	require.NoError(t, s.MarkAutomationWorkItemApplying(context.Background(), "item-1", result))
	mDB.AssertExpectations(t)
}

// A re-pin replaces the payload of the item the job holds, and nothing else: no state, no
// result, no failure accounting.
func TestUpdateAutomationWorkItemPayloadStoresItVerbatim(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	payload := json.RawMessage(`{"groupFilter":"tags:alert","latestAlertId":"alert-2"}`)

	stmt := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SET payload = $2::jsonb") &&
			strings.Contains(sql, "WHERE id = $1 AND state = 'running'") &&
			!strings.Contains(sql, "SET state") &&
			!strings.Contains(sql, "result =") &&
			!strings.Contains(sql, "failed_run_ids")
	})

	mDB.On("Query", mock.Anything, stmt, "item-1", string(payload)).Return(rowsYielding(1), nil)

	require.NoError(t, s.UpdateAutomationWorkItemPayload(context.Background(), "item-1", payload))
	mDB.AssertExpectations(t)
}

func TestUpdateAutomationWorkItemPayloadOnVanishedItem(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "item-1", `{}`).Return(emptyRows(), nil)

	err := s.UpdateAutomationWorkItemPayload(context.Background(), "item-1", json.RawMessage(`{}`))
	assert.ErrorIs(t, err, ErrAutomationWorkItemNotFound)
}

func TestUpdateAutomationWorkItemPayloadRefusesAnEmptyPayload(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	assert.Error(t, s.UpdateAutomationWorkItemPayload(context.Background(), "item-1", nil))
	assert.Error(t, s.UpdateAutomationWorkItemPayload(context.Background(), "", json.RawMessage(`{}`)))
	assertNoStatements(t, mDB)
}

// Moving to applying is the checkpoint the apply step resumes from, so an item parked there
// with nothing stored would be unrecoverable: reconciliation leaves applying items alone.
func TestMarkAutomationWorkItemApplyingRefusesAnEmptyResult(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	assert.Error(t, s.MarkAutomationWorkItemApplying(context.Background(), "item-1", nil))
	assertNoStatements(t, mDB)
}

// Every transition guards the state it is legal from, so a replayed call cannot pull a
// finished item back out and hand its group a second session.
func TestWorkItemTransitionsGuardTheirFromState(t *testing.T) {
	guards := map[string]struct {
		states string
		call   func(*Store) error
	}{
		"applying": {claimedWorkItemStates, func(s *Store) error {
			return s.MarkAutomationWorkItemApplying(context.Background(), "item-1", json.RawMessage(`{"ok":true}`))
		}},
		"complete": {claimedWorkItemStates, func(s *Store) error {
			return s.CompleteAutomationWorkItem(context.Background(), "item-1")
		}},
		"requeue": {claimedWorkItemStates, func(s *Store) error {
			return s.RequeueAutomationWorkItem(context.Background(), "item-1", "truncated")
		}},
		"fail": {openWorkItemStates, func(s *Store) error {
			return s.FailAutomationWorkItem(context.Background(), "item-1", "gave up")
		}},
		"session": {openWorkItemStates, func(s *Store) error {
			return s.EnsureAutomationWorkItemSession(context.Background(), "item-1", "session-9")
		}},
	}

	for name, guard := range guards {
		t.Run(name, func(t *testing.T) {
			mDB := &mockdb.MockDB{}
			s := &Store{db: mDB}

			mDB.On("Query", mock.Anything, sqlContains("state IN "+guard.states), mock.Anything, mock.Anything).
				Return(emptyRows(), nil).Maybe()
			mDB.On("Query", mock.Anything, sqlContains("state IN "+guard.states), mock.Anything).
				Return(emptyRows(), nil).Maybe()

			// A guarded statement that matches nothing reports it rather than passing.
			assert.ErrorIs(t, guard.call(s), ErrAutomationWorkItemNotFound)
			mDB.AssertExpectations(t)
		})
	}
}

func TestWorkItemTransitionOnVanishedItem(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "item-1").Return(emptyRows(), nil)

	err := s.CompleteAutomationWorkItem(context.Background(), "item-1")

	assert.ErrorIs(t, err, ErrAutomationWorkItemNotFound)
}

func TestWorkItemTransitionRequiresAnId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	assert.Error(t, s.CompleteAutomationWorkItem(context.Background(), ""))
	assertNoStatements(t, mDB)
}

func TestReconcileAutomationRunsSweepsEveryOpenRun(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)

	openRuns := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "UPDATE automation_runs") &&
			strings.Contains(sql, "WHERE ended_at IS NULL") &&
			strings.Contains(sql, "SET state = 'failed'")
	})

	mTx.On("Query", mock.Anything, stoppingRunsSql(), "").Return(emptyRows(), nil).Once()
	mTx.On("Query", mock.Anything, openRuns).Return(emptyRows(), nil).Once()
	mTx.On("Query", mock.Anything, sqlContains("UPDATE automation_work_items")).
		Return(emptyRows(), nil)

	_, err := s.ReconcileAutomationRuns(context.Background())

	require.NoError(t, err)
	mTx.AssertExpectations(t)
}

func TestReconcileAutomationRunsCounts(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)

	mTx.On("Query", mock.Anything, stoppingRunsSql(), "").Return(runIdRows("run-s"), nil)
	mTx.On("Query", mock.Anything, sqlContains("run_id::text = ANY($2::text[])"), "ERROR_AUTOMATION_RUN_STOPPED", []string{"run-s"}).
		Return(rowsYielding(1), nil)
	mTx.On("Query", mock.Anything, sqlContains("SET state = 'failed'")).Return(rowsYielding(2), nil)
	mTx.On("Query", mock.Anything, sqlContains("WHERE state = 'running'")).Return(rowsYielding(3), nil)

	result, err := s.ReconcileAutomationRuns(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 2, result.FailedRuns)
	assert.Equal(t, 1, result.StoppedRuns)
	assert.Equal(t, 4, result.ResetItems, "items from stopped and failed runs both go back to pending")
	mTx.AssertExpectations(t)
	assertPlaceholdersBound(t, &mTx.Mock)
}

// Items left applying already hold their conclusion, so resuming them costs no second
// session. Touching them here would throw that away and pay for the LLM twice.
func TestReconcileAutomationRunsLeavesApplyingItemsAlone(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, stoppingRunsSql(), "").Return(emptyRows(), nil)
	mTx.On("Query", mock.Anything, mock.Anything).Return(emptyRows(), nil)

	_, err := s.ReconcileAutomationRuns(context.Background())
	require.NoError(t, err)

	touchesApplying := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "state = 'applying'")
	})
	mTx.AssertNotCalled(t, "Query", mock.Anything, touchesApplying)
}

// The reset must not count the attempt again: the claim that died already did, and
// double counting halves the retry budget.
func TestReconcileAutomationRunsDoesNotRecountAttempts(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, stoppingRunsSql(), "").Return(emptyRows(), nil)
	mTx.On("Query", mock.Anything, mock.Anything).Return(emptyRows(), nil)

	_, err := s.ReconcileAutomationRuns(context.Background())
	require.NoError(t, err)

	recounts := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "attempts")
	})
	mTx.AssertNotCalled(t, "Query", mock.Anything, recounts)
}

// The run that died failed its item; without that a payload that kills the process would be
// retried on every start.
func TestReconcileAutomationRunsCountsTheDeadRunAsFailed(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, stoppingRunsSql(), "").Return(emptyRows(), nil)
	mTx.On("Query", mock.Anything, mock.Anything).Return(emptyRows(), nil)

	_, err := s.ReconcileAutomationRuns(context.Background())
	require.NoError(t, err)

	records := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "WHERE state = 'running'") &&
			strings.Contains(sql, "ELSE array_append(failed_run_ids, run_id::text) END")
	})
	mTx.AssertCalled(t, "Query", mock.Anything, records)
}

// A partial reconcile is worse than none: it would leave items owned by a process that
// is gone while a new run starts alongside them.
func TestReconcileAutomationRunsRollsBackOnFailure(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, stoppingRunsSql(), "").Return(emptyRows(), nil)
	mTx.On("Query", mock.Anything, sqlContains("UPDATE automation_runs")).Return(rowsYielding(1), nil)
	mTx.On("Query", mock.Anything, sqlContains("UPDATE automation_work_items")).
		Return((*mockdb.MockRows)(nil), errors.New("connection lost"))

	_, err := s.ReconcileAutomationRuns(context.Background())

	assert.Error(t, err)
	mTx.AssertNotCalled(t, "Commit")
	mTx.AssertCalled(t, "Rollback", mock.Anything)
}

func rowsYielding(n int) *mockdb.MockRows {
	mRows := &mockdb.MockRows{}

	for i := 0; i < n; i++ {
		mRows.On("Next").Return(true).Once()
	}

	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	return mRows
}

// Appending rather than overwriting is what keeps a failed attempt's transcript reachable:
// each claim starts a fresh root session, and the previous one is only findable from here.
func TestEnsureAutomationWorkItemSessionAppends(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	appendOnly := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "array_append(session_ids, $2)") &&
			strings.Contains(sql, "$2 = ANY(session_ids)")
	})

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Once()
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, appendOnly, "item-1", "session-9").Return(mRows, nil)

	require.NoError(t, s.EnsureAutomationWorkItemSession(context.Background(), "item-1", "session-9"))
	mDB.AssertExpectations(t)
}

// The claim starts a new attempt, so it clears the previous conclusion -- but not the
// session history, which is the record of what earlier attempts did.
func TestClaimNextAutomationWorkItemKeepsSessionHistory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, testAutomationId, testRunId, 3).Return(emptyRows(), nil)

	_, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId, 3)
	require.NoError(t, err)

	clearsSessions := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "session_ids = NULL") ||
			strings.Contains(sql, "session_ids = '{}'")
	})
	mDB.AssertNotCalled(t, "Query", mock.Anything, clearsSessions, mock.Anything)
}

// The claiming run takes ownership, so a run that resumes an item another run enqueued is
// credited with the work rather than the dead run that found it.
func TestClaimNextAutomationWorkItemTakesOverTheRun(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, sqlContains("run_id = $2"), testAutomationId, testRunId, 3).
		Return(emptyRows(), nil)

	_, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId, 3)

	require.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestClaimNextAutomationWorkItemRequiresARunId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, "", 3)

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

// error is the failure reason, so a run that succeeded records none even when the caller
// passes one.
func TestCloseAutomationRunDropsTheCauseOnSuccess(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "run-1", "succeeded", "").Return(emptyRows(), nil)

	err := s.CloseAutomationRun(context.Background(), "run-1", model.AutomationRunSucceeded, "boom")

	assert.ErrorIs(t, err, ErrAutomationRunNotOpen)
	mDB.AssertExpectations(t)
}

func TestGetAutomationRunRequiresAnId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.GetAutomationRun(context.Background(), "")

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

func TestListOpenAutomationWorkItemsRequiresAnAutomationId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.ListOpenAutomationWorkItems(context.Background(), "")

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

func TestEnsureAutomationWorkItemsRequiresAnAutomationId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.EnsureAutomationWorkItems(context.Background(), "run-1",
		[]*model.AutomationWorkItem{{GroupKey: "group-a"}})

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

func TestFailStaleAutomationWorkItemsRequiresAnAutomationId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.FailStaleAutomationWorkItems(context.Background(), "", "cause")

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

// applying is the state the sweep must not reach: its conclusion is already paid for and
// its alerts still need stamping.
func TestFailStaleAutomationWorkItemsSparesApplying(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	stale := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "UPDATE automation_work_items") &&
			strings.Contains(sql, "state = 'failed'") &&
			strings.Contains(sql, "state IN "+staleWorkItemStates) &&
			!strings.Contains(sql, "applying")
	})

	mDB.On("Query", mock.Anything, stale, testAutomationId, "ERROR_AUTOMATION_PARAMS_CHANGED").
		Return(rowsYielding(3), nil)

	failed, err := s.FailStaleAutomationWorkItems(context.Background(), testAutomationId,
		"ERROR_AUTOMATION_PARAMS_CHANGED")

	require.NoError(t, err)
	assert.Equal(t, 3, failed)
	mDB.AssertExpectations(t)
}

func TestFailPendingAutomationWorkItemsRequiresAnAutomationId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.FailPendingAutomationWorkItems(context.Background(), "", "cause")

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

// A delete leaves a run that already claimed its item alone, so running must stay out of it.
func TestFailPendingAutomationWorkItemsSparesRunning(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	pending := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "UPDATE automation_work_items") &&
			strings.Contains(sql, "state = 'failed'") &&
			strings.Contains(sql, "state IN "+pendingWorkItemStates) &&
			!strings.Contains(sql, "running")
	})

	mDB.On("Query", mock.Anything, pending, testAutomationId, "ERROR_AUTOMATION_DELETED").
		Return(rowsYielding(2), nil)

	failed, err := s.FailPendingAutomationWorkItems(context.Background(), testAutomationId,
		"ERROR_AUTOMATION_DELETED")

	require.NoError(t, err)
	assert.Equal(t, 2, failed)
	mDB.AssertExpectations(t)
}

// An orphan has no run left to resume its apply step, so unlike the per-automation sweeps
// this one has to reach applying too.
func TestFailOrphanedAutomationWorkItemsIncludesApplying(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	orphaned := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "UPDATE automation_work_items") &&
			strings.Contains(sql, "state = 'failed'") &&
			strings.Contains(sql, "state IN "+openWorkItemStates) &&
			strings.Contains(sql, "NOT (automation_id = ANY($1::uuid[]))")
	})

	live := []string{testAutomationId}

	mDB.On("Query", mock.Anything, orphaned, live, "ERROR_AUTOMATION_DELETED").
		Return(rowsYielding(4), nil)

	failed, err := s.FailOrphanedAutomationWorkItems(context.Background(), live,
		"ERROR_AUTOMATION_DELETED")

	require.NoError(t, err)
	assert.Equal(t, 4, failed)
	mDB.AssertExpectations(t)
}

// The per-tick sweep only reaches unclaimed work, so a run still under way for a removed
// automation keeps what it holds.
func TestFailOrphanedPendingAutomationWorkItemsLeavesClaimedWork(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	orphaned := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "state IN "+pendingWorkItemStates) &&
			strings.Contains(sql, "NOT (automation_id = ANY($1::uuid[]))")
	})

	live := []string{testAutomationId}

	mDB.On("Query", mock.Anything, orphaned, live, "ERROR_AUTOMATION_DELETED").
		Return(rowsYielding(1), nil)

	failed, err := s.FailOrphanedPendingAutomationWorkItems(context.Background(), live,
		"ERROR_AUTOMATION_DELETED")

	require.NoError(t, err)
	assert.Equal(t, 1, failed)
	mDB.AssertExpectations(t)
}

// No automation is defined, so every open item is orphaned. The empty list has to reach the
// statement as an empty array rather than being treated as "no filter".
func TestFailOrphanedAutomationWorkItemsSweepsAllWhenNothingIsLive(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	live := []string{}

	mDB.On("Query", mock.Anything, mock.Anything, live, "ERROR_AUTOMATION_DELETED").
		Return(rowsYielding(2), nil)

	failed, err := s.FailOrphanedAutomationWorkItems(context.Background(), live,
		"ERROR_AUTOMATION_DELETED")

	require.NoError(t, err)
	assert.Equal(t, 2, failed)
	mDB.AssertExpectations(t)
}

func TestFailAbandonedAutomationRunRequiresAnAutomationId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.FailAbandonedAutomationRun(context.Background(), "", "abandoned")

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

// Only an open row of that automation is touched; the cause is what the run history shows.
func TestFailAbandonedAutomationRunCounts(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, stoppingRunsSql(), "", testAutomationId).Return(emptyRows(), nil)
	mTx.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "SET state = 'failed'") &&
			strings.Contains(sql, "WHERE automation_id = $1 AND ended_at IS NULL")
	}), testAutomationId, "abandoned").Return(rowsYielding(1), nil)

	failed, err := s.FailAbandonedAutomationRun(context.Background(), testAutomationId, "abandoned")

	require.NoError(t, err)
	assert.Equal(t, 1, failed)
	mTx.AssertExpectations(t)
}

// A stopping row whose close never landed must not be charged as abandoned: its items go
// back uncharged and it ends stopped at its stop time, before the failing sweep runs.
func TestFailAbandonedAutomationRunClosesAStoppingRowAsStopped(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}
	changes := 0
	s.OnAutomationChange(func() { changes++ })

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, sqlContainsAll(append(stoppingRunsSqlFragments, "automation_id = $2::uuid AND stopped_by IS NOT NULL")...),
		"", testAutomationId).Return(runIdRows(testRunId), nil).Once()
	mTx.On("Query", mock.Anything, requeueStoppedItemsSql(), "ERROR_AUTOMATION_RUN_STOPPED", []string{testRunId}).
		Return(rowsYielding(2), nil).Once()
	mTx.On("Query", mock.Anything, sqlContains("SET state = 'failed'"), testAutomationId, "abandoned").
		Return(emptyRows(), nil).Once()

	closed, err := s.FailAbandonedAutomationRun(context.Background(), testAutomationId, "abandoned")

	require.NoError(t, err)
	assert.Equal(t, 1, closed)
	assert.Equal(t, 1, changes)
	mTx.AssertExpectations(t)
	assertPlaceholdersBound(t, &mTx.Mock)
}

func TestFailAbandonedAutomationRunRollsBackAStoppingCloseOnFailure(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, stoppingRunsSql(), "", testAutomationId).Return(runIdRows(testRunId), nil)
	mTx.On("Query", mock.Anything, requeueStoppedItemsSql(), mock.Anything, mock.Anything).
		Return((*mockdb.MockRows)(nil), errors.New("connection lost"))

	_, err := s.FailAbandonedAutomationRun(context.Background(), testAutomationId, "abandoned")

	assert.Error(t, err)
	mTx.AssertNotCalled(t, "Commit", mock.Anything)
	mTx.AssertCalled(t, "Rollback", mock.Anything)
}

func TestAutomationWritesReportOnlyRealChanges(t *testing.T) {
	ctx := context.Background()
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}
	changes := 0
	s.OnAutomationChange(func() { changes++ })

	mDB.On("Query", mock.Anything, mock.Anything, "item-1").Return(rowsYielding(1), nil).Once()
	require.NoError(t, s.CompleteAutomationWorkItem(ctx, "item-1"))
	assert.Equal(t, 1, changes)

	mDB.On("Query", mock.Anything, mock.Anything, "gone").Return(emptyRows(), nil).Once()
	assert.ErrorIs(t, s.CompleteAutomationWorkItem(ctx, "gone"), ErrAutomationWorkItemNotFound)
	assert.Equal(t, 1, changes, "a write that matched nothing changed nothing")

	mDB.On("Query", mock.Anything, mock.Anything, testAutomationId, "stale").Return(rowsYielding(0), nil).Once()
	_, err := s.FailStaleAutomationWorkItems(ctx, testAutomationId, "stale")
	require.NoError(t, err)
	assert.Equal(t, 1, changes)

	mDB.On("Query", mock.Anything, mock.Anything, otherAutomationId, "stale").Return(rowsYielding(2), nil).Once()
	_, err = s.FailStaleAutomationWorkItems(ctx, otherAutomationId, "stale")
	require.NoError(t, err)
	assert.Equal(t, 2, changes)

	mDB.On("Query", mock.Anything, mock.Anything, testAutomationId, testRunId, 3).Return(emptyRows(), nil).Once()
	item, err := s.ClaimNextAutomationWorkItem(ctx, testAutomationId, testRunId, 3)
	require.NoError(t, err)
	assert.Nil(t, item)
	assert.Equal(t, 2, changes, "nothing to claim")
}

// The statement every stopped close runs. The fragments pin what makes it correct: the first
// stopper and stop time survive, and ended_at reads stopped_at's pre-update value.
var stoppingRunsSqlFragments = []string{
	"UPDATE automation_runs",
	"SET state = 'stopped'",
	"stopped_by = COALESCE(stopped_by, NULLIF($1, ''))",
	"stopped_at = COALESCE(stopped_at, now())",
	"ended_at = COALESCE(stopped_at, now())",
	"WHERE ended_at IS NULL AND",
}

func stoppingRunsSql() any {
	return sqlContainsAll(stoppingRunsSqlFragments...)
}

var sqlPlaceholder = regexp.MustCompile(`\$(\d+)`)

// assertPlaceholdersBound checks every statement m received references each argument it was
// given, and no more. Postgres refuses to prepare a statement with an unreferenced argument,
// and a mock accepts it.
func assertPlaceholdersBound(t assert.TestingT, m *mock.Mock) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	for _, call := range m.Calls {
		if call.Method != "Query" && call.Method != "QueryRow" && call.Method != "Exec" {
			continue
		}

		sql := call.Arguments.String(1)
		argCount := len(call.Arguments) - 2
		referenced := map[int]bool{}

		for _, match := range sqlPlaceholder.FindAllStringSubmatch(sql, -1) {
			n, _ := strconv.Atoi(match[1])
			referenced[n] = true
		}

		for n := 1; n <= argCount; n++ {
			assert.True(t, referenced[n], "argument $%d is never referenced in:%s", n, sql)
		}

		for n := range referenced {
			assert.LessOrEqual(t, n, argCount, "placeholder $%d has no argument in:%s", n, sql)
		}
	}
}

func TestAssertPlaceholdersBound(t *testing.T) {
	bound := &mock.Mock{}
	bound.Calls = []mock.Call{{Method: "Query", Arguments: mock.Arguments{nil, "SELECT $1, $2", "a", "b"}}}
	assertPlaceholdersBound(t, bound)

	for name, args := range map[string]mock.Arguments{
		"unreferenced argument": {nil, "SELECT $2", "a", "b"},
		"missing argument":      {nil, "SELECT $1, $2", "a"},
	} {
		inner := &failureRecorder{}
		unbound := &mock.Mock{}
		unbound.Calls = []mock.Call{{Method: "Query", Arguments: args}}
		assertPlaceholdersBound(inner, unbound)
		assert.True(t, inner.failed, name)
	}
}

type failureRecorder struct {
	failed bool
}

func (r *failureRecorder) Errorf(string, ...any) {
	r.failed = true
}

// Only running items of the stopped runs, and failed_run_ids untouched, so nothing is charged.
func requeueStoppedItemsSql() any {
	return mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "UPDATE automation_work_items") &&
			strings.Contains(sql, "SET state = 'pending', run_id = NULL") &&
			strings.Contains(sql, "WHERE state = 'running' AND run_id::text = ANY($2::text[])") &&
			!strings.Contains(sql, "failed_run_ids")
	})
}

// runIdRows yields one RETURNING id::text row per id.
func runIdRows(ids ...string) *mockdb.MockRows {
	mRows := &mockdb.MockRows{}

	for _, id := range ids {
		mRows.On("Next").Return(true).Once()
		mRows.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
			*(args.Get(0).(*string)) = id
		}).Return(nil).Once()
	}

	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	return mRows
}

func TestMarkAutomationRunStoppingKeepsTheFirstStopper(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}
	changes := 0
	s.OnAutomationChange(func() { changes++ })

	mark := sqlContainsAll("SET stopped_by = NULLIF($2, ''), stopped_at = now()",
		"WHERE id = $1 AND ended_at IS NULL AND stopped_by IS NULL")

	mDB.On("Query", mock.Anything, mark, testRunId, "user-1").Return(rowsYielding(1), nil).Once()
	require.NoError(t, s.MarkAutomationRunStopping(context.Background(), testRunId, "user-1"))
	assert.Equal(t, 1, changes)

	// A second Stop, or one against a closed row, matches nothing and changes nothing.
	mDB.On("Query", mock.Anything, mark, testRunId, "user-2").Return(emptyRows(), nil).Once()
	require.NoError(t, s.MarkAutomationRunStopping(context.Background(), testRunId, "user-2"))
	assert.Equal(t, 1, changes)
	mDB.AssertExpectations(t)
}

func TestMarkAutomationRunStoppingRequiresAnId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	assert.Error(t, s.MarkAutomationRunStopping(context.Background(), "", "user-1"))
	assertNoStatements(t, mDB)
}

func TestCloseAutomationRunClearsTheStopper(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, sqlContains("stopped_by = NULL, stopped_at = NULL"), "run-1", "failed", "boom").
		Return(rowsYielding(1), nil)

	require.NoError(t, s.CloseAutomationRun(context.Background(), "run-1", model.AutomationRunFailed, "boom"))
	mDB.AssertExpectations(t)
}

func TestCloseAutomationRunRefusesStopped(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	assert.Error(t, s.CloseAutomationRun(context.Background(), "run-1", model.AutomationRunStopped, ""))
	assertNoStatements(t, mDB)
}

func TestCloseStoppedAutomationRunRequeuesOnlyItsRunningItems(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}
	changes := 0
	s.OnAutomationChange(func() { changes++ })

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, sqlContainsAll(append(stoppingRunsSqlFragments, "automation_id = $2::uuid AND id = $3::uuid")...),
		"user-1", testAutomationId, testRunId).Return(runIdRows(testRunId), nil).Once()
	mTx.On("Query", mock.Anything, requeueStoppedItemsSql(), "ERROR_AUTOMATION_RUN_STOPPED", []string{testRunId}).
		Return(rowsYielding(3), nil).Once()

	requeued, err := s.CloseStoppedAutomationRun(context.Background(), testAutomationId, testRunId, "ERROR_AUTOMATION_RUN_STOPPED", "user-1")

	require.NoError(t, err)
	assert.Equal(t, 3, requeued)
	assert.Equal(t, 1, changes)
	mTx.AssertExpectations(t)
	mTx.AssertNotCalled(t, "Query", mock.Anything, sqlContains("stopped_by IS NOT NULL"), mock.Anything, mock.Anything, mock.Anything)
	assertPlaceholdersBound(t, &mTx.Mock)
}

func TestCloseStoppedAutomationRunWithNoItems(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Query", append([]any{mock.Anything, stoppingRunsSql()}, anyArgs(3)...)...).Return(runIdRows(testRunId), nil)
	mTx.On("Query", mock.Anything, requeueStoppedItemsSql(), mock.Anything, mock.Anything).Return(emptyRows(), nil)

	requeued, err := s.CloseStoppedAutomationRun(context.Background(), testAutomationId, testRunId, "stopped", "")

	require.NoError(t, err)
	assert.Equal(t, 0, requeued)
	mTx.AssertCalled(t, "Commit", mock.Anything)
}

// A closed row, or another automation's, matches nothing; the caller tells that apart from a
// close that worked.
func TestCloseStoppedAutomationRunNotOpen(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}
	changes := 0
	s.OnAutomationChange(func() { changes++ })

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, stoppingRunsSql(), mock.Anything, otherAutomationId, testRunId).
		Return(emptyRows(), nil)

	_, err := s.CloseStoppedAutomationRun(context.Background(), otherAutomationId, testRunId, "stopped", "user-1")

	assert.ErrorIs(t, err, ErrAutomationRunNotOpen)
	assert.Equal(t, 0, changes)
	mTx.AssertNotCalled(t, "Query", mock.Anything, requeueStoppedItemsSql(), mock.Anything, mock.Anything)
	mTx.AssertNotCalled(t, "Commit", mock.Anything)
}

func TestCloseStoppedAutomationRunRollsBackOnFailure(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Query", append([]any{mock.Anything, stoppingRunsSql()}, anyArgs(3)...)...).Return(runIdRows(testRunId), nil)
	mTx.On("Query", mock.Anything, requeueStoppedItemsSql(), mock.Anything, mock.Anything).
		Return((*mockdb.MockRows)(nil), errors.New("connection lost"))

	_, err := s.CloseStoppedAutomationRun(context.Background(), testAutomationId, testRunId, "stopped", "user-1")

	assert.Error(t, err)
	mTx.AssertNotCalled(t, "Commit", mock.Anything)
	mTx.AssertCalled(t, "Rollback", mock.Anything)
}

func TestCloseStoppedAutomationRunRequiresIds(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.CloseStoppedAutomationRun(context.Background(), "", testRunId, "stopped", "")
	assert.Error(t, err)

	_, err = s.CloseStoppedAutomationRun(context.Background(), testAutomationId, "", "stopped", "")
	assert.Error(t, err)

	assertNoStatements(t, mDB)
}

// A restart while a run was stopping honors the Stop, ending it stopped; only rows nobody
// stopped are failed and charged.
func TestReconcileAutomationRunsClosesStoppingRunsAsStopped(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Commit", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, sqlContainsAll(append(stoppingRunsSqlFragments, "WHERE ended_at IS NULL AND stopped_by IS NOT NULL")...),
		"").Return(runIdRows("run-s"), nil).Once()
	mTx.On("Query", mock.Anything, requeueStoppedItemsSql(), "ERROR_AUTOMATION_RUN_STOPPED", []string{"run-s"}).
		Return(rowsYielding(1), nil).Once()
	mTx.On("Query", mock.Anything, sqlContains("SET state = 'failed'")).Return(emptyRows(), nil).Once()
	mTx.On("Query", mock.Anything, sqlContains("WHERE state = 'running'")).Return(emptyRows(), nil).Once()

	result, err := s.ReconcileAutomationRuns(context.Background())

	require.NoError(t, err)
	assert.Equal(t, &AutomationRunReconcileResult{StoppedRuns: 1, ResetItems: 1}, result)
	mTx.AssertExpectations(t)
	assertPlaceholdersBound(t, &mTx.Mock)
}

func TestEnsureAutomationWorkItemSessionRecordsItsRun(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	// The same guard on both arrays is what keeps them in step: the run is appended exactly
	// when the session is.
	inStep := sqlContainsAll(
		"session_ids = CASE WHEN $2 = ANY(session_ids)",
		"session_run_ids = CASE WHEN $2 = ANY(session_ids)",
		"THEN session_run_ids",
		"ELSE array_append(session_run_ids, COALESCE(run_id::text, '')) END")

	mDB.On("Query", mock.Anything, inStep, "item-1", "session-9").Return(rowsYielding(1), nil)

	require.NoError(t, s.EnsureAutomationWorkItemSession(context.Background(), "item-1", "session-9"))
	mDB.AssertExpectations(t)
}
