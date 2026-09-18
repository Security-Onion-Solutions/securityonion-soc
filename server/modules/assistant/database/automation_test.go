// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"encoding/json"
	"errors"
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
	mRow.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(err)

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

	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO automation_runs"), testAutomationId).
		Return(erroringRow(&pgconn.PgError{Code: "23505", ConstraintName: idxRunsOneInFlight}))

	run, err := s.OpenAutomationRun(context.Background(), testAutomationId)

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
	mDB.On("QueryRow", mock.Anything, mock.Anything, testAutomationId).Return(erroringRow(fkViolation))

	_, err := s.OpenAutomationRun(context.Background(), testAutomationId)

	assert.NotErrorIs(t, err, ErrAutomationRunInFlight)
	assert.ErrorIs(t, err, fkViolation)
}

// Two unique indexes can fire on one statement, so the constraint name is what makes
// the mapping specific rather than the 23505 alone.
func TestOpenAutomationRunIgnoresOtherUniqueViolations(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, testAutomationId).
		Return(erroringRow(&pgconn.PgError{Code: "23505", ConstraintName: "some_other_index"}))

	_, err := s.OpenAutomationRun(context.Background(), testAutomationId)

	assert.NotErrorIs(t, err, ErrAutomationRunInFlight)
}

func TestOpenAutomationRunRequiresAnAutomationId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.OpenAutomationRun(context.Background(), "")

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
	// same item; the attempt counter is what lets the caller bound retries.
	claim := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "FOR UPDATE SKIP LOCKED") &&
			strings.Contains(sql, "attempts = attempts + 1") &&
			strings.Contains(sql, "ORDER BY created_at")
	})

	mDB.On("Query", mock.Anything, claim, testAutomationId, testRunId).Return(emptyRows(), nil)

	item, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId)

	assert.Nil(t, item)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

// An attempts filter would wedge the item: unclaimable, yet still blocking its group.
// Retry policy lives in the kind.
func TestClaimNextAutomationWorkItemDoesNotFilterOnAttempts(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, testAutomationId, testRunId).Return(emptyRows(), nil)

	_, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId)
	require.NoError(t, err)

	capped := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "attempts <")
	})
	mDB.AssertNotCalled(t, "Query", mock.Anything, capped, mock.Anything)
}

// Requeueing must preserve attempts. Resetting it is the bug: a count that restarts every
// pass can never reach a cap, which is how a failing group retried forever.
func TestRequeueAutomationWorkItemKeepsAttempts(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	requeue := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "state = 'pending'") &&
			strings.Contains(sql, "result = NULL")
	})

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Once()
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, requeue, "item-1", "truncated").Return(mRows, nil)

	require.NoError(t, s.RequeueAutomationWorkItem(context.Background(), "item-1", "truncated"))

	// Neither attempts nor the session history may be reset: attempts is what reaches the
	// cap, and session_ids is what keeps a failed try's transcript reachable.
	resets := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "attempts") || strings.Contains(sql, "session_ids")
	})
	mDB.AssertNotCalled(t, "Query", mock.Anything, resets, mock.Anything, mock.Anything)
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
			strings.Contains(sql, "WHERE ended_at IS NULL")
	})

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

	mTx.On("Query", mock.Anything, sqlContains("UPDATE automation_runs")).
		Return(rowsYielding(2), nil)
	mTx.On("Query", mock.Anything, sqlContains("UPDATE automation_work_items")).
		Return(rowsYielding(3), nil)

	result, err := s.ReconcileAutomationRuns(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 2, result.FailedRuns)
	assert.Equal(t, 3, result.ResetItems)
	mTx.AssertExpectations(t)
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
	mTx.On("Query", mock.Anything, mock.Anything).Return(emptyRows(), nil)

	_, err := s.ReconcileAutomationRuns(context.Background())
	require.NoError(t, err)

	recounts := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "attempts")
	})
	mTx.AssertNotCalled(t, "Query", mock.Anything, recounts)
}

// A partial reconcile is worse than none: it would leave items owned by a process that
// is gone while a new run starts alongside them.
func TestReconcileAutomationRunsRollsBackOnFailure(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
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

	mDB.On("Query", mock.Anything, mock.Anything, testAutomationId, testRunId).Return(emptyRows(), nil)

	_, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId)
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

	mDB.On("Query", mock.Anything, sqlContains("run_id = $2"), testAutomationId, testRunId).
		Return(emptyRows(), nil)

	_, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId)

	require.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestClaimNextAutomationWorkItemRequiresARunId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, "")

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
