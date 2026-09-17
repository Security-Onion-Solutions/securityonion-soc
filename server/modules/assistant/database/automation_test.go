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

	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO automation_runs"), "nightly").
		Return(erroringRow(&pgconn.PgError{Code: "23505", ConstraintName: idxRunsOneInFlight}))

	run, err := s.OpenAutomationRun(context.Background(), "nightly")

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
	mDB.On("QueryRow", mock.Anything, mock.Anything, "nightly").Return(erroringRow(fkViolation))

	_, err := s.OpenAutomationRun(context.Background(), "nightly")

	assert.NotErrorIs(t, err, ErrAutomationRunInFlight)
	assert.ErrorIs(t, err, fkViolation)
}

// Two unique indexes can fire on one statement, so the constraint name is what makes
// the mapping specific rather than the 23505 alone.
func TestOpenAutomationRunIgnoresOtherUniqueViolations(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("QueryRow", mock.Anything, mock.Anything, "nightly").
		Return(erroringRow(&pgconn.PgError{Code: "23505", ConstraintName: "some_other_index"}))

	_, err := s.OpenAutomationRun(context.Background(), "nightly")

	assert.NotErrorIs(t, err, ErrAutomationRunInFlight)
}

func TestOpenAutomationRunRequiresAName(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.OpenAutomationRun(context.Background(), "")

	assert.Error(t, err)
	mDB.AssertNotCalled(t, "QueryRow")
}

// last_run_time is stamped from the same statement that closes the run, so the task and
// its history cannot disagree.
func TestCloseAutomationRunStampsTheTask(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	bothTables := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "automation_runs") && strings.Contains(sql, "automations")
	})

	mRows := &mockdb.MockRows{}
	mRows.On("Next").Return(true).Once()
	mRows.On("Close").Return()

	mDB.On("Query", mock.Anything, bothTables, "run-1", "succeeded", "").Return(mRows, nil)

	require.NoError(t, s.CloseAutomationRun(context.Background(), "run-1", model.AutomationRunSucceeded, ""))
	mDB.AssertExpectations(t)
}

// Closing an already-closed run must be visible: a double close means something
// miscounted, and swallowing it hides reconciliation bugs.
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
	mDB.AssertNotCalled(t, "Query")
}

func TestClaimNextAutomationWorkItemUsesSkipLocked(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	// SKIP LOCKED is what keeps two pool goroutines inside one run from claiming the
	// same item; the attempt counter is what bounds retries of a poison payload.
	claim := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "FOR UPDATE SKIP LOCKED") &&
			strings.Contains(sql, "attempts = attempts + 1") &&
			strings.Contains(sql, "ORDER BY created_at")
	})

	mDB.On("Query", mock.Anything, claim, "nightly", 3).Return(emptyRows(), nil)

	item, err := s.ClaimNextAutomationWorkItem(context.Background(), "nightly", 3)

	assert.Nil(t, item)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestEnsureAutomationWorkItemsEmptyBatchTouchesNothing(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	items, err := s.EnsureAutomationWorkItems(context.Background(), "run-1", nil)

	assert.Nil(t, items)
	assert.NoError(t, err)
	mDB.AssertNotCalled(t, "Query")
}

// ON CONFLICT infers a partial unique index only from an identical predicate, so the
// statement builds its clause from the same constant the migration is checked against.
func TestEnsureAutomationWorkItemsIsIdempotent(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	upsert := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "ON CONFLICT (automation_name, group_key) WHERE state IN "+openWorkItemStates) &&
			strings.Contains(sql, "DO NOTHING")
	})

	mDB.On("Query", mock.Anything, upsert, "nightly", "run-1",
		[]string{"group-a"}, []string{`{"ids":["1"]}`}).Return(emptyRows(), nil)

	items, err := s.EnsureAutomationWorkItems(context.Background(), "run-1", []*model.AutomationWorkItem{
		{AutomationName: "nightly", GroupKey: "group-a", Payload: json.RawMessage(`{"ids":["1"]}`)},
	})

	require.NoError(t, err)
	assert.Empty(t, items)
	mDB.AssertExpectations(t)
}

// A nil payload cannot bind as an empty string: jsonb rejects it.
func TestEnsureAutomationWorkItemsDefaultsNilPayload(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "nightly", "run-1",
		[]string{"group-a"}, []string{"{}"}).Return(emptyRows(), nil)

	_, err := s.EnsureAutomationWorkItems(context.Background(), "run-1",
		[]*model.AutomationWorkItem{{AutomationName: "nightly", GroupKey: "group-a"}})

	require.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestEnsureAutomationWorkItemsRejectsMixedAutomations(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.EnsureAutomationWorkItems(context.Background(), "run-1", []*model.AutomationWorkItem{
		{AutomationName: "nightly", GroupKey: "a"},
		{AutomationName: "hourly", GroupKey: "b"},
	})

	assert.Error(t, err)
	mDB.AssertNotCalled(t, "Query")
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

func TestWorkItemTransitionOnVanishedItem(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "item-1").Return(emptyRows(), nil)

	err := s.CompleteAutomationWorkItem(context.Background(), "item-1")

	assert.ErrorIs(t, err, ErrAutomationWorkItemGone)
}

func TestWorkItemTransitionRequiresAnId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	assert.Error(t, s.CompleteAutomationWorkItem(context.Background(), ""))
	mDB.AssertNotCalled(t, "Query")
}

func TestListOpenAutomationWorkItemsReturnsEmptySlice(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, sqlContains("state IN "+openWorkItemStates), "nightly").
		Return(emptyRows(), nil)

	items, err := s.ListOpenAutomationWorkItems(context.Background(), "nightly")

	require.NoError(t, err)
	assert.NotNil(t, items, "an empty list must marshal as [] rather than null")
	assert.Empty(t, items)
}

func TestEnsureAutomationRunResultAuditRejectsDuplicatesInOneBatch(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	// ON CONFLICT DO UPDATE cannot affect a row twice; Postgres raises rather than
	// picking a winner, so the batch is checked before it is sent.
	err := s.EnsureAutomationRunResultAudit(context.Background(), "run-1", []*model.AutomationRunResultAudit{
		{AlertId: "alert-1", Recommendation: "acknowledge"},
		{AlertId: "alert-1", Recommendation: "escalate"},
	})

	assert.Error(t, err)
	mDB.AssertNotCalled(t, "Exec")
}

func TestEnsureAutomationRunResultAuditEmptyBatchTouchesNothing(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	require.NoError(t, s.EnsureAutomationRunResultAudit(context.Background(), "run-1", nil))
	mDB.AssertNotCalled(t, "Exec")
}

func TestEnsureAutomationRunResultAuditUpsertsSoAResumedApplyConverges(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	upsert := mock.MatchedBy(func(sql string) bool {
		return strings.Contains(sql, "ON CONFLICT (run_id, alert_id) DO UPDATE")
	})

	mDB.On("Exec", mock.Anything, upsert, "run-1",
		[]string{"alert-1"}, []string{"item-1"}, []string{"acknowledge"}, []string{"benign"}, []bool{true}).
		Return(nil)

	err := s.EnsureAutomationRunResultAudit(context.Background(), "run-1", []*model.AutomationRunResultAudit{
		{AlertId: "alert-1", WorkItemId: "item-1", Recommendation: "acknowledge", Reason: "benign", Inherited: true},
	})

	require.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestDeleteAutomationRefusesWhileARunIsInFlight(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, sqlContains("DELETE FROM automations"), "nightly").
		Return(emptyRows(), nil)

	// The task still exists, so the delete was refused rather than missing.
	stillThere := &mockdb.MockRows{}
	stillThere.On("Next").Return(true).Once()
	stillThere.On("Close").Return()
	mTx.On("Query", mock.Anything, sqlContains("SELECT 1 FROM automations"), "nightly").
		Return(stillThere, nil)

	err := s.DeleteAutomation(context.Background(), "nightly")

	assert.ErrorIs(t, err, ErrAutomationRunInFlight)
	mTx.AssertNotCalled(t, "Commit")
}

func TestDeleteAutomationNotFound(t *testing.T) {
	mDB := &mockdb.MockDB{}
	mTx := &mockdb.MockTx{}
	s := &Store{db: mDB}

	mDB.On("Begin", mock.Anything).Return(mTx, nil)
	mTx.On("Rollback", mock.Anything).Return(nil)
	mTx.On("Query", mock.Anything, mock.Anything, "gone").Return(emptyRows(), nil)
	mTx.On("Query", mock.Anything, sqlContains("SELECT 1 FROM automations"), "gone").
		Return(emptyRows(), nil)

	err := s.DeleteAutomation(context.Background(), "gone")

	assert.ErrorIs(t, err, ErrAutomationNotFound)
}

func TestAddAutomationDuplicateName(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything, mock.Anything).
		Return(&pgconn.PgError{Code: "23505", ConstraintName: "automations_pkey"})

	mDB.On("QueryRow", mock.Anything, sqlContains("INSERT INTO automations"),
		"nightly", "alert_triage", "{}", false, 300, "owner-1").Return(mRow)

	err := s.AddAutomation(context.Background(), &model.Automation{
		Name: "nightly", Kind: "alert_triage", IntervalSeconds: 300, Owner: "owner-1",
	})

	assert.ErrorIs(t, err, ErrAutomationExists)
	mDB.AssertExpectations(t)
}

func TestUpdateAutomationNotFound(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, sqlContains("UPDATE automations"),
		"gone", "{}", false, 300, "owner-1").Return(emptyRows(), nil)

	err := s.UpdateAutomation(context.Background(), &model.Automation{
		Name: "gone", IntervalSeconds: 300, Owner: "owner-1",
	})

	assert.ErrorIs(t, err, ErrAutomationNotFound)
}

// The sweep matches on ended_at rather than a list of states, which is what makes it
// cover 'queued' -- and anything added later -- without someone remembering to extend an
// enumeration. Narrowing it to state = 'running' would strand a queued run inside the
// in-flight index and block its automation forever.
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
