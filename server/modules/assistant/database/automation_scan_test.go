// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func anyArgs(n int) []any {
	args := make([]any, n)
	for i := range args {
		args[i] = mock.Anything
	}

	return args
}

func sqlContainsAll(subs ...string) any {
	return mock.MatchedBy(func(sql string) bool {
		for _, sub := range subs {
			if !strings.Contains(sql, sub) {
				return false
			}
		}

		return true
	})
}

func ptrTime(t time.Time) *time.Time { return &t }

func ptrString(s string) *string { return &s }

type automationRunRow struct {
	id, automationId, state string
	startTime, endTime      *time.Time
	failure                 *string
}

// Fills the six destinations in automationRunColumns order, so a column added to the
// projection without a matching destination fails here.
func expectAutomationRunRow(mRows *mockdb.MockRows, row automationRunRow) {
	mRows.On("Scan", anyArgs(6)...).Run(func(args mock.Arguments) {
		*(args.Get(0).(*string)) = row.id
		*(args.Get(1).(*string)) = row.automationId
		*(args.Get(2).(*string)) = row.state
		*(args.Get(3).(**time.Time)) = row.startTime
		*(args.Get(4).(**time.Time)) = row.endTime
		*(args.Get(5).(**string)) = row.failure
	}).Return(nil).Once()
}

func automationRunRows(rows ...automationRunRow) *mockdb.MockRows {
	mRows := &mockdb.MockRows{}

	for _, row := range rows {
		mRows.On("Next").Return(true).Once()
		expectAutomationRunRow(mRows, row)
	}

	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	return mRows
}

type automationWorkItemRow struct {
	id, automationId, groupKey, state string
	runId, failure                    *string
	payload, result                   []byte
	attempts                          int
	sessionIds                        []string
	createTime, updateTime            *time.Time
}

// Fills the twelve destinations in automationWorkItemColumns order.
func expectAutomationWorkItemRow(mRows *mockdb.MockRows, row automationWorkItemRow) {
	mRows.On("Scan", anyArgs(12)...).Run(func(args mock.Arguments) {
		*(args.Get(0).(*string)) = row.id
		*(args.Get(1).(*string)) = row.automationId
		*(args.Get(2).(**string)) = row.runId
		*(args.Get(3).(*string)) = row.groupKey
		*(args.Get(4).(*[]byte)) = row.payload
		*(args.Get(5).(*string)) = row.state
		*(args.Get(6).(*int)) = row.attempts
		*(args.Get(7).(*[]string)) = row.sessionIds
		*(args.Get(8).(*[]byte)) = row.result
		*(args.Get(9).(**string)) = row.failure
		*(args.Get(10).(**time.Time)) = row.createTime
		*(args.Get(11).(**time.Time)) = row.updateTime
	}).Return(nil).Once()
}

func automationWorkItemRows(rows ...automationWorkItemRow) *mockdb.MockRows {
	mRows := &mockdb.MockRows{}

	for _, row := range rows {
		mRows.On("Next").Return(true).Once()
		expectAutomationWorkItemRow(mRows, row)
	}

	mRows.On("Next").Return(false)
	mRows.On("Err").Return(nil)
	mRows.On("Close").Return()

	return mRows
}

func fullWorkItemRow() automationWorkItemRow {
	created := time.Date(2026, 9, 15, 16, 0, 5, 0, time.UTC)
	updated := time.Date(2026, 9, 15, 16, 2, 41, 0, time.UTC)

	return automationWorkItemRow{
		id:           "item-1",
		automationId: testAutomationId,
		runId:        ptrString("run-1"),
		groupKey:     "rule.name:Suspicious PowerShell",
		payload:      []byte(`{"ids":["1","2"]}`),
		state:        string(model.AutomationWorkItemApplying),
		attempts:     2,
		sessionIds:   []string{"session-1", "session-2"},
		result:       []byte(`{"recommendation":"acknowledge"}`),
		failure:      ptrString("truncated"),
		createTime:   &created,
		updateTime:   &updated,
	}
}

// Every value is distinct so a transposed pair of destinations cannot pass.
func TestScanAutomationRunRowMapsEveryColumn(t *testing.T) {
	started := time.Date(2026, 9, 15, 16, 0, 2, 0, time.UTC)
	ended := time.Date(2026, 9, 15, 16, 3, 2, 0, time.UTC)

	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, sqlContains(automationRunColumns), "run-1").
		Return(automationRunRows(automationRunRow{
			id:           "run-1",
			automationId: testAutomationId,
			state:        string(model.AutomationRunFailed),
			startTime:    &started,
			endTime:      &ended,
			failure:      ptrString("boom"),
		}), nil)

	run, err := s.GetAutomationRun(context.Background(), "run-1")

	require.NoError(t, err)
	assert.Equal(t, "run-1", run.Id)
	assert.Equal(t, testAutomationId, run.AutomationId)
	assert.Equal(t, model.AutomationRunFailed, run.State)
	assert.Equal(t, &started, run.StartTime)
	assert.Equal(t, &ended, run.EndTime)
	assert.Equal(t, "boom", run.Error)
	mDB.AssertExpectations(t)
}

// OpenAutomationRun reads the same projection through the same helper, so the mapping is
// pinned on both paths rather than only on the read.
func TestOpenAutomationRunMapsEveryColumn(t *testing.T) {
	started := time.Date(2026, 9, 15, 16, 0, 2, 0, time.UTC)

	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", anyArgs(6)...).Run(func(args mock.Arguments) {
		*(args.Get(0).(*string)) = "run-1"
		*(args.Get(1).(*string)) = testAutomationId
		*(args.Get(2).(*string)) = string(model.AutomationRunRunning)
		*(args.Get(3).(**time.Time)) = &started
	}).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains(automationRunColumns), testAutomationId).Return(mRow)

	run, err := s.OpenAutomationRun(context.Background(), testAutomationId)

	require.NoError(t, err)
	assert.Equal(t, "run-1", run.Id)
	assert.Equal(t, testAutomationId, run.AutomationId)
	assert.Equal(t, model.AutomationRunRunning, run.State)
	assert.Equal(t, &started, run.StartTime)
	assert.Nil(t, run.EndTime)
	assert.Empty(t, run.Error)
	mDB.AssertExpectations(t)
}

// A run in flight has no end time and no error, and those arrive as NULL.
func TestScanAutomationRunRowLeavesNullColumnsEmpty(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "run-1").
		Return(automationRunRows(automationRunRow{
			id:           "run-1",
			automationId: testAutomationId,
			state:        string(model.AutomationRunRunning),
			startTime:    ptrTime(time.Date(2026, 9, 15, 16, 0, 2, 0, time.UTC)),
		}), nil)

	run, err := s.GetAutomationRun(context.Background(), "run-1")

	require.NoError(t, err)
	assert.Nil(t, run.EndTime)
	assert.Empty(t, run.Error)
}

func TestGetAutomationRunNotFound(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, "run-1").Return(emptyRows(), nil)

	_, err := s.GetAutomationRun(context.Background(), "run-1")

	assert.ErrorIs(t, err, ErrAutomationRunNotFound)
}

// Every value is distinct so a transposed pair of destinations cannot pass.
func TestScanAutomationWorkItemRowMapsEveryColumn(t *testing.T) {
	row := fullWorkItemRow()

	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, sqlContains(automationWorkItemColumns), testAutomationId, testRunId).
		Return(automationWorkItemRows(row), nil)

	item, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId)

	require.NoError(t, err)
	require.NotNil(t, item)
	assert.Equal(t, "item-1", item.Id)
	assert.Equal(t, testAutomationId, item.AutomationId)
	assert.Equal(t, "run-1", item.RunId)
	assert.Equal(t, "rule.name:Suspicious PowerShell", item.GroupKey)
	assert.JSONEq(t, `{"ids":["1","2"]}`, string(item.Payload))
	assert.Equal(t, model.AutomationWorkItemApplying, item.State)
	assert.Equal(t, 2, item.Attempts)
	assert.Equal(t, []string{"session-1", "session-2"}, item.SessionIds)
	assert.JSONEq(t, `{"recommendation":"acknowledge"}`, string(item.Result))
	assert.Equal(t, "truncated", item.Error)
	assert.Equal(t, row.createTime, item.CreateTime)
	assert.Equal(t, row.updateTime, item.UpdateTime)
	mDB.AssertExpectations(t)
}

// A freshly enqueued item has no run, no result and no error; Result must stay nil
// rather than become an empty RawMessage, which would not unmarshal.
func TestScanAutomationWorkItemRowLeavesNullColumnsEmpty(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, testAutomationId, testRunId).
		Return(automationWorkItemRows(automationWorkItemRow{
			id:           "item-1",
			automationId: testAutomationId,
			groupKey:     "group-a",
			payload:      []byte(`{}`),
			state:        string(model.AutomationWorkItemPending),
			sessionIds:   []string{},
		}), nil)

	item, err := s.ClaimNextAutomationWorkItem(context.Background(), testAutomationId, testRunId)

	require.NoError(t, err)
	assert.Empty(t, item.RunId)
	assert.Empty(t, item.Error)
	assert.Nil(t, item.Result)
}

// The clauses are optional and independent, so the placeholder numbering has to be
// derived rather than written out.
func TestListAutomationRunsNumbersItsArguments(t *testing.T) {
	cases := []struct {
		name      string
		query     AutomationRunQuery
		fragments []string
		args      []any
	}{
		{
			name:      "unfiltered",
			fragments: []string{"FROM automation_runs ORDER BY started_at DESC, id", "LIMIT $1"},
			args:      []any{defaultAutomationRunLimit},
		},
		{
			name:      "by automation",
			query:     AutomationRunQuery{AutomationId: testAutomationId},
			fragments: []string{"WHERE automation_id = $1", "LIMIT $2"},
			args:      []any{testAutomationId, defaultAutomationRunLimit},
		},
		{
			name:      "limit only",
			query:     AutomationRunQuery{Limit: 10},
			fragments: []string{"LIMIT $1"},
			args:      []any{10},
		},
		{
			name:      "offset only",
			query:     AutomationRunQuery{Offset: 5},
			fragments: []string{"LIMIT $1", "OFFSET $2"},
			args:      []any{defaultAutomationRunLimit, 5},
		},
		{
			name:      "every clause",
			query:     AutomationRunQuery{AutomationId: testAutomationId, Limit: 10, Offset: 5},
			fragments: []string{"WHERE automation_id = $1", "LIMIT $2", "OFFSET $3"},
			args:      []any{testAutomationId, 10, 5},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mDB := &mockdb.MockDB{}
			s := &Store{db: mDB}

			expect := append([]any{mock.Anything, sqlContainsAll(tc.fragments...)}, tc.args...)
			mDB.On("Query", expect...).Return(emptyRows(), nil)

			runs, err := s.ListAutomationRuns(context.Background(), tc.query)

			require.NoError(t, err)
			assert.NotNil(t, runs, "an empty history is [] rather than null")
			mDB.AssertExpectations(t)
		})
	}
}

func TestListAutomationRunsReturnsEveryRow(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, defaultAutomationRunLimit).Return(automationRunRows(
		automationRunRow{id: "run-2", automationId: testAutomationId, state: "running"},
		automationRunRow{id: "run-1", automationId: testAutomationId, state: "succeeded"},
	), nil)

	runs, err := s.ListAutomationRuns(context.Background(), AutomationRunQuery{})

	require.NoError(t, err)
	require.Len(t, runs, 2)
	assert.Equal(t, "run-2", runs[0].Id)
	assert.Equal(t, model.AutomationRunSucceeded, runs[1].State)
}

// MAX over no rows is NULL, which is how an automation that has never finished a run
// reports itself.
func TestLatestAutomationRunTimeHandlesNoHistory(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything).Return(nil)

	mDB.On("QueryRow", mock.Anything, sqlContains("MAX(ended_at)"), testAutomationId).Return(mRow)

	latest, err := s.LatestAutomationRunTime(context.Background(), testAutomationId)

	require.NoError(t, err)
	assert.Nil(t, latest)
}

func TestLatestAutomationRunTimeReturnsTheLastEnd(t *testing.T) {
	ended := time.Date(2026, 9, 15, 16, 3, 2, 0, time.UTC)

	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mRow := &mockdb.MockRow{}
	mRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*(args.Get(0).(**time.Time)) = &ended
	}).Return(nil)

	mDB.On("QueryRow", mock.Anything, mock.Anything, testAutomationId).Return(mRow)

	latest, err := s.LatestAutomationRunTime(context.Background(), testAutomationId)

	require.NoError(t, err)
	assert.Equal(t, &ended, latest)
}

func TestListOpenAutomationWorkItemsReadsTheOpenSetOldestFirst(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	open := sqlContainsAll("state IN "+openWorkItemStates, "ORDER BY created_at")
	mDB.On("Query", mock.Anything, open, testAutomationId).Return(automationWorkItemRows(
		automationWorkItemRow{id: "item-1", automationId: testAutomationId, groupKey: "a", state: "pending"},
		automationWorkItemRow{id: "item-2", automationId: testAutomationId, groupKey: "b", state: "applying"},
	), nil)

	items, err := s.ListOpenAutomationWorkItems(context.Background(), testAutomationId)

	require.NoError(t, err)
	require.Len(t, items, 2)
	assert.Equal(t, "item-1", items[0].Id)
	assert.Equal(t, model.AutomationWorkItemApplying, items[1].State)
	mDB.AssertExpectations(t)
}

func TestListAutomationWorkItemsReadsOneRun(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, sqlContains("WHERE run_id = $1"), "run-1").
		Return(automationWorkItemRows(fullWorkItemRow()), nil)

	items, err := s.ListAutomationWorkItems(context.Background(), "run-1")

	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "run-1", items[0].RunId)
	mDB.AssertExpectations(t)
}

func TestListAutomationWorkItemsRequiresARunId(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	_, err := s.ListAutomationWorkItems(context.Background(), "")

	assert.Error(t, err)
	assertNoStatements(t, mDB)
}

// The caller submits what it receives, so a skipped group must not appear in the
// return even though it was in the batch.
func TestEnsureAutomationWorkItemsReturnsOnlyWhatItInserted(t *testing.T) {
	mDB := &mockdb.MockDB{}
	s := &Store{db: mDB}

	mDB.On("Query", mock.Anything, mock.Anything, testAutomationId, "run-1",
		[]string{"group-a", "group-b"}, []string{"{}", "{}"}).
		Return(automationWorkItemRows(automationWorkItemRow{
			id:           "item-1",
			automationId: testAutomationId,
			runId:        ptrString("run-1"),
			groupKey:     "group-b",
			payload:      []byte(`{}`),
			state:        string(model.AutomationWorkItemPending),
		}), nil)

	inserted, err := s.EnsureAutomationWorkItems(context.Background(), "run-1", []*model.AutomationWorkItem{
		{AutomationId: testAutomationId, GroupKey: "group-a", Payload: json.RawMessage(`{}`)},
		{AutomationId: testAutomationId, GroupKey: "group-b", Payload: json.RawMessage(`{}`)},
	})

	require.NoError(t, err)
	require.Len(t, inserted, 1)
	assert.Equal(t, "group-b", inserted[0].GroupKey)
	mDB.AssertExpectations(t)
}
