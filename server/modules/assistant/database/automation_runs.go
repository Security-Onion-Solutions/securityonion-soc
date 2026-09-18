// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// The in-flight index, named here because OpenAutomationRun maps a violation of it to
// ErrAutomationRunInFlight and must not catch any other unique index.
const idxRunsOneInFlight = "idx_automation_runs_one_in_flight"

const automationRunColumns = `id, automation_id, state, started_at, ended_at, error`

const defaultAutomationRunLimit = 10000

// Takes db.Row rather than db.Rows so the single-row insert and the multi-row reads share
// one mapping: db.Rows satisfies db.Row, and nothing here needs more than Scan.
func scanAutomationRunRow(row db.Row) (*model.AutomationRunRecord, error) {
	run := &model.AutomationRunRecord{}

	var state string
	var failure *string

	if err := row.Scan(&run.Id, &run.AutomationId, &state, &run.StartTime, &run.EndTime, &failure); err != nil {
		return nil, err
	}

	run.State = model.AutomationRunState(state)

	if failure != nil {
		run.Error = *failure
	}

	return run, nil
}

// OpenAutomationRun starts a run. It returns ErrAutomationRunInFlight when the partial
// unique index refuses it, which is the only correct way to answer "is this already
// running": asking first and inserting second races every other caller.
func (s *Store) OpenAutomationRun(ctx context.Context, automationId string) (*model.AutomationRunRecord, error) {
	if automationId == "" {
		return nil, fmt.Errorf("cannot open a run without an automation id")
	}

	run, err := scanAutomationRunRow(s.db.QueryRow(ctx, `
		INSERT INTO automation_runs (automation_id, state)
		VALUES ($1, 'running')
		RETURNING `+automationRunColumns,
		automationId))

	if isUniqueViolation(err, idxRunsOneInFlight) {
		return nil, ErrAutomationRunInFlight
	}

	if err != nil {
		return nil, err
	}

	return run, nil
}

// CloseAutomationRun moves a run to a terminal state. Closing an already-closed run returns
// ErrAutomationRunNotOpen rather than succeeding quietly, because a double close means
// something miscounted and that should be visible.
func (s *Store) CloseAutomationRun(ctx context.Context, runId string, state model.AutomationRunState, cause string) error {
	if runId == "" {
		return fmt.Errorf("cannot close a run without an id")
	}

	if !state.IsTerminal() {
		return fmt.Errorf("cannot close a run into non-terminal state %q", state)
	}

	// The column is the failure reason; a succeeded run has none to record.
	if state != model.AutomationRunFailed {
		cause = ""
	}

	rows, err := s.db.Query(ctx, `
		UPDATE automation_runs
		SET state = $2, ended_at = now(), error = NULLIF($3, '')
		WHERE id = $1 AND ended_at IS NULL
		RETURNING id`,
		runId, string(state), cause)
	if err != nil {
		return err
	}

	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}

		return ErrAutomationRunNotOpen
	}

	return nil
}

func (s *Store) GetAutomationRun(ctx context.Context, runId string) (*model.AutomationRunRecord, error) {
	if runId == "" {
		return nil, fmt.Errorf("cannot get a run without an id")
	}

	rows, err := s.db.Query(ctx, `SELECT `+automationRunColumns+` FROM automation_runs WHERE id = $1`, runId)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}

		return nil, ErrAutomationRunNotFound
	}

	return scanAutomationRunRow(rows)
}

// AutomationRunQuery narrows a run listing. The zero value lists the newest
// defaultAutomationRunLimit runs.
type AutomationRunQuery struct {
	AutomationId string
	Limit        int
	Offset       int
}

func (s *Store) ListAutomationRuns(ctx context.Context, query AutomationRunQuery) ([]*model.AutomationRunRecord, error) {
	stmt := `SELECT ` + automationRunColumns + ` FROM automation_runs`
	args := []any{}

	if query.AutomationId != "" {
		args = append(args, query.AutomationId)
		stmt += fmt.Sprintf(` WHERE automation_id = $%d`, len(args))
	}

	stmt += ` ORDER BY started_at DESC, id`

	limit := query.Limit
	if limit <= 0 {
		limit = defaultAutomationRunLimit
	}

	args = append(args, limit)
	stmt += fmt.Sprintf(` LIMIT $%d`, len(args))

	if query.Offset > 0 {
		args = append(args, query.Offset)
		stmt += fmt.Sprintf(` OFFSET $%d`, len(args))
	}

	rows, err := s.db.Query(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	runs := []*model.AutomationRunRecord{}

	for rows.Next() {
		run, err := scanAutomationRunRow(rows)
		if err != nil {
			return nil, err
		}

		runs = append(runs, run)
	}

	return runs, rows.Err()
}

// LatestAutomationRunTime reports when an automation last finished, derived from its run
// history rather than stored, so config carries only what a human set.
func (s *Store) LatestAutomationRunTime(ctx context.Context, automationId string) (*time.Time, error) {
	var endedAt *time.Time

	err := s.db.QueryRow(ctx,
		`SELECT MAX(ended_at) FROM automation_runs WHERE automation_id = $1`, automationId).
		Scan(&endedAt)

	return endedAt, err
}
