// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// The in-flight index, named here because OpenAutomationRun maps a violation of it to
// ErrAutomationRunInFlight and must not catch any other unique index.
const idxRunsOneInFlight = "idx_automation_runs_one_in_flight"

const automationRunColumns = `id, automation_id, state, started_at, ended_at, error`

func scanAutomationRunRow(rows db.Rows) (*model.AutomationRunRecord, error) {
	run := &model.AutomationRunRecord{}

	var state string
	var failure *string

	if err := rows.Scan(&run.Id, &run.AutomationId, &state, &run.StartTime, &run.EndTime, &failure); err != nil {
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

	run := &model.AutomationRunRecord{}

	var state string
	var failure *string

	err := s.db.QueryRow(ctx, `
		INSERT INTO automation_runs (automation_id, state)
		VALUES ($1, 'running')
		RETURNING `+automationRunColumns,
		automationId).
		Scan(&run.Id, &run.AutomationId, &state, &run.StartTime, &run.EndTime, &failure)

	if isUniqueViolation(err, idxRunsOneInFlight) {
		return nil, ErrAutomationRunInFlight
	}

	if err != nil {
		return nil, err
	}

	run.State = model.AutomationRunState(state)

	if failure != nil {
		run.Error = *failure
	}

	return run, nil
}

// CloseAutomationRun moves a run to a terminal state and stamps its automation's
// last_run_time from the same statement, so the two can never disagree. Closing an
// already-closed run returns ErrAutomationRunNotOpen rather than succeeding quietly,
// because a double close means something miscounted and that should be visible.
func (s *Store) CloseAutomationRun(ctx context.Context, runId string, state model.AutomationRunState, cause string) error {
	if runId == "" {
		return fmt.Errorf("cannot close a run without an id")
	}

	if !state.IsTerminal() {
		return fmt.Errorf("cannot close a run into non-terminal state %q", state)
	}

	rows, err := s.db.Query(ctx, `
		WITH closed AS (
			UPDATE automation_runs
			SET state = $2, ended_at = now(), error = NULLIF($3, '')
			WHERE id = $1 AND ended_at IS NULL
			RETURNING automation_id, ended_at
		)
		UPDATE automations a
		SET last_run_time = closed.ended_at, updated_at = now()
		FROM closed
		WHERE a.id = closed.automation_id
		RETURNING a.last_run_time`,
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
	rows, err := s.db.Query(ctx, `SELECT `+automationRunColumns+` FROM automation_runs WHERE id = $1`, runId)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}

		return nil, ErrAutomationNotFound
	}

	return scanAutomationRunRow(rows)
}

// AutomationRunQuery narrows a run listing. The zero value lists every run, newest
// first.
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

	if query.Limit > 0 {
		args = append(args, query.Limit)
		stmt += fmt.Sprintf(` LIMIT $%d`, len(args))
	}

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
