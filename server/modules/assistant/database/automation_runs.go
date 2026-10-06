// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

// The in-flight index, named here because OpenAutomationRun maps a violation of it to
// ErrAutomationRunInFlight and must not catch any other unique index.
const idxRunsOneInFlight = "idx_automation_runs_one_in_flight"

const automationRunColumns = `id, automation_id, state, started_at, ended_at, error`

// The states idx_automation_runs_one_in_flight covers.
const inFlightRunStates = `('queued', 'running')`

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

	s.automationChanged()

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

	s.automationChanged()

	return nil
}

// FailAbandonedAutomationRun fails the open run of an automation, if there is one. Only the
// caller knows nothing owns it; the scheduler calls this when the in-flight index refuses an
// open for an automation it has no run registered for.
func (s *Store) FailAbandonedAutomationRun(ctx context.Context, automationId, cause string) (int, error) {
	if automationId == "" {
		return 0, fmt.Errorf("cannot fail a run without an automation id")
	}

	return s.countAutomationChanges(countAffected(ctx, s.db, `
		UPDATE automation_runs
		SET state = 'failed', ended_at = now(), error = NULLIF($2, '')
		WHERE automation_id = $1 AND ended_at IS NULL
		RETURNING id`, automationId, cause))
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
	// Only runs queued or running.
	InFlight bool
	// Only runs that have ended.
	Finished bool
	// Drops succeeded runs that worked no item.
	HideEmpty bool
	// Matched case-insensitively against the run's error and its items' group keys and errors.
	Search string
	// Also match Search.
	SearchAutomationIds []string
	SearchRunId         string
	Limit               int
	Offset              int
}

// The items a run last worked or failed, as CountAutomationWorkItemsByRun counts them.
const runWorkItemsClause = `FROM automation_work_items w
	WHERE (w.run_id = automation_runs.id OR w.failed_run_ids @> ARRAY[automation_runs.id::text])`

// escapeLike makes value match literally inside an ILIKE pattern escaped by backslash.
func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// where renders the query's filters, numbering placeholders after any already in args.
func (query AutomationRunQuery) where(args []any) (string, []any) {
	where := []string{}

	if query.AutomationId != "" {
		args = append(args, query.AutomationId)
		where = append(where, fmt.Sprintf(`automation_id = $%d`, len(args)))
	}

	if query.InFlight {
		where = append(where, `state IN `+inFlightRunStates)
	}

	if query.Finished {
		where = append(where, `state NOT IN `+inFlightRunStates)
	}

	if query.HideEmpty {
		kept := `state = 'failed'`

		// A run asked for by id shows even when it worked nothing.
		if query.SearchRunId != "" {
			args = append(args, query.SearchRunId)
			kept += fmt.Sprintf(` OR id = $%d::uuid`, len(args))
		}

		where = append(where, `(`+kept+` OR EXISTS (SELECT 1 `+runWorkItemsClause+`))`)
	}

	if query.Search != "" {
		args = append(args, "%"+escapeLike(query.Search)+"%")
		pattern := len(args)

		matches := []string{
			fmt.Sprintf(`error ILIKE $%d ESCAPE '\'`, pattern),
			fmt.Sprintf(`EXISTS (SELECT 1 %s AND (w.group_key ILIKE $%d ESCAPE '\' OR w.error ILIKE $%d ESCAPE '\'))`,
				runWorkItemsClause, pattern, pattern),
		}

		if len(query.SearchAutomationIds) > 0 {
			args = append(args, query.SearchAutomationIds)
			matches = append(matches, fmt.Sprintf(`automation_id = ANY($%d::uuid[])`, len(args)))
		}

		if query.SearchRunId != "" {
			args = append(args, query.SearchRunId)
			matches = append(matches, fmt.Sprintf(`id = $%d::uuid`, len(args)))
		}

		where = append(where, `(`+strings.Join(matches, ` OR `)+`)`)
	}

	if len(where) == 0 {
		return "", args
	}

	return ` WHERE ` + strings.Join(where, ` AND `), args
}

// CountAutomationRuns counts the runs ListAutomationRuns would list, ignoring Limit and Offset.
func (s *Store) CountAutomationRuns(ctx context.Context, query AutomationRunQuery) (int, error) {
	where, args := query.where([]any{})

	var count int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM automation_runs`+where, args...).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

func (s *Store) ListAutomationRuns(ctx context.Context, query AutomationRunQuery) ([]*model.AutomationRunRecord, error) {
	where, args := query.where([]any{})
	stmt := `SELECT ` + automationRunColumns + ` FROM automation_runs` + where + ` ORDER BY started_at DESC, id`

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

// LatestAutomationRunStartTimes reports when each listed automation last started a run, keyed
// by id; each is one probe of idx_automation_runs_automation_id_started_at, whatever the history.
func (s *Store) LatestAutomationRunStartTimes(ctx context.Context, automationIds []string) (map[string]time.Time, error) {
	// pgx sends []string as text[]; automation_id is uuid.
	rows, err := s.db.Query(ctx, `
		SELECT a.id, r.started_at
		FROM unnest($1::uuid[]) AS a(id)
		CROSS JOIN LATERAL (
			SELECT started_at FROM automation_runs
			WHERE automation_id = a.id
			ORDER BY started_at DESC
			LIMIT 1
		) r`, automationIds)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	latest := map[string]time.Time{}

	for rows.Next() {
		var id string
		var started time.Time

		if err := rows.Scan(&id, &started); err != nil {
			return nil, err
		}

		latest[id] = started
	}

	return latest, rows.Err()
}
