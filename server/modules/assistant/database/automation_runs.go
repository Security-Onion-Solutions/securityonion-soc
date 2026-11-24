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

const automationRunColumns = `id, automation_id, state, started_at, ended_at, error, started_by, stopped_by, stopped_at`

// The error a stopped run leaves on the items it requeued, matching the assistant's
// ErrAutomationRunStopped, for the paths that close a stopping row without the engine.
const automationRunStoppedCause = "ERROR_AUTOMATION_RUN_STOPPED"

// The states idx_automation_runs_one_in_flight covers.
const inFlightRunStates = `('queued', 'running')`

const defaultAutomationRunLimit = 10000

// Takes db.Row rather than db.Rows so the single-row insert and the multi-row reads share
// one mapping: db.Rows satisfies db.Row, and nothing here needs more than Scan.
func scanAutomationRunRow(row db.Row) (*model.AutomationRunRecord, error) {
	run := &model.AutomationRunRecord{}

	var state string
	var failure, startedBy, stoppedBy *string

	if err := row.Scan(&run.Id, &run.AutomationId, &state, &run.StartTime, &run.EndTime, &failure,
		&startedBy, &stoppedBy, &run.StopTime); err != nil {
		return nil, err
	}

	run.State = model.AutomationRunState(state)

	if failure != nil {
		run.Error = *failure
	}

	if startedBy != nil {
		run.StartedBy = *startedBy
	}

	if stoppedBy != nil {
		run.StoppedBy = *stoppedBy
	}

	return run, nil
}

// OpenAutomationRun starts a run. It returns ErrAutomationRunInFlight when the partial
// unique index refuses it, which is the only correct way to answer "is this already
// running": asking first and inserting second races every other caller. startedBy is empty
// for a scheduled run.
func (s *Store) OpenAutomationRun(ctx context.Context, automationId, startedBy string) (*model.AutomationRunRecord, error) {
	if automationId == "" {
		return nil, fmt.Errorf("cannot open a run without an automation id")
	}

	run, err := scanAutomationRunRow(s.db.QueryRow(ctx, `
		INSERT INTO automation_runs (automation_id, state, started_by)
		VALUES ($1, 'running', NULLIF($2, ''))
		RETURNING `+automationRunColumns,
		automationId, startedBy))

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

	// Stopped runs close through CloseStoppedAutomationRun, which also requeues their items.
	if state == model.AutomationRunStopped {
		return fmt.Errorf("cannot close a run as stopped without requeueing its items")
	}

	// The column is the failure reason; a succeeded run has none to record.
	if state != model.AutomationRunFailed {
		cause = ""
	}

	// Never written as stopped here, so a Stop that lost to an earlier cause, or to the run
	// ending on its own, leaves no stopper behind on the closed row.
	rows, err := s.db.Query(ctx, `
		UPDATE automation_runs
		SET state = $2, ended_at = now(), error = NULLIF($3, ''), stopped_by = NULL, stopped_at = NULL
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

// MarkAutomationRunStopping records who stopped an open run, and when, before its cancel is
// sent. The first stopper wins and keeps the first stop time.
func (s *Store) MarkAutomationRunStopping(ctx context.Context, runId, stoppedBy string) error {
	if runId == "" {
		return fmt.Errorf("cannot mark a run stopping without an id")
	}

	_, err := s.countAutomationChanges(countAffected(ctx, s.db, `
		UPDATE automation_runs
		SET stopped_by = NULLIF($2, ''), stopped_at = now()
		WHERE id = $1 AND ended_at IS NULL AND stopped_by IS NULL
		RETURNING id`, runId, stoppedBy))

	return err
}

// CloseStoppedAutomationRun closes one open run as stopped and returns the items it still
// held running to the queue without charging it. It returns ErrAutomationRunNotOpen when that
// automation has no open row with that id. stoppedBy only attributes a row no Stop marked.
func (s *Store) CloseStoppedAutomationRun(ctx context.Context, automationId, runId, cause, stoppedBy string) (int, error) {
	if automationId == "" || runId == "" {
		return 0, fmt.Errorf("cannot close a stopped run without an automation id and a run id")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("database: begin transaction: %w", err)
	}

	defer tx.Rollback(ctx)

	runs, requeued, err := closeStoppingRuns(ctx, tx, automationId, runId, cause, stoppedBy)
	if err != nil {
		return 0, err
	}

	if runs == 0 {
		return 0, ErrAutomationRunNotOpen
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}

	s.automationChanged()

	return requeued, nil
}

// closeStoppingRuns closes open runs as stopped, requeueing their running items uncharged, so
// every path that ends a stopped run ends it the same way. An empty automationId matches every
// automation. A runId closes that run whether or not a Stop marked it; without one, only rows a
// Stop marked close. stoppedBy attributes a row no Stop marked.
//
// ended_at reads stopped_at as it was before this UPDATE, and now() is fixed for the whole
// transaction, so ended_at always equals the stopped_at the row ends with.
func closeStoppingRuns(ctx context.Context, q rowQuerier, automationId, runId, cause, stoppedBy string) (int, int, error) {
	args := []any{stoppedBy}
	where := []string{`ended_at IS NULL`}

	if automationId != "" {
		args = append(args, automationId)
		where = append(where, fmt.Sprintf(`automation_id = $%d::uuid`, len(args)))
	}

	if runId != "" {
		args = append(args, runId)
		where = append(where, fmt.Sprintf(`id = $%d::uuid`, len(args)))
	} else {
		where = append(where, `stopped_by IS NOT NULL`)
	}

	rows, err := q.Query(ctx, `
		UPDATE automation_runs
		SET state = 'stopped',
		    stopped_by = COALESCE(stopped_by, NULLIF($1, '')),
		    stopped_at = COALESCE(stopped_at, now()),
		    ended_at = COALESCE(stopped_at, now())
		WHERE `+strings.Join(where, ` AND `)+`
		RETURNING id::text`, args...)
	if err != nil {
		return 0, 0, err
	}

	runIds := []string{}

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()

			return 0, 0, err
		}

		runIds = append(runIds, id)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	if len(runIds) == 0 {
		return 0, 0, nil
	}

	// failed_run_ids is left alone: stopping is not the item's fault. applying items keep
	// their checkpoint, so the next run replays only the apply step. run_id is released so a
	// later sweep that fails the item isn't read as this run failing it; session_run_ids still
	// ties the item's sessions to this run.
	requeued, err := countAffected(ctx, q, `
		UPDATE automation_work_items
		SET state = 'pending', run_id = NULL, result = NULL, error = NULLIF($1, ''), updated_at = now()
		WHERE state = 'running' AND run_id::text = ANY($2::text[])
		RETURNING id`, cause, runIds)
	if err != nil {
		return 0, 0, err
	}

	return len(runIds), requeued, nil
}

// FailAbandonedAutomationRun closes the open run of an automation, if there is one. Only the
// caller knows nothing owns it; the scheduler calls this when the in-flight index refuses an
// open for an automation it has no run registered for. A row a Stop marked closes as stopped,
// its running items uncharged; any other row fails. It returns the number of runs it closed.
func (s *Store) FailAbandonedAutomationRun(ctx context.Context, automationId, cause string) (int, error) {
	if automationId == "" {
		return 0, fmt.Errorf("cannot fail a run without an automation id")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("database: begin transaction: %w", err)
	}

	defer tx.Rollback(ctx)

	stopped, _, err := closeStoppingRuns(ctx, tx, automationId, "", automationRunStoppedCause, "")
	if err != nil {
		return 0, err
	}

	failed, err := countAffected(ctx, tx, `
		UPDATE automation_runs
		SET state = 'failed', ended_at = now(), error = NULLIF($2, '')
		WHERE automation_id = $1 AND ended_at IS NULL
		RETURNING id`, automationId, cause)
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}

	return s.countAutomationChanges(stopped+failed, nil)
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
	// Drops succeeded runs that worked no item and that no user started.
	HideEmpty bool
	// Matched case-insensitively against the run's error and its items' group keys and errors.
	Search string
	// Also match Search.
	SearchAutomationIds []string
	SearchRunId         string
	Limit               int
	Offset              int
}

// The items a run last worked, failed or ran a session for, as CountAutomationWorkItemsByRun counts them.
const runWorkItemsClause = `FROM automation_work_items w
	WHERE (w.run_id = automation_runs.id OR w.failed_run_ids @> ARRAY[automation_runs.id::text]
	       OR w.session_run_ids @> ARRAY[automation_runs.id::text])`

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
		// A user acted on a stopped run or one they started, so it shows even when it worked nothing.
		kept := `state IN ('failed', 'stopped') OR started_by IS NOT NULL`

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
