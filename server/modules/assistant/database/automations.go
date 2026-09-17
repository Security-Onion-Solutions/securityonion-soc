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

const automationColumns = `id, display_name, kind, params, enabled, interval_seconds, user_id, created_at, updated_at, last_run_time`

func scanAutomationRow(rows db.Rows) (*model.Automation, error) {
	automation := &model.Automation{Auditable: model.Auditable{Kind: "automation"}}

	var params []byte

	err := rows.Scan(&automation.Id, &automation.DisplayName, &automation.AutomationKind, &params,
		&automation.Enabled, &automation.IntervalSeconds, &automation.UserId,
		&automation.CreateTime, &automation.UpdateTime, &automation.LastRunTime)
	if err != nil {
		return nil, err
	}

	automation.Params = json.RawMessage(params)

	return automation, nil
}

// AddAutomation inserts a new automation and fills in the id the database generated. A
// caller-supplied id is ignored: identity is the server's to assign, and everything
// downstream keys on it.
func (s *Store) AddAutomation(ctx context.Context, automation *model.Automation) error {
	if automation.UserId == "" {
		return fmt.Errorf("cannot save an automation without a user")
	}

	return s.db.QueryRow(ctx, `
		INSERT INTO automations (display_name, kind, params, enabled, interval_seconds, user_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`,
		automation.DisplayName, automation.AutomationKind, jsonbOrEmpty(automation.Params),
		automation.Enabled, automation.IntervalSeconds, automation.UserId).
		Scan(&automation.Id, &automation.CreateTime, &automation.UpdateTime)
}

// UpdateAutomation rewrites an automation in place. Neither the id nor the kind is
// settable: the id is identity, and the params were validated against the kind, so
// changing kinds is a delete and a create.
func (s *Store) UpdateAutomation(ctx context.Context, automation *model.Automation) error {
	if automation.Id == "" {
		return fmt.Errorf("cannot update an automation without an id")
	}

	rows, err := s.db.Query(ctx, `
		UPDATE automations
		SET display_name = $2, params = $3, enabled = $4, interval_seconds = $5,
		    user_id = $6, updated_at = now()
		WHERE id = $1
		RETURNING kind, created_at, updated_at`,
		automation.Id, automation.DisplayName, jsonbOrEmpty(automation.Params),
		automation.Enabled, automation.IntervalSeconds, automation.UserId)
	if err != nil {
		return err
	}

	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}

		return ErrAutomationNotFound
	}

	return rows.Scan(&automation.AutomationKind, &automation.CreateTime, &automation.UpdateTime)
}

func (s *Store) GetAutomation(ctx context.Context, id string) (*model.Automation, error) {
	rows, err := s.db.Query(ctx, `SELECT `+automationColumns+` FROM automations WHERE id = $1`, id)
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

	return scanAutomationRow(rows)
}

func (s *Store) ListAutomations(ctx context.Context) ([]*model.Automation, error) {
	rows, err := s.db.Query(ctx, `SELECT `+automationColumns+` FROM automations ORDER BY display_name, id`)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	automations := []*model.Automation{}

	for rows.Next() {
		automation, err := scanAutomationRow(rows)
		if err != nil {
			return nil, err
		}

		automations = append(automations, automation)
	}

	return automations, rows.Err()
}

// DeleteAutomation removes an automation and its history. It refuses while a run is in
// flight, because a kind mid-run would otherwise keep writing rows for an automation that
// no longer exists. The history is cleared here rather than by a cascade so that refusal
// stays possible: a foreign key would have to choose between cascading and blocking, and
// blocking would strand the automation behind runs nothing ever closes.
func (s *Store) DeleteAutomation(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("cannot delete an automation without an id")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin transaction: %w", err)
	}

	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		DELETE FROM automations a
		WHERE a.id = $1
		  AND NOT EXISTS (SELECT 1 FROM automation_runs r
		                  WHERE r.automation_id = a.id
		                    AND r.state IN ('queued', 'running'))
		RETURNING a.id`, id)
	if err != nil {
		return err
	}

	deleted := rows.Next()
	scanErr := rows.Err()

	rows.Close()

	if scanErr != nil {
		return scanErr
	}

	if !deleted {
		// Either the automation is gone or a run holds it. Read inside the same transaction
		// rather than on a second connection, which would see its own snapshot.
		return explainFailedDelete(ctx, tx, id)
	}

	// Runs cascade to their own audit rows; work items reference runs with ON DELETE
	// SET NULL, so they must be cleared by automation.
	if err := tx.Exec(ctx, `DELETE FROM automation_work_items WHERE automation_id = $1`, id); err != nil {
		return err
	}

	if err := tx.Exec(ctx, `DELETE FROM automation_runs WHERE automation_id = $1`, id); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// explainFailedDelete tells a refusal apart from a miss after the delete matched nothing.
func explainFailedDelete(ctx context.Context, tx db.Tx, id string) error {
	rows, err := tx.Query(ctx, `SELECT 1 FROM automations WHERE id = $1`, id)
	if err != nil {
		return err
	}

	defer rows.Close()

	if rows.Next() {
		return ErrAutomationRunInFlight
	}

	if err := rows.Err(); err != nil {
		return err
	}

	return ErrAutomationNotFound
}
