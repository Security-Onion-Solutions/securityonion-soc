// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"fmt"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

// EnsureAutomationRunSession links a run to a session it created. Idempotent on
// (run_id, session_id) so a write retried after a crash does not duplicate the trail.
func (s *Store) EnsureAutomationRunSession(ctx context.Context, rs *model.AutomationRunSession) error {
	if rs.RunId == "" || rs.SessionId == "" {
		return fmt.Errorf("cannot record a run session without a run id and a session id")
	}

	return s.db.Exec(ctx, `
		INSERT INTO automation_run_sessions (run_id, session_id, work_item_id, purpose)
		VALUES ($1, $2, NULLIF($3, '')::uuid, $4)
		ON CONFLICT (run_id, session_id) DO NOTHING`,
		rs.RunId, rs.SessionId, rs.WorkItemId, rs.Purpose)
}

// EnsureAutomationRunResultAudit records what a run concluded about each alert. Re-recording an
// alert overwrites its recommendation, so an apply step resumed after a crash converges
// instead of conflicting.
//
// Callers must not pass the same alert twice in one batch: ON CONFLICT DO UPDATE cannot
// affect a row a second time, and Postgres raises rather than picking a winner.
func (s *Store) EnsureAutomationRunResultAudit(ctx context.Context, runId string, alerts []*model.AutomationRunResultAudit) error {
	if len(alerts) == 0 {
		return nil
	}

	if runId == "" {
		return fmt.Errorf("cannot record run alerts without a run id")
	}

	alertIds := make([]string, 0, len(alerts))
	workItemIds := make([]string, 0, len(alerts))
	recommendations := make([]string, 0, len(alerts))
	reasons := make([]string, 0, len(alerts))
	inherited := make([]bool, 0, len(alerts))

	seen := make(map[string]struct{}, len(alerts))

	for _, alert := range alerts {
		if _, dup := seen[alert.AlertId]; dup {
			return fmt.Errorf("cannot record alert %s twice in one batch", alert.AlertId)
		}

		seen[alert.AlertId] = struct{}{}

		alertIds = append(alertIds, alert.AlertId)
		workItemIds = append(workItemIds, alert.WorkItemId)
		recommendations = append(recommendations, alert.Recommendation)
		reasons = append(reasons, alert.Reason)
		inherited = append(inherited, alert.Inherited)
	}

	return s.db.Exec(ctx, `
		INSERT INTO automation_run_result_audit (run_id, alert_id, work_item_id, recommendation, reason, inherited)
		SELECT $1, a.alert_id, NULLIF(a.work_item_id, '')::uuid, a.recommendation, a.reason, a.inherited
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::boolean[])
			AS a(alert_id, work_item_id, recommendation, reason, inherited)
		ON CONFLICT (run_id, alert_id) DO UPDATE
		SET work_item_id = EXCLUDED.work_item_id, recommendation = EXCLUDED.recommendation,
		    reason = EXCLUDED.reason, inherited = EXCLUDED.inherited`,
		runId, alertIds, workItemIds, recommendations, reasons, inherited)
}

func (s *Store) ListAutomationRunSessions(ctx context.Context, runId string) ([]*model.AutomationRunSession, error) {
	rows, err := s.db.Query(ctx, `
		SELECT run_id, session_id, work_item_id, purpose, created_at
		FROM automation_run_sessions
		WHERE run_id = $1
		ORDER BY created_at`, runId)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	sessions := []*model.AutomationRunSession{}

	for rows.Next() {
		rs := &model.AutomationRunSession{}

		var workItemId *string

		if err := rows.Scan(&rs.RunId, &rs.SessionId, &workItemId, &rs.Purpose, &rs.CreateTime); err != nil {
			return nil, err
		}

		if workItemId != nil {
			rs.WorkItemId = *workItemId
		}

		sessions = append(sessions, rs)
	}

	return sessions, rows.Err()
}

func (s *Store) ListAutomationRunResultAudit(ctx context.Context, runId string) ([]*model.AutomationRunResultAudit, error) {
	rows, err := s.db.Query(ctx, `
		SELECT run_id, alert_id, work_item_id, recommendation, reason, inherited, created_at
		FROM automation_run_result_audit
		WHERE run_id = $1
		ORDER BY created_at, alert_id`, runId)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	alerts := []*model.AutomationRunResultAudit{}

	for rows.Next() {
		alert := &model.AutomationRunResultAudit{}

		var workItemId *string

		err := rows.Scan(&alert.RunId, &alert.AlertId, &workItemId, &alert.Recommendation,
			&alert.Reason, &alert.Inherited, &alert.CreateTime)
		if err != nil {
			return nil, err
		}

		if workItemId != nil {
			alert.WorkItemId = *workItemId
		}

		alerts = append(alerts, alert)
	}

	return alerts, rows.Err()
}
