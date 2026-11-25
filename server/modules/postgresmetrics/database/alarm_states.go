// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const moduleName = "postgresmetrics"

// Migrate runs any pending database migrations for postgresmetrics.
func (s *Store) Migrate(ctx context.Context) error {
	if s.db == nil {
		return errors.New("database connection cannot be nil")
	}
	return s.db.Migrate(ctx, migrationFS, moduleName)
}

// GetAlarmStates retrieves all persisted alarm states.
func (s *Store) GetAlarmStates(ctx context.Context) ([]model.AlarmState, error) {
	if s.db == nil {
		return []model.AlarmState{}, nil
	}
	query := `
		SELECT alarm_id, node_id, status, current_value, threshold, operator,
		       metric, metric_key, triggered_at, cleared_at, first_breached_at,
		       duration_active_seconds, last_evaluated, updated_at
		FROM alarm_states
		ORDER BY status DESC, updated_at DESC;
	`
	rows, err := s.db.Query(ctx, query)
	if err != nil {
		if s.isMissingRelationError(err) {
			return []model.AlarmState{}, nil
		}
		return nil, fmt.Errorf("database: query alarm states: %w", err)
	}
	defer rows.Close()

	states := make([]model.AlarmState, 0)
	for rows.Next() {
		var state model.AlarmState
		var triggeredAt, clearedAt, firstBreachedAt *time.Time
		err := rows.Scan(
			&state.AlarmID,
			&state.NodeID,
			&state.Status,
			&state.CurrentValue,
			&state.Threshold,
			&state.Operator,
			&state.Metric,
			&state.MetricKey,
			&triggeredAt,
			&clearedAt,
			&firstBreachedAt,
			&state.DurationActiveSeconds,
			&state.LastEvaluated,
			&state.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("database: scan alarm state: %w", err)
		}
		state.TriggeredAt = triggeredAt
		state.ClearedAt = clearedAt
		state.FirstBreachedAt = firstBreachedAt
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: rows err: %w", err)
	}
	return states, nil
}

// GetAlarmState retrieves the state for a specific alarm and node combination.
func (s *Store) GetAlarmState(ctx context.Context, alarmID, nodeID string) (*model.AlarmState, error) {
	if s.db == nil {
		return nil, nil
	}
	query := `
		SELECT alarm_id, node_id, status, current_value, threshold, operator,
		       metric, metric_key, triggered_at, cleared_at, first_breached_at,
		       duration_active_seconds, last_evaluated, updated_at
		FROM alarm_states
		WHERE alarm_id = $1 AND node_id = $2;
	`
	row := s.db.QueryRow(ctx, query, alarmID, nodeID)
	var state model.AlarmState
	var triggeredAt, clearedAt, firstBreachedAt *time.Time
	err := row.Scan(
		&state.AlarmID,
		&state.NodeID,
		&state.Status,
		&state.CurrentValue,
		&state.Threshold,
		&state.Operator,
		&state.Metric,
		&state.MetricKey,
		&triggeredAt,
		&clearedAt,
		&firstBreachedAt,
		&state.DurationActiveSeconds,
		&state.LastEvaluated,
		&state.UpdatedAt,
	)
	if err != nil {
		if s.isMissingRelationError(err) || strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return nil, nil
		}
		return nil, err
	}
	state.TriggeredAt = triggeredAt
	state.ClearedAt = clearedAt
	state.FirstBreachedAt = firstBreachedAt
	return &state, nil
}

// UpsertAlarmState inserts or updates an alarm state record.
func (s *Store) UpsertAlarmState(ctx context.Context, state *model.AlarmState) error {
	if state == nil {
		return errors.New("alarm state cannot be nil")
	}
	if s.db == nil {
		return nil
	}

	query := `
		INSERT INTO alarm_states (
			alarm_id, node_id, status, current_value, threshold, operator,
			metric, metric_key, triggered_at, cleared_at, first_breached_at,
			duration_active_seconds, last_evaluated, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (alarm_id, node_id) DO UPDATE SET
			status = EXCLUDED.status,
			current_value = EXCLUDED.current_value,
			threshold = EXCLUDED.threshold,
			operator = EXCLUDED.operator,
			metric = EXCLUDED.metric,
			metric_key = EXCLUDED.metric_key,
			triggered_at = EXCLUDED.triggered_at,
			cleared_at = EXCLUDED.cleared_at,
			first_breached_at = EXCLUDED.first_breached_at,
			duration_active_seconds = EXCLUDED.duration_active_seconds,
			last_evaluated = EXCLUDED.last_evaluated,
			updated_at = EXCLUDED.updated_at;
	`
	now := time.Now().UTC()
	if state.LastEvaluated.IsZero() {
		state.LastEvaluated = now
	}
	state.UpdatedAt = now

	return s.db.Exec(
		ctx,
		query,
		state.AlarmID,
		state.NodeID,
		state.Status,
		state.CurrentValue,
		state.Threshold,
		state.Operator,
		state.Metric,
		state.MetricKey,
		state.TriggeredAt,
		state.ClearedAt,
		state.FirstBreachedAt,
		state.DurationActiveSeconds,
		state.LastEvaluated,
		state.UpdatedAt,
	)
}

// DeleteAlarmStatesForAlarm removes all state records associated with an alarm ID.
func (s *Store) DeleteAlarmStatesForAlarm(ctx context.Context, alarmID string) error {
	if s.db == nil {
		return nil
	}
	query := `DELETE FROM alarm_states WHERE alarm_id = $1;`
	return s.db.Exec(ctx, query, alarmID)
}
