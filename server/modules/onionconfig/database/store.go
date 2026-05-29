// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Package database provides all Postgres access for the onionconfig module.
// All queries are routed through Store to keep DB concerns isolated from
// business logic.
package database

import (
	"context"
	"embed"
	"fmt"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/db"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const moduleName = "onionconfig"

// Store encapsulates all Postgres operations for onionconfig.
type Store struct {
	db db.DB
}

// SettingRow is the raw DB representation of a setting.
type SettingRow struct {
	SettingID        string
	Value            *string // JSON-encoded
	DuplicatedFromID string
	NodeID           string
}

// AuditEntry records a change to a setting.
type AuditEntry struct {
	SettingID string
	NodeID    string
	Timestamp time.Time
	UserID    string
	OldValue  *string // JSON-encoded
	NewValue  *string // JSON-encoded
	Note      string
}

// New wraps an existing DB connection and runs pending migrations.
func New(ctx context.Context, database db.DB) (*Store, error) {
	if err := database.Migrate(ctx, migrationFS, moduleName); err != nil {
		return nil, fmt.Errorf("database: migrate: %w", err)
	}
	return &Store{db: database}, nil
}

// GetAllSettings returns every row from the settings table.
func (s *Store) GetAllSettings(ctx context.Context) ([]SettingRow, error) {
	rows, err := s.db.Query(ctx, `
		SELECT setting_id,
		       COALESCE(value::text, 'null'),
		       COALESCE(duplicated_from_id, ''),
		       node_id
		FROM settings
		ORDER BY setting_id, node_id`)
	if err != nil {
		return nil, fmt.Errorf("database: GetAllSettings: %w", err)
	}
	defer rows.Close()

	var result []SettingRow
	for rows.Next() {
		var r SettingRow
		if err := rows.Scan(&r.SettingID, &r.Value, &r.DuplicatedFromID, &r.NodeID); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// GetSetting returns a single setting by ID and optional nodeID (empty string = global).
func (s *Store) GetSetting(ctx context.Context, settingID, nodeID string) (*SettingRow, error) {
	var r SettingRow
	err := s.db.QueryRow(ctx, `
		SELECT setting_id,
		       COALESCE(value::text, 'null'),
		       COALESCE(duplicated_from_id, ''),
		       node_id
		FROM settings
		WHERE setting_id = $1 AND node_id = $2`,
		settingID, nodeID,
	).Scan(&r.SettingID, &r.Value, &r.DuplicatedFromID, &r.NodeID)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// GetAuditHistory returns paged audit records for a specific setting and node.
func (s *Store) GetAuditHistory(ctx context.Context, settingID, nodeID string, limit, offset int, sort, order string) ([]AuditEntry, int, error) {
	var total int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM audit_settings WHERE setting_id = $1 AND node_id = $2`, settingID, nodeID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("database: GetAuditHistory count: %w", err)
	}

	orderBy := s.mapSort(sort, order)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
		SELECT setting_id,
		       node_id,
		       ts,
		       user_id,
		       old_value,
		       new_value,
		       COALESCE(note, '')
		FROM audit_settings
		WHERE setting_id = $1 AND node_id = $2
		ORDER BY %s
		LIMIT $3 OFFSET $4`, orderBy),
		settingID, nodeID, limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("database: GetAuditHistory: %w", err)
	}
	defer rows.Close()

	var result []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.SettingID, &a.NodeID, &a.Timestamp, &a.UserID, &a.OldValue, &a.NewValue, &a.Note); err != nil {
			return nil, 0, err
		}
		result = append(result, a)
	}
	return result, total, rows.Err()
}

// GetAllAuditHistory returns paged audit records for all settings.
func (s *Store) GetAllAuditHistory(ctx context.Context, limit, offset int, sort, order string) ([]AuditEntry, int, error) {
	var total int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM audit_settings`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("database: GetAllAuditHistory count: %w", err)
	}

	orderBy := s.mapSort(sort, order)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
		SELECT setting_id,
		       node_id,
		       ts,
		       user_id,
		       old_value,
		       new_value,
		       COALESCE(note, '')
		FROM audit_settings
		ORDER BY %s
		LIMIT $1 OFFSET $2`, orderBy),
		limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("database: GetAllAuditHistory: %w", err)
	}
	defer rows.Close()

	var result []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.SettingID, &a.NodeID, &a.Timestamp, &a.UserID, &a.OldValue, &a.NewValue, &a.Note); err != nil {
			return nil, 0, err
		}
		result = append(result, a)
	}
	return result, total, rows.Err()
}

func (s *Store) mapSort(sort, order string) string {
	col := "ts"
	switch sort {
	case "user", "userId":
		col = "user_id"
	case "settingId":
		col = "setting_id"
	case "node", "nodeId":
		col = "node_id"
	case "oldValue":
		col = "old_value"
	case "newValue":
		col = "new_value"
	}

	dir := "DESC"
	if order == "asc" {
		dir = "ASC"
	}
	return fmt.Sprintf("%s %s", col, dir)
}

// GetRevertState returns the values to which settings should be reverted in order to undo all changes
// that occurred on or after the given timestamp.
func (s *Store) GetRevertState(ctx context.Context, ts time.Time) ([]SettingRow, error) {
	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT ON (setting_id, node_id)
			setting_id, node_id, old_value
		FROM audit_settings
		WHERE ts >= $1
		ORDER BY setting_id, node_id, ts ASC`,
		ts.UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("database: GetRevertState: %w", err)
	}
	defer rows.Close()

	var result []SettingRow
	for rows.Next() {
		var r SettingRow
		if err := rows.Scan(&r.SettingID, &r.NodeID, &r.Value); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// UpdateSettingWithAudit applies a setting change and records an audit log entry within a single transaction.
func (s *Store) UpdateSettingWithAudit(ctx context.Context, row SettingRow, audit AuditEntry, remove bool) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database: begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if remove {
		if err := s.deleteSetting(ctx, tx, row.SettingID, row.NodeID); err != nil {
			return fmt.Errorf("database: delete setting: %w", err)
		}
	} else {
		if err := s.upsertSetting(ctx, tx, row); err != nil {
			return fmt.Errorf("database: upsert setting: %w", err)
		}
	}

	if err := s.insertAudit(ctx, tx, audit); err != nil {
		return fmt.Errorf("database: insert audit: %w", err)
	}

	return tx.Commit(ctx)
}

// RecordAudit inserts an audit record into the database.
func (s *Store) RecordAudit(ctx context.Context, entry AuditEntry) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.insertAudit(ctx, tx, entry); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// GetAuditEntryAtTimestamp returns the audit entry for a specific setting/node at or before the given timestamp.
func (s *Store) GetAuditEntryAtTimestamp(ctx context.Context, settingID, nodeID string, ts time.Time) (*AuditEntry, error) {
	var a AuditEntry
	err := s.db.QueryRow(ctx, `
		SELECT setting_id,
		       node_id,
		       ts,
		       user_id,
		       old_value,
		       new_value,
		       COALESCE(note, '')
		FROM audit_settings
		WHERE setting_id = $1 AND node_id = $2 AND ts <= $3::timestamptz + interval '1 second'
		ORDER BY ts DESC
		LIMIT 1`,
		settingID, nodeID, ts.UTC(),
	).Scan(&a.SettingID, &a.NodeID, &a.Timestamp, &a.UserID, &a.OldValue, &a.NewValue, &a.Note)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) upsertSetting(ctx context.Context, tx db.Tx, row SettingRow) error {
	var dupID *string
	if row.DuplicatedFromID != "" {
		dupID = &row.DuplicatedFromID
	}
	err := tx.Exec(ctx, `
		INSERT INTO settings (setting_id, value, duplicated_from_id, node_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (setting_id, node_id)
		DO UPDATE SET value = EXCLUDED.value,
		              duplicated_from_id = EXCLUDED.duplicated_from_id`,
		row.SettingID, row.Value, dupID, row.NodeID,
	)
	return err
}

func (s *Store) deleteSetting(ctx context.Context, tx db.Tx, settingID, nodeID string) error {
	err := tx.Exec(ctx, `
		DELETE FROM settings
		WHERE setting_id = $1 AND node_id = $2`,
		settingID, nodeID,
	)
	return err
}

func (s *Store) insertAudit(ctx context.Context, tx db.Tx, entry AuditEntry) error {
	err := tx.Exec(ctx, `
		INSERT INTO audit_settings (setting_id, node_id, ts, user_id, old_value, new_value, note)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.SettingID, entry.NodeID, entry.Timestamp.UTC(), entry.UserID, entry.OldValue, entry.NewValue, entry.Note,
	)
	return err
}
