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
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	pgcommon "github.com/security-onion-solutions/securityonion-soc/db/postgres"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const moduleName = "onionconfig"

// Store encapsulates all Postgres operations for onionconfig.
type Store struct {
	db *pgcommon.DB
}

// SettingRow is the raw DB representation of a setting.
type SettingRow struct {
	SettingID        string
	Value            string // JSON-encoded
	DuplicatedFromID string
	NodeID           string
}

// AuditEntry records a change to a setting.
type AuditEntry struct {
	SettingID string
	NodeID    string
	Timestamp time.Time
	UserID    string
	OldValue  string // JSON-encoded
	NewValue  string // JSON-encoded
	Note      string
}

// New opens a connection pool and runs pending migrations.
func New(ctx context.Context, cfg pgcommon.Config) (*Store, error) {
	db, err := pgcommon.Open(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: connect: %w", err)
	}
	if err := db.Migrate(ctx, migrationFS, moduleName); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the underlying connection pool.
func (s *Store) Close() {
	s.db.Close()
}

// GetAllSettings returns every row from the settings table.
func (s *Store) GetAllSettings(ctx context.Context) ([]SettingRow, error) {
	rows, err := s.db.Query(ctx, `
		SELECT setting_id,
		       COALESCE(value::text, 'null'),
		       COALESCE(duplicated_from_id, ''),
		       COALESCE(node_id, '')
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
	var nid *string
	if nodeID != "" {
		nid = &nodeID
	}
	err := s.db.QueryRow(ctx, `
		SELECT setting_id,
		       COALESCE(value::text, 'null'),
		       COALESCE(duplicated_from_id, ''),
		       COALESCE(node_id, '')
		FROM settings
		WHERE setting_id = $1 AND node_id IS NOT DISTINCT FROM $2`,
		settingID, nid,
	).Scan(&r.SettingID, &r.Value, &r.DuplicatedFromID, &r.NodeID)
	if err != nil {
		return nil, err
	}
	return &r, nil
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

func (s *Store) upsertSetting(ctx context.Context, tx pgx.Tx, row SettingRow) error {
	valJSON, err := encodeValue(row.Value)
	if err != nil {
		return err
	}
	var nodeID *string
	if row.NodeID != "" {
		nodeID = &row.NodeID
	}
	var dupID *string
	if row.DuplicatedFromID != "" {
		dupID = &row.DuplicatedFromID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO settings (setting_id, value, duplicated_from_id, node_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (setting_id, COALESCE(node_id, ''))
		DO UPDATE SET value = EXCLUDED.value,
		              duplicated_from_id = EXCLUDED.duplicated_from_id`,
		row.SettingID, valJSON, dupID, nodeID,
	)
	return err
}

func (s *Store) deleteSetting(ctx context.Context, tx pgx.Tx, settingID, nodeID string) error {
	var nid *string
	if nodeID != "" {
		nid = &nodeID
	}
	_, err := tx.Exec(ctx, `
		DELETE FROM settings
		WHERE setting_id = $1 AND node_id IS NOT DISTINCT FROM $2`,
		settingID, nid,
	)
	return err
}

func (s *Store) insertAudit(ctx context.Context, tx pgx.Tx, entry AuditEntry) error {
	oldJSON, err := encodeValue(entry.OldValue)
	if err != nil {
		return err
	}
	newJSON, err := encodeValue(entry.NewValue)
	if err != nil {
		return err
	}
	var nid *string
	if entry.NodeID != "" {
		nid = &entry.NodeID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_settings (setting_id, node_id, ts, user_id, old_value, new_value, note)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.SettingID, nid, entry.Timestamp.UTC(), entry.UserID, oldJSON, newJSON, entry.Note,
	)
	return err
}

// encodeValue converts a string value to JSONB-compatible JSON.
// A plain string is wrapped in JSON quotes; a value that is already valid JSON is passed through.
func encodeValue(v string) ([]byte, error) {
	if v == "" || v == "null" {
		return []byte("null"), nil
	}
	if json.Valid([]byte(v)) {
		return []byte(v), nil
	}
	return json.Marshal(v)
}
