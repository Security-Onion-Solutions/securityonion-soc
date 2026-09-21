// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/security-onion-solutions/securityonion-soc/db"

	"github.com/jackc/pgx/v5/pgconn"
)

// The automation store's error surface, grouped so callers mapping them to status codes
// can see the whole set. ErrAutomationWorkItemNotFound also covers an item that is no
// longer in a state its transition is legal from.
var (
	ErrAutomationRunNotFound      = errors.New("ERROR_AUTOMATION_RUN_NOT_FOUND")
	ErrAutomationRunInFlight      = errors.New("ERROR_AUTOMATION_RUN_IN_FLIGHT")
	ErrAutomationRunNotOpen       = errors.New("ERROR_AUTOMATION_RUN_NOT_OPEN")
	ErrAutomationWorkItemNotFound = errors.New("ERROR_AUTOMATION_WORK_ITEM_NOT_FOUND")
)

// isUniqueViolation reports whether err is Postgres refusing a duplicate against the
// named index. Matching the constraint name and not just the code keeps one statement's
// several unique indexes from collapsing into the same error.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError

	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// jsonbOrEmpty renders raw JSON for a jsonb bind. jsonb rejects an empty string, so a
// nil or empty value becomes an empty object.
func jsonbOrEmpty(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}

	return string(raw)
}

// rowQuerier is the one method countAffected needs, so it can run against the pool or
// inside a transaction.
type rowQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (db.Rows, error)
}

// countAffected runs a statement that returns one row per row it changed, because Exec
// discards the rows-affected count.
func countAffected(ctx context.Context, q rowQuerier, stmt string, args ...any) (int, error) {
	rows, err := q.Query(ctx, stmt, args...)
	if err != nil {
		return 0, err
	}

	defer rows.Close()

	count := 0

	for rows.Next() {
		count++
	}

	return count, rows.Err()
}
