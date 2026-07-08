// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"errors"

	"github.com/apex/log"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/security-onion-solutions/securityonion-soc/db"
)

type Store struct {
	db db.DB
}

func New(database db.DB) *Store {
	return &Store{db: database}
}

func (s *Store) handleQueryError(err error, operation string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
		log.Debugf("Postgres metrics: relation in %s does not exist; skipping", operation)
	} else {
		log.Warnf("Postgres metrics: %s query failed: %v", operation, err)
	}
}

func (s *Store) isMissingRelationError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}
