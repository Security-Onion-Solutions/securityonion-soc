// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"

	"github.com/apex/log"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

const migrationAssistantData = "assistant_data_from_elasticsearch"

// isMigrationComplete checks whether a named migration has already been recorded as complete.
func isMigrationComplete(ctx context.Context, pool *pgxpool.Pool, name string) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM migrations WHERE name = $1)`, name).Scan(&exists)
	return exists, err
}

// markMigrationComplete records that a named migration has completed successfully.
func markMigrationComplete(ctx context.Context, pool *pgxpool.Pool, name string) error {
	_, err := pool.Exec(ctx, `INSERT INTO migrations (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`, name)
	return err
}

// migrateAssistantData migrates existing assistant data from Elasticsearch to PostgreSQL.
// It uses a migrations table to track completion — the migration runs exactly once.
// Individual sessions and messages use ON CONFLICT DO NOTHING for idempotency,
// so a partial failure can be safely retried.
func migrateAssistantData(ctx context.Context, pool *pgxpool.Pool, esStore server.Assistantstore, pgStore *PostgresAssistantstore) error {
	done, err := isMigrationComplete(ctx, pool, migrationAssistantData)
	if err != nil {
		return err
	}
	if done {
		log.Info("Assistant data migration already completed, skipping")
		return nil
	}

	// Get all sessions from ES (including deleted ones).
	// We pass GetSessionsWithIncludeDeleted to capture everything.
	sessions, err := esStore.GetSessions(ctx, model.GetSessionsWithIncludeDeleted(true))
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		log.Info("No assistant sessions found in Elasticsearch, marking migration complete")
		return markMigrationComplete(ctx, pool, migrationAssistantData)
	}

	log.WithField("sessionCount", len(sessions)).Info("Migrating assistant sessions from Elasticsearch to PostgreSQL")

	migratedSessions := 0
	migratedMessages := 0

	for _, session := range sessions {
		if err := pgStore.insertSessionDirect(ctx, session); err != nil {
			log.WithError(err).WithField("sessionId", session.SessionId).Warn("Failed to migrate session, skipping")
			continue
		}
		migratedSessions++

		history, err := esStore.GetChatHistory(ctx, session.SessionId)
		if err != nil {
			log.WithError(err).WithField("sessionId", session.SessionId).Warn("Failed to get chat history for migration, skipping messages")
			continue
		}

		for _, msg := range history {
			if err := pgStore.insertMessageDirect(ctx, msg); err != nil {
				log.WithError(err).WithField("messageId", msg.Id).Warn("Failed to migrate message, skipping")
				continue
			}
			migratedMessages++
		}
	}

	log.WithFields(log.Fields{
		"migratedSessions": migratedSessions,
		"migratedMessages": migratedMessages,
		"totalSessions":    len(sessions),
	}).Info("Assistant data migration complete")

	return markMigrationComplete(ctx, pool, migrationAssistantData)
}
