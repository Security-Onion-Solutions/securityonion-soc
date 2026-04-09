// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

// migrateAssistantData migrates existing assistant data from Elasticsearch to PostgreSQL.
// It reads all sessions and chat messages from the existing Assistantstore (ES) and inserts
// them into the new PostgreSQL store. This runs once during Init — after migration,
// postgres takes over as the sole Assistantstore.
func migrateAssistantData(ctx context.Context, esStore server.Assistantstore, pgStore *PostgresAssistantstore) error {
	// Check if postgres already has data (migration already done)
	existing, err := pgStore.GetSessions(ctx, model.GetSessionsWithIncludeDeleted(true))
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		log.WithField("sessionCount", len(existing)).Info("PostgreSQL already has assistant data, skipping migration")
		return nil
	}

	// Get all sessions from ES (including deleted)
	sessions, err := esStore.GetSessions(ctx, model.GetSessionsWithIncludeDeleted(true))
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		log.Info("No assistant sessions found in Elasticsearch, nothing to migrate")
		return nil
	}

	log.WithField("sessionCount", len(sessions)).Info("Migrating assistant sessions from Elasticsearch to PostgreSQL")

	for _, session := range sessions {
		// Insert session directly into postgres (bypass the context-based userId)
		if err := pgStore.insertSessionDirect(ctx, session); err != nil {
			log.WithError(err).WithField("sessionId", session.SessionId).Warn("Failed to migrate session, skipping")
			continue
		}

		// Get chat history for this session from ES
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
		}
	}

	log.WithField("sessionCount", len(sessions)).Info("Assistant data migration complete")
	return nil
}
