// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

const migrationAssistantData = "assistant_data_from_elasticsearch"

// esMigrationConfig holds the connection info needed to query Elasticsearch directly
// for the chat migration. We bypass the Assistantstore interface because it enforces
// RBAC which requires a user context that doesn't exist during module startup.
type esMigrationConfig struct {
	HostUrl      string
	Username     string
	Password     string
	ChatIndex    string
	SessionIndex string
	SchemaPrefix string
}

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
// Queries ES directly via HTTP to bypass RBAC which requires a user context.
func migrateAssistantData(ctx context.Context, pool *pgxpool.Pool, esCfg *esMigrationConfig, pgStore *PostgresAssistantstore) error {
	done, err := isMigrationComplete(ctx, pool, migrationAssistantData)
	if err != nil {
		return err
	}
	if done {
		log.Info("Assistant data migration already completed, skipping")
		return nil
	}

	if esCfg == nil || esCfg.HostUrl == "" {
		log.Info("No Elasticsearch config available, marking migration complete with no data")
		return markMigrationComplete(ctx, pool, migrationAssistantData)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	sessions, err := fetchSessionsFromES(ctx, client, esCfg)
	if err != nil {
		log.WithError(err).Warn("Failed to fetch sessions from Elasticsearch, marking migration complete anyway")
		return markMigrationComplete(ctx, pool, migrationAssistantData)
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

		messages, err := fetchMessagesFromES(ctx, client, esCfg, session.SessionId)
		if err != nil {
			log.WithError(err).WithField("sessionId", session.SessionId).Warn("Failed to fetch messages, skipping")
			continue
		}

		for _, msg := range messages {
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

// fetchSessionsFromES queries Elasticsearch directly for all assistant sessions.
func fetchSessionsFromES(ctx context.Context, client *http.Client, cfg *esMigrationConfig) ([]*model.AssistantSession, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				cfg.SchemaPrefix + "kind": "session",
			},
		},
		"size": 10000,
	}

	hits, err := esSearch(ctx, client, cfg, cfg.SessionIndex, query)
	if err != nil {
		return nil, err
	}

	sessions := make([]*model.AssistantSession, 0, len(hits))
	for _, hit := range hits {
		session, err := parseSessionFromHit(hit, cfg.SchemaPrefix)
		if err != nil {
			log.WithError(err).Warn("Failed to parse session from ES hit, skipping")
			continue
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// fetchMessagesFromES queries Elasticsearch directly for all messages in a session.
func fetchMessagesFromES(ctx context.Context, client *http.Client, cfg *esMigrationConfig, sessionId string) ([]*model.StoredMessage, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []interface{}{
					map[string]interface{}{
						"term": map[string]interface{}{
							cfg.SchemaPrefix + "kind": "chat",
						},
					},
					map[string]interface{}{
						"term": map[string]interface{}{
							cfg.SchemaPrefix + "chat.sessionId": sessionId,
						},
					},
				},
			},
		},
		"size": 10000,
		"sort": []interface{}{
			map[string]interface{}{
				"@timestamp": map[string]interface{}{"order": "asc"},
			},
		},
	}

	hits, err := esSearch(ctx, client, cfg, cfg.ChatIndex, query)
	if err != nil {
		return nil, err
	}

	messages := make([]*model.StoredMessage, 0, len(hits))
	for _, hit := range hits {
		msg, err := parseMessageFromHit(hit, cfg.SchemaPrefix)
		if err != nil {
			log.WithError(err).Warn("Failed to parse message from ES hit, skipping")
			continue
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

// esSearch performs a raw HTTP search against Elasticsearch.
func esSearch(ctx context.Context, client *http.Client, cfg *esMigrationConfig, index string, query map[string]interface{}) ([]map[string]interface{}, error) {
	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/%s/_search", cfg.HostUrl, index)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Username != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ES search failed: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source map[string]interface{} `json:"_source"`
				Id     string                 `json:"_id"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	hits := make([]map[string]interface{}, 0, len(result.Hits.Hits))
	for _, h := range result.Hits.Hits {
		if h.Source == nil {
			continue
		}
		h.Source["_id"] = h.Id
		hits = append(hits, h.Source)
	}

	return hits, nil
}

// parseSessionFromHit converts an ES _source document to an AssistantSession.
func parseSessionFromHit(hit map[string]interface{}, schemaPrefix string) (*model.AssistantSession, error) {
	sessionObj, ok := hit[schemaPrefix+"session"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing session object")
	}

	session := &model.AssistantSession{}
	if id, ok := hit["_id"].(string); ok {
		session.Id = id
	}
	if v, ok := sessionObj["sessionId"].(string); ok {
		session.SessionId = v
	}
	if v, ok := sessionObj["userId"].(string); ok {
		session.UserId = v
	}
	if v, ok := sessionObj["title"].(string); ok {
		session.Title = v
	}
	if v, ok := sessionObj["type"].(string); ok {
		session.Type = v
	}
	if v, ok := sessionObj["entityId"].(string); ok {
		session.EntityId = v
	}
	if tags, ok := sessionObj["tags"].([]interface{}); ok {
		session.Tags = make([]string, 0, len(tags))
		for _, t := range tags {
			if s, ok := t.(string); ok {
				session.Tags = append(session.Tags, s)
			}
		}
	}
	if v, ok := sessionObj["createTime"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			session.CreateTime = &t
		}
	}
	if v, ok := sessionObj["updateTime"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			session.UpdateTime = &t
		}
	}
	if v, ok := sessionObj["deleteTime"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			session.DeleteTime = &t
		}
	}

	return session, nil
}

// parseMessageFromHit converts an ES _source document to a StoredMessage.
func parseMessageFromHit(hit map[string]interface{}, schemaPrefix string) (*model.StoredMessage, error) {
	chatObj, ok := hit[schemaPrefix+"chat"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing chat object")
	}

	msg := &model.StoredMessage{}
	if id, ok := hit["_id"].(string); ok {
		msg.Id = id
	}
	if v, ok := chatObj["sessionId"].(string); ok {
		msg.SessionId = v
	}
	if v, ok := chatObj["userId"].(string); ok {
		msg.UserId = v
	}
	if v, ok := chatObj["model"].(string); ok {
		msg.Model = v
	}
	if tags, ok := chatObj["tags"].([]interface{}); ok {
		msg.Tags = make([]string, 0, len(tags))
		for _, t := range tags {
			if s, ok := t.(string); ok {
				msg.Tags = append(msg.Tags, s)
			}
		}
	}
	if v, ok := chatObj["createTime"].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			msg.CreateTime = &t
		}
	}

	// Re-marshal the message sub-object to JSON and unmarshal into model.Message
	if messageObj, ok := chatObj["message"].(map[string]interface{}); ok {
		msgBytes, err := json.Marshal(messageObj)
		if err == nil {
			msg.Message = &model.Message{}
			if err := json.Unmarshal(msgBytes, msg.Message); err != nil {
				return nil, fmt.Errorf("failed to unmarshal message content: %w", err)
			}
		}
	}

	if msg.Message == nil {
		return nil, fmt.Errorf("missing message content")
	}

	return msg, nil
}
