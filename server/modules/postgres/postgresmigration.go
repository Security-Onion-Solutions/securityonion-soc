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

const defaultPageSize = 1000

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
	PageSize     int
	VerifyCert   bool
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

// recordMigrationFailure writes a single bad hit to the quarantine table. Used so that parse
// or insert failures on one record don't cause silent data loss — the raw source is preserved
// for later inspection. Errors writing to quarantine are logged but not propagated; we don't
// want quarantine itself to block the migration.
func recordMigrationFailure(ctx context.Context, pool *pgxpool.Pool, hitType, esId, sessionId, errMsg string, rawHit map[string]interface{}) {
	raw, err := json.Marshal(rawHit)
	if err != nil {
		raw = []byte("{}")
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO assistant_migration_failures (hit_type, es_id, session_id, error_message, raw_hit)
		 VALUES ($1, $2, $3, $4, $5)`,
		hitType, esId, sessionId, errMsg, raw); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"hitType":   hitType,
			"esId":      esId,
			"sessionId": sessionId,
		}).Warn("Failed to record migration failure in quarantine table")
	}
}

// migrateAssistantData migrates existing assistant data from Elasticsearch to PostgreSQL.
// It uses a migrations table to track completion — the migration runs exactly once per
// successful drain. Queries ES directly via HTTP to bypass RBAC which requires a user context.
//
// Error semantics:
//   - Transport/HTTP errors from Elasticsearch return an error and do NOT mark the migration
//     complete, so a transient outage retries on the next startup. Inserts are idempotent
//     (ON CONFLICT DO NOTHING) so retry-from-scratch is safe.
//   - Parse and per-record insert errors are written to assistant_migration_failures and the
//     migration continues. A summary log line reports the counts at the end.
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

	pageSize := esCfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !esCfg.VerifyCert},
		},
	}

	log.Info("Starting assistant data migration from Elasticsearch to PostgreSQL")

	var migratedSessions, migratedMessages, parseFailures, insertFailures int

	sessionQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				esCfg.SchemaPrefix + "kind": "session",
			},
		},
	}

	// Stable sort: @timestamp is written on every so-* document; _id breaks ties.
	sort := []interface{}{
		map[string]interface{}{"@timestamp": map[string]interface{}{"order": "asc"}},
		map[string]interface{}{"_id": map[string]interface{}{"order": "asc"}},
	}

	err = esSearchPaged(ctx, client, esCfg, esCfg.SessionIndex, sessionQuery, sort, pageSize, func(hit map[string]interface{}) error {
		esId, _ := hit["_id"].(string)

		session, err := parseSessionFromHit(hit, esCfg.SchemaPrefix)
		if err != nil {
			parseFailures++
			recordMigrationFailure(ctx, pool, "session", esId, "", err.Error(), hit)
			return nil
		}

		if err := pgStore.insertSessionDirect(ctx, session); err != nil {
			insertFailures++
			recordMigrationFailure(ctx, pool, "session", esId, session.SessionId, err.Error(), hit)
			return nil
		}
		migratedSessions++

		msgQuery := map[string]interface{}{
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []interface{}{
						map[string]interface{}{
							"term": map[string]interface{}{
								esCfg.SchemaPrefix + "kind": "chat",
							},
						},
						map[string]interface{}{
							"term": map[string]interface{}{
								esCfg.SchemaPrefix + "chat.sessionId": session.SessionId,
							},
						},
					},
				},
			},
		}

		msgErr := esSearchPaged(ctx, client, esCfg, esCfg.ChatIndex, msgQuery, sort, pageSize, func(msgHit map[string]interface{}) error {
			msgEsId, _ := msgHit["_id"].(string)

			msg, err := parseMessageFromHit(msgHit, esCfg.SchemaPrefix)
			if err != nil {
				parseFailures++
				recordMigrationFailure(ctx, pool, "message", msgEsId, session.SessionId, err.Error(), msgHit)
				return nil
			}

			if err := pgStore.insertMessageDirect(ctx, msg); err != nil {
				insertFailures++
				recordMigrationFailure(ctx, pool, "message", msgEsId, session.SessionId, err.Error(), msgHit)
				return nil
			}
			migratedMessages++
			return nil
		})

		if msgErr != nil {
			// Transport-level failure fetching this session's messages — abort the whole migration.
			// Returning an error aborts the outer session pager and propagates upward.
			return fmt.Errorf("failed to page messages for session %s: %w", session.SessionId, msgErr)
		}

		return nil
	})

	if err != nil {
		return err
	}

	summary := log.Fields{
		"migratedSessions": migratedSessions,
		"migratedMessages": migratedMessages,
		"parseFailures":    parseFailures,
		"insertFailures":   insertFailures,
	}
	log.WithFields(summary).Info("Assistant data migration complete")
	if parseFailures > 0 || insertFailures > 0 {
		log.WithFields(summary).Warn("Assistant data migration had failures — see assistant_migration_failures table for details")
	}

	return markMigrationComplete(ctx, pool, migrationAssistantData)
}

// esSearchPaged repeatedly POSTs /_search with search_after until the index is drained.
// The baseQuery must NOT contain "size", "sort", or "search_after" — the pager owns those.
// handler is invoked once per hit in document order; returning an error aborts the scan
// and is propagated to the caller (distinguishable from transport errors only by context).
func esSearchPaged(
	ctx context.Context,
	client *http.Client,
	cfg *esMigrationConfig,
	index string,
	baseQuery map[string]interface{},
	sort []interface{},
	pageSize int,
	handler func(hit map[string]interface{}) error,
) error {
	var searchAfter []interface{}

	for {
		query := make(map[string]interface{}, len(baseQuery)+3)
		for k, v := range baseQuery {
			query[k] = v
		}
		query["size"] = pageSize
		query["sort"] = sort
		if searchAfter != nil {
			query["search_after"] = searchAfter
		}

		hits, lastSort, err := esSearchOnePage(ctx, client, cfg, index, query)
		if err != nil {
			return err
		}

		for _, hit := range hits {
			if err := handler(hit); err != nil {
				return err
			}
		}

		if len(hits) < pageSize {
			return nil
		}
		if lastSort == nil {
			// Defensive: if ES returned a full page but no sort values on the last hit,
			// we'd loop forever. Treat as end-of-stream and log — shouldn't happen given
			// our sort keys are always populated.
			log.WithField("index", index).Warn("esSearchPaged: last hit missing sort values, stopping pagination")
			return nil
		}
		searchAfter = lastSort
	}
}

// esSearchOnePage runs a single _search against Elasticsearch and returns the hits plus the
// sort values of the last hit (for use as the next search_after cursor).
func esSearchOnePage(ctx context.Context, client *http.Client, cfg *esMigrationConfig, index string, query map[string]interface{}) ([]map[string]interface{}, []interface{}, error) {
	body, err := json.Marshal(query)
	if err != nil {
		return nil, nil, err
	}

	url := fmt.Sprintf("%s/%s/_search", cfg.HostUrl, index)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Username != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("ES search failed: %d - %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source map[string]interface{} `json:"_source"`
				Id     string                 `json:"_id"`
				Sort   []interface{}          `json:"sort"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, nil, err
	}

	hits := make([]map[string]interface{}, 0, len(result.Hits.Hits))
	var lastSort []interface{}
	for _, h := range result.Hits.Hits {
		if h.Source == nil {
			continue
		}
		h.Source["_id"] = h.Id
		hits = append(hits, h.Source)
		lastSort = h.Sort
	}

	return hits, lastSort, nil
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
