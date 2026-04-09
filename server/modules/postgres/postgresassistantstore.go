// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type PostgresAssistantstore struct {
	server *server.Server
	pool   *pgxpool.Pool
}

func NewPostgresAssistantstore(srv *server.Server, pool *pgxpool.Pool) *PostgresAssistantstore {
	return &PostgresAssistantstore{
		server: srv,
		pool:   pool,
	}
}

func (store *PostgresAssistantstore) SaveChat(ctx context.Context, chat *model.StoredMessage) error {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	if chat == nil || chat.Message == nil {
		return fmt.Errorf("chat and message must not be nil")
	}

	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)
	if chat.Id == "" {
		chat.Id = uuid.New().String()
	}

	now := time.Now()
	chat.CreateTime = &now
	chat.UserId = userId

	messageJSON, err := json.Marshal(chat.Message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	tagsJSON, err := json.Marshal(chat.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	_, err = store.pool.Exec(ctx,
		`INSERT INTO assistant_messages (id, session_id, user_id, model, tags, message, create_time)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		chat.Id, chat.SessionId, userId, chat.Model, tagsJSON, messageJSON, now)

	return err
}

func (store *PostgresAssistantstore) GetChatHistory(ctx context.Context, sessionId string) ([]*model.StoredMessage, error) {
	if sessionId == "" {
		return nil, fmt.Errorf("sessionId must not be empty")
	}

	// Look up the session to check ownership/sharing for RBAC
	existing, err := store.GetSessions(ctx, model.GetSessionsWithSessionId(sessionId), model.GetSessionsWithIncludeDeleted(true))
	if err != nil {
		return nil, err
	}

	if len(existing) == 0 {
		return nil, fmt.Errorf("Object not found")
	}

	session := existing[0]
	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)

	if session.UserId == userId {
		if err := store.server.CheckAuthorized(ctx, "read_authored", "assistant"); err != nil {
			return nil, err
		}
	} else if slices.Contains(session.Tags, "shared") {
		if err := store.server.CheckAuthorized(ctx, "read_shared", "assistant"); err != nil {
			return nil, err
		}
	} else {
		if err := store.server.CheckAuthorized(ctx, "read_all", "assistant"); err != nil {
			return nil, err
		}
	}

	rows, err := store.pool.Query(ctx,
		`SELECT id, session_id, user_id, model, tags, message, create_time, update_time
		 FROM assistant_messages
		 WHERE session_id = $1
		 ORDER BY create_time ASC`, sessionId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*model.StoredMessage
	for rows.Next() {
		msg, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}

	if messages == nil {
		messages = []*model.StoredMessage{}
	}

	return messages, rows.Err()
}

func (store *PostgresAssistantstore) CreateSession(ctx context.Context, session *model.AssistantSession) error {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	if session == nil {
		return fmt.Errorf("session must not be nil")
	}

	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)
	if session.Id == "" {
		session.Id = uuid.New().String()
	}

	now := time.Now()
	session.CreateTime = &now
	session.UserId = userId

	tagsJSON, err := json.Marshal(session.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	_, err = store.pool.Exec(ctx,
		`INSERT INTO assistant_sessions (id, session_id, user_id, title, type, entity_id, tags, create_time)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		session.Id, session.SessionId, userId, session.Title, session.Type, session.EntityId, tagsJSON, now)

	return err
}

func (store *PostgresAssistantstore) GetSessions(ctx context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
	options := &model.GetSessionsOpts{}
	for _, opt := range opts {
		opt(options)
	}

	query := `SELECT id, session_id, user_id, title, type, entity_id, tags, create_time, update_time, delete_time
	          FROM assistant_sessions WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if !options.IncludeDeleted() {
		query += " AND delete_time IS NULL"
	}

	if options.UserId() != "" {
		query += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, options.UserId())
		argIdx++
	}

	if options.SessionId() != "" {
		query += fmt.Sprintf(" AND session_id = $%d", argIdx)
		args = append(args, options.SessionId())
		argIdx++
	}

	start, end := options.Range()
	if !start.IsZero() {
		query += fmt.Sprintf(" AND create_time >= $%d", argIdx)
		args = append(args, start)
		argIdx++
	}
	if !end.IsZero() {
		query += fmt.Sprintf(" AND create_time <= $%d", argIdx)
		args = append(args, end)
		argIdx++
	}

	query += " ORDER BY create_time DESC"

	rows, err := store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*model.AssistantSession
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	if sessions == nil {
		sessions = []*model.AssistantSession{}
	}

	// Filter sessions by RBAC permissions (ownership, shared, read_all)
	sessions = store.filterSessionsByRbac(ctx, sessions)

	if options.Usage() {
		if err := store.populateSessionUsage(ctx, sessions); err != nil {
			log.WithError(err).Warn("Failed to populate session usage")
		}
	}

	return sessions, rows.Err()
}

func (store *PostgresAssistantstore) filterSessionsByRbac(ctx context.Context, sessions []*model.AssistantSession) []*model.AssistantSession {
	logger := log.FromContext(ctx)
	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)
	filteredOut := 0

	var canReadAll, canReadShared, canReadAuthored *bool

	filtered := make([]*model.AssistantSession, 0, len(sessions))
	for _, s := range sessions {
		if s.UserId == userId {
			if canReadAuthored == nil {
				err := store.server.CheckAuthorized(ctx, "read_authored", "assistant")
				canReadAuthored = util.Ptr(err == nil)
			}
			if *canReadAuthored {
				filtered = append(filtered, s)
			} else {
				filteredOut++
			}
		} else if slices.Contains(s.Tags, "shared") {
			if canReadShared == nil {
				err := store.server.CheckAuthorized(ctx, "read_shared", "assistant")
				canReadShared = util.Ptr(err == nil)
			}
			if *canReadShared {
				filtered = append(filtered, s)
			} else {
				filteredOut++
			}
		} else {
			if canReadAll == nil {
				err := store.server.CheckAuthorized(ctx, "read_all", "assistant")
				canReadAll = util.Ptr(err == nil)
			}
			if *canReadAll {
				filtered = append(filtered, s)
			} else {
				filteredOut++
			}
		}
	}

	if filteredOut != 0 {
		logger.WithField("filteredSessions", filteredOut).Info("filtering out sessions by RBAC")
	}

	return filtered
}

func (store *PostgresAssistantstore) UpdateSessionTags(ctx context.Context, sessionId string, tags []string) error {
	if err := store.server.CheckAuthorized(ctx, "write_authored", "assistant"); err != nil {
		return err
	}

	if sessionId == "" {
		return fmt.Errorf("sessionId must not be empty")
	}

	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)

	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	now := time.Now()
	result, err := store.pool.Exec(ctx,
		`UPDATE assistant_sessions SET tags = $1, update_time = $2
		 WHERE session_id = $3 AND user_id = $4 AND delete_time IS NULL`,
		tagsJSON, now, sessionId, userId)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("session not found or not owned by user: %s", sessionId)
	}

	return nil
}

func (store *PostgresAssistantstore) DeleteSession(ctx context.Context, sessionId string) error {
	if err := store.server.CheckAuthorized(ctx, "delete_authored", "assistant"); err != nil {
		return err
	}

	if sessionId == "" {
		return fmt.Errorf("sessionId must not be empty")
	}

	userId, _ := ctx.Value(web.ContextKeyRequestorId).(string)

	now := time.Now()
	result, err := store.pool.Exec(ctx,
		`UPDATE assistant_sessions SET delete_time = $1, update_time = $1
		 WHERE session_id = $2 AND user_id = $3 AND delete_time IS NULL`,
		now, sessionId, userId)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("session not found or not owned by user: %s", sessionId)
	}

	return nil
}

func (store *PostgresAssistantstore) GetUsage(ctx context.Context, start time.Time, end time.Time) ([]*model.UserUsage, error) {
	rows, err := store.pool.Query(ctx,
		`SELECT
			m.user_id,
			m.model,
			COUNT(*) as message_count,
			COALESCE(SUM((m.message->'usage'->>'inputTokens')::int), 0) as input_tokens,
			COALESCE(SUM((m.message->'usage'->>'outputTokens')::int), 0) as output_tokens,
			COALESCE(SUM((m.message->'usage'->>'credits')::int), 0) as credits,
			COUNT(DISTINCT m.session_id) as session_count
		 FROM assistant_messages m
		 WHERE m.create_time >= $1 AND m.create_time <= $2
		 GROUP BY m.user_id, m.model`,
		start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	userMap := make(map[string]*model.UserUsage)
	for rows.Next() {
		var userId, modelName string
		var messageCount, inputTokens, outputTokens, credits, sessionCount int

		if err := rows.Scan(&userId, &modelName, &messageCount, &inputTokens, &outputTokens, &credits, &sessionCount); err != nil {
			return nil, err
		}

		usage, ok := userMap[userId]
		if !ok {
			usage = &model.UserUsage{
				UserId:     userId,
				ModelUsage: make(map[string]*model.ModelUsageStats),
			}
			userMap[userId] = usage
		}

		usage.TotalInputTokens += inputTokens
		usage.TotalOutputTokens += outputTokens
		usage.TotalCredits += credits
		usage.TotalMessages += messageCount
		if sessionCount > usage.TotalSessions {
			usage.TotalSessions = sessionCount
		}

		if modelName != "" {
			usage.ModelUsage[modelName] = &model.ModelUsageStats{
				ModelInputTokens:  inputTokens,
				ModelOutputTokens: outputTokens,
				ModelCredits:      credits,
				ModelMessages:     messageCount,
			}
		}
	}

	result := make([]*model.UserUsage, 0, len(userMap))
	for _, u := range userMap {
		result = append(result, u)
	}

	return result, rows.Err()
}

func (store *PostgresAssistantstore) populateSessionUsage(ctx context.Context, sessions []*model.AssistantSession) error {
	for _, session := range sessions {
		rows, err := store.pool.Query(ctx,
			`SELECT
				m.model,
				COUNT(*) as message_count,
				COALESCE(SUM((m.message->'usage'->>'inputTokens')::int), 0) as input_tokens,
				COALESCE(SUM((m.message->'usage'->>'outputTokens')::int), 0) as output_tokens,
				COALESCE(SUM((m.message->'usage'->>'credits')::int), 0) as credits
			 FROM assistant_messages m
			 WHERE m.session_id = $1
			 GROUP BY m.model`,
			session.SessionId)
		if err != nil {
			return err
		}

		usage := &model.SessionUsage{
			ModelUsage: make(map[string]*model.ModelUsageStats),
		}

		for rows.Next() {
			var modelName string
			var messageCount, inputTokens, outputTokens, credits int

			if err := rows.Scan(&modelName, &messageCount, &inputTokens, &outputTokens, &credits); err != nil {
				rows.Close()
				return err
			}

			usage.TotalInputTokens += inputTokens
			usage.TotalOutputTokens += outputTokens
			usage.TotalCredits += credits
			usage.TotalMessages += messageCount

			if modelName != "" {
				usage.ModelUsage[modelName] = &model.ModelUsageStats{
					ModelInputTokens:  inputTokens,
					ModelOutputTokens: outputTokens,
					ModelCredits:      credits,
					ModelMessages:     messageCount,
				}
			}
		}
		rows.Close()

		session.Usage = usage
	}

	return nil
}

// insertSessionDirect inserts a session with its original metadata (used during migration).
func (store *PostgresAssistantstore) insertSessionDirect(ctx context.Context, session *model.AssistantSession) error {
	tagsJSON, err := json.Marshal(session.Tags)
	if err != nil {
		tagsJSON = []byte("[]")
	}

	_, err = store.pool.Exec(ctx,
		`INSERT INTO assistant_sessions (id, session_id, user_id, title, type, entity_id, tags, create_time, update_time, delete_time)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (session_id) DO NOTHING`,
		session.Id, session.SessionId, session.UserId, session.Title, session.Type, session.EntityId,
		tagsJSON, session.CreateTime, session.UpdateTime, session.DeleteTime)

	return err
}

// insertMessageDirect inserts a message with its original metadata (used during migration).
func (store *PostgresAssistantstore) insertMessageDirect(ctx context.Context, msg *model.StoredMessage) error {
	messageJSON, err := json.Marshal(msg.Message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	tagsJSON, err := json.Marshal(msg.Tags)
	if err != nil {
		tagsJSON = []byte("[]")
	}

	_, err = store.pool.Exec(ctx,
		`INSERT INTO assistant_messages (id, session_id, user_id, model, tags, message, create_time, update_time)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (id) DO NOTHING`,
		msg.Id, msg.SessionId, msg.UserId, msg.Model, tagsJSON, messageJSON, msg.CreateTime, msg.UpdateTime)

	return err
}

func scanSession(rows pgx.Rows) (*model.AssistantSession, error) {
	session := &model.AssistantSession{}
	var tagsJSON []byte

	err := rows.Scan(
		&session.Id,
		&session.SessionId,
		&session.UserId,
		&session.Title,
		&session.Type,
		&session.EntityId,
		&tagsJSON,
		&session.CreateTime,
		&session.UpdateTime,
		&session.DeleteTime,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(tagsJSON, &session.Tags); err != nil {
		session.Tags = []string{}
	}

	return session, nil
}

func scanMessage(rows pgx.Rows) (*model.StoredMessage, error) {
	msg := &model.StoredMessage{}
	var tagsJSON, messageJSON []byte

	err := rows.Scan(
		&msg.Id,
		&msg.SessionId,
		&msg.UserId,
		&msg.Model,
		&tagsJSON,
		&messageJSON,
		&msg.CreateTime,
		&msg.UpdateTime,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(tagsJSON, &msg.Tags); err != nil {
		msg.Tags = []string{}
	}

	msg.Message = &model.Message{}
	if err := json.Unmarshal(messageJSON, msg.Message); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return msg, nil
}
