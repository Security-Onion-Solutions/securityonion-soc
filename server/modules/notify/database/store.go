// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Package database provides all Postgres access for the notify module.
// All queries are routed through Store to keep DB concerns isolated from
// business logic.
package database

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/db"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const moduleName = "notify"

// Store encapsulates all Postgres operations for notify.
type Store struct {
	db db.DB
}

// New wraps an existing DB connection and runs pending migrations.
func New(ctx context.Context, database db.DB) (*Store, error) {
	if database == nil {
		return nil, errors.New("database connection cannot be nil")
	}
	if err := database.Migrate(ctx, migrationFS, moduleName); err != nil {
		return nil, fmt.Errorf("database: migrate: %w", err)
	}
	return &Store{db: database}, nil
}

// SanitizeLinks removes any links with dangerous or unsupported URI schemes (e.g. javascript:, data:, vbscript:).
func SanitizeLinks(links map[string]string) map[string]string {
	if links == nil {
		return nil
	}
	clean := make(map[string]string)
	for name, rawURL := range links {
		if isSafeURL(rawURL) {
			clean[name] = rawURL
		}
	}
	return clean
}

func isSafeURL(rawURL string) bool {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "data:") || strings.HasPrefix(lower, "vbscript:") {
		return false
	}
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "#") {
		return true
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return false
	}
	if u.Scheme == "" && !strings.Contains(trimmed, ":") {
		return true
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// InsertNotification stores a new notification record in PostgreSQL.
func (s *Store) InsertNotification(ctx context.Context, payload *model.NotificationPayload) error {
	if payload == nil {
		return errors.New("notification payload cannot be nil")
	}

	if payload.ID == "" {
		payload.ID = uuid.New().String()
	}
	if payload.Timestamp.IsZero() {
		payload.Timestamp = time.Now().UTC()
	}

	sanitizedLinks := SanitizeLinks(payload.Links)

	fieldsJSON, err := json.Marshal(payload.Fields)
	if err != nil || payload.Fields == nil {
		fieldsJSON = []byte("{}")
	}

	linksJSON, err := json.Marshal(sanitizedLinks)
	if err != nil || sanitizedLinks == nil {
		linksJSON = []byte("{}")
	}

	attachmentsJSON, err := json.Marshal(payload.Attachments)
	if err != nil || payload.Attachments == nil {
		attachmentsJSON = []byte("[]")
	}

	query := `
		INSERT INTO notifications (id, source, title, summary, severity, fields, links, attachments, silence_key, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO NOTHING`

	err = s.db.Exec(ctx, query,
		payload.ID,
		payload.Source,
		payload.Title,
		payload.Summary,
		payload.Severity,
		string(fieldsJSON),
		string(linksJSON),
		string(attachmentsJSON),
		payload.SilenceKey,
		payload.Timestamp,
	)
	if err != nil {
		log.WithError(err).WithField("notificationId", payload.ID).Error("Failed to store notification in PostgreSQL")
		return fmt.Errorf("failed to store notification in postgres: %w", err)
	}

	return nil
}

// GetNotifications queries notifications and their user states for a given username and optional creation timestamp cutoff.
func (s *Store) GetNotifications(ctx context.Context, username, filter string, createdAfter time.Time) ([]*model.NotificationRecord, error) {
	query := `
		SELECT n.id, n.source, n.title, n.summary, n.severity, n.fields, n.links, n.attachments, n.silence_key, n.created_at,
		       COALESCE(us.is_read, FALSE) AS is_read,
		       us.read_at,
		       COALESCE(us.is_dismissed, FALSE) AS is_dismissed,
		       us.dismissed_at
		FROM notifications n
		LEFT JOIN notification_user_states us ON n.id = us.notification_id AND us.user_id = $1
		WHERE 1=1`

	var args []any
	args = append(args, username)

	if !createdAfter.IsZero() {
		args = append(args, createdAfter)
		query += fmt.Sprintf(" AND n.created_at >= $%d", len(args))
	}

	if filter == "unread" {
		query += " AND COALESCE(us.is_read, FALSE) = FALSE AND COALESCE(us.is_dismissed, FALSE) = FALSE"
	} else if filter == "dismissed" {
		query += " AND COALESCE(us.is_dismissed, FALSE) = TRUE"
	} else if filter == "all" {
		// all includes all active and dismissed notifications
	} else {
		// default / "active": show active notifications (both read and unread, but not dismissed)
		query += " AND COALESCE(us.is_dismissed, FALSE) = FALSE"
	}

	query += " ORDER BY n.created_at DESC"

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		log.FromContext(ctx).WithError(err).Error("failed to query notifications from database")
		return nil, fmt.Errorf("failed to query notifications: %w", err)
	}
	defer rows.Close()

	var notifications []*model.NotificationRecord
	for rows.Next() {
		var id, source, title, summary, severity string
		var fieldsJSON, linksJSON, attachmentsJSON []byte
		var silenceKey *string
		var createdAt time.Time
		var isRead, isDismissed bool
		var readAt, dismissedAt *time.Time

		err := rows.Scan(&id, &source, &title, &summary, &severity, &fieldsJSON, &linksJSON, &attachmentsJSON, &silenceKey, &createdAt, &isRead, &readAt, &isDismissed, &dismissedAt)
		if err != nil {
			log.FromContext(ctx).WithError(err).Error("failed to scan notification row")
			return nil, fmt.Errorf("failed to read notifications: %w", err)
		}

		var fields map[string]string
		_ = json.Unmarshal(fieldsJSON, &fields)

		var links map[string]string
		_ = json.Unmarshal(linksJSON, &links)

		var attachments []model.Attachment
		_ = json.Unmarshal(attachmentsJSON, &attachments)

		var silenceKeyVal string
		if silenceKey != nil {
			silenceKeyVal = *silenceKey
		}

		notifications = append(notifications, &model.NotificationRecord{
			ID:          id,
			Source:      source,
			Title:       title,
			Summary:     summary,
			Severity:    severity,
			Fields:      fields,
			Links:       links,
			Attachments: attachments,
			SilenceKey:  silenceKeyVal,
			CreatedAt:   createdAt,
			IsRead:      isRead,
			ReadAt:      readAt,
			IsDismissed: isDismissed,
			DismissedAt: dismissedAt,
		})
	}

	if notifications == nil {
		notifications = make([]*model.NotificationRecord, 0)
	}

	return notifications, nil
}

// GetLastUnreadTime returns the created_at timestamp of the newest unread/undismissed notification.
func (s *Store) GetLastUnreadTime(ctx context.Context, username string, createdAfter time.Time) (*time.Time, error) {
	query := `
		SELECT n.created_at
		FROM notifications n
		LEFT JOIN notification_user_states us ON n.id = us.notification_id AND us.user_id = $1
		WHERE COALESCE(us.is_read, FALSE) = FALSE AND COALESCE(us.is_dismissed, FALSE) = FALSE`

	var args []any
	args = append(args, username)

	if !createdAfter.IsZero() {
		args = append(args, createdAfter)
		query += fmt.Sprintf(" AND n.created_at >= $%d", len(args))
	}

	query += " ORDER BY n.created_at DESC LIMIT 1"

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		log.FromContext(ctx).WithError(err).Error("failed to query last unread notification time")
		return nil, fmt.Errorf("failed to query last unread notification time: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		var createdAt time.Time
		if err := rows.Scan(&createdAt); err != nil {
			log.FromContext(ctx).WithError(err).Error("failed to scan last unread notification timestamp")
			return nil, fmt.Errorf("failed to scan last unread timestamp: %w", err)
		}
		return &createdAt, nil
	}

	return nil, nil
}

// SetRead updates or inserts the read state for a user and notification.
func (s *Store) SetRead(ctx context.Context, id, username string, isRead bool) error {
	var readAt *time.Time
	if isRead {
		now := time.Now().UTC()
		readAt = &now
	}

	query := `
		INSERT INTO notification_user_states (notification_id, user_id, is_read, read_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (notification_id, user_id) DO UPDATE
		SET is_read = EXCLUDED.is_read, read_at = EXCLUDED.read_at`

	err := s.db.Exec(ctx, query, id, username, isRead, readAt)
	if err != nil {
		log.FromContext(ctx).WithError(err).Error("failed to update notification read state")
		return fmt.Errorf("failed to update read state: %w", err)
	}

	return nil
}

// SetDismissed updates or inserts the dismissal state for a user and notification.
func (s *Store) SetDismissed(ctx context.Context, id, username string, isDismissed bool) error {
	var dismissedAt *time.Time
	if isDismissed {
		now := time.Now().UTC()
		dismissedAt = &now
	}

	query := `
		INSERT INTO notification_user_states (notification_id, user_id, is_dismissed, dismissed_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (notification_id, user_id) DO UPDATE
		SET is_dismissed = EXCLUDED.is_dismissed, dismissed_at = EXCLUDED.dismissed_at`

	err := s.db.Exec(ctx, query, id, username, isDismissed, dismissedAt)
	if err != nil {
		log.FromContext(ctx).WithError(err).Error("failed to update notification dismiss state")
		return fmt.Errorf("failed to update dismiss state: %w", err)
	}

	return nil
}

// GetAuditLogs retrieves audit records for a given notification.
func (s *Store) GetAuditLogs(ctx context.Context, id string) ([]*model.NotificationAuditEntry, error) {
	query := `
		SELECT user_id, is_read, read_at, is_dismissed, dismissed_at
		FROM notification_user_states
		WHERE notification_id = $1`

	rows, err := s.db.Query(ctx, query, id)
	if err != nil {
		log.FromContext(ctx).WithError(err).Error("failed to query notification audit logs from database")
		return nil, fmt.Errorf("failed to query notification audit logs: %w", err)
	}
	defer rows.Close()

	var auditList []*model.NotificationAuditEntry
	for rows.Next() {
		var userId string
		var isRead, isDismissed bool
		var readAt, dismissedAt *time.Time

		if err := rows.Scan(&userId, &isRead, &readAt, &isDismissed, &dismissedAt); err != nil {
			log.FromContext(ctx).WithError(err).Error("failed to scan audit row")
			return nil, fmt.Errorf("failed to read notification audit logs: %w", err)
		}

		auditList = append(auditList, &model.NotificationAuditEntry{
			UserID:      userId,
			IsRead:      isRead,
			ReadAt:      readAt,
			IsDismissed: isDismissed,
			DismissedAt: dismissedAt,
		})
	}

	if auditList == nil {
		auditList = make([]*model.NotificationAuditEntry, 0)
	}

	return auditList, nil
}
