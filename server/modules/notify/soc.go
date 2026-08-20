// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
)

type SOCChannel struct {
	server *server.Server
}

func NewSOCChannel(srv *server.Server) *SOCChannel {
	return &SOCChannel{
		server: srv,
	}
}

func (c *SOCChannel) Type() string {
	return model.ChannelTypeSOC
}

func (c *SOCChannel) ValidateConfig(params map[string]interface{}) error {
	if params == nil {
		return nil
	}

	if modeVal, ok := params["attachmentMode"]; ok {
		modeStr, isStr := modeVal.(string)
		if !isStr {
			return errors.New("attachmentMode must be a string")
		}
		switch modeStr {
		case model.AttachmentModeLink, model.AttachmentModeAttach, model.AttachmentModeBoth:
			// Valid
		default:
			return fmt.Errorf("invalid attachmentMode: %s (must be '%s', '%s', or '%s')",
				modeStr, model.AttachmentModeLink, model.AttachmentModeAttach, model.AttachmentModeBoth)
		}
	}

	if storeVal, ok := params["storeInPostgres"]; ok {
		if _, isBool := storeVal.(bool); !isBool {
			return errors.New("storeInPostgres must be a boolean")
		}
	}

	return nil
}

func (c *SOCChannel) Send(ctx context.Context, params map[string]interface{}, payload *model.NotificationPayload) error {
	if payload == nil {
		return errors.New("notification payload cannot be nil")
	}

	if payload.ID == "" {
		payload.ID = uuid.New().String()
	}
	if payload.Timestamp.IsZero() {
		payload.Timestamp = time.Now().UTC()
	}

	storeInPostgres := true
	if params != nil {
		if val, ok := params["storeInPostgres"]; ok {
			if boolVal, isBool := val.(bool); isBool {
				storeInPostgres = boolVal
			}
		}
	}

	if !storeInPostgres {
		log.WithField("notificationId", payload.ID).Debug("storeInPostgres is false; skipping database insertion")
		return nil
	}

	if c.server == nil || c.server.DB == nil {
		log.WithField("notificationId", payload.ID).Debug("PostgreSQL DB not configured or available; skipping database insertion")
		return nil
	}

	fieldsJSON, err := json.Marshal(payload.Fields)
	if err != nil || payload.Fields == nil {
		fieldsJSON = []byte("{}")
	}

	linksJSON, err := json.Marshal(payload.Links)
	if err != nil || payload.Links == nil {
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

	err = c.server.DB.Exec(ctx, query,
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
