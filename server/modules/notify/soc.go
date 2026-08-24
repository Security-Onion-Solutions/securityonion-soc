// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/notify/database"
)

type SOCChannel struct {
	server *server.Server
	store  *database.Store
}

func NewSOCChannel(srv *server.Server, store *database.Store) *SOCChannel {
	return &SOCChannel{
		server: srv,
		store:  store,
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

	payload.Links = database.SanitizeLinks(payload.Links)

	storeInPostgres := true
	if params != nil {
		if val, ok := params["storeInPostgres"]; ok {
			if boolVal, isBool := val.(bool); isBool {
				storeInPostgres = boolVal
			}
		}
	}

	var err error
	if storeInPostgres {
		if c.store != nil {
			err = c.store.InsertNotification(ctx, payload)
		} else if c.server != nil && c.server.DB != nil {
			var store *database.Store
			store, err = database.New(ctx, c.server.DB)
			if err == nil {
				err = store.InsertNotification(ctx, payload)
			}
		} else {
			log.WithField("notificationId", payload.ID).Debug("PostgreSQL DB not configured or available; skipping database insertion")
		}
	} else {
		log.WithField("notificationId", payload.ID).Debug("storeInPostgres is false; skipping database insertion")
	}

	if err != nil {
		return err
	}

	if c.server != nil && c.server.Host != nil {
		c.server.Host.Broadcast("notification", "notifications", payload)
	}

	return nil
}
