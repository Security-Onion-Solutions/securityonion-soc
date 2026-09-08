// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"errors"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/notify/database"
	"github.com/security-onion-solutions/securityonion-soc/web"
)

type NotificationstoreImpl struct {
	server *server.Server
	store  *database.Store
}

func NewNotificationstore(srv *server.Server, store *database.Store) *NotificationstoreImpl {
	return &NotificationstoreImpl{
		server: srv,
		store:  store,
	}
}

func (s *NotificationstoreImpl) getUser(ctx context.Context) *model.User {
	if val := ctx.Value(web.ContextKeyRequestorId); val != nil {
		if reqId, ok := val.(string); ok && reqId != "" {
			if s.server != nil && s.server.Userstore != nil {
				if u, err := s.server.Userstore.GetUserById(ctx, reqId); err == nil && u != nil {
					return u
				}
			}
		}
	}
	return nil
}

func (s *NotificationstoreImpl) getUsername(ctx context.Context) (string, error) {
	if val := ctx.Value(web.ContextKeyRunAsUsername); val != nil {
		if username, ok := val.(string); ok && username != "" {
			return username, nil
		}
	}
	if u := s.getUser(ctx); u != nil && u.Email != "" {
		return u.Email, nil
	}
	return "", errors.New("unauthorized: missing user in context")
}

func (s *NotificationstoreImpl) GetNotifications(ctx context.Context, filter string) ([]*model.NotificationRecord, error) {
	if s.server != nil {
		if err := s.server.CheckAuthorized(ctx, "read", "notifications"); err != nil {
			return nil, err
		}
	}

	username, err := s.getUsername(ctx)
	if err != nil {
		return nil, err
	}

	var createdAfter time.Time
	if u := s.getUser(ctx); u != nil && !u.CreateTime.IsZero() {
		createdAfter = u.CreateTime
	}

	if s.store == nil {
		if s.server == nil || s.server.DB == nil {
			return nil, errors.New("database not configured")
		}
		st, err := database.New(ctx, s.server.DB)
		if err != nil {
			return nil, err
		}
		s.store = st
	}

	return s.store.GetNotifications(ctx, username, filter, createdAfter)
}

func (s *NotificationstoreImpl) GetLastUnreadTime(ctx context.Context) (*time.Time, error) {
	if s.server != nil {
		if err := s.server.CheckAuthorized(ctx, "read", "notifications"); err != nil {
			return nil, err
		}
	}

	username, err := s.getUsername(ctx)
	if err != nil {
		return nil, err
	}

	var createdAfter time.Time
	if u := s.getUser(ctx); u != nil && !u.CreateTime.IsZero() {
		createdAfter = u.CreateTime
	}

	if s.store == nil {
		if s.server == nil || s.server.DB == nil {
			return nil, errors.New("database not configured")
		}
		st, err := database.New(ctx, s.server.DB)
		if err != nil {
			return nil, err
		}
		s.store = st
	}

	return s.store.GetLastUnreadTime(ctx, username, createdAfter)
}

func (s *NotificationstoreImpl) SetRead(ctx context.Context, id string, isRead bool) error {
	if s.server != nil {
		if err := s.server.CheckAuthorized(ctx, "write", "notifications"); err != nil {
			return err
		}
	}

	username, err := s.getUsername(ctx)
	if err != nil {
		return err
	}

	if id == "" {
		return errors.New("missing notification id")
	}

	if s.store == nil {
		if s.server == nil || s.server.DB == nil {
			return errors.New("database not configured")
		}
		st, err := database.New(ctx, s.server.DB)
		if err != nil {
			return err
		}
		s.store = st
	}

	return s.store.SetRead(ctx, id, username, isRead)
}

func (s *NotificationstoreImpl) SetDismissed(ctx context.Context, id string, isDismissed bool) error {
	if s.server != nil {
		if err := s.server.CheckAuthorized(ctx, "write", "notifications"); err != nil {
			return err
		}
	}

	username, err := s.getUsername(ctx)
	if err != nil {
		return err
	}

	if id == "" {
		return errors.New("missing notification id")
	}

	if s.store == nil {
		if s.server == nil || s.server.DB == nil {
			return errors.New("database not configured")
		}
		st, err := database.New(ctx, s.server.DB)
		if err != nil {
			return err
		}
		s.store = st
	}

	return s.store.SetDismissed(ctx, id, username, isDismissed)
}

func (s *NotificationstoreImpl) GetAuditLogs(ctx context.Context, id string) ([]*model.NotificationAuditEntry, error) {
	if s.server != nil {
		if err := s.server.CheckAuthorized(ctx, "read_all", "notifications"); err != nil {
			return nil, err
		}
	}

	if id == "" {
		return nil, errors.New("missing notification id")
	}

	if s.store == nil {
		if s.server == nil || s.server.DB == nil {
			return nil, errors.New("database not configured")
		}
		st, err := database.New(ctx, s.server.DB)
		if err != nil {
			return nil, err
		}
		s.store = st
	}

	return s.store.GetAuditLogs(ctx, id)
}
