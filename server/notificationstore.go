// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type Notificationstore interface {
	GetNotifications(ctx context.Context, filter string) ([]*model.NotificationRecord, error)
	GetLastUnreadTime(ctx context.Context) (*time.Time, error)
	SetRead(ctx context.Context, id string, isRead bool) error
	SetDismissed(ctx context.Context, id string, isDismissed bool) error
	GetAuditLogs(ctx context.Context, id string) ([]*model.NotificationAuditEntry, error)
}

//go:generate mockgen -destination mock/mock_notificationstore.go -package mock . Notificationstore
