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

type Assistantstore interface {
	SaveChat(context.Context, *model.StoredMessage) error
	GetChatHistory(context.Context, string) ([]*model.StoredMessage, error)
	GetSessions(context.Context, ...model.GetSessionsOpt) ([]*model.AssistantSession, error)
	CreateSession(context.Context, *model.AssistantSession) error
	UpdateSessionTags(ctx context.Context, sessionId string, tags []string) error
	DeleteSession(context.Context, string) error

	GetUsage(context.Context, time.Time, time.Time) ([]*model.UserUsage, error)
}

//go:generate mockgen -destination mock/mock_assistantstore.go -package mock . Assistantstore
