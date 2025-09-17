// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type Assistantstore interface {
	SaveChat(context.Context, *model.StoredMessage) error
	GetChatHistory(context.Context, string) ([]*model.StoredMessage, error)
	GetSessions(ctx context.Context, userId string) ([]*model.AssistantSession, error)
	CreateSession(ctx context.Context, session *model.AssistantSession) error
	DeleteSession(context.Context, string) error
}

//go:generate mockgen -destination mock/mock_assistantstore.go -package mock . Assistantstore
