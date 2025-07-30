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
	SaveChat(ctx context.Context, chat *model.StoredMessage) error
	GetChatHistory(ctx context.Context, conversationId string) ([]*model.StoredMessage, error)
	GetPreviousConversations(ctx context.Context, userId string) ([]*model.StoredMessage, error)
}

//go:generate mockgen -destination mock/mock_assistantstore.go -package mock . Assistantstore
