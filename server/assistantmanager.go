// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type AssistantManager interface {
	Chat(context.Context, []*model.ChatMessage, ...model.ChatOpt) (*model.ChatResponse, error)
	ChatStream(ctx context.Context, messages []*model.ChatMessage) (*http.Response, error)
	ExecuteTool(ctx context.Context, toolName string, params string) (*model.ToolResult, error)
	Balance(context.Context) (*model.BalanceResponse, error)
}

//go:generate mockgen -destination mock/mock_assistantmanager.go -package mock . AssistantManager
