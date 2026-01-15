// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	Chat(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error)
	ChatStream(ctx context.Context, aiModel string, messages []*model.Message) (*http.Response, error)
	ExecuteTool(ctx context.Context, toolName string, params string, auxData string) (*model.ToolResponse, error)
	Balance(ctx context.Context, aiModel string) (*model.BalanceResponse, error)
	Health(ctx context.Context, aiModel string) (*model.HealthResponse, error)
}

type AssistantAdapter interface {
	Name() string
	SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error)
	SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, error)
	GetBalance(ctx context.Context) (*model.BalanceResponse, error)
	GetHealth(ctx context.Context) (*model.HealthResponse, error)
}

//go:generate mockgen -destination mock/mock_assistantmanager.go -package mock . AssistantManager
