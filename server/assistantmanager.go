package server

import (
	"context"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type AssistantManager interface {
	Chat(context.Context, []*model.ChatMessage) (*model.ChatResponse, error)
	ChatStream(ctx context.Context, messages []*model.ChatMessage) (*http.Response, error)
	Balance(context.Context) (*model.BalanceResponse, error)
}

//go:generate mockgen -destination mock/mock_assistantmanager.go -package mock . AssistantManager
