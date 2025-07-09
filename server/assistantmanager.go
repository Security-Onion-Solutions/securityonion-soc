package server

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type AssistantManager interface {
	Chat(context.Context, string) (*model.ChatResponse, error)
	Balance(context.Context) (*model.BalanceResponse, error)
}
