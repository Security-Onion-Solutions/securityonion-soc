// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

// ErrToolTurnBusy is returned when a tool request can't acquire its session's turn
// lock because another tool turn for that session is already running. The handler
// maps it to 409 Conflict so the client can retry, rather than blocking the request.
var ErrToolTurnBusy = errors.New("ERROR_TOOL_TURN_BUSY")

// ErrAgentBusy is returned when a chat turn's agent is at its maxConcurrentInstances.
// The handler maps it to 409 Conflict so the client can try again later.
var ErrAgentBusy = errors.New("ERROR_AGENT_BUSY")

// ErrToolUseNotFound is returned when a tool request names a toolUseId with no
// matching assistant tool_use in the session (or the session itself can't be
// found). The handler maps it to 404 Not Found.
var ErrToolUseNotFound = errors.New("ERROR_TOOL_USE_NOT_FOUND")

// ErrSessionNotFound is returned when a session lookup by id finds nothing the
// caller may read. The handler maps it to 404 Not Found.
var ErrSessionNotFound = errors.New("ERROR_SESSION_NOT_FOUND")

// ErrSessionNotRoot is returned when an operation that only applies to a root
// session targets a delegation sub-session. The handler maps it to 400.
var ErrSessionNotRoot = errors.New("ERROR_SESSION_NOT_ROOT")

// ErrToolAlreadyResolved is returned when the targeted tool_use already has a
// tool_result in the session's history, so approving or rejecting it again must
// not re-execute the tool or duplicate the result. The handler maps it to 400.
var ErrToolAlreadyResolved = errors.New("ERROR_TOOL_ALREADY_RESOLVED")

// ErrToolRequestMismatch is returned when the targeted tool_use exists but the
// request does not describe it: the tool name or params differ from what the
// assistant asked to run. The handler maps it to 400.
var ErrToolRequestMismatch = errors.New("ERROR_TOOL_REQUEST_MISMATCH")

type AssistantManager interface {
	Send(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) ([]*model.Message, error)
	SendStream(ctx context.Context, aiModel string, messages []*model.Message, opts ...model.ChatOpt) (*http.Response, *model.AuxMessageData, error)
	AcquireTurnSlot(ctx context.Context, sessionId string, selector string) (release func(), err error)
	ChatInSession(ctx context.Context, incMsg *model.IncomingMessage, entityType, entityId string) ([]*model.Message, error)
	ChatStreamInSession(ctx context.Context, incMsg *model.IncomingMessage, entityType, entityId string) (*http.Response, *model.AuxMessageData, func(rawResponse []byte) error, error)
	ToolInSession(ctx context.Context, toolReq *model.ToolRequest, toolName string) ([]*model.Message, error)
	ToolStreamInSession(ctx context.Context, toolReq *model.ToolRequest, toolName string) (*model.StreamedTurn, error)
	RunAgentSession(ctx context.Context, req *model.AgentSessionRequest) (*model.AgentSessionResult, error)
	ValidateAgentSessionRequest(req *model.AgentSessionRequest) error
	ResolveDelegationStream(ctx context.Context, childSession *model.AssistantSession, childFinalText string) (*model.StreamedTurn, error)
	ExecuteTool(ctx context.Context, toolName string, toolReq *model.ToolRequest) (*model.ToolResponse, error)
	Balance(ctx context.Context, aiModel string) (*model.BalanceResponse, error)
	Health(ctx context.Context, aiModel string) (*model.HealthResponse, error)
	SaveAgent(ctx context.Context, originalName string, agent *model.StoredAgent) error
	DeleteAgent(ctx context.Context, name string) error
	SaveSkill(ctx context.Context, originalName string, skill *model.StoredSkill) error
	DeleteSkill(ctx context.Context, name string) error
	ListAutomations(ctx context.Context) ([]*model.Automation, error)
	GetAutomation(ctx context.Context, id string) (*model.Automation, error)
	SaveAutomation(ctx context.Context, automation *model.Automation) error
	DeleteAutomation(ctx context.Context, id string) error
	Embed(ctx context.Context, aiModel string, input []string) (*model.EmbeddingResponse, error)
	ListMemories(ctx context.Context, filter *model.MemoryFilter) (*model.MemoryResults, error)
	SaveMemory(ctx context.Context, mem *model.Memory) error
	RemoveMemory(ctx context.Context, id string) error
	FilterEvents(events []*model.EventRecord, extraFields ...string) []map[string]any
}

type AssistantAdapter interface {
	Protocol() string
	SendMessage(ctx context.Context, req *model.ChatRequest) (*model.Message, error)
	SendMessageStream(ctx context.Context, req *model.ChatRequest) (*http.Response, *model.AuxMessageData, error)
	GetBalance(ctx context.Context) (*model.BalanceResponse, error)
	GetHealth(ctx context.Context) (*model.HealthResponse, error)
	Embed(ctx context.Context, req *model.EmbeddingRequest) (*model.EmbeddingResponse, error)
	SupportsEmbeddings() bool
}

//go:generate mockgen -destination mock/mock_assistantmanager.go -package mock . AssistantManager
