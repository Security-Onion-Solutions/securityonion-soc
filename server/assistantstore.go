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
	SavePartialChat(context.Context, *model.StoredMessage) error
	FinishPartialChat(context.Context, *model.StoredMessage) error
	GetChatHistory(context.Context, *model.AssistantSession) ([]*model.StoredMessage, error)
	GetSessions(context.Context, ...model.GetSessionsOpt) ([]*model.AssistantSession, error)
	DoesUserOwnSession(ctx context.Context, userId string, sessionId string) (ownedByUser bool, sessionExists bool, isAutomation bool, err error)
	CreateSession(context.Context, *model.AssistantSession) error
	CloneSession(ctx context.Context, sessionId string) (*model.AssistantSession, error)
	UpdateSessionTags(ctx context.Context, sessionId string, tags []string) error
	ToggleSessionsTag(ctx context.Context, sessionIds []string, tag string, present bool) error
	DeleteSession(context.Context, string) error

	GetUsage(context.Context, time.Time, time.Time) ([]*model.UserUsage, error)
	FindSessionsPendingMemoryScan(ctx context.Context, dontScanBefore *time.Time, maxMemoryRetries int) ([]*model.AssistantSessionDetails, error)
	UpdateSessionMemoryScanIndex(ctx context.Context, sessionId string, scannedIndex int) error
	IncrementSessionMemoryErrors(ctx context.Context, sessionId string) error
}

//go:generate mockgen -destination mock/mock_assistantstore.go -package mock . Assistantstore

//go:generate mockgen -destination mock/mock_alerttriageupdater.go -package mock . AlertTriageUpdater
type AlertTriageUpdater interface {
	// AlertTriageUpdate records the outcome on every alert the update selects and returns only
	// once the update has landed, even when it ran as a background task.
	AlertTriageUpdate(ctx context.Context, update *model.AlertTriageUpdate) (*model.EventUpdateResults, error)
}
