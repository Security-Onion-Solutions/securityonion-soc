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
	// GetChatHistoryOutlines is GetChatHistory for several sessions at once, without text, tool inputs or tool output.
	GetChatHistoryOutlines(context.Context, []*model.AssistantSession) ([][]*model.StoredMessage, error)
	GetSessions(context.Context, ...model.GetSessionsOpt) ([]*model.AssistantSession, error)
	DoesUserOwnSession(ctx context.Context, userId string, sessionId string) (ownedByUser bool, sessionExists bool, isAutomation bool, sessionModel string, err error)
	CreateSession(context.Context, *model.AssistantSession) error
	// CloneSession copies a session; non-empty entityType/entityId replace the root copy's.
	CloneSession(ctx context.Context, sessionId, entityType, entityId string) (*model.AssistantSession, error)
	UpdateSessionTags(ctx context.Context, sessionId string, tags []string) error
	ToggleSessionsTag(ctx context.Context, sessionIds []string, tag string, present bool) error
	DeleteSession(context.Context, string) error

	GetUsage(context.Context, time.Time, time.Time) ([]*model.UserUsage, error)
	FindSessionsPendingMemoryScan(ctx context.Context, dontScanBefore *time.Time, maxMemoryRetries int) ([]*model.AssistantSessionDetails, error)
	UpdateSessionMemoryScanIndex(ctx context.Context, sessionId string, scannedIndex int) error
	IncrementSessionMemoryErrors(ctx context.Context, sessionId string) error
}

//go:generate mockgen -destination mock/mock_assistantstore.go -package mock . Assistantstore

// Delegation depth is capped well below this; the bound only guards a corrupt parent chain.
const maxSessionAncestors = 16

// GetRootSessionId walks a delegated sub-agent's session up to the top-level chat, which
// is what a person opens. A failed lookup stops at the last session resolved.
func GetRootSessionId(ctx context.Context, store Assistantstore, sessionId string) string {
	if sessionId == "" || store == nil {
		return sessionId
	}

	current := sessionId
	for range maxSessionAncestors {
		sessions, err := store.GetSessions(ctx,
			model.GetSessionsWithSessionId(current),
			model.GetSessionsWithIncludeDeleted(true),
			model.GetSessionsWithMessageMeta(false),
			model.GetSessionsWithAutomationSessions(true))
		if err != nil || len(sessions) == 0 || sessions[0].ParentSessionId == "" {
			return current
		}
		current = sessions[0].ParentSessionId
	}

	return current
}

// GetSessionTree returns the session followed by every delegated sub-session.
func GetSessionTree(ctx context.Context, store Assistantstore, sessionId string) ([]*model.AssistantSession, error) {
	return store.GetSessions(ctx,
		model.GetSessionsWithSessionId(sessionId),
		model.GetSessionsWithAutomationSessions(true),
		model.GetSessionsWithDescendants(true),
		model.GetSessionsWithMessageMeta(false))
}

// SetSessionTreeShared adds or removes the shared tag on a session and its delegated
// sub-sessions in one write. A shared session is readable through its sub-sessions too,
// so the tag must follow every descendant.
func SetSessionTreeShared(ctx context.Context, store Assistantstore, tree []*model.AssistantSession, shared bool) error {
	ids := make([]string, len(tree))
	for i, s := range tree {
		ids[i] = s.SessionId
	}

	return store.ToggleSessionsTag(ctx, ids, model.SessionTagShared, shared)
}

//go:generate mockgen -destination mock/mock_alerttriageupdater.go -package mock . AlertTriageUpdater
type AlertTriageUpdater interface {
	// AlertTriageUpdate records the outcome on every alert the update selects and returns only
	// once the update has landed, even when it ran as a background task.
	AlertTriageUpdate(ctx context.Context, update *model.AlertTriageUpdate) (*model.EventUpdateResults, error)
	// AlertTriageSchemaPrefix names the event sub-object the ledger lives under, for building the scan.
	AlertTriageSchemaPrefix() string
}
