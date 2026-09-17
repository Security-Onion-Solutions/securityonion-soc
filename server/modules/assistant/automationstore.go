// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

// AutomationStore is the slice of the assistant's Postgres store that automations use.
//
//go:generate mockgen -destination mock/mock_automationstore.go -package mock . AutomationStore
type AutomationStore interface {
	EnsureAutomationWorkItems(ctx context.Context, runId string, items []*model.AutomationWorkItem) ([]*model.AutomationWorkItem, error)
	ClaimNextAutomationWorkItem(ctx context.Context, automationName string, maxAttempts int) (*model.AutomationWorkItem, error)
	SetAutomationWorkItemSession(ctx context.Context, itemId, sessionId string) error
	MarkAutomationWorkItemApplying(ctx context.Context, itemId string, result json.RawMessage) error
	CompleteAutomationWorkItem(ctx context.Context, itemId string) error
	FailAutomationWorkItem(ctx context.Context, itemId, cause string) error
	ListOpenAutomationWorkItems(ctx context.Context, automationName string) ([]*model.AutomationWorkItem, error)
	EnsureAutomationRunSession(ctx context.Context, rs *model.AutomationRunSession) error
	EnsureAutomationRunResultAudit(ctx context.Context, runId string, alerts []*model.AutomationRunResultAudit) error
}
