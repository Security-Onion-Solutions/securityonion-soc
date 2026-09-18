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

type AutomationStore interface {
	EnsureAutomationWorkItems(ctx context.Context, runId string, items []*model.AutomationWorkItem) ([]*model.AutomationWorkItem, error)
	ClaimNextAutomationWorkItem(ctx context.Context, automationId, runId string) (*model.AutomationWorkItem, error)
	EnsureAutomationWorkItemSession(ctx context.Context, itemId, sessionId string) error
	MarkAutomationWorkItemApplying(ctx context.Context, itemId string, result json.RawMessage) error
	CompleteAutomationWorkItem(ctx context.Context, itemId string) error
	RequeueAutomationWorkItem(ctx context.Context, itemId, cause string) error
	FailAutomationWorkItem(ctx context.Context, itemId, cause string) error
	ListOpenAutomationWorkItems(ctx context.Context, automationId string) ([]*model.AutomationWorkItem, error)
}

//go:generate mockgen -destination mock/mock_automationstore.go -package mock . AutomationStore
