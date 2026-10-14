// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

// automationSessionStore is what the session lookup reads; *database.Store satisfies it.
type automationSessionStore interface {
	GetAutomationWorkItemBySession(ctx context.Context, sessionId string) (*model.AutomationWorkItem, error)
}

// AutomationForSession returns the automation whose work item ran sessionId or an ancestor of
// it. A session no automation ran is nil; one whose automation is gone is ErrAutomationNotFound.
func (ac *AssistantCoordinator) AutomationForSession(ctx context.Context, sessionId string) (*model.Automation, error) {
	if ac.store == nil {
		return nil, ErrNoDatabase
	}

	return ac.automationForSession(ctx, ac.store, sessionId)
}

func (ac *AssistantCoordinator) automationForSession(ctx context.Context, store automationSessionStore, sessionId string) (*model.Automation, error) {
	// Items record root sessions only, so a child is looked up through its root.
	rootId, _ := resolveRootSession(ctx, ac.srv, sessionId)

	item, err := store.GetAutomationWorkItemBySession(ctx, rootId)
	if err != nil || item == nil {
		return nil, err
	}

	return ac.loadAutomation(ctx, item.AutomationId)
}
