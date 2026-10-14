// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type fakeAutomationSessionStore struct {
	item    *model.AutomationWorkItem
	err     error
	queried []string
}

func (f *fakeAutomationSessionStore) GetAutomationWorkItemBySession(_ context.Context, sessionId string) (*model.AutomationWorkItem, error) {
	f.queried = append(f.queried, sessionId)

	return f.item, f.err
}

func TestAutomationForSession(t *testing.T) {
	const automationId = "5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90"

	stored := storedAutomation(automationId, "Nightly")
	stored.Params = json.RawMessage(`{"groupBy":["rule.uuid"]}`)

	tree := []*model.AssistantSession{
		{SessionId: "root", Type: alertTriageKindName},
		{SessionId: "child", ParentSessionId: "root"},
		{SessionId: "grandchild", ParentSessionId: "child"},
	}

	tests := []struct {
		name        string
		sessionId   string
		sessions    []*model.AssistantSession
		getErr      error
		settings    []*model.Setting
		store       *fakeAutomationSessionStore
		wantQueried string
		wantId      string
		wantSystem  bool
		wantErr     error
		wantNil     bool
	}{
		{
			name:        "a sub-session resolves to its root",
			sessionId:   "grandchild",
			sessions:    tree,
			settings:    []*model.Setting{automationsSetting(t, stored)},
			store:       &fakeAutomationSessionStore{item: &model.AutomationWorkItem{AutomationId: automationId}},
			wantQueried: "root",
			wantId:      automationId,
		},
		{
			name:        "a chat no automation ran is nil",
			sessionId:   "root",
			sessions:    tree,
			settings:    []*model.Setting{automationsSetting(t, stored)},
			store:       &fakeAutomationSessionStore{},
			wantQueried: "root",
			wantNil:     true,
		},
		{
			name:        "a builtin without a stored copy is the shipped one",
			sessionId:   "root",
			sessions:    tree,
			settings:    []*model.Setting{automationsSetting(t)},
			store:       &fakeAutomationSessionStore{item: &model.AutomationWorkItem{AutomationId: BuiltinAlertTriageAutomationId}},
			wantQueried: "root",
			wantId:      BuiltinAlertTriageAutomationId,
			wantSystem:  true,
		},
		{
			name:        "a deleted automation is not found",
			sessionId:   "root",
			sessions:    tree,
			settings:    []*model.Setting{automationsSetting(t)},
			store:       &fakeAutomationSessionStore{item: &model.AutomationWorkItem{AutomationId: automationId}},
			wantQueried: "root",
			wantErr:     ErrAutomationNotFound,
		},
		{
			name:        "a failed root walk queries the last id resolved",
			sessionId:   "child",
			sessions:    tree,
			getErr:      errors.New("down"),
			settings:    []*model.Setting{automationsSetting(t, stored)},
			store:       &fakeAutomationSessionStore{},
			wantQueried: "child",
			wantNil:     true,
		},
		{
			name:        "a store error passes through",
			sessionId:   "root",
			sessions:    tree,
			settings:    []*model.Setting{automationsSetting(t, stored)},
			store:       &fakeAutomationSessionStore{err: errors.New("db down")},
			wantQueried: "root",
			wantErr:     errors.New("db down"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &automationConfigstore{}
			cfg.settings = tt.settings

			ac := automationCoordinator(cfg)
			ac.setupBuiltinAutomations()
			ac.srv.Assistantstore = sessionTreeStore(gomock.NewController(t), tt.sessions, tt.getErr)

			automation, err := ac.automationForSession(context.Background(), tt.store, tt.sessionId)

			assert.Equal(t, []string{tt.wantQueried}, tt.store.queried)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Nil(t, automation)
				if errors.Is(tt.wantErr, ErrAutomationNotFound) {
					assert.ErrorIs(t, err, ErrAutomationNotFound)
				} else {
					assert.EqualError(t, err, tt.wantErr.Error())
				}

				return
			}

			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, automation)

				return
			}

			require.NotNil(t, automation)
			assert.Equal(t, tt.wantId, automation.Id)
			assert.Equal(t, tt.wantSystem, automation.IsSystem)

			if !tt.wantSystem {
				assert.JSONEq(t, string(stored.Params), string(automation.Params))
			}
		})
	}
}

// A missing store means the attachment is unknown, not absent: the database can be removed
// from config after automations have run.
func TestAutomationForSessionWithoutDatabase(t *testing.T) {
	ac := automationCoordinator(&automationConfigstore{})

	automation, err := ac.AutomationForSession(context.Background(), "root")

	assert.ErrorIs(t, err, ErrNoDatabase)
	assert.Nil(t, automation)
}
