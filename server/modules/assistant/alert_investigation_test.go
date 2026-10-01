// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// investigationEventstore records the investigation scripts it is asked to add, as isDelete flags.
type investigationEventstore struct {
	*server.FakeEventstore
	scripts   []bool
	updateErr error
}

func (s *investigationEventstore) AddInvestigationUpdateScripts(criteria *model.EventUpdateCriteria, _ time.Time, _ string, isDelete bool, _ ...string) {
	s.scripts = append(s.scripts, isDelete)
}

func (s *investigationEventstore) Update(ctx context.Context, criteria *model.EventUpdateCriteria) (*model.EventUpdateResults, error) {
	if s.updateErr != nil {
		return nil, s.updateErr
	}

	return s.FakeEventstore.Update(ctx, criteria)
}

type investigationTriageStore struct {
	*mock.MockAssistantstore
}

func (s investigationTriageStore) AlertTriageUpdate(ctx context.Context, update *model.AlertTriageUpdate) (*model.EventUpdateResults, error) {
	return nil, nil
}

func (s investigationTriageStore) AlertTriageSchemaPrefix() string { return "so_" }

// deniedOperationAuthorizer allows everything except one operation.
type deniedOperationAuthorizer struct{ denied string }

func (a deniedOperationAuthorizer) CheckContextOperationAuthorized(ctx context.Context, operation, target string) error {
	if operation == a.denied {
		return model.NewUnauthorized("fake-subject", operation, target)
	}

	return nil
}

func (a deniedOperationAuthorizer) CheckUserOperationAuthorized(userId, operation, target string) error {
	return a.CheckContextOperationAuthorized(context.Background(), operation, target)
}

func newInvestigationCoordinator(t *testing.T, alerts ...*model.EventRecord) (*AssistantCoordinator, *mock.MockAssistantstore, *investigationEventstore) {
	t.Helper()
	ctrl := gomock.NewController(t)
	store := mock.NewMockAssistantstore(ctrl)
	events := &investigationEventstore{FakeEventstore: &server.FakeEventstore{
		SearchResults: []*model.EventSearchResults{{TotalEvents: len(alerts), Events: alerts}},
		UpdateResults: []*model.EventUpdateResults{{UpdatedCount: 1}},
	}}

	srv := &server.Server{
		Authorizer:     &rbac.FakeAuthorizer{Authorized: true},
		Assistantstore: investigationTriageStore{store},
		Eventstore:     events,
	}

	return NewAssistantCoordinator(srv), store, events
}

func investigationContext() context.Context {
	return context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")
}

func TestAttachInvestigation(t *testing.T) {
	ac, _, events := newInvestigationCoordinator(t)

	err := ac.AttachInvestigation(investigationContext(), "alert-123", "session-456")

	assert.NoError(t, err)
	assert.Equal(t, []bool{false}, events.scripts)
	assert.NotNil(t, events.InputUpdateCriterias[0].ParsedQuery)
}

func TestAlertInvestigationQuotesSocId(t *testing.T) {
	for _, isDelete := range []bool{false, true} {
		ac, _, events := newInvestigationCoordinator(t)

		// Injection-shaped socId must end up quoted and escaped, not spliced into the query raw
		err := ac.updateAlertInvestigation(investigationContext(), `abc" OR soc_id:"*`, "session-456", isDelete)

		assert.NoError(t, err)
		assert.Equal(t, `_id:"abc\" OR soc_id:\"*"`, events.InputUpdateCriterias[0].ParsedQuery.String())
	}
}

func TestAlertInvestigationRequiresEventsWrite(t *testing.T) {
	ac, _, events := newInvestigationCoordinator(t)
	ac.srv.Authorizer = deniedOperationAuthorizer{denied: "write"}

	assert.Error(t, ac.AttachInvestigation(investigationContext(), "alert-123", "session-456"))
	assert.Error(t, ac.DetachInvestigation(investigationContext(), "alert-123", "session-456"))
	assert.Empty(t, events.InputUpdateCriterias)
}

func TestAttachInvestigationNoAlert(t *testing.T) {
	ac, _, events := newInvestigationCoordinator(t)
	events.UpdateResults = []*model.EventUpdateResults{{}}

	err := ac.AttachInvestigation(investigationContext(), "nonexistent-alert", "session-456")

	assert.ErrorContains(t, err, "no alert found")
}

func TestAlertInvestigationUpdateFails(t *testing.T) {
	ac, _, events := newInvestigationCoordinator(t)
	events.updateErr = errors.New("update failed")

	assert.ErrorContains(t, ac.AttachInvestigation(investigationContext(), "alert-123", "session-456"), "update failed")
	assert.ErrorContains(t, ac.DetachInvestigation(investigationContext(), "alert-123", "session-456"), "update failed")
}

func TestDetachInvestigation(t *testing.T) {
	ac, _, events := newInvestigationCoordinator(t)

	err := ac.DetachInvestigation(investigationContext(), "alert-123", "session-456")

	assert.NoError(t, err)
	assert.Equal(t, []bool{true}, events.scripts)
}

func TestDetachSessionInvestigation(t *testing.T) {
	ac, store, events := newInvestigationCoordinator(t)
	store.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", "session-456").Return(true, true, false, "", nil)
	store.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return([]*model.AssistantSession{
		{SessionId: "session-456", Type: "alert_investigation", EntityId: "alert-123"},
	}, nil)

	err := ac.DetachSessionInvestigation(investigationContext(), "session-456")

	assert.NoError(t, err)
	assert.Equal(t, []bool{true}, events.scripts)
}

func TestDetachSessionInvestigationLeavesOtherSessionsAlone(t *testing.T) {
	ac, store, events := newInvestigationCoordinator(t)
	store.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", "session-456").Return(true, true, false, "", nil)
	store.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return([]*model.AssistantSession{
		{SessionId: "session-456", Type: "general"},
	}, nil)

	assert.NoError(t, ac.DetachSessionInvestigation(investigationContext(), "session-456"))
	assert.Empty(t, events.scripts)
}

// The session is still deleted, so lookup and update failures are only logged.
func TestDetachSessionInvestigationFailuresDoNotBlockDeletion(t *testing.T) {
	ac, store, _ := newInvestigationCoordinator(t)
	store.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", "session-456").Return(true, true, false, "", nil)
	store.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return(nil, errors.New("database error"))

	assert.NoError(t, ac.DetachSessionInvestigation(investigationContext(), "session-456"))

	ac, store, events := newInvestigationCoordinator(t)
	events.updateErr = errors.New("update failed")
	store.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", "session-456").Return(true, true, false, "", nil)
	store.EXPECT().GetSessions(gomock.Any(), gomock.Any()).Return([]*model.AssistantSession{
		{SessionId: "session-456", Type: "alert_investigation", EntityId: "alert-123"},
	}, nil)

	assert.NoError(t, ac.DetachSessionInvestigation(investigationContext(), "session-456"))
}

func TestDetachSessionInvestigationRefusesOthersSessions(t *testing.T) {
	tests := []struct {
		name    string
		owned   bool
		exists  bool
		lookErr error
		want    error
	}{
		{name: "someone else's", owned: false, exists: true, want: server.ErrSessionAccessDenied},
		{name: "missing", owned: false, exists: false, want: server.ErrSessionNotFound},
		{name: "lookup fails", lookErr: errors.New("es down")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ac, store, events := newInvestigationCoordinator(t)
			store.EXPECT().DoesUserOwnSession(gomock.Any(), "test-user-123", "session-456").Return(test.owned, test.exists, false, "", test.lookErr)

			err := ac.DetachSessionInvestigation(investigationContext(), "session-456")

			if test.want != nil {
				assert.ErrorIs(t, err, test.want)
			} else {
				assert.ErrorIs(t, err, test.lookErr)
			}
			assert.Empty(t, events.scripts, "nothing is unlinked")
		})
	}
}

func TestCloneSessionOntoAlertFromManualInvestigation(t *testing.T) {
	ac, store, events := newInvestigationCoordinator(t, &model.EventRecord{
		Id: "alert-1",
		Payload: map[string]interface{}{"event.so_investigations": []interface{}{
			map[string]interface{}{"session_id": "other", "user_id": "u1"},
			map[string]interface{}{"session_id": "src-1", "user_id": "u2"},
		}},
	})
	store.EXPECT().CloneSession(gomock.Any(), "src-1", "alert_investigation", "alert-1").Return(&model.AssistantSession{SessionId: "clone-1"}, nil)

	clone, err := ac.CloneSessionOntoAlert(investigationContext(), "src-1", "alert-1")

	assert.NoError(t, err)
	assert.Equal(t, "clone-1", clone.SessionId)
	assert.Equal(t, []bool{false}, events.scripts, "the copy is recorded on the alert")
}

func TestCloneSessionOntoAlertFromAnOlderAlertsSingleValue(t *testing.T) {
	ac, store, _ := newInvestigationCoordinator(t, &model.EventRecord{
		Id:      "alert-1",
		Payload: map[string]interface{}{"event.investigation_session_id": "src-1"},
	})
	store.EXPECT().CloneSession(gomock.Any(), "src-1", "alert_investigation", "alert-1").Return(&model.AssistantSession{SessionId: "clone-1"}, nil)

	_, err := ac.CloneSessionOntoAlert(investigationContext(), "src-1", "alert-1")

	assert.NoError(t, err)
}

func TestCloneSessionOntoAlertFromTriage(t *testing.T) {
	ac, store, events := newInvestigationCoordinator(t, &model.EventRecord{
		Id:      "alert-1",
		Payload: map[string]interface{}{"event.so_alerttriage.session_id": "src-1"},
	})
	store.EXPECT().CloneSession(gomock.Any(), "src-1", "alert_investigation", "alert-1").Return(&model.AssistantSession{SessionId: "clone-1"}, nil)

	_, err := ac.CloneSessionOntoAlert(investigationContext(), "src-1", "alert-1")

	assert.NoError(t, err)
	assert.Equal(t, []bool{false}, events.scripts)
}

func TestCloneSessionOntoAlertRefused(t *testing.T) {
	tests := []struct {
		name   string
		socId  string
		alerts []*model.EventRecord
	}{
		{name: "the alert does not reference the session", socId: "alert-1", alerts: []*model.EventRecord{{
			Id: "alert-1", Payload: map[string]interface{}{"event.investigation_session_id": "someone-else"},
		}}},
		{name: "no such alert", socId: "alert-1"},
		{name: "the lookup matched another event by its uid", socId: "alert-1", alerts: []*model.EventRecord{{
			Id: "other-doc", Payload: map[string]interface{}{"event.investigation_session_id": "src-1"},
		}}},
		{name: "an id that could alter the lookup query", socId: `x" OR _id:*`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ac, _, events := newInvestigationCoordinator(t, test.alerts...)

			_, err := ac.CloneSessionOntoAlert(investigationContext(), "src-1", test.socId)

			assert.ErrorIs(t, err, server.ErrSessionNotOnAlert)
			assert.Empty(t, events.scripts)
		})
	}
}

func TestCloneSessionOntoAlertRequiresEventsWrite(t *testing.T) {
	ac, _, events := newInvestigationCoordinator(t)
	ac.srv.Authorizer = deniedOperationAuthorizer{denied: "write"}

	_, err := ac.CloneSessionOntoAlert(investigationContext(), "src-1", "alert-1")

	var unauthorized *model.Unauthorized
	assert.ErrorAs(t, err, &unauthorized)
	assert.Empty(t, events.InputSearchCriterias, "refused before looking up the alert")
}

func TestCloneSessionOntoAlertStampFailureKeepsTheCopy(t *testing.T) {
	ac, store, events := newInvestigationCoordinator(t, &model.EventRecord{
		Id: "alert-1", Payload: map[string]interface{}{"event.investigation_session_id": "src-1"},
	})
	events.updateErr = errors.New("es down")
	store.EXPECT().CloneSession(gomock.Any(), "src-1", "alert_investigation", "alert-1").Return(&model.AssistantSession{SessionId: "clone-1"}, nil)

	clone, err := ac.CloneSessionOntoAlert(investigationContext(), "src-1", "alert-1")

	assert.NoError(t, err)
	assert.Equal(t, "clone-1", clone.SessionId)
}
