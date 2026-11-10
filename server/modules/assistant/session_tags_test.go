// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func newSessionTagCoordinator(t *testing.T, authorized bool) (*AssistantCoordinator, *mock.MockAssistantstore, *mock.MockCasestore) {
	t.Helper()
	ctrl := gomock.NewController(t)
	store := mock.NewMockAssistantstore(ctrl)
	cases := mock.NewMockCasestore(ctrl)

	srv := &server.Server{
		Authorizer:     &rbac.FakeAuthorizer{Authorized: authorized},
		Assistantstore: store,
		Casestore:      cases,
	}

	return NewAssistantCoordinator(srv), store, cases
}

func sessionTagContext() context.Context {
	return context.WithValue(context.Background(), web.ContextKeyRequestorId, "owner")
}

func expectTagLookup(t *testing.T, store *mock.MockAssistantstore, descendants bool, sessions []*model.AssistantSession, err error) {
	t.Helper()
	store.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
		applied := &model.GetSessionsOpts{}
		for _, opt := range opts {
			opt(applied)
		}
		assert.Equal(t, []string{"root"}, applied.SessionIds())
		assert.True(t, applied.IncludeAutomationSessions())
		assert.Equal(t, descendants, applied.Descendants())
		assert.False(t, applied.MessageMeta())

		return sessions, err
	})
}

func TestUpdateSessionTag_Reserved(t *testing.T) {
	type testCase struct {
		tag     string
		present bool
	}
	cases := []testCase{{tag: "Memory", present: true}}
	for _, tag := range model.ReservedSessionTags {
		cases = append(cases, testCase{tag: tag, present: true}, testCase{tag: tag, present: false})
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s-%t", tc.tag, tc.present), func(t *testing.T) {
			// No store expectations: a reserved tag is refused before any lookup.
			ac, _, _ := newSessionTagCoordinator(t, true)

			err := ac.UpdateSessionTag(sessionTagContext(), "root", tc.tag, tc.present)
			assert.ErrorIs(t, err, server.ErrSessionTagReserved)
		})
	}
}

func TestUpdateSessionTag_Blank(t *testing.T) {
	for _, tag := range []string{"", "   "} {
		t.Run(fmt.Sprintf("%q", tag), func(t *testing.T) {
			// No store expectations: a blank tag is refused before any lookup.
			ac, _, _ := newSessionTagCoordinator(t, true)

			err := ac.UpdateSessionTag(sessionTagContext(), "root", tag, true)
			assert.ErrorIs(t, err, server.ErrSessionTagInvalid)
		})
	}
}

func TestUpdateSessionTag_Trims(t *testing.T) {
	t.Run("reserved", func(t *testing.T) {
		ac, _, _ := newSessionTagCoordinator(t, true)

		err := ac.UpdateSessionTag(sessionTagContext(), "root", " automation ", true)
		assert.ErrorIs(t, err, server.ErrSessionTagReserved)
	})

	t.Run("exists", func(t *testing.T) {
		ac, store, _ := newSessionTagCoordinator(t, true)
		expectTagLookup(t, store, false, []*model.AssistantSession{{SessionId: "root", UserId: "owner", Tags: []string{"case-1"}}}, nil)

		err := ac.UpdateSessionTag(sessionTagContext(), "root", " case-1 ", true)
		assert.ErrorIs(t, err, server.ErrSessionTagExists)
	})

	t.Run("written", func(t *testing.T) {
		ac, store, _ := newSessionTagCoordinator(t, true)
		expectTagLookup(t, store, false, []*model.AssistantSession{{SessionId: "root", UserId: "owner"}}, nil)
		store.EXPECT().ToggleSessionsTag(gomock.Any(), []string{"root"}, "case-1", true).Return(nil)

		err := ac.UpdateSessionTag(sessionTagContext(), "root", " case-1 ", true)
		assert.NoError(t, err)
	})
}

func TestUpdateSessionTag_Rejected(t *testing.T) {
	owned := &model.AssistantSession{SessionId: "root", UserId: "owner", Tags: []string{"case-1"}}
	automation := &model.AssistantSession{SessionId: "root", UserId: "owner", Tags: []string{model.SessionTagAutomation, model.SessionTagShared}}
	notOwned := &model.AssistantSession{SessionId: "root", UserId: "someone-else", Tags: []string{model.SessionTagShared, "case-1"}}
	sharedOwned := &model.AssistantSession{SessionId: "root", UserId: "owner", Tags: []string{model.SessionTagShared}}
	lookupErr := errors.New("es down")
	caseErr := errors.New("case lookup failed")

	tests := []struct {
		name        string
		root        *model.AssistantSession
		lookupErr   error
		noRequestor bool
		tag         string
		present     bool
		cases       []string
		caseErr     error
		wantErr     error
		wantMsg     string
	}{
		{name: "not found", tag: "case-1", present: true, wantErr: server.ErrSessionNotFound},
		{name: "lookup fails", lookupErr: lookupErr, tag: "case-1", present: true, wantErr: lookupErr},
		{name: "automation add", root: automation, tag: "investigation", present: true, wantErr: server.ErrSessionAutomationTags},
		{name: "automation remove shared", root: automation, tag: model.SessionTagShared, present: false, wantErr: server.ErrSessionAutomationTags},
		{name: "not owner add", root: notOwned, tag: "case-2", present: true, wantErr: server.ErrSessionAccessDenied},
		{name: "not owner remove", root: notOwned, tag: "case-1", present: false, wantErr: server.ErrSessionAccessDenied},
		{name: "not owner add shared", root: notOwned, tag: model.SessionTagShared, present: true, wantErr: server.ErrSessionAccessDenied},
		{name: "not owner remove shared", root: notOwned, tag: model.SessionTagShared, present: false, wantErr: server.ErrSessionAccessDenied},
		{name: "no requestor", root: owned, noRequestor: true, tag: "case-2", present: true, wantErr: server.ErrSessionAccessDenied},
		{name: "remove missing tag", root: owned, tag: "case-2", present: false, wantErr: server.ErrSessionTagMissing},
		{name: "remove attached to cases", root: sharedOwned, tag: model.SessionTagShared, present: false, cases: []string{"case-1", "case-2"}, wantErr: server.ErrSessionAttachedToCases, wantMsg: "ERROR_SESSION_ATTACHED_TO_CASES 2"},
		{name: "case lookup failure", root: owned, tag: "case-1", present: false, caseErr: caseErr, wantErr: caseErr},
		{name: "tag exists", root: owned, tag: "case-1", present: true, wantErr: server.ErrSessionTagExists},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// No ToggleSessionsTag expectation, so any write fails the test.
			ac, store, caseStore := newSessionTagCoordinator(t, true)

			var sessions []*model.AssistantSession
			if tc.root != nil {
				sessions = []*model.AssistantSession{tc.root}
			}
			expectTagLookup(t, store, tc.tag == model.SessionTagShared, sessions, tc.lookupErr)

			if tc.cases != nil || tc.caseErr != nil {
				caseStore.EXPECT().GetCaseIdsWithArtifact(gomock.Any(), "assistant_chat", "root").Return(tc.cases, tc.caseErr)
			}

			ctx := sessionTagContext()
			if tc.noRequestor {
				ctx = context.Background()
			}

			err := ac.UpdateSessionTag(ctx, "root", tc.tag, tc.present)
			assert.ErrorIs(t, err, tc.wantErr)
			if tc.wantMsg != "" {
				assert.EqualError(t, err, tc.wantMsg)
			}
		})
	}
}

func TestUpdateSessionTag_OneSession(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		present  bool
		rootTags []string
	}{
		{name: "add", tag: "case-2", present: true, rootTags: []string{"case-1"}},
		{name: "remove", tag: "case-1", present: false, rootTags: []string{"case-1", "case-2"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac, store, caseStore := newSessionTagCoordinator(t, true)
			expectTagLookup(t, store, false, []*model.AssistantSession{{SessionId: "root", UserId: "owner", Tags: tc.rootTags}}, nil)
			caseStore.EXPECT().GetCaseIdsWithArtifact(gomock.Any(), "assistant_chat", "root").Return([]string{}, nil).AnyTimes()
			store.EXPECT().ToggleSessionsTag(gomock.Any(), []string{"root"}, tc.tag, tc.present).Return(nil)

			err := ac.UpdateSessionTag(sessionTagContext(), "root", tc.tag, tc.present)
			assert.NoError(t, err)
		})
	}
}

// Re-sharing a session that already has the tag still writes, so descendants
// that missed an earlier cascade catch up.
func TestUpdateSessionTag_SharedCascades(t *testing.T) {
	tests := []struct {
		name     string
		present  bool
		rootTags []string
	}{
		{name: "add", present: true, rootTags: []string{"case-1"}},
		{name: "remove", present: false, rootTags: []string{model.SessionTagShared, "case-1"}},
		{name: "reshare", present: true, rootTags: []string{model.SessionTagShared}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac, store, caseStore := newSessionTagCoordinator(t, true)
			expectTagLookup(t, store, true, []*model.AssistantSession{
				{SessionId: "root", UserId: "owner", Tags: tc.rootTags},
				{SessionId: "child", UserId: "owner", ParentSessionId: "root"},
				{SessionId: "grand", UserId: "owner", ParentSessionId: "child", Tags: []string{model.SessionTagShared}},
			}, nil)
			caseStore.EXPECT().GetCaseIdsWithArtifact(gomock.Any(), "assistant_chat", "root").Return([]string{}, nil).AnyTimes()
			store.EXPECT().ToggleSessionsTag(gomock.Any(), []string{"root", "child", "grand"}, model.SessionTagShared, tc.present).Return(nil)

			err := ac.UpdateSessionTag(sessionTagContext(), "root", model.SessionTagShared, tc.present)
			assert.NoError(t, err)
		})
	}
}

func TestUpdateSessionTag_NoCasestore(t *testing.T) {
	ac, store, _ := newSessionTagCoordinator(t, true)
	ac.srv.Casestore = nil
	expectTagLookup(t, store, true, []*model.AssistantSession{{SessionId: "root", UserId: "owner", Tags: []string{model.SessionTagShared}}}, nil)
	store.EXPECT().ToggleSessionsTag(gomock.Any(), []string{"root"}, model.SessionTagShared, false).Return(nil)

	err := ac.UpdateSessionTag(sessionTagContext(), "root", model.SessionTagShared, false)
	assert.NoError(t, err)
}

func TestUpdateSessionTag_WriteFails(t *testing.T) {
	writeErr := errors.New("es down")
	ac, store, _ := newSessionTagCoordinator(t, true)
	expectTagLookup(t, store, false, []*model.AssistantSession{{SessionId: "root", UserId: "owner"}}, nil)
	store.EXPECT().ToggleSessionsTag(gomock.Any(), []string{"root"}, "case-1", true).Return(writeErr)

	err := ac.UpdateSessionTag(sessionTagContext(), "root", "case-1", true)
	assert.ErrorIs(t, err, writeErr)
}

func TestUpdateSessionTag_Unauthorized(t *testing.T) {
	// No store expectations: a refused caller reads nothing.
	ac, _, _ := newSessionTagCoordinator(t, false)

	err := ac.UpdateSessionTag(sessionTagContext(), "root", "case-1", true)

	var unauthorized *model.Unauthorized
	assert.ErrorAs(t, err, &unauthorized)
	assert.Equal(t, "write_authored", unauthorized.Operation)
	assert.Equal(t, "assistant", unauthorized.Target)
}
