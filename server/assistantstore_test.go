// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// treeStore serves GetSessions from sessions, honoring the descendants option the way the
// elastic store does: the matched session first, then its sub-sessions.
func treeStore(ctrl *gomock.Controller, sessions []*model.AssistantSession, getErr error) *mock.MockAssistantstore {
	store := mock.NewMockAssistantstore(ctrl)
	store.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
			if getErr != nil {
				return nil, getErr
			}

			o := &model.GetSessionsOpts{}
			for _, opt := range opts {
				opt(o)
			}

			var out []*model.AssistantSession
			for _, id := range o.SessionIds() {
				for _, s := range sessions {
					if s.SessionId == id {
						out = append(out, s)
					}
				}
			}
			if o.Descendants() {
				for i := 0; i < len(out); i++ {
					for _, s := range sessions {
						if s.ParentSessionId == out[i].SessionId {
							out = append(out, s)
						}
					}
				}
			}

			return out, nil
		}).AnyTimes()

	return store
}

func sessionTree(tags ...string) []*model.AssistantSession {
	return []*model.AssistantSession{
		{SessionId: "root", Tags: tags},
		{SessionId: "child", ParentSessionId: "root", Tags: tags},
		{SessionId: "grand", ParentSessionId: "child", Tags: tags},
	}
}

func TestGetRootSessionId(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := treeStore(ctrl, sessionTree(), nil)

	assert.Equal(t, "root", GetRootSessionId(context.Background(), store, "grand"))
	assert.Equal(t, "root", GetRootSessionId(context.Background(), store, "root"))
	assert.Equal(t, "", GetRootSessionId(context.Background(), store, ""))
	assert.Equal(t, "grand", GetRootSessionId(context.Background(), nil, "grand"))

	failing := treeStore(ctrl, nil, errors.New("es down"))
	assert.Equal(t, "grand", GetRootSessionId(context.Background(), failing, "grand"))
}

func TestGetRootSessionId_StopsOnParentCycle(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := treeStore(ctrl, []*model.AssistantSession{
		{SessionId: "a", ParentSessionId: "b"},
		{SessionId: "b", ParentSessionId: "a"},
	}, nil)

	assert.Contains(t, []string{"a", "b"}, GetRootSessionId(context.Background(), store, "a"))
}

func TestGetSessionTree(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := treeStore(ctrl, sessionTree(), nil)

	tree, err := GetSessionTree(context.Background(), store, "child")

	assert.NoError(t, err)
	assert.Len(t, tree, 2)
	assert.Equal(t, "child", tree[0].SessionId)
	assert.Equal(t, "grand", tree[1].SessionId)
}
