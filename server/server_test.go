// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var (
	handled        = NewEntryMatcher(LogLevelEq(log.InfoLevel), LogMessageEq("Handled request"))
	didNotComplete = NewEntryMatcher(LogLevelEq(log.WarnLevel), LogMessageContains("Request did not complete successfully"))
	specificTime   = time.Date(2025, 1, 1, 12, 30, 0, 0, time.UTC)
)

func NewMockServer(t *testing.T, ctrl *gomock.Controller, cfg *config.ServerConfig) *Server {
	srv := &Server{
		Config: cfg,
		Host: &web.Host{
			Authorizer: &rbac.FakeAuthorizer{},
		},
		Datastore:        &FakeDatastore{},
		AdminClientstore: mock.NewMockAdminClientstore(ctrl),
		AdminUserstore:   mock.NewMockAdminUserstore(ctrl),
		Clientstore:      mock.NewMockClientstore(ctrl),
		Userstore:        mock.NewMockUserstore(ctrl),
		Rolestore:        &FakeRolestore{},
		Eventstore:       &FakeEventstore{},
		Casestore:        mock.NewMockCasestore(ctrl),
		Detectionstore:   mock.NewMockDetectionstore(ctrl),
		Configstore:      &MemConfigStore{},
		GridMembersstore: mock.NewMockGridMembersstore(ctrl),
		Metrics:          &FakeMetrics{},
		Authorizer:       &rbac.FakeAuthorizer{},
		Agent:            nil,
		Context:          context.Background(),
		DetectionEngines: sync.Map{}, // map[model.EngineName]DetectionEngine{},
	}

	return srv
}

func NewInMemoryLogger() (h *memory.Handler, l log.Interface) {
	h = memory.New()

	l = &log.Logger{Handler: h, Level: log.DebugLevel}
	l = l.WithField("test", true)

	return h, l
}

func NewTestContext(rctx *chi.Context) context.Context {
	ctx := context.Background()

	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	ctx = context.WithValue(ctx, web.ContextKeyRequestId, "00000000-0000-0000-0000-000000000000")
	ctx = context.WithValue(ctx, web.ContextKeyRequestorId, "11111111-1111-1111-1111-111111111111")

	if rctx != nil {
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}

	return ctx
}

func TestNewServer(tester *testing.T) {
	licensing.Test("foo", 0, 0, "", "")
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")
	assert.NotNil(tester, srv.Host)
	assert.Equal(tester, licensing.LICENSE_STATUS_ACTIVE, licensing.GetStatus())
	assert.NotNil(tester, srv.ApiRouter)
}

func TestNewServer_SocUrlExceeded(tester *testing.T) {
	licensing.Test("foo", 0, 0, "foo", "")
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")
	assert.NotNil(tester, srv.Host)
	assert.Equal(tester, licensing.LICENSE_STATUS_EXCEEDED, licensing.GetStatus())
}

func TestDeveloperAuthorization(tester *testing.T) {
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")
	cfg.DeveloperEnabled = true

	authErr := srv.CheckAuthorized(context.Background(), "read", "users")
	assert.NoError(tester, authErr)
}

func TestMissingAuthorization(tester *testing.T) {
	cfg := &config.ServerConfig{}
	srv := NewServer(cfg, "")

	authErr := srv.CheckAuthorized(context.Background(), "read", "users")
	assert.Error(tester, authErr)
	assert.Equal(tester, "Missing Authorizer module", authErr.Error())
}

func TestFailedAuthorization(tester *testing.T) {
	srv := NewFakeUnauthorizedServer()

	authErr := srv.CheckAuthorized(context.Background(), "read", "users")
	assert.Error(tester, authErr)
	assert.Contains(tester, authErr.Error(), "not authorized to perform operation 'read' on target 'users'")
}

func TestTryGetUser(tester *testing.T) {
	ctrl := gomock.NewController(tester)
	defer ctrl.Finish()

	cfg := &config.ServerConfig{}
	srv := NewMockServer(tester, ctrl, cfg)

	// Agent Case
	srv.Agent = &model.User{Id: AGENT_ID, Email: "agent@so.org"}
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, AGENT_ID)
	user, err := srv.TryGetUser(ctx)
	assert.NoError(tester, err)
	assert.Equal(tester, srv.Agent, user)

	// Client Case (starts with socl_)
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, "socl_client123")
	user, err = srv.TryGetUser(ctx)
	assert.NoError(tester, err)
	assert.Nil(tester, user)

	// Real User Case
	userID := "11111111-1111-1111-1111-111111111111"
	ctx = context.WithValue(context.Background(), web.ContextKeyRequestorId, userID)
	srv.Userstore.(*mock.MockUserstore).EXPECT().GetUserById(gomock.Any(), userID).Return(&model.User{Id: userID, FirstName: "Test"}, nil)

	user, err = srv.TryGetUser(ctx)
	assert.NoError(tester, err)
	assert.NotNil(tester, user)
	assert.Equal(tester, userID, user.Id)
}
