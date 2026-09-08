// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package notify

import (
	"context"
	"errors"
	"testing"
	"time"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/mock/gomock"
)

func newTestServer(authorized bool, db *mockdb.MockDB) *server.Server {
	if db != nil {
		db.On("Migrate", mock.Anything, mock.Anything, "notify").Return(nil).Maybe()
	}
	return &server.Server{
		Authorizer: &rbac.FakeAuthorizer{Authorized: authorized},
		DB:         db,
	}
}

func TestStoreGetNotifications_Success(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	mockRows := new(mockdb.MockRows)
	mockRows.On("Close").Return()
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	fixedTime := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*(args[0].(*string)) = "notif-1"
		*(args[1].(*string)) = "detection"
		*(args[2].(*string)) = "Title"
		*(args[3].(*string)) = "Summary"
		*(args[4].(*string)) = "high"
		*(args[5].(*[]byte)) = []byte(`{"key": "val"}`)
		*(args[6].(*[]byte)) = []byte(`{"link": "url"}`)
		*(args[7].(*[]byte)) = []byte("[]")
		*(args[8].(**string)) = nil
		*(args[9].(*time.Time)) = fixedTime
		*(args[10].(*bool)) = true
		*(args[11].(**time.Time)) = &fixedTime
		*(args[12].(*bool)) = false
		*(args[13].(**time.Time)) = nil
	}).Return(nil).Once()

	mDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "admin").Return(mockRows, nil).Once()

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	res, err := store.GetNotifications(ctx, "unread")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "notif-1", res[0].ID)
	assert.Equal(t, true, res[0].IsRead)
	assert.Equal(t, false, res[0].IsDismissed)
	assert.Equal(t, "val", res[0].Fields["key"])
}

func TestStoreGetNotifications_WithUserstoreCreationDate(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)

	userCreated := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	mockUserstore := servermock.NewMockUserstore(gomock.NewController(t))
	mockUserstore.EXPECT().GetUserById(gomock.Any(), "user-uuid-123").Return(&model.User{
		Id:         "user-uuid-123",
		Email:      "analyst@soc.local",
		CreateTime: userCreated,
	}, nil).AnyTimes()
	srv.Userstore = mockUserstore

	store := NewNotificationstore(srv, nil)

	mockRows := new(mockdb.MockRows)
	mockRows.On("Close").Return()
	mockRows.On("Next").Return(false).Once()

	mDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "analyst@soc.local", userCreated).Return(mockRows, nil).Once()

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-uuid-123")
	res, err := store.GetNotifications(ctx, "all")
	assert.NoError(t, err)
	assert.Empty(t, res)
	mDB.AssertExpectations(t)
}

func TestStoreGetNotifications_Unauthorized(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(false, mDB)
	store := NewNotificationstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	res, err := store.GetNotifications(ctx, "")
	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestStoreGetNotifications_MissingUser(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	res, err := store.GetNotifications(context.Background(), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing user in context")
	assert.Nil(t, res)
}

func TestStoreGetNotifications_DBError(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	mDB.On("Query", mock.Anything, mock.Anything, "admin").Return(new(mockdb.MockRows), errors.New("db error")).Once()

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	res, err := store.GetNotifications(ctx, "")
	assert.Error(t, err)
	assert.Nil(t, res)
}

func TestStoreSetRead_Success(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	mDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "notif-1", "admin", true, mock.Anything).Return(nil).Once()

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	err := store.SetRead(ctx, "notif-1", true)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestStoreSetRead_MissingID(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	err := store.SetRead(ctx, "", true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing notification id")
}

func TestStoreSetRead_Unauthorized(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(false, mDB)
	store := NewNotificationstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	err := store.SetRead(ctx, "notif-1", true)
	assert.Error(t, err)
}

func TestStoreSetDismissed_Success(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	mDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "notif-1", "admin", true, mock.Anything).Return(nil).Once()

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	err := store.SetDismissed(ctx, "notif-1", true)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestStoreSetDismissed_MissingID(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	err := store.SetDismissed(ctx, "", true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing notification id")
}

func TestStoreGetAuditLogs_Success(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	mockRows := new(mockdb.MockRows)
	mockRows.On("Close").Return()
	mockRows.On("Next").Return(true).Once()
	mockRows.On("Next").Return(false).Once()

	fixedTime := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	mockRows.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		*(args[0].(*string)) = "user1"
		*(args[1].(*bool)) = true
		*(args[2].(**time.Time)) = &fixedTime
		*(args[3].(*bool)) = true
		*(args[4].(**time.Time)) = &fixedTime
	}).Return(nil).Once()

	mDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "notif-1").Return(mockRows, nil).Once()

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	auditLogs, err := store.GetAuditLogs(ctx, "notif-1")
	assert.NoError(t, err)
	assert.Len(t, auditLogs, 1)
	assert.Equal(t, "user1", auditLogs[0].UserID)
	assert.Equal(t, true, auditLogs[0].IsRead)
	assert.Equal(t, true, auditLogs[0].IsDismissed)
}

func TestStoreGetAuditLogs_MissingID(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	auditLogs, err := store.GetAuditLogs(ctx, "")
	assert.Error(t, err)
	assert.Nil(t, auditLogs)
}

func TestStoreGetLastUnreadTime_Success(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := newTestServer(true, mDB)
	store := NewNotificationstore(srv, nil)

	mockRows := new(mockdb.MockRows)
	mockRows.On("Close").Return()
	mockRows.On("Next").Return(true).Once()

	fixedTime := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	mockRows.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*(args[0].(*time.Time)) = fixedTime
	}).Return(nil).Once()

	mDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "admin").Return(mockRows, nil).Once()

	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	tRes, err := store.GetLastUnreadTime(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, tRes)
	assert.Equal(t, fixedTime, *tRes)
}
