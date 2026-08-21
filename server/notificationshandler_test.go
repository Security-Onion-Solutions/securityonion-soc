// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetNotifications(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := servermock.NewMockNotificationstore(ctrl)
	srv := NewFakeAuthorizedServer(nil)
	srv.Notificationstore = mockStore

	h := NewNotificationHandler(srv)

	fixedTime := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	expectedRecords := []*model.NotificationRecord{
		{
			ID:          "notif-1",
			Source:      "detection",
			Title:       "Title",
			Summary:     "Summary",
			Severity:    "high",
			CreatedAt:   fixedTime,
			IsRead:      true,
			IsDismissed: false,
		},
	}

	mockStore.EXPECT().GetNotifications(gomock.Any(), "unread").Return(expectedRecords, nil).Times(1)

	r := httptest.NewRequest("GET", "/api/notifications?filter=unread", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetNotifications(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []*model.NotificationRecord
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "notif-1", resp[0].ID)
	assert.Equal(t, true, resp[0].IsRead)
	assert.Equal(t, false, resp[0].IsDismissed)
}

func TestGetNotifications_NoLicense(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("GET", "/api/notifications", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetNotifications(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "ERROR_LICENSE_INVALID", w.Body.String())
}

func TestGetNotifications_StoreNil(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	srv.Notificationstore = nil

	r := chi.NewRouter()
	RegisterNotificationRoutes(srv, r, "/api/notifications")

	req := httptest.NewRequest("GET", "/api/notifications", nil)
	ctx := context.WithValue(req.Context(), web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestGetNotifications_StoreError(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := servermock.NewMockNotificationstore(ctrl)
	srv := NewFakeAuthorizedServer(nil)
	srv.Notificationstore = mockStore

	h := NewNotificationHandler(srv)

	mockStore.EXPECT().GetNotifications(gomock.Any(), "").Return(nil, errors.New("database failure")).Times(1)

	r := httptest.NewRequest("GET", "/api/notifications", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetNotifications(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetNotifications_Unauthorized(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := servermock.NewMockNotificationstore(ctrl)
	srv := NewFakeAuthorizedServer(nil)
	srv.Notificationstore = mockStore

	h := NewNotificationHandler(srv)

	mockStore.EXPECT().GetNotifications(gomock.Any(), "").Return(nil, errors.New("unauthorized: missing user in context")).Times(1)

	r := httptest.NewRequest("GET", "/api/notifications", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetNotifications(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPutRead(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := servermock.NewMockNotificationstore(ctrl)
	srv := NewFakeAuthorizedServer(nil)
	srv.Notificationstore = mockStore

	h := NewNotificationHandler(srv)

	mockStore.EXPECT().SetRead(gomock.Any(), "notif-1", true).Return(nil).Times(1)

	body := []byte(`{"isRead": true}`)
	r := httptest.NewRequest("PUT", "/api/notifications/notif-1/read", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	// Setup URLParam "id"
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "notif-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutRead(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPutRead_NoLicense(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	h := NewNotificationHandler(srv)

	body := []byte(`{"isRead": true}`)
	r := httptest.NewRequest("PUT", "/api/notifications/notif-1/read", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "notif-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutRead(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "ERROR_LICENSE_INVALID", w.Body.String())
}

func TestPutRead_InvalidBody(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := servermock.NewMockNotificationstore(ctrl)
	srv := NewFakeAuthorizedServer(nil)
	srv.Notificationstore = mockStore

	h := NewNotificationHandler(srv)

	body := []byte(`{invalid-json}`)
	r := httptest.NewRequest("PUT", "/api/notifications/notif-1/read", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "notif-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutRead(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPutDismiss(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := servermock.NewMockNotificationstore(ctrl)
	srv := NewFakeAuthorizedServer(nil)
	srv.Notificationstore = mockStore

	h := NewNotificationHandler(srv)

	mockStore.EXPECT().SetDismissed(gomock.Any(), "notif-1", true).Return(nil).Times(1)

	body := []byte(`{"isDismissed": true}`)
	r := httptest.NewRequest("PUT", "/api/notifications/notif-1/dismiss", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	// Setup URLParam "id"
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "notif-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutDismiss(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPutDismiss_NoLicense(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	h := NewNotificationHandler(srv)

	body := []byte(`{"isDismissed": true}`)
	r := httptest.NewRequest("PUT", "/api/notifications/notif-1/dismiss", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestStart, time.Now())

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "notif-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutDismiss(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "ERROR_LICENSE_INVALID", w.Body.String())
}

func TestGetAudit(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStore := servermock.NewMockNotificationstore(ctrl)
	srv := NewFakeAuthorizedServer(nil)
	srv.Notificationstore = mockStore

	h := NewNotificationHandler(srv)

	fixedTime := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	expectedAudit := []*model.NotificationAuditEntry{
		{
			UserID:      "user1",
			IsRead:      true,
			ReadAt:      &fixedTime,
			IsDismissed: true,
			DismissedAt: &fixedTime,
		},
	}

	mockStore.EXPECT().GetAuditLogs(gomock.Any(), "notif-1").Return(expectedAudit, nil).Times(1)

	r := httptest.NewRequest("GET", "/api/notifications/notif-1/audit", nil)

	// Setup URLParam "id"
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "notif-1")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetAudit(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []*model.NotificationAuditEntry
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "user1", resp[0].UserID)
}

func TestGetAudit_NoLicense(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("GET", "/api/notifications/notif-1/audit", nil)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "notif-1")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetAudit(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "ERROR_LICENSE_INVALID", w.Body.String())
}
