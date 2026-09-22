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

type fakeTestChannel struct {
	channelType         string
	supportsRecipients  bool
	supportsAttachments bool
	supportsLinks       bool
	lastPayload         *model.NotificationPayload
	sendErr             error
}

func (f *fakeTestChannel) Type() string {
	return f.channelType
}

func (f *fakeTestChannel) SupportsRecipients() bool {
	return f.supportsRecipients
}

func (f *fakeTestChannel) SupportsAttachments() bool {
	return f.supportsAttachments
}

func (f *fakeTestChannel) SupportsLinks() bool {
	return f.supportsLinks
}

func (f *fakeTestChannel) ValidateConfig(params map[string]interface{}) error {
	return nil
}

func (f *fakeTestChannel) Send(ctx context.Context, params map[string]interface{}, payload *model.NotificationPayload) error {
	f.lastPayload = payload
	return f.sendErr
}

type fakeTestNotifier struct {
	channels             map[string]NotificationChannel
	destinations         map[string]model.DestinationConfig
	lastSentPayload      *model.NotificationPayload
	lastSentDestinations []string
	sendErr              error
}

func (f *fakeTestNotifier) Send(ctx context.Context, payload *model.NotificationPayload, destinations ...string) error {
	f.lastSentPayload = payload
	f.lastSentDestinations = destinations
	if len(destinations) > 0 && f.channels != nil {
		for _, destId := range destinations {
			if dest, ok := f.destinations[destId]; ok {
				if ch, ok := f.channels[dest.Type]; ok {
					_ = ch.Send(ctx, dest.Params, payload)
				}
			} else if ch, ok := f.channels["soc"]; ok && destId == "soc-bell" {
				_ = ch.Send(ctx, nil, payload)
			}
		}
	}
	return f.sendErr
}

func (f *fakeTestNotifier) SendWithSilence(ctx context.Context, payload *model.NotificationPayload, silence *model.SilenceParams, destinations ...string) error {
	return nil
}

func (f *fakeTestNotifier) RegisterChannel(channel NotificationChannel) {
	if f.channels == nil {
		f.channels = make(map[string]NotificationChannel)
	}
	f.channels[channel.Type()] = channel
}

func (f *fakeTestNotifier) GetChannel(channelType string) (NotificationChannel, bool) {
	ch, ok := f.channels[channelType]
	return ch, ok
}

func (f *fakeTestNotifier) GetDestinations() map[string]model.DestinationConfig {
	return f.destinations
}

func TestGetDestinations_Success(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	dests := map[string]model.DestinationConfig{
		"soc-bell": {
			ID:          "soc-bell",
			Name:        "SOC Bell",
			Type:        "soc",
			Enabled:     true,
			ScheduleIDs: []string{"work-hours"},
			Severities:  []string{"high", "critical"},
		},
	}
	destsJSON, _ := json.Marshal(dests)

	scheds := []model.Schedule{
		{
			ID:       "work-hours",
			Name:     "Work Hours",
			Enabled:  true,
			Timezone: "UTC",
			Definitions: []model.ScheduleDefinition{
				{
					Type:   model.ScheduleTypeDaily,
					AllDay: true,
				},
			},
		},
	}
	schedsJSON, _ := json.Marshal(scheds)

	srv := NewFakeAuthorizedServer(nil)
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{
			"soc": &fakeTestChannel{channelType: "soc", supportsRecipients: true, supportsAttachments: true, supportsLinks: true},
		},
	}
	srv.Notifier = fakeNotif
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
		{
			Id:    "soc.config.server.schedules",
			Value: string(schedsJSON),
		},
	})
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("GET", "/api/notifications/destinations", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetDestinations(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []model.DestinationConfig
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "soc-bell", resp[0].ID)
	assert.Equal(t, "SOC Bell", resp[0].Name)
	assert.Equal(t, []string{"work-hours"}, resp[0].ScheduleIDs)
	assert.Equal(t, []string{"high", "critical"}, resp[0].Severities)
	assert.True(t, resp[0].RecipientsSupported)
}

func TestGetDestinations_DefaultFallback(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("GET", "/api/notifications/destinations", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetDestinations(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []model.DestinationConfig
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "soc-bell", resp[0].ID)
}

func TestPostDestination_Success(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{
			"soc": &fakeTestChannel{channelType: "soc"},
		},
	}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	newDest := model.DestinationConfig{
		ID:         "new-dest",
		Name:       "New Destination",
		Type:       "soc",
		Enabled:    true,
		Severities: []string{"critical"},
	}
	body, _ := json.Marshal(newDest)

	r := httptest.NewRequest("POST", "/api/notifications/destinations", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostDestination(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify saved to configstore
	setting, err := srv.Configstore.GetSetting(ctx, "soc.config.server.modules.notification.destinations")
	assert.NoError(t, err)
	assert.Contains(t, setting.Value, "new-dest")
	assert.Contains(t, setting.Value, "New Destination")
}

func TestPostDestination_DuplicateID(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialDests := map[string]model.DestinationConfig{
		"dest-1": {
			ID:   "dest-1",
			Name: "Dest 1",
			Type: "soc",
		},
	}
	destsJSON, _ := json.Marshal(initialDests)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
	})
	h := NewNotificationHandler(srv)

	duplicateDest := model.DestinationConfig{
		ID:   "dest-1",
		Name: "Duplicate",
		Type: "soc",
	}
	body, _ := json.Marshal(duplicateDest)

	r := httptest.NewRequest("POST", "/api/notifications/destinations", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostDestination(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPostDestination_EmptyName(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{
			"soc": &fakeTestChannel{channelType: "soc"},
		},
	}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	destWithEmptyName := model.DestinationConfig{
		ID:   "custom-soc",
		Name: "",
		Type: "soc",
	}
	body, _ := json.Marshal(destWithEmptyName)

	r := httptest.NewRequest("POST", "/api/notifications/destinations", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostDestination(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPutDestination_Success(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialDests := map[string]model.DestinationConfig{
		"dest-1": {
			ID:      "dest-1",
			Name:    "Old Name",
			Type:    "soc",
			Enabled: true,
		},
	}
	destsJSON, _ := json.Marshal(initialDests)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
	})
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{
			"soc": &fakeTestChannel{channelType: "soc"},
		},
	}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	updatedDest := model.DestinationConfig{
		Name:       "Updated Name",
		Type:       "soc",
		Enabled:    false,
		Severities: []string{"high"},
	}
	body, _ := json.Marshal(updatedDest)

	r := httptest.NewRequest("PUT", "/api/notifications/destinations/dest-1", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "dest-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutDestination(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	setting, err := srv.Configstore.GetSetting(ctx, "soc.config.server.modules.notification.destinations")
	assert.NoError(t, err)
	assert.Contains(t, setting.Value, "Updated Name")
	assert.Contains(t, setting.Value, `"enabled":false`)
}

func TestPutDestination_NotFound(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})
	h := NewNotificationHandler(srv)

	updatedDest := model.DestinationConfig{
		Name: "Non-existent",
		Type: "soc",
	}
	body, _ := json.Marshal(updatedDest)

	r := httptest.NewRequest("PUT", "/api/notifications/destinations/nonexistent", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nonexistent")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutDestination(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteDestination_Success(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialDests := map[string]model.DestinationConfig{
		"dest-1": {
			ID:   "dest-1",
			Name: "Dest To Delete",
			Type: "soc",
		},
	}
	destsJSON, _ := json.Marshal(initialDests)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
	})
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("DELETE", "/api/notifications/destinations/dest-1", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "dest-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.DeleteDestination(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	setting, err := srv.Configstore.GetSetting(ctx, "soc.config.server.modules.notification.destinations")
	assert.NoError(t, err)
	assert.NotContains(t, setting.Value, "dest-1")
}

func TestDeleteDestination_DefaultSOCBell(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("DELETE", "/api/notifications/destinations/soc-bell", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "soc-bell")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.DeleteDestination(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteDestination_NotFound(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("DELETE", "/api/notifications/destinations/nonexistent", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nonexistent")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.DeleteDestination(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPostSendNotification_Global(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	fakeNotif := &fakeTestNotifier{}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	bodyJSON := `{"title":"System Wide Alert","summary":"Global notification","severity":"critical","recipients":["user-1","user-2"],"bypassSchedules":true}`
	r := httptest.NewRequest("POST", "/api/notifications/send", bytes.NewBufferString(bodyJSON))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostSendNotification(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, fakeNotif.lastSentPayload)
	assert.Equal(t, "System Wide Alert", fakeNotif.lastSentPayload.Title)
	assert.Equal(t, "Global notification", fakeNotif.lastSentPayload.Summary)
	assert.Equal(t, "critical", fakeNotif.lastSentPayload.Severity)
	assert.Equal(t, []string{"user-1", "user-2"}, fakeNotif.lastSentPayload.Recipients)
	assert.Equal(t, model.SourceClient, fakeNotif.lastSentPayload.Source)
	assert.True(t, fakeNotif.lastSentPayload.BypassSchedules)
	assert.Empty(t, fakeNotif.lastSentDestinations)
}

func TestPostSendNotification_MissingTitle_ReturnsBadRequest(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	fakeNotif := &fakeTestNotifier{}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	bodyJSON := `{"title":"   ","summary":"No title"}`
	r := httptest.NewRequest("POST", "/api/notifications/send", bytes.NewBufferString(bodyJSON))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostSendNotification(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPostSendNotification_TitleTooLong_ReturnsBadRequest(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	fakeNotif := &fakeTestNotifier{}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	longTitle := string(bytes.Repeat([]byte("a"), 256))
	bodyJSON, _ := json.Marshal(map[string]string{"title": longTitle})
	r := httptest.NewRequest("POST", "/api/notifications/send", bytes.NewReader(bodyJSON))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostSendNotification(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPostTestDestination_Success(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialDests := map[string]model.DestinationConfig{
		"soc-bell": {
			ID:   "soc-bell",
			Name: "SOC Notification Bell",
			Type: "soc",
		},
	}
	destsJSON, _ := json.Marshal(initialDests)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
	})
	ch := &fakeTestChannel{channelType: "soc"}
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{
			"soc": ch,
		},
	}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("POST", "/api/notifications/destinations/soc-bell/test?title=Test%3A+SOC+Notification+Bell", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "soc-bell")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostTestDestination(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, fakeNotif.lastSentPayload)
	assert.Contains(t, fakeNotif.lastSentPayload.Title, "Test: SOC Notification Bell")
	assert.Equal(t, model.SourceClient, fakeNotif.lastSentPayload.Source)
	assert.Nil(t, fakeNotif.lastSentPayload.Recipients)
}

func TestPostTestDestination_Targeted(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialDests := map[string]model.DestinationConfig{
		"soc-bell": {
			ID:   "soc-bell",
			Name: "SOC Notification Bell",
			Type: "soc",
		},
	}
	destsJSON, _ := json.Marshal(initialDests)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
	})
	ch := &fakeTestChannel{channelType: "soc"}
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{
			"soc": ch,
		},
	}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("POST", "/api/notifications/destinations/soc-bell/test?targeted=true&title=Test+%28Targeted%29%3A+SOC+Notification+Bell", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-uuid-123")
	ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "soc-bell")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostTestDestination(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, fakeNotif.lastSentPayload)
	assert.Contains(t, fakeNotif.lastSentPayload.Title, "Test (Targeted): SOC Notification Bell")
	assert.Equal(t, model.SourceClient, fakeNotif.lastSentPayload.Source)
	assert.Equal(t, []string{"user-uuid-123"}, fakeNotif.lastSentPayload.Recipients)
}

func TestPostTestDestination_LocalizedTitleAndSummary(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialDests := map[string]model.DestinationConfig{
		"soc-bell": {
			ID:   "soc-bell",
			Name: "SOC Notification Bell",
			Type: "soc",
		},
	}
	destsJSON, _ := json.Marshal(initialDests)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
	})
	ch := &fakeTestChannel{channelType: "soc"}
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{
			"soc": ch,
		},
	}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("POST", "/api/notifications/destinations/soc-bell/test?title=Prueba%3A+Campana&summary=Resumen+personalizado", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "soc-bell")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostTestDestination(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, fakeNotif.lastSentPayload)
	assert.Equal(t, "Prueba: Campana", fakeNotif.lastSentPayload.Title)
	assert.Equal(t, "Resumen personalizado", fakeNotif.lastSentPayload.Summary)
}

func TestPostTestDestination_Targeted_RecipientsDisabled_BroadcastsToAll(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	enableFalse := false
	initialDests := map[string]model.DestinationConfig{
		"soc-bell": {
			ID:               "soc-bell",
			Name:             "SOC Notification Bell",
			Type:             "soc",
			Enabled:          true,
			EnableRecipients: &enableFalse,
			SkipIfRecipients: false,
		},
	}
	destsJSON, _ := json.Marshal(initialDests)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
	})

	ch := &fakeTestChannel{channelType: "soc", supportsRecipients: true}
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{
			"soc": ch,
		},
		destinations: initialDests,
	}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("POST", "/api/notifications/destinations/soc-bell/test?targeted=true&title=Test+%28Targeted%29%3A+SOC+Notification+Bell", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "user-uuid-123")
	ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "soc-bell")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostTestDestination(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, fakeNotif.lastSentPayload)
	assert.Contains(t, fakeNotif.lastSentPayload.Title, "Test (Targeted): SOC Notification Bell")
}

func TestPostTestDestination_NotFound(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})
	srv.Notifier = &fakeTestNotifier{}
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("POST", "/api/notifications/destinations/nonexistent/test?title=Test", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nonexistent")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostTestDestination(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPostTestDestination_DriverMissing(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialDests := map[string]model.DestinationConfig{
		"matrix-dest": {
			ID:   "matrix-dest",
			Name: "Matrix Alert",
			Type: "matrix",
		},
	}
	destsJSON, _ := json.Marshal(initialDests)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.modules.notification.destinations",
			Value: string(destsJSON),
		},
	})
	fakeNotif := &fakeTestNotifier{
		channels: map[string]NotificationChannel{},
	}
	srv.Notifier = fakeNotif
	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("POST", "/api/notifications/destinations/matrix-dest/test?title=Matrix+Test", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "matrix-dest")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostTestDestination(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPostDestination_InvalidID(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})

	h := NewNotificationHandler(srv)

	newDest := model.DestinationConfig{
		ID:   "invalid id with spaces!",
		Name: "Invalid Channel",
		Type: "soc",
	}
	body, _ := json.Marshal(newDest)

	r := httptest.NewRequest("POST", "/api/notifications/destinations", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostDestination(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), web.GENERIC_ERROR_MESSAGE)
}

func TestPutDestination_InvalidID(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})

	h := NewNotificationHandler(srv)

	dest := model.DestinationConfig{
		Name: "Channel",
		Type: "soc",
	}
	body, _ := json.Marshal(dest)

	r := httptest.NewRequest("PUT", "/api/notifications/destinations/bad!id", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "bad!id")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutDestination(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), web.GENERIC_ERROR_MESSAGE)
}

func TestPostDestination_NameTooLong(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})

	h := NewNotificationHandler(srv)

	newDest := model.DestinationConfig{
		Name: string(make([]byte, model.MAX_DESTINATION_NAME_LEN+1)),
		Type: "soc",
	}
	body, _ := json.Marshal(newDest)

	r := httptest.NewRequest("POST", "/api/notifications/destinations", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostDestination(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), web.GENERIC_ERROR_MESSAGE)
}

func TestPutDestination_NameTooLong(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})

	h := NewNotificationHandler(srv)

	dest := model.DestinationConfig{
		Name: string(make([]byte, model.MAX_DESTINATION_NAME_LEN+1)),
		Type: "soc",
	}
	body, _ := json.Marshal(dest)

	r := httptest.NewRequest("PUT", "/api/notifications/destinations/dest-1", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "dest-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutDestination(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), web.GENERIC_ERROR_MESSAGE)
}

func TestDeleteDestination_InvalidID(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{})

	h := NewNotificationHandler(srv)

	r := httptest.NewRequest("DELETE", "/api/notifications/destinations/bad!id", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "bad!id")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.DeleteDestination(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), web.GENERIC_ERROR_MESSAGE)
}
