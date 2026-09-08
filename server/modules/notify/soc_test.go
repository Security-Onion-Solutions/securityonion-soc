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
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSOCChannelType(t *testing.T) {
	ch := NewSOCChannel(nil, nil)
	assert.Equal(t, model.ChannelTypeSOC, ch.Type())
}

func TestSOCChannelValidateConfig(t *testing.T) {
	ch := NewSOCChannel(nil, nil)

	// nil params
	assert.NoError(t, ch.ValidateConfig(nil))

	// valid params
	assert.NoError(t, ch.ValidateConfig(map[string]interface{}{
		"storeInPostgres": true,
		"attachmentMode":  model.AttachmentModeLink,
	}))
	assert.NoError(t, ch.ValidateConfig(map[string]interface{}{
		"attachmentMode": model.AttachmentModeAttach,
	}))
	assert.NoError(t, ch.ValidateConfig(map[string]interface{}{
		"attachmentMode": model.AttachmentModeBoth,
	}))

	// invalid attachmentMode string
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"attachmentMode": "invalid",
	}))

	// non-string attachmentMode
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"attachmentMode": 123,
	}))

	// non-boolean storeInPostgres
	assert.Error(t, ch.ValidateConfig(map[string]interface{}{
		"storeInPostgres": "true",
	}))
}

func TestSOCChannelSendNilPayload(t *testing.T) {
	ch := NewSOCChannel(nil, nil)
	err := ch.Send(context.Background(), nil, nil)
	assert.Error(t, err)
}

func TestSOCChannelSendNilDB(t *testing.T) {
	srv := &server.Server{}
	ch := NewSOCChannel(srv, nil)

	payload := &model.NotificationPayload{
		Source:   model.SourceMetric,
		Title:    "Disk Space Low",
		Summary:  "Root partition is 95% full",
		Severity: model.NotificationSeverityCritical,
	}

	err := ch.Send(context.Background(), nil, payload)
	assert.NoError(t, err)
	assert.NotEmpty(t, payload.ID)
	assert.False(t, payload.Timestamp.IsZero())
}

func TestSOCChannelSendStoreInPostgresFalse(t *testing.T) {
	mDB := new(mockdb.MockDB)
	srv := &server.Server{DB: mDB}
	ch := NewSOCChannel(srv, nil)

	payload := &model.NotificationPayload{
		ID:       "custom-id",
		Source:   model.SourceDetection,
		Title:    "Alert",
		Summary:  "Summary",
		Severity: model.NotificationSeverityHigh,
	}

	// storeInPostgres is false, no DB call should be made
	err := ch.Send(context.Background(), map[string]interface{}{"storeInPostgres": false}, payload)
	assert.NoError(t, err)
	mDB.AssertNotCalled(t, "Exec", mock.Anything, mock.Anything, mock.Anything)
}

func TestSOCChannelSendWithMockDB(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mDB.On("Migrate", mock.Anything, mock.Anything, "notify").Return(nil).Maybe()
	srv := &server.Server{DB: mDB}
	ch := NewSOCChannel(srv, nil)

	fixedTime := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	payload := &model.NotificationPayload{
		ID:        "notif-123",
		Source:    model.SourceDetection,
		Title:     "Suricata Alert",
		Summary:   "ET SCAN Potential SSH Scan",
		Severity:  model.NotificationSeverityHigh,
		Timestamp: fixedTime,
		Fields: map[string]string{
			"src_ip": "192.168.1.100",
			"dst_ip": "10.0.0.1",
		},
		Links: map[string]string{
			"View in SOC": "https://soc.local/#/alerts/123",
		},
		Attachments: []model.Attachment{
			{Filename: "event.json", ContentType: "application/json", URL: "https://soc.local/events/123"},
		},
		SilenceKey: "rule_12345_192.168.1.100",
	}

	mDB.On("Exec", ctx, mock.Anything,
		"notif-123",
		model.SourceDetection,
		"Suricata Alert",
		"ET SCAN Potential SSH Scan",
		model.NotificationSeverityHigh,
		mock.MatchedBy(func(s string) bool { return len(s) > 0 }),
		mock.MatchedBy(func(s string) bool { return len(s) > 0 }),
		mock.MatchedBy(func(s string) bool { return len(s) > 0 }),
		"rule_12345_192.168.1.100",
		fixedTime,
	).Return(nil).Once()

	err := ch.Send(ctx, map[string]interface{}{"storeInPostgres": true}, payload)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestSOCChannelSendDBError(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mDB.On("Migrate", mock.Anything, mock.Anything, "notify").Return(nil).Maybe()
	srv := &server.Server{DB: mDB}
	ch := NewSOCChannel(srv, nil)

	payload := &model.NotificationPayload{
		ID:       "notif-err",
		Source:   model.SourceReport,
		Title:    "Report Failed",
		Summary:  "Failed to generate report",
		Severity: model.NotificationSeverityMedium,
	}

	mDB.On("Exec", ctx, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(errors.New("connection closed")).Once()

	err := ch.Send(ctx, nil, payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection closed")
	mDB.AssertExpectations(t)
}

func TestSOCChannelSend_BroadcastWebSocket(t *testing.T) {
	ctx := context.Background()
	mDB := new(mockdb.MockDB)
	mDB.On("Migrate", mock.Anything, mock.Anything, "notify").Return(nil).Maybe()

	host := web.NewHost("127.0.0.1:0", "", 1000, "1.0", []byte("12345678901234567890123456789012"))
	srv := &server.Server{
		DB:   mDB,
		Host: host,
	}
	ch := NewSOCChannel(srv, nil)

	payload := &model.NotificationPayload{
		ID:        "notif-ws",
		Source:    model.SourceDetection,
		Title:     "WS Alert",
		Summary:   "WS Summary",
		Severity:  model.NotificationSeverityHigh,
		Timestamp: time.Now().UTC(),
	}

	mDB.On("Exec", ctx, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Once()

	err := ch.Send(ctx, nil, payload)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}
