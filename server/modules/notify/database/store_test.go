// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"errors"
	"testing"
	"time"

	mockdb "github.com/security-onion-solutions/securityonion-soc/db/mock"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNew_NilDB(t *testing.T) {
	s, err := New(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, s)
}

func TestNew_MigrateSuccess(t *testing.T) {
	mDB := new(mockdb.MockDB)
	mDB.On("Migrate", mock.Anything, mock.Anything, "notify").Return(nil).Once()

	s, err := New(context.Background(), mDB)
	assert.NoError(t, err)
	assert.NotNil(t, s)
	mDB.AssertExpectations(t)
}

func TestNew_MigrateError(t *testing.T) {
	mDB := new(mockdb.MockDB)
	mDB.On("Migrate", mock.Anything, mock.Anything, "notify").Return(errors.New("migration failed")).Once()

	s, err := New(context.Background(), mDB)
	assert.Error(t, err)
	assert.Nil(t, s)
	mDB.AssertExpectations(t)
}

func TestStore_InsertNotification_Success(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := &Store{db: mDB}

	payload := &model.NotificationPayload{
		ID:        "notif-1",
		Source:    "detection",
		Title:     "Title",
		Summary:   "Summary",
		Severity:  "high",
		Timestamp: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
	}

	mDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "notif-1", "detection", "Title", "Summary", "high", mock.Anything, mock.Anything, mock.Anything, "", payload.Timestamp).
		Return(nil).Once()

	err := s.InsertNotification(context.Background(), payload)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestStore_InsertNotification_NilPayload(t *testing.T) {
	s := &Store{}
	err := s.InsertNotification(context.Background(), nil)
	assert.Error(t, err)
}

func TestStore_GetNotifications(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := &Store{db: mDB}

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

	userCreated := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	mDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "admin", userCreated).Return(mockRows, nil).Once()

	res, err := s.GetNotifications(context.Background(), "admin", "active", userCreated)
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "notif-1", res[0].ID)
	assert.Equal(t, "val", res[0].Fields["key"])
}

func TestStore_SetRead(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := &Store{db: mDB}

	mDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "notif-1", "admin", true, mock.Anything).Return(nil).Once()

	err := s.SetRead(context.Background(), "notif-1", "admin", true)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestStore_SetDismissed(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := &Store{db: mDB}

	mDB.On("Exec", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "notif-1", "admin", true, mock.Anything).Return(nil).Once()

	err := s.SetDismissed(context.Background(), "notif-1", "admin", true)
	assert.NoError(t, err)
	mDB.AssertExpectations(t)
}

func TestStore_GetAuditLogs(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := &Store{db: mDB}

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

	res, err := s.GetAuditLogs(context.Background(), "notif-1")
	assert.NoError(t, err)
	assert.Len(t, res, 1)
	assert.Equal(t, "user1", res[0].UserID)
}

func TestStore_GetLastUnreadTime_Found(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := &Store{db: mDB}

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

	tRes, err := s.GetLastUnreadTime(context.Background(), "admin", time.Time{})
	assert.NoError(t, err)
	assert.NotNil(t, tRes)
	assert.Equal(t, fixedTime, *tRes)
}

func TestStore_GetLastUnreadTime_NotFound(t *testing.T) {
	mDB := new(mockdb.MockDB)
	s := &Store{db: mDB}

	mockRows := new(mockdb.MockRows)
	mockRows.On("Close").Return()
	mockRows.On("Next").Return(false).Once()

	mDB.On("Query", mock.Anything, mock.MatchedBy(func(sql string) bool {
		return len(sql) > 0
	}), "admin").Return(mockRows, nil).Once()

	tRes, err := s.GetLastUnreadTime(context.Background(), "admin", time.Time{})
	assert.NoError(t, err)
	assert.Nil(t, tRes)
}

func TestSanitizeLinks(t *testing.T) {
	assert.Nil(t, SanitizeLinks(nil))

	raw := map[string]string{
		"valid_https": "https://soc.example.com/#/alerts/1",
		"valid_http":  "http://soc.example.com/",
		"valid_rel":   "/alerts/123",
		"valid_hash":  "#/alerts/123",
		"js_bad":      "javascript:alert(1)",
		"JS_BAD":      "JavaScript:alert(1)",
		"data_bad":    "data:text/html,<script>alert(1)</script>",
		"vb_bad":      "vbscript:msgbox('hi')",
		"ftp_bad":     "ftp://example.com/file",
	}

	sanitized := SanitizeLinks(raw)
	assert.NotNil(t, sanitized)
	assert.Equal(t, "https://soc.example.com/#/alerts/1", sanitized["valid_https"])
	assert.Equal(t, "http://soc.example.com/", sanitized["valid_http"])
	assert.Equal(t, "/alerts/123", sanitized["valid_rel"])
	assert.Equal(t, "#/alerts/123", sanitized["valid_hash"])
	assert.NotContains(t, sanitized, "js_bad")
	assert.NotContains(t, sanitized, "JS_BAD")
	assert.NotContains(t, sanitized, "data_bad")
	assert.NotContains(t, sanitized, "vb_bad")
	assert.NotContains(t, sanitized, "ftp_bad")
}
