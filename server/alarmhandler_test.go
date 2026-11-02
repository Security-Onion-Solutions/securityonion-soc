// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"github.com/security-onion-solutions/securityonion-soc/model"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestGetAlarms(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	fakeStore.Alarms = []model.Alarm{
		{
			ID:              "alarm-1",
			Name:            "High CPU",
			Enabled:         true,
			Metric:          "cpu",
			Operator:        "gt",
			Threshold:       "80",
			Severity:        "high",
			DurationSeconds: 120,
		},
	}

	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	r := httptest.NewRequest("GET", "/api/alarms", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetAlarms(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []model.Alarm
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "alarm-1", resp[0].ID)
}

func TestGetAlarmMetrics(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	fakeStore.Metrics = []model.AlarmMetricInfo{
		{Metric: "cpu", TitleKey: "metricsCpuUsage"},
	}

	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	r := httptest.NewRequest("GET", "/api/alarms/metrics", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetMetrics(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []model.AlarmMetricInfo
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp)
}

func TestGetAlarmStates(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	fakeStore.States = []model.AlarmState{
		{AlarmID: "alarm-1", NodeID: "node-1", Status: "alarm"},
	}

	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	r := httptest.NewRequest("GET", "/api/alarms/states", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetStates(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []model.AlarmState
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
}

func TestGetAlarmStates_StoreNil(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = nil

	h := NewAlarmHandler(srv)

	r := httptest.NewRequest("GET", "/api/alarms/states", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetStates(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []*model.AlarmState
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Empty(t, resp)
}

func TestGetAlarm(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	fakeStore.Alarms = []model.Alarm{
		{
			ID:        "alarm-1",
			Name:      "High CPU",
			Enabled:   true,
			Metric:    "cpu",
			Operator:  "gt",
			Threshold: "80",
			Severity:  "high",
		},
	}

	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "alarm-1")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	r := httptest.NewRequest("GET", "/api/alarms/alarm-1", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	h.GetAlarm(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp model.Alarm
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "alarm-1", resp.ID)
}

func TestPostAlarm(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	alarmReq := model.Alarm{
		Name:            "Disk Full",
		Enabled:         true,
		Metric:          "disk",
		MetricKey:       "disk_used_root",
		Operator:        "gt",
		Threshold:       "90",
		DurationSeconds: 60,
		Severity:        "critical",
		ClearedSeverity: "info",
		Note:            "Disk root usage above 90%",
	}
	body, _ := json.Marshal(alarmReq)

	r := httptest.NewRequest("POST", "/api/alarms", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostAlarm(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp model.Alarm
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "Disk Full", resp.Name)
}

func TestPostAlarm_InvalidThreshold(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	fakeStore.Err = errors.New("alarm threshold must be a valid number")

	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	newAlarm := model.Alarm{
		Name:      "Bad Numeric Threshold",
		Metric:    "cpu",
		Operator:  "gt",
		Threshold: "1;3",
		Severity:  "high",
	}
	body, _ := json.Marshal(newAlarm)

	r := httptest.NewRequest("POST", "/api/alarms/", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostAlarm(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPutAlarm(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	fakeStore.Alarms = []model.Alarm{
		{
			ID:        "alarm-1",
			Name:      "High CPU",
			Enabled:   true,
			Metric:    "cpu",
			Operator:  "gt",
			Threshold: "80",
			Severity:  "high",
		},
	}

	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	updatedAlarm := model.Alarm{
		Name:      "High CPU Modified",
		Enabled:   false,
		Metric:    "cpu",
		Operator:  "gt",
		Threshold: "85",
		Severity:  "critical",
	}
	body, _ := json.Marshal(updatedAlarm)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "alarm-1")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	r := httptest.NewRequest("PUT", "/api/alarms/alarm-1", bytes.NewReader(body)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.PutAlarm(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp model.Alarm
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "High CPU Modified", resp.Name)
	assert.False(t, resp.Enabled)
}

func TestDeleteAlarm(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	fakeStore.Alarms = []model.Alarm{
		{
			ID:        "alarm-1",
			Name:      "High CPU",
			Enabled:   true,
			Metric:    "cpu",
			Operator:  "gt",
			Threshold: "80",
			Severity:  "high",
		},
	}

	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "alarm-1")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	r := httptest.NewRequest("DELETE", "/api/alarms/alarm-1", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	h.DeleteAlarm(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, fakeStore.Alarms)
}

func TestAlarmHandler_PostEvaluate(t *testing.T) {
	fakeStore := NewFakeAlarmstore()
	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = fakeStore

	h := NewAlarmHandler(srv)

	r := httptest.NewRequest("POST", "/api/alarms/evaluate", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostEvaluate(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, fakeStore.Evaluated)
}

func TestRegisterAlarmRoutes_StoreNil(t *testing.T) {
	srv := NewFakeAuthorizedServer(nil)
	srv.Alarmstore = nil

	r := chi.NewRouter()
	RegisterAlarmRoutes(srv, r, "/api/alarms")

	// GET /states should succeed with 200 OK and empty array when Alarmstore is nil
	req := httptest.NewRequest("GET", "/api/alarms/states", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var states []*model.AlarmState
	err := json.Unmarshal(w.Body.Bytes(), &states)
	assert.NoError(t, err)
	assert.Empty(t, states)

	// Other routes should return 405 Method Not Allowed
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/alarms"},
		{"GET", "/api/alarms/metrics"},
		{"GET", "/api/alarms/alarm-1"},
		{"POST", "/api/alarms"},
		{"PUT", "/api/alarms/alarm-1"},
		{"DELETE", "/api/alarms/alarm-1"},
		{"POST", "/api/alarms/evaluate"},
	}

	for _, rt := range routes {
		req := httptest.NewRequest(rt.method, rt.path, nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, "expected 405 for %s %s", rt.method, rt.path)
	}
}
