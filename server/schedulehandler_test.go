// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestGetSchedules(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialSchedules := []model.Schedule{
		{
			ID:          "sch-1",
			Name:        "Work Hours",
			Enabled:     true,
			Timezone:    "UTC",
			Definitions: []model.ScheduleDefinition{},
		},
	}
	schedulesJSON, _ := json.Marshal(initialSchedules)
	settings := []*model.Setting{
		{
			Id:    "soc.config.server.schedules",
			Value: string(schedulesJSON),
		},
	}
	srv.Configstore = NewMemConfigStore(settings)

	h := NewScheduleHandler(srv)

	r := httptest.NewRequest("GET", "/api/schedules", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.GetSchedules(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []model.Schedule
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "sch-1", resp[0].ID)
}

func TestPostSchedule(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore(nil)

	h := NewScheduleHandler(srv)

	newSched := model.Schedule{
		ID:          "sch-2",
		Name:        "Off Hours",
		Enabled:     true,
		Timezone:    "UTC",
		Definitions: []model.ScheduleDefinition{},
	}
	body, _ := json.Marshal(newSched)

	r := httptest.NewRequest("POST", "/api/schedules", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostSchedule(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	// Retrieve settings from store to verify update
	settings, err := srv.Configstore.GetSettings(ctx, true)
	assert.NoError(t, err)

	var schedules []model.Schedule
	for _, s := range settings {
		if s.Id == "soc.config.server.schedules" {
			err = json.Unmarshal([]byte(s.Value), &schedules)
			assert.NoError(t, err)
			break
		}
	}
	assert.Len(t, schedules, 1)
	assert.Equal(t, "sch-2", schedules[0].ID)
}

func TestPutSchedule(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialSchedules := []model.Schedule{
		{
			ID:          "sch-1",
			Name:        "Old Name",
			Enabled:     true,
			Timezone:    "UTC",
			Definitions: []model.ScheduleDefinition{},
		},
	}
	schedulesJSON, _ := json.Marshal(initialSchedules)
	settings := []*model.Setting{
		{
			Id:    "soc.config.server.schedules",
			Value: string(schedulesJSON),
		},
	}
	srv.Configstore = NewMemConfigStore(settings)

	h := NewScheduleHandler(srv)

	updatedSched := model.Schedule{
		ID:          "sch-1",
		Name:        "New Name",
		Enabled:     true,
		Timezone:    "UTC",
		Definitions: []model.ScheduleDefinition{},
	}
	body, _ := json.Marshal(updatedSched)

	r := httptest.NewRequest("PUT", "/api/schedules/sch-1", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "sch-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutSchedule(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	// Retrieve settings from store to verify update
	settings, err := srv.Configstore.GetSettings(ctx, true)
	assert.NoError(t, err)

	var schedules []model.Schedule
	for _, s := range settings {
		if s.Id == "soc.config.server.schedules" {
			err = json.Unmarshal([]byte(s.Value), &schedules)
			assert.NoError(t, err)
			break
		}
	}
	assert.Len(t, schedules, 1)
	assert.Equal(t, "New Name", schedules[0].Name)
}

func TestDeleteSchedule(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	initialSchedules := []model.Schedule{
		{
			ID:          "sch-1",
			Name:        "To Be Deleted",
			Enabled:     true,
			Timezone:    "UTC",
			Definitions: []model.ScheduleDefinition{},
		},
	}
	schedulesJSON, _ := json.Marshal(initialSchedules)
	settings := []*model.Setting{
		{
			Id:    "soc.config.server.schedules",
			Value: string(schedulesJSON),
		},
	}
	srv.Configstore = NewMemConfigStore(settings)

	h := NewScheduleHandler(srv)

	r := httptest.NewRequest("DELETE", "/api/schedules/sch-1", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "sch-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.DeleteSchedule(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	// Retrieve settings from store to verify update
	settings, err := srv.Configstore.GetSettings(ctx, true)
	assert.NoError(t, err)

	var schedules []model.Schedule
	for _, s := range settings {
		if s.Id == "soc.config.server.schedules" {
			err = json.Unmarshal([]byte(s.Value), &schedules)
			assert.NoError(t, err)
			break
		}
	}
	assert.Len(t, schedules, 0)
}

func TestPostEvaluate(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	h := NewScheduleHandler(srv)

	reqData := EvaluateScheduleRequest{
		Schedule: model.Schedule{
			ID:       "eval-sch",
			Enabled:  true,
			Timezone: "UTC",
			Definitions: []model.ScheduleDefinition{
				{
					Type:      model.ScheduleTypeDaily,
					StartTime: "09:00",
					EndTime:   "17:00",
				},
			},
		},
		Timestamp: "2026-09-14T12:00:00Z", // Active
	}
	body, _ := json.Marshal(reqData)

	r := httptest.NewRequest("POST", "/api/schedules/evaluate", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostEvaluate(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp EvaluateScheduleResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Active)
}
