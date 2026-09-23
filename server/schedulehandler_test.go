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

func TestGetSchedules_SingleObjectFormat(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	singleJSON := `{"definitions":[{"daysOfMonth":[1],"endTime":"17:00","months":[1],"startTime":"08:00","type":"annually"}],"enabled":true,"id":"cb4963c2-eede-48e2-b654-49a7f093b94f","name":"Holidays","timezone":"America/New_York"}`
	settings := []*model.Setting{
		{
			Id:    "soc.config.server.schedules",
			Value: singleJSON,
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
	assert.Equal(t, "cb4963c2-eede-48e2-b654-49a7f093b94f", resp[0].ID)
	assert.Equal(t, "Holidays", resp[0].Name)
}

func TestPostSchedule(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore(nil)

	h := NewScheduleHandler(srv)

	newSched := model.Schedule{
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
	assert.NotEmpty(t, schedules[0].ID)
	assert.Equal(t, "Off Hours", schedules[0].Name)
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

func TestPutSchedule_EmptyName(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore(nil)

	h := NewScheduleHandler(srv)

	sched := model.Schedule{
		ID:   "sch-1",
		Name: "   ",
	}
	body, _ := json.Marshal(sched)

	r := httptest.NewRequest("PUT", "/api/schedules/sch-1", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "sch-1")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutSchedule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
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

func TestPostSchedule_CycleRejected(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore(nil)

	h := NewScheduleHandler(srv)

	// Attempt to create Schedule with self-exclusion
	newSched := model.Schedule{
		ID:                 "sch-self",
		Name:               "Schedule Self",
		Enabled:            true,
		Timezone:           "UTC",
		Definitions:        []model.ScheduleDefinition{},
		ExcludeScheduleIDs: []string{"sch-self"},
	}
	body, _ := json.Marshal(newSched)

	r := httptest.NewRequest("POST", "/api/schedules", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostSchedule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPutSchedule_CycleRejected(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	initialSchedules := []model.Schedule{
		{
			ID:                 "sch-a",
			Name:               "Schedule A",
			Enabled:            true,
			Timezone:           "UTC",
			Definitions:        []model.ScheduleDefinition{},
			ExcludeScheduleIDs: []string{"sch-b"},
		},
		{
			ID:                 "sch-b",
			Name:               "Schedule B",
			Enabled:            true,
			Timezone:           "UTC",
			Definitions:        []model.ScheduleDefinition{},
			ExcludeScheduleIDs: []string{},
		},
	}
	schedulesJSON, _ := json.Marshal(initialSchedules)

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.schedules",
			Value: string(schedulesJSON),
		},
	})

	h := NewScheduleHandler(srv)

	// Update Schedule B to exclude Schedule A -> creates cycle
	updatedSched := model.Schedule{
		ID:                 "sch-b",
		Name:               "Schedule B Updated",
		Enabled:            true,
		Timezone:           "UTC",
		Definitions:        []model.ScheduleDefinition{},
		ExcludeScheduleIDs: []string{"sch-a"},
	}
	body, _ := json.Marshal(updatedSched)

	r := httptest.NewRequest("PUT", "/api/schedules/sch-b", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "sch-b")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutSchedule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPostEvaluate_WithExclusion(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	holidaySched := model.Schedule{
		ID:       "us-holiday",
		Name:     "US Holiday",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []model.ScheduleDefinition{
			{
				Type:        model.ScheduleTypeAnnually,
				Months:      []int{12},
				DaysOfMonth: []int{25},
				AllDay:      true,
			},
		},
	}
	schedulesJSON, _ := json.Marshal([]model.Schedule{holidaySched})

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.schedules",
			Value: string(schedulesJSON),
		},
	})
	h := NewScheduleHandler(srv)

	reqData := EvaluateScheduleRequest{
		Schedule: model.Schedule{
			ID:                 "work-hours",
			Enabled:            true,
			Timezone:           "UTC",
			ExcludeScheduleIDs: []string{"us-holiday"},
			Definitions: []model.ScheduleDefinition{
				{
					Type:      model.ScheduleTypeDaily,
					StartTime: "08:00",
					EndTime:   "17:00",
				},
			},
		},
		Timestamp: "2026-12-25T10:00:00Z", // Holiday -> suppressed
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
	assert.False(t, resp.Active)
}

func TestGetSchedules_ManualCycleSanitizedOnLoad(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	// Simulate someone manually placing a cycle directly into Pillar/DB
	manualCyclicSchedules := []model.Schedule{
		{
			ID:                 "sch-a",
			Name:               "Schedule A",
			Enabled:            true,
			Timezone:           "UTC",
			Definitions:        []model.ScheduleDefinition{},
			ExcludeScheduleIDs: []string{"sch-b"},
		},
		{
			ID:                 "sch-b",
			Name:               "Schedule B",
			Enabled:            true,
			Timezone:           "UTC",
			Definitions:        []model.ScheduleDefinition{},
			ExcludeScheduleIDs: []string{"sch-c"},
		},
		{
			ID:                 "sch-c",
			Name:               "Schedule C",
			Enabled:            true,
			Timezone:           "UTC",
			Definitions:        []model.ScheduleDefinition{},
			ExcludeScheduleIDs: []string{"sch-a"}, // Closes the cycle
		},
	}
	schedulesJSON, _ := json.Marshal(manualCyclicSchedules)

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.schedules",
			Value: string(schedulesJSON),
		},
	})

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
	assert.Len(t, resp, 3)

	// Verify the cycle was broken by dropping sch-a from sch-c
	assert.Equal(t, []string{"sch-b"}, resp[0].ExcludeScheduleIDs)
	assert.Equal(t, []string{"sch-c"}, resp[1].ExcludeScheduleIDs)
	assert.Empty(t, resp[2].ExcludeScheduleIDs)
}

func TestIsScheduleActiveInConfig(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Empty scheduleID -> true, nil
	active, err := IsScheduleActiveInConfig(ctx, nil, "", now)
	assert.NoError(t, err)
	assert.True(t, active)

	// 2. Nil store -> true, nil
	active, err = IsScheduleActiveInConfig(ctx, nil, "any-sched", now)
	assert.NoError(t, err)
	assert.True(t, active)

	// 3. Store with active schedule
	scheds := []model.Schedule{
		{
			ID:       "sched-active",
			Name:     "Active",
			Enabled:  true,
			Timezone: "UTC",
			Definitions: []model.ScheduleDefinition{
				{Type: model.ScheduleTypeDaily, AllDay: true},
			},
		},
		{
			ID:          "sched-disabled",
			Name:        "Disabled",
			Enabled:     false,
			Timezone:    "UTC",
			Definitions: []model.ScheduleDefinition{},
		},
	}
	schedulesJSON, _ := json.Marshal(scheds)
	store := NewMemConfigStore([]*model.Setting{
		{
			Id:    "soc.config.server.schedules",
			Value: string(schedulesJSON),
		},
	})

	active, err = IsScheduleActiveInConfig(ctx, store, "sched-active", now)
	assert.NoError(t, err)
	assert.True(t, active)

	active, err = IsScheduleActiveInConfig(ctx, store, "sched-disabled", now)
	assert.NoError(t, err)
	assert.False(t, active)

	active, err = IsScheduleActiveInConfig(ctx, store, "non-existent", now)
	assert.NoError(t, err)
	assert.True(t, active)
}

func TestPostSchedule_InvalidID(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore(nil)

	h := NewScheduleHandler(srv)

	sched := model.Schedule{
		ID:   "invalid schedule id with spaces!",
		Name: "Valid Name",
	}
	body, _ := json.Marshal(sched)

	r := httptest.NewRequest("POST", "/api/schedules", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostSchedule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPostSchedule_DescriptionTooLong(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore(nil)

	h := NewScheduleHandler(srv)

	sched := model.Schedule{
		Name:        "Valid Name",
		Description: string(make([]byte, model.MAX_SCHEDULE_DESCRIPTION_LEN+1)),
	}
	body, _ := json.Marshal(sched)

	r := httptest.NewRequest("POST", "/api/schedules", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PostSchedule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPutSchedule_InvalidID(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore(nil)

	h := NewScheduleHandler(srv)

	sched := model.Schedule{
		Name: "Valid Name",
	}
	body, _ := json.Marshal(sched)

	r := httptest.NewRequest("PUT", "/api/schedules/bad!id", bytes.NewReader(body))
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "bad!id")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.PutSchedule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSchedule_InvalidID(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	srv := NewFakeAuthorizedServer(nil)
	srv.Configstore = NewMemConfigStore(nil)

	h := NewScheduleHandler(srv)

	r := httptest.NewRequest("DELETE", "/api/schedules/bad!id", nil)
	ctx := context.WithValue(context.Background(), web.ContextKeyRunAsUsername, "admin")
	ctx = context.WithValue(ctx, web.ContextKeyRequestStart, time.Now())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "bad!id")
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.DeleteSchedule(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
