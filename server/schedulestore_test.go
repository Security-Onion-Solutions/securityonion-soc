// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestSchedulestore_GetSchedules(t *testing.T) {
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
	cfgStore := NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingServerSchedules,
			Value: string(schedulesJSON),
		},
	})
	srv := &Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	schedStore := NewSchedulestore(srv)

	ctx := context.Background()
	schedules, err := schedStore.GetSchedules(ctx)
	assert.NoError(t, err)
	assert.Len(t, schedules, 1)
	assert.Equal(t, "sch-1", schedules[0].ID)
}

func TestSchedulestore_GetSchedule(t *testing.T) {
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
	cfgStore := NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingServerSchedules,
			Value: string(schedulesJSON),
		},
	})
	srv := &Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	schedStore := NewSchedulestore(srv)

	ctx := context.Background()

	// Invalid ID
	_, err := schedStore.GetSchedule(ctx, "invalid id!")
	assert.ErrorIs(t, err, ErrInvalidScheduleID)

	// Not Found
	_, err = schedStore.GetSchedule(ctx, "sch-nonexistent")
	assert.ErrorIs(t, err, ErrScheduleNotFound)

	// Success
	sched, err := schedStore.GetSchedule(ctx, "sch-1")
	assert.NoError(t, err)
	assert.NotNil(t, sched)
	assert.Equal(t, "sch-1", sched.ID)
	assert.Equal(t, "Work Hours", sched.Name)
}

func TestSchedulestore_CreateSchedule(t *testing.T) {
	cfgStore := NewMemConfigStore([]*model.Setting{})
	srv := &Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	schedStore := NewSchedulestore(srv)

	ctx := context.Background()

	// Nil schedule
	_, err := schedStore.CreateSchedule(ctx, nil)
	assert.Error(t, err)

	// Invalid name
	_, err = schedStore.CreateSchedule(ctx, &model.Schedule{
		Name: string(make([]byte, 300)),
	})
	assert.Error(t, err)

	// Invalid description
	_, err = schedStore.CreateSchedule(ctx, &model.Schedule{
		Name:        "Valid Name",
		Description: string(make([]byte, 4001)),
	})
	assert.Error(t, err)

	// Invalid ID
	_, err = schedStore.CreateSchedule(ctx, &model.Schedule{
		ID:   "invalid!id",
		Name: "Valid Name",
	})
	assert.ErrorIs(t, err, ErrInvalidScheduleID)

	// Cycle in DAG
	_, err = schedStore.CreateSchedule(ctx, &model.Schedule{
		ID:                 "sch-self",
		Name:               "Self Exclusion",
		ExcludeScheduleIDs: []string{"sch-self"},
	})
	assert.Error(t, err)

	// Success creation
	created, err := schedStore.CreateSchedule(ctx, &model.Schedule{
		Name: "New Schedule",
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, created.ID)

	// Duplicate ID
	_, err = schedStore.CreateSchedule(ctx, &model.Schedule{
		ID:   created.ID,
		Name: "Duplicate",
	})
	assert.ErrorIs(t, err, ErrDuplicateScheduleID)

	// Verify saved to configstore
	setting, err := cfgStore.GetSetting(ctx, ConfigSettingServerSchedules)
	assert.NoError(t, err)
	assert.Contains(t, setting.Value, created.ID)
}

func TestSchedulestore_UpdateSchedule(t *testing.T) {
	initialSchedules := []model.Schedule{
		{
			ID:          "sch-1",
			Name:        "Initial Name",
			Definitions: []model.ScheduleDefinition{},
		},
	}
	schedulesJSON, _ := json.Marshal(initialSchedules)
	cfgStore := NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingServerSchedules,
			Value: string(schedulesJSON),
		},
	})
	srv := &Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	schedStore := NewSchedulestore(srv)

	ctx := context.Background()

	// Invalid ID
	_, err := schedStore.UpdateSchedule(ctx, "invalid!id", &model.Schedule{Name: "Name"})
	assert.ErrorIs(t, err, ErrInvalidScheduleID)

	// Not found
	_, err = schedStore.UpdateSchedule(ctx, "sch-nonexistent", &model.Schedule{Name: "Name"})
	assert.ErrorIs(t, err, ErrScheduleNotFound)

	// Success
	updated, err := schedStore.UpdateSchedule(ctx, "sch-1", &model.Schedule{
		Name: "Updated Name",
	})
	assert.NoError(t, err)
	assert.Equal(t, "sch-1", updated.ID)
	assert.Equal(t, "Updated Name", updated.Name)

	// Verify saved in configstore
	setting, err := cfgStore.GetSetting(ctx, ConfigSettingServerSchedules)
	assert.NoError(t, err)
	assert.Contains(t, setting.Value, "Updated Name")
}

func TestSchedulestore_DeleteSchedule(t *testing.T) {
	initialSchedules := []model.Schedule{
		{
			ID:          "sch-1",
			Name:        "To Delete",
			Definitions: []model.ScheduleDefinition{},
		},
	}
	schedulesJSON, _ := json.Marshal(initialSchedules)
	cfgStore := NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingServerSchedules,
			Value: string(schedulesJSON),
		},
	})
	srv := &Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	schedStore := NewSchedulestore(srv)

	ctx := context.Background()

	// Invalid ID
	err := schedStore.DeleteSchedule(ctx, "invalid!id")
	assert.ErrorIs(t, err, ErrInvalidScheduleID)

	// Not found
	err = schedStore.DeleteSchedule(ctx, "sch-nonexistent")
	assert.ErrorIs(t, err, ErrScheduleNotFound)

	// Success
	err = schedStore.DeleteSchedule(ctx, "sch-1")
	assert.NoError(t, err)

	// Verify removed in configstore
	setting, err := cfgStore.GetSetting(ctx, ConfigSettingServerSchedules)
	assert.NoError(t, err)
	assert.NotContains(t, setting.Value, "sch-1")
}

func TestSchedulestore_EvaluateSchedule(t *testing.T) {
	holidaySched := model.Schedule{
		ID:       "us-holiday",
		Name:     "Holidays",
		Enabled:  true,
		Timezone: "America/New_York",
		Definitions: []model.ScheduleDefinition{
			{
				Type:        model.ScheduleTypeAnnually,
				Months:      []int{12},
				DaysOfMonth: []int{25},
				StartTime:   "00:00",
				EndTime:     "23:59",
			},
		},
	}
	schedulesJSON, _ := json.Marshal([]model.Schedule{holidaySched})
	cfgStore := NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingServerSchedules,
			Value: string(schedulesJSON),
		},
	})
	srv := &Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: true},
	}
	schedStore := NewSchedulestore(srv)

	ctx := context.Background()

	workSched := model.Schedule{
		ID:                 "work-hours",
		Name:               "Work Hours",
		Enabled:            true,
		Timezone:           "America/New_York",
		ExcludeScheduleIDs: []string{"us-holiday"},
		Definitions: []model.ScheduleDefinition{
			{
				Type:      model.ScheduleTypeDaily,
				StartTime: "09:00",
				EndTime:   "17:00",
			},
		},
	}

	// Active on regular day during hours
	regularDay := time.Date(2026, 9, 14, 14, 0, 0, 0, time.UTC)
	active, err := schedStore.EvaluateSchedule(ctx, &workSched, regularDay)
	assert.NoError(t, err)
	assert.True(t, active)

	// Inactive on Christmas due to exclusion
	christmas := time.Date(2026, 12, 25, 14, 0, 0, 0, time.UTC)
	active, err = schedStore.EvaluateSchedule(ctx, &workSched, christmas)
	assert.NoError(t, err)
	assert.False(t, active)
}

func TestSchedulestore_IsScheduleActive(t *testing.T) {
	workSched := model.Schedule{
		ID:       "work-hours",
		Name:     "Work Hours",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []model.ScheduleDefinition{
			{
				Type:      model.ScheduleTypeDaily,
				StartTime: "09:00",
				EndTime:   "17:00",
			},
		},
	}
	schedulesJSON, _ := json.Marshal([]model.Schedule{workSched})
	cfgStore := NewMemConfigStore([]*model.Setting{
		{
			Id:    ConfigSettingServerSchedules,
			Value: string(schedulesJSON),
		},
	})
	srv := &Server{
		Configstore: cfgStore,
	}
	schedStore := NewSchedulestore(srv)

	ctx := context.Background()

	// Empty ID returns true
	active, err := schedStore.IsScheduleActive(ctx, "", time.Now())
	assert.NoError(t, err)
	assert.True(t, active)

	// Active within hours
	active, err = schedStore.IsScheduleActive(ctx, "work-hours", time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC))
	assert.NoError(t, err)
	assert.True(t, active)

	// Inactive outside hours
	active, err = schedStore.IsScheduleActive(ctx, "work-hours", time.Date(2026, 9, 14, 20, 0, 0, 0, time.UTC))
	assert.NoError(t, err)
	assert.False(t, active)
}

func TestSchedulestore_Unauthorized(t *testing.T) {
	cfgStore := NewMemConfigStore([]*model.Setting{})
	srv := &Server{
		Configstore: cfgStore,
		Authorizer:  &rbac.FakeAuthorizer{Authorized: false},
	}
	schedStore := NewSchedulestore(srv)

	ctx := context.Background()

	_, err := schedStore.GetSchedules(ctx)
	assert.Error(t, err)

	_, err = schedStore.GetSchedule(ctx, "sch-1")
	assert.Error(t, err)

	_, err = schedStore.CreateSchedule(ctx, &model.Schedule{Name: "New"})
	assert.Error(t, err)

	_, err = schedStore.UpdateSchedule(ctx, "sch-1", &model.Schedule{Name: "Update"})
	assert.Error(t, err)

	err = schedStore.DeleteSchedule(ctx, "sch-1")
	assert.Error(t, err)

	_, err = schedStore.EvaluateSchedule(ctx, &model.Schedule{Name: "Eval"}, time.Now())
	assert.Error(t, err)
}
