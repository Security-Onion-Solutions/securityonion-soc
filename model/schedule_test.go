// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsScheduleActive_NilOrDisabled(t *testing.T) {
	// Nil schedule should be active by default (always active)
	active, err := IsScheduleActive(nil, time.Now())
	assert.NoError(t, err)
	assert.True(t, active)

	// Schedule with no definitions should be active by default
	sched := &Schedule{
		ID:          "test",
		Enabled:     true,
		Definitions: []ScheduleDefinition{},
	}
	active, err = IsScheduleActive(sched, time.Now())
	assert.NoError(t, err)
	assert.True(t, active)

	// Disabled schedule should never be active
	sched.Enabled = false
	sched.Definitions = []ScheduleDefinition{
		{
			Type:   ScheduleTypeDaily,
			AllDay: true,
		},
	}
	active, err = IsScheduleActive(sched, time.Now())
	assert.NoError(t, err)
	assert.False(t, active)
}

func TestIsScheduleActive_Daily(t *testing.T) {
	// UTC schedule
	sched := &Schedule{
		ID:       "daily-standard",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []ScheduleDefinition{
			{
				Type:      ScheduleTypeDaily,
				StartTime: "08:00",
				EndTime:   "17:00",
			},
		},
	}

	// Active within standard window (08:00 - 17:00)
	t1 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	active, err := IsScheduleActive(sched, t1)
	assert.NoError(t, err)
	assert.True(t, active)

	// Inactive before window
	t2 := time.Date(2026, 9, 14, 7, 59, 59, 0, time.UTC)
	active, err = IsScheduleActive(sched, t2)
	assert.NoError(t, err)
	assert.False(t, active)

	// Inactive after window (half-open, so 17:00 is inactive)
	t3 := time.Date(2026, 9, 14, 17, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(sched, t3)
	assert.NoError(t, err)
	assert.False(t, active)

	// Daily Overnight: 22:00 to 06:00
	schedOvernight := &Schedule{
		ID:       "daily-overnight",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []ScheduleDefinition{
			{
				Type:      ScheduleTypeDaily,
				StartTime: "22:00",
				EndTime:   "06:00",
			},
		},
	}

	// Active at 23:00 UTC
	t4 := time.Date(2026, 9, 14, 23, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedOvernight, t4)
	assert.NoError(t, err)
	assert.True(t, active)

	// Active at 02:00 UTC
	t5 := time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedOvernight, t5)
	assert.NoError(t, err)
	assert.True(t, active)

	// Inactive at 12:00 UTC
	t6 := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedOvernight, t6)
	assert.NoError(t, err)
	assert.False(t, active)
}

func TestIsScheduleActive_Weekly(t *testing.T) {
	// Mon-Fri 08:00 - 17:00
	sched := &Schedule{
		ID:       "weekly-workhours",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []ScheduleDefinition{
			{
				Type:       ScheduleTypeWeekly,
				DaysOfWeek: []int{1, 2, 3, 4, 5},
				StartTime:  "08:00",
				EndTime:    "17:00",
			},
		},
	}

	// Monday 12:00 (active)
	t1 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) // 2026-09-14 is Monday
	active, err := IsScheduleActive(sched, t1)
	assert.NoError(t, err)
	assert.True(t, active)

	// Saturday 12:00 (inactive, wrong day)
	t2 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC) // 2026-09-19 is Saturday
	active, err = IsScheduleActive(sched, t2)
	assert.NoError(t, err)
	assert.False(t, active)

	// Monday 06:00 (inactive, wrong time)
	t3 := time.Date(2026, 9, 14, 6, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(sched, t3)
	assert.NoError(t, err)
	assert.False(t, active)

	// Weekly Overnight crossing midnight: Mon-Fri 22:00 - 06:00
	schedOvernight := &Schedule{
		ID:       "weekly-overnight",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []ScheduleDefinition{
			{
				Type:       ScheduleTypeWeekly,
				DaysOfWeek: []int{1, 2, 3, 4, 5}, // Mon-Fri
				StartTime:  "22:00",
				EndTime:    "06:00",
			},
		},
	}

	// Monday 23:00 (active, Monday start)
	t4 := time.Date(2026, 9, 14, 23, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedOvernight, t4)
	assert.NoError(t, err)
	assert.True(t, active)

	// Tuesday 02:00 (active, part of Monday night)
	t5 := time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedOvernight, t5)
	assert.NoError(t, err)
	assert.True(t, active)

	// Monday 02:00 (inactive, because Sunday was NOT in DaysOfWeek)
	t6 := time.Date(2026, 9, 14, 2, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedOvernight, t6)
	assert.NoError(t, err)
	assert.False(t, active)

	// Saturday 02:00 (active, part of Friday night)
	t7 := time.Date(2026, 9, 19, 2, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedOvernight, t7)
	assert.NoError(t, err)
	assert.True(t, active)

	// Sunday 02:00 (inactive, part of Saturday night which is not scheduled)
	t8 := time.Date(2026, 9, 20, 2, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedOvernight, t8)
	assert.NoError(t, err)
	assert.False(t, active)
}

func TestIsScheduleActive_Monthly(t *testing.T) {
	// Monthly on days 1st and 15th, and last day of month (-1)
	sched := &Schedule{
		ID:       "monthly-days",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []ScheduleDefinition{
			{
				Type:        ScheduleTypeMonthly,
				DaysOfMonth: []int{1, 15, -1},
				AllDay:      true,
			},
		},
	}

	// Sep 1st (active)
	t1 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	active, err := IsScheduleActive(sched, t1)
	assert.NoError(t, err)
	assert.True(t, active)

	// Sep 15th (active)
	t2 := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(sched, t2)
	assert.NoError(t, err)
	assert.True(t, active)

	// Sep 30th (active, last day of September)
	t3 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(sched, t3)
	assert.NoError(t, err)
	assert.True(t, active)

	// Sep 29th (inactive)
	t4 := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(sched, t4)
	assert.NoError(t, err)
	assert.False(t, active)

	// Monthly on 1st & 3rd Tuesday
	schedNth := &Schedule{
		ID:       "monthly-nth",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []ScheduleDefinition{
			{
				Type:        ScheduleTypeMonthly,
				WeekNumbers: []int{1, 3},
				DaysOfWeek:  []int{2}, // Tuesday
				AllDay:      true,
			},
		},
	}

	// Sep 1st, 2026 is 1st Tuesday (active)
	t5 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedNth, t5)
	assert.NoError(t, err)
	assert.True(t, active)

	// Sep 8th, 2026 is 2nd Tuesday (inactive)
	t6 := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedNth, t6)
	assert.NoError(t, err)
	assert.False(t, active)

	// Sep 15th, 2026 is 3rd Tuesday (active)
	t7 := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedNth, t7)
	assert.NoError(t, err)
	assert.True(t, active)
}

func TestIsScheduleActive_Annually(t *testing.T) {
	// Christmas (Dec 25th)
	schedChristmas := &Schedule{
		ID:       "annual-christmas",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []ScheduleDefinition{
			{
				Type:        ScheduleTypeAnnually,
				Months:      []int{12},
				DaysOfMonth: []int{25},
				AllDay:      true,
			},
		},
	}

	t1 := time.Date(2026, 12, 25, 12, 0, 0, 0, time.UTC)
	active, err := IsScheduleActive(schedChristmas, t1)
	assert.NoError(t, err)
	assert.True(t, active)

	t2 := time.Date(2026, 12, 24, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedChristmas, t2)
	assert.NoError(t, err)
	assert.False(t, active)

	// Thanksgiving (4th Thursday in November)
	schedThanksgiving := &Schedule{
		ID:       "annual-thanksgiving",
		Enabled:  true,
		Timezone: "UTC",
		Definitions: []ScheduleDefinition{
			{
				Type:        ScheduleTypeAnnually,
				Months:      []int{11},
				WeekNumbers: []int{4},
				DaysOfWeek:  []int{4}, // Thursday
				AllDay:      true,
			},
		},
	}

	// Nov 26, 2026 is the 4th Thursday (active)
	t3 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedThanksgiving, t3)
	assert.NoError(t, err)
	assert.True(t, active)

	// Nov 19, 2026 is the 3rd Thursday (inactive)
	t4 := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(schedThanksgiving, t4)
	assert.NoError(t, err)
	assert.False(t, active)
}

func TestIsScheduleActive_Timezones(t *testing.T) {
	// Schedule defined in America/New_York (EST/EDT) for standard work hours 09:00 - 17:00
	sched := &Schedule{
		ID:       "tz-ny-workhours",
		Enabled:  true,
		Timezone: "America/New_York",
		Definitions: []ScheduleDefinition{
			{
				Type:      ScheduleTypeDaily,
				StartTime: "09:00",
				EndTime:   "17:00",
			},
		},
	}

	// At 14:00 UTC, it is 10:00 AM America/New_York (active)
	t1 := time.Date(2026, 9, 14, 14, 0, 0, 0, time.UTC)
	active, err := IsScheduleActive(sched, t1)
	assert.NoError(t, err)
	assert.True(t, active)

	// At 22:00 UTC, it is 18:00 (6:00 PM) America/New_York (inactive)
	t2 := time.Date(2026, 9, 14, 22, 0, 0, 0, time.UTC)
	active, err = IsScheduleActive(sched, t2)
	assert.NoError(t, err)
	assert.False(t, active)
}
