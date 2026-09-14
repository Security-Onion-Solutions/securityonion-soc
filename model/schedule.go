// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"time"
)

const (
	ScheduleTypeDaily    = "daily"
	ScheduleTypeWeekly   = "weekly"
	ScheduleTypeMonthly  = "monthly"
	ScheduleTypeAnnually = "annually"
)

// @Description ScheduleDefinition represents a single recurrence definition within a schedule.
type ScheduleDefinition struct {
	// The type of recurrence: daily, weekly, monthly, annually
	Type string `json:"type" example:"weekly"`
	// Start time in HH:MM format (24-hour, e.g. "08:00")
	StartTime string `json:"startTime,omitempty" example:"08:00"`
	// End time in HH:MM format (24-hour, e.g. "17:00")
	EndTime string `json:"endTime,omitempty" example:"17:00"`
	// If true, the schedule is active all day (00:00-24:00)
	AllDay bool `json:"allDay,omitempty" example:"false"`
	// For weekly/monthly schedules: days of the week (0=Sunday, 1=Monday, ..., 6=Saturday)
	DaysOfWeek []int `json:"daysOfWeek,omitempty" example:"[1,2,3,4,5]"`
	// For monthly/annually schedules: days of the month (1-31, -1 for last day of month)
	DaysOfMonth []int `json:"daysOfMonth,omitempty" example:"[1,15,-1]"`
	// For monthly/annually schedules: week numbers within the month (1, 2, 3, 4, 5, -1 for last occurrence)
	WeekNumbers []int `json:"weekNumbers,omitempty" example:"[1,3]"`
	// For annual schedules: month numbers (1=January, ..., 12=December)
	Months []int `json:"months,omitempty" example:"[12]"`
}

// @Description Schedule represents a reusable activation schedule.
type Schedule struct {
	// Unique identifier for the schedule
	ID string `json:"id" example:"after-hours-and-weekends"`
	// Human-readable name
	Name string `json:"name" example:"After Hours & Weekends"`
	// Description of the schedule
	Description string `json:"description,omitempty" example:"Mon-Fri 17:00-08:00 and all day Saturday and Sunday"`
	// Indicates whether the schedule is active/enabled
	Enabled bool `json:"enabled" example:"true"`
	// IANA timezone identifier, e.g. "America/New_York" or "UTC"
	Timezone string `json:"timezone" example:"America/New_York"`
	// Array of recurrence definitions
	Definitions []ScheduleDefinition `json:"definitions"`
}

// IsScheduleActive evaluates if the given schedule is active at the specified UTC time.
// 1. Disabled / Nil Guard: If schedule == nil or len(Definitions) == 0, returns true.
//    If !schedule.Enabled, returns false.
// 2. Timezone Conversion: Converts utcNow into schedule.Timezone (fallback to UTC on error).
// 3. OR Logic Across Definitions: If any definition matches, returns true.
func IsScheduleActive(schedule *Schedule, utcNow time.Time) (bool, error) {
	if schedule == nil || len(schedule.Definitions) == 0 {
		return true, nil
	}

	if !schedule.Enabled {
		return false, nil
	}

	loc, err := time.LoadLocation(schedule.Timezone)
	if err != nil {
		loc = time.UTC
	}

	localTime := utcNow.In(loc)

	for _, def := range schedule.Definitions {
		if isDefinitionActive(def, localTime) {
			return true, nil
		}
	}

	return false, nil
}

func isDefinitionActive(def ScheduleDefinition, t time.Time) bool {
	currentStr := t.Format("15:04")

	// Check if overnight window crossing midnight (e.g. 22:00 to 06:00)
	isOvernight := !def.AllDay && def.StartTime != "" && def.EndTime != "" && def.StartTime > def.EndTime

	if isOvernight {
		// Active today (matches recurrence) from StartTime to 24:00 (represented as currentStr >= StartTime)
		if matchesDay(def, t) && currentStr >= def.StartTime {
			return true
		}
		// Active yesterday (matches recurrence) from 00:00 to EndTime (represented as currentStr < EndTime)
		yesterday := t.AddDate(0, 0, -1)
		if matchesDay(def, yesterday) && currentStr < def.EndTime {
			return true
		}
		return false
	}

	// Standard window (or AllDay)
	if !matchesDay(def, t) {
		return false
	}
	if def.AllDay {
		return true
	}
	if def.StartTime == "" || def.EndTime == "" {
		return false
	}
	return currentStr >= def.StartTime && currentStr < def.EndTime
}

func matchesDay(def ScheduleDefinition, t time.Time) bool {
	switch def.Type {
	case ScheduleTypeDaily:
		return true

	case ScheduleTypeWeekly:
		return sliceContains(def.DaysOfWeek, int(t.Weekday()))

	case ScheduleTypeMonthly:
		return matchesMonthlyRecurrence(def, t)

	case ScheduleTypeAnnually:
		if !sliceContains(def.Months, int(t.Month())) {
			return false
		}
		if len(def.DaysOfMonth) == 0 && len(def.WeekNumbers) == 0 {
			return true
		}
		return matchesMonthlyRecurrence(def, t)

	default:
		return false
	}
}

func matchesMonthlyRecurrence(def ScheduleDefinition, t time.Time) bool {
	if len(def.DaysOfMonth) > 0 {
		for _, dom := range def.DaysOfMonth {
			if dom == t.Day() {
				return true
			}
			if dom == -1 {
				// Last day of month: adding 1 day changes the month
				if t.AddDate(0, 0, 1).Month() != t.Month() {
					return true
				}
			}
		}
	}

	if len(def.WeekNumbers) > 0 && len(def.DaysOfWeek) > 0 {
		if sliceContains(def.DaysOfWeek, int(t.Weekday())) {
			nth := (t.Day()-1)/7 + 1
			isLast := t.AddDate(0, 0, 7).Month() != t.Month()
			for _, wn := range def.WeekNumbers {
				if wn == nth || (wn == -1 && isLast) {
					return true
				}
			}
		}
	}

	return false
}

func sliceContains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
