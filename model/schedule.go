// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

const (
	ScheduleTypeDaily    = "daily"
	ScheduleTypeWeekly   = "weekly"
	ScheduleTypeMonthly  = "monthly"
	ScheduleTypeAnnually = "annually"

	MAX_SCHEDULE_ID_LEN          = 40
	MAX_SCHEDULE_NAME_LEN        = 50
	MAX_SCHEDULE_DESCRIPTION_LEN = 1000
)

var scheduleIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// IsValidScheduleID validates that a schedule ID contains only safe alphanumeric, underscore, hyphen, or dot characters and does not exceed the maximum allowed length.
func IsValidScheduleID(id string) bool {
	return id != "" && len(id) <= MAX_SCHEDULE_ID_LEN && scheduleIDRegex.MatchString(id)
}

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
	// Unique identifier for the schedule (max 40 characters)
	ID string `json:"id" example:"after-hours-and-weekends"`
	// Human-readable name (max 50 characters)
	Name string `json:"name" example:"After Hours & Weekends"`
	// Description of the schedule (max 1000 characters)
	Description string `json:"description,omitempty" example:"Mon-Fri 17:00-08:00 and all day Saturday and Sunday"`
	// Indicates whether the schedule is active/enabled
	Enabled bool `json:"enabled" example:"true"`
	// IANA timezone identifier, e.g. "America/New_York" or "UTC"
	Timezone string `json:"timezone" example:"America/New_York"`
	// Array of recurrence definitions
	Definitions []ScheduleDefinition `json:"definitions"`
	// Array of schedule IDs to exclude (exception/blackout schedules)
	ExcludeScheduleIDs []string `json:"excludeScheduleIds,omitempty"`
}

// BuildScheduleLookup constructs a map of Schedule ID -> *Schedule from a slice of schedules.
func BuildScheduleLookup(schedules []Schedule) map[string]*Schedule {
	lookup := make(map[string]*Schedule, len(schedules))
	for i := range schedules {
		lookup[schedules[i].ID] = &schedules[i]
	}
	return lookup
}

// ValidateScheduleName verifies that the given schedule name is not empty or pure whitespace and does not exceed the maximum allowed length.
func ValidateScheduleName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("schedule name cannot be empty")
	}
	if len(name) > MAX_SCHEDULE_NAME_LEN {
		return errors.New("schedule name exceeds maximum allowed length")
	}
	return nil
}

// ValidateScheduleDescription verifies that the schedule description does not exceed the maximum allowed length.
func ValidateScheduleDescription(description string) error {
	if len(description) > MAX_SCHEDULE_DESCRIPTION_LEN {
		return errors.New("schedule description exceeds maximum allowed length")
	}
	return nil
}

// SanitizeScheduleDAG inspects a slice of schedules and returns a sanitized copy
// where any self-references, non-existent schedule references, or circular dependencies
// are automatically resolved by dropping the offending exclusion edge that introduces the cycle.
func SanitizeScheduleDAG(schedules []Schedule) []Schedule {
	if len(schedules) == 0 {
		return []Schedule{}
	}

	result := make([]Schedule, len(schedules))
	copy(result, schedules)

	// Map of schedule ID existence
	existingIDs := make(map[string]bool, len(schedules))
	for _, s := range schedules {
		existingIDs[s.ID] = true
	}

	// Adjacency graph of accepted valid edges
	validGraph := make(map[string][]string, len(schedules))
	for _, s := range schedules {
		validGraph[s.ID] = []string{}
	}

	// Helper: check if toID can reach fromID in the current validGraph
	canReach := func(fromID, toID string) bool {
		visited := make(map[string]bool)
		var dfs func(curr string) bool
		dfs = func(curr string) bool {
			if curr == toID {
				return true
			}
			if visited[curr] {
				return false
			}
			visited[curr] = true
			for _, neighbor := range validGraph[curr] {
				if dfs(neighbor) {
					return true
				}
			}
			return false
		}
		return dfs(fromID)
	}

	for i := range result {
		cleanedExcludes := make([]string, 0, len(result[i].ExcludeScheduleIDs))
		for _, excludeID := range result[i].ExcludeScheduleIDs {
			// 1. Drop self references
			if excludeID == result[i].ID {
				continue
			}
			// 2. Drop references to non-existent schedules
			if !existingIDs[excludeID] {
				continue
			}
			// 3. Drop edge if excludeID can already reach result[i].ID (which would complete a cycle)
			if canReach(excludeID, result[i].ID) {
				continue
			}

			cleanedExcludes = append(cleanedExcludes, excludeID)
			validGraph[result[i].ID] = append(validGraph[result[i].ID], excludeID)
		}
		result[i].ExcludeScheduleIDs = cleanedExcludes
	}

	return result
}

// ValidateScheduleDAG verifies that the given target schedule (and its exclusions)
// does not introduce any direct or indirect circular dependencies among allSchedules.
func ValidateScheduleDAG(target *Schedule, allSchedules []Schedule) error {
	if target == nil {
		return nil
	}

	graph := make(map[string][]string)
	for _, s := range allSchedules {
		if s.ID == target.ID {
			graph[s.ID] = target.ExcludeScheduleIDs
		} else {
			graph[s.ID] = s.ExcludeScheduleIDs
		}
	}
	if _, exists := graph[target.ID]; !exists {
		graph[target.ID] = target.ExcludeScheduleIDs
	}

	// 1. Direct self-reference check
	for nodeID, neighbors := range graph {
		for _, neighborID := range neighbors {
			if nodeID == neighborID {
				return errors.New("schedule cannot exclude itself: " + nodeID)
			}
		}
	}

	// 2. Transitive cycle detection (DFS with 3-color state)
	visited := make(map[string]int) // 0 = unvisited, 1 = visiting (in stack), 2 = visited

	var checkCycle func(nodeID string, path []string) error
	checkCycle = func(nodeID string, path []string) error {
		visited[nodeID] = 1
		currentPath := append(path, nodeID)

		for _, neighborID := range graph[nodeID] {
			if visited[neighborID] == 1 {
				cycleStr := ""
				for _, p := range currentPath {
					cycleStr += p + " -> "
				}
				cycleStr += neighborID
				return errors.New("circular schedule dependency detected: " + cycleStr)
			}
			if visited[neighborID] == 0 {
				if err := checkCycle(neighborID, currentPath); err != nil {
					return err
				}
			}
		}

		visited[nodeID] = 2
		return nil
	}

	for id := range graph {
		if visited[id] == 0 {
			if err := checkCycle(id, nil); err != nil {
				return err
			}
		}
	}

	return nil
}

// IsScheduleActive evaluates if the given schedule is active at the specified UTC time.
// 1. Disabled / Nil Guard: If schedule == nil or (len(Definitions) == 0 and len(ExcludeScheduleIDs) == 0), returns true.
//    If !schedule.Enabled, returns false.
// 2. Timezone Conversion: Converts utcNow into schedule.Timezone (fallback to UTC on error).
// 3. OR Logic Across Definitions: If any definition matches, base schedule is active.
// 4. Exception / Exclusion Evaluation: If base schedule is active, evaluates ExcludeScheduleIDs.
//    If any enabled exclusion schedule is active at utcNow, returns false.
// Optional lookup map can be provided to resolve ExcludeScheduleIDs.
func IsScheduleActive(schedule *Schedule, utcNow time.Time, lookup ...map[string]*Schedule) (bool, error) {
	var allSchedules map[string]*Schedule
	if len(lookup) > 0 && lookup[0] != nil {
		allSchedules = lookup[0]
	}
	return isScheduleActiveRecursive(schedule, allSchedules, utcNow, make(map[string]bool))
}

func isScheduleActiveRecursive(schedule *Schedule, allSchedules map[string]*Schedule, utcNow time.Time, visited map[string]bool) (bool, error) {
	if schedule == nil {
		return true, nil
	}

	if !schedule.Enabled {
		return false, nil
	}

	// Prevent circular recursion if a cycle exists at runtime
	if visited[schedule.ID] {
		return false, nil
	}
	visited[schedule.ID] = true

	// If no definitions and no exclusions, schedule is always active
	if len(schedule.Definitions) == 0 && len(schedule.ExcludeScheduleIDs) == 0 {
		return true, nil
	}

	baseActive := len(schedule.Definitions) == 0 // if no definitions, base is active unless suppressed
	if len(schedule.Definitions) > 0 {
		loc, err := time.LoadLocation(schedule.Timezone)
		if err != nil {
			loc = time.UTC
		}

		localTime := utcNow.In(loc)

		for _, def := range schedule.Definitions {
			if isDefinitionActive(def, localTime) {
				baseActive = true
				break
			}
		}
	}

	if !baseActive {
		return false, nil
	}

	// Base is active; check if suppressed by any exclusion schedule
	if len(schedule.ExcludeScheduleIDs) > 0 && allSchedules != nil {
		for _, excludeID := range schedule.ExcludeScheduleIDs {
			if excludeSched, exists := allSchedules[excludeID]; exists && excludeSched != nil {
				// Copy visited map for branch isolation
				visitedCopy := make(map[string]bool, len(visited))
				for k, v := range visited {
					visitedCopy[k] = v
				}

				excludedActive, err := isScheduleActiveRecursive(excludeSched, allSchedules, utcNow, visitedCopy)
				if err == nil && excludedActive {
					return false, nil // Suppressed by active exclusion schedule
				}
			}
		}
	}

	return true, nil
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

// UnmarshalSchedules parses a schedule string (JSON array, JSON object, or newline-delimited JSON objects)
// into a slice of sanitized Schedule structs.
func UnmarshalSchedules(val string) ([]Schedule, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return []Schedule{}, nil
	}

	var schedules []Schedule

	// 1. Try standard JSON array format
	if strings.HasPrefix(val, "[") {
		if err := json.Unmarshal([]byte(val), &schedules); err == nil {
			return SanitizeScheduleDAG(schedules), nil
		}
	}

	// 2. Try newline-delimited JSON objects (produced when loaded from YAML pillars)
	lines := strings.Split(val, "\n")
	schedules = nil
	allLinesParsed := true
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var s Schedule
		if err := json.Unmarshal([]byte(line), &s); err == nil {
			schedules = append(schedules, s)
		} else {
			allLinesParsed = false
			break
		}
	}
	if allLinesParsed && len(schedules) > 0 {
		return SanitizeScheduleDAG(schedules), nil
	}

	// 3. Try single JSON object
	var single Schedule
	if err := json.Unmarshal([]byte(val), &single); err == nil {
		return SanitizeScheduleDAG([]Schedule{single}), nil
	}

	return nil, errors.New("invalid schedule format: unable to parse JSON")
}

// IsScheduleIDActive evaluates whether the schedule identified by scheduleID is active at evalTime
// given a slice of available schedules. If scheduleID is empty, it returns (true, true).
// If scheduleID is missing or corrupt, it fails open and returns (true, false) so notifications are not dropped.
func IsScheduleIDActive(schedules []Schedule, scheduleID string, evalTime time.Time) (active bool, found bool) {
	if scheduleID == "" {
		return true, true
	}
	lookup := BuildScheduleLookup(schedules)
	sched, exists := lookup[scheduleID]
	if !exists {
		return true, false
	}
	isActive, err := IsScheduleActive(sched, evalTime, lookup)
	if err != nil {
		return true, true
	}
	return isActive, true
}
