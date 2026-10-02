// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	MAX_ALARM_ID_LEN        = 64
	MAX_ALARM_NAME_LEN      = 100
	MAX_ALARM_NOTE_LEN      = 1000
	MAX_ALARM_THRESHOLD_LEN = 100

	AlarmOperatorGT       = "gt"
	AlarmOperatorGTE      = "gte"
	AlarmOperatorLT       = "lt"
	AlarmOperatorLTE      = "lte"
	AlarmOperatorEQ       = "eq"
	AlarmOperatorNEQ      = "ne"
	AlarmOperatorContains = "contains"

	AlarmStatusOk     = "ok"
	AlarmStatusActive = "alarm"

	AlarmMetricTypeNumeric = "numeric"
	AlarmMetricTypeString  = "string"
	AlarmMetricTypeBool    = "bool"

	AlarmMetricScopeNode      = "node"
	AlarmMetricScopeContainer = "container"
)

var alarmIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// IsValidAlarmID validates that an alarm ID contains safe characters and within maximum length.
func IsValidAlarmID(id string) bool {
	return id != "" && len(id) <= MAX_ALARM_ID_LEN && alarmIDRegex.MatchString(id)
}

// ValidateAlarmName checks that the alarm name is present and within allowed limits.
func ValidateAlarmName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("alarm name is required")
	}
	if len(trimmed) > MAX_ALARM_NAME_LEN {
		return errors.New("alarm name exceeds maximum allowed length")
	}
	return nil
}

// ValidateAlarmNote checks that the note does not exceed length limits.
func ValidateAlarmNote(note string) error {
	if len(note) > MAX_ALARM_NOTE_LEN {
		return errors.New("alarm note exceeds maximum allowed length")
	}
	return nil
}

// ValidateAlarmThreshold checks that the threshold is non-empty and within length limits.
func ValidateAlarmThreshold(threshold string) error {
	trimmed := strings.TrimSpace(threshold)
	if trimmed == "" {
		return errors.New("alarm threshold is required")
	}
	if len(trimmed) > MAX_ALARM_THRESHOLD_LEN {
		return errors.New("alarm threshold exceeds maximum allowed length")
	}
	return nil
}

// ValidateAlarm validates all required fields and constraints on an Alarm.
func ValidateAlarm(alarm *Alarm) error {
	if alarm == nil {
		return errors.New("alarm cannot be nil")
	}
	if err := ValidateAlarmName(alarm.Name); err != nil {
		return err
	}
	if err := ValidateAlarmNote(alarm.Note); err != nil {
		return err
	}
	if strings.TrimSpace(alarm.Metric) == "" {
		return errors.New("alarm metric is required")
	}
	if !IsValidAlarmOperator(alarm.Operator) {
		return errors.New("invalid alarm operator")
	}
	if err := ValidateAlarmThreshold(alarm.Threshold); err != nil {
		return err
	}
	if strings.TrimSpace(alarm.Severity) == "" {
		return errors.New("alarm severity is required")
	}
	if alarm.DurationSeconds < 0 {
		return errors.New("alarm duration cannot be negative")
	}
	return nil
}

// IsValidAlarmOperator validates that the operator is one of the supported operators.
func IsValidAlarmOperator(op string) bool {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case AlarmOperatorGT, AlarmOperatorGTE, AlarmOperatorLT, AlarmOperatorLTE,
		AlarmOperatorEQ, AlarmOperatorNEQ, AlarmOperatorContains,
		">", ">=", "<", "<=", "==", "!=":
		return true
	default:
		return false
	}
}

// NormalizeOperator returns standard operator identifier.
func NormalizeOperator(op string) string {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case ">", AlarmOperatorGT:
		return AlarmOperatorGT
	case ">=", AlarmOperatorGTE:
		return AlarmOperatorGTE
	case "<", AlarmOperatorLT:
		return AlarmOperatorLT
	case "<=", AlarmOperatorLTE:
		return AlarmOperatorLTE
	case "==", "=", AlarmOperatorEQ:
		return AlarmOperatorEQ
	case "!=", "<>", AlarmOperatorNEQ:
		return AlarmOperatorNEQ
	case AlarmOperatorContains:
		return AlarmOperatorContains
	default:
		return strings.ToLower(strings.TrimSpace(op))
	}
}

// @Description Alarm defines the configuration for a metric alarm.
type Alarm struct {
	// Unique identifier assigned by the server.
	ID string `json:"id" example:"a1b2c3d4-e5f6-7890-abcd-ef1234567890"`
	// Human-readable display name for this alarm (required, max 100 characters).
	Name string `json:"name" example:"High CPU Usage"`
	// Indicates whether this alarm is actively evaluated.
	Enabled bool `json:"enabled" example:"true"`
	// Optional node ID to scope this alarm to. If empty or "all", applies across all grid nodes.
	NodeID string `json:"nodeId,omitempty" example:"sensor-01"`
	// Metric identifier to evaluate (e.g. cpu, memory, disk, load, process_status).
	Metric string `json:"metric" example:"cpu"`
	// Optional sub-key or field name within the metric (e.g. cpu_used, disk_used_root).
	MetricKey string `json:"metricKey,omitempty" example:"cpu_used"`
	// Comparison operator (gt, gte, lt, lte, eq, ne, contains).
	Operator string `json:"operator" example:"gt"`
	// Threshold value for comparison (numeric, string, or boolean).
	Threshold string `json:"threshold" example:"80"`
	// Duration in seconds the condition must persist before triggering an alarm.
	DurationSeconds int `json:"durationSeconds" example:"120"`
	// Severity level when the alarm triggers (info, low, medium, high, critical).
	Severity string `json:"severity" example:"high"`
	// Optional severity level for alarm cleared notification. Set to "none" or empty to suppress cleared notifications.
	ClearedSeverity string `json:"clearedSeverity,omitempty" example:"info"`
	// Optional destination IDs to dispatch to. If empty, uses system notification routing.
	Destinations []string `json:"destinations,omitempty" example:"soc-bell"`
	// Optional user recipient IDs. If empty, broadcasts according to system routing.
	Recipients []string `json:"recipients,omitempty" example:"user-1"`
	// Optional user note included as notification summary.
	Note string `json:"note,omitempty" example:"Sensor node CPU exceeded critical threshold."`
}

// @Description AlarmState represents the live persisted state of an alarm evaluation.
type AlarmState struct {
	// Alarm identifier.
	AlarmID string `json:"alarmId" example:"a1b2c3d4-e5f6-7890-abcd-ef1234567890"`
	// Grid node identifier.
	NodeID string `json:"nodeId" example:"sensor-01"`
	// Current state status: 'ok' or 'alarm'.
	Status string `json:"status" example:"alarm"`
	// Most recently evaluated metric value.
	CurrentValue string `json:"currentValue" example:"85.4"`
	// Configured threshold value.
	Threshold string `json:"threshold" example:"80"`
	// Comparison operator.
	Operator string `json:"operator" example:"gt"`
	// Metric identifier.
	Metric string `json:"metric" example:"cpu"`
	// Metric sub-key.
	MetricKey string `json:"metricKey,omitempty" example:"cpu_used"`
	// Timestamp when alarm condition was first triggered.
	TriggeredAt *time.Time `json:"triggeredAt,omitempty"`
	// Timestamp when alarm condition cleared.
	ClearedAt *time.Time `json:"clearedAt,omitempty"`
	// Timestamp when condition first breached (for duration tracking).
	FirstBreachedAt *time.Time `json:"firstBreachedAt,omitempty"`
	// Total duration in seconds the alarm has been active.
	DurationActiveSeconds int `json:"durationActiveSeconds,omitempty"`
	// Timestamp when alarm was last evaluated.
	LastEvaluated time.Time `json:"lastEvaluated"`
	// Timestamp of last record update.
	UpdatedAt time.Time `json:"updatedAt"`
}

// @Description AlarmMetricInfo provides metadata for an available grid metric datapoint.
type AlarmMetricInfo struct {
	// Metric identifier.
	Metric string `json:"metric" example:"cpu"`
	// Localization key for the metric title.
	TitleKey string `json:"titleKey,omitempty" example:"metricsCpuUsage"`
	// Available sub-keys or field names for this metric.
	Keys []string `json:"keys" example:"cpu_used"`
	// Localization keys for the sub-keys.
	LabelKeys []string `json:"labelKeys,omitempty" example:"cpuUsageAbbr"`
	// Datapoint data type: 'numeric', 'string', 'bool'.
	Type string `json:"type" example:"numeric"`
	// Unit of measurement: 'percent', 'bytes', 'seconds', etc.
	Units string `json:"units,omitempty" example:"percent"`
	// Scope of the metric: 'node' or 'container'.
	Scope string `json:"scope,omitempty" example:"node"`
}

// UnmarshalAlarms parses a JSON array string into an Alarm slice.
func UnmarshalAlarms(raw string) ([]Alarm, error) {
	if strings.TrimSpace(raw) == "" {
		return []Alarm{}, nil
	}
	var alarms []Alarm
	if err := json.Unmarshal([]byte(raw), &alarms); err != nil {
		return nil, err
	}
	return alarms, nil
}
