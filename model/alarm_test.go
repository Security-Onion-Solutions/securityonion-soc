// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAlarm(t *testing.T) {
	t.Run("nil alarm", func(t *testing.T) {
		err := ValidateAlarm(nil)
		assert.Error(t, err)
	})

	t.Run("empty name", func(t *testing.T) {
		a := &Alarm{
			Name:     "",
			Metric:   "cpu",
			Operator: "gt",
			Severity: "high",
		}
		err := ValidateAlarm(a)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "alarm name is required")
	})

	t.Run("name exceeds max length", func(t *testing.T) {
		a := &Alarm{
			Name:     strings.Repeat("a", MAX_ALARM_NAME_LEN+1),
			Metric:   "cpu",
			Operator: "gt",
			Severity: "high",
		}
		err := ValidateAlarm(a)
		assert.Error(t, err)
	})

	t.Run("note exceeds max length", func(t *testing.T) {
		a := &Alarm{
			Name:     "Valid Name",
			Note:     strings.Repeat("n", MAX_ALARM_NOTE_LEN+1),
			Metric:   "cpu",
			Operator: "gt",
			Severity: "high",
		}
		err := ValidateAlarm(a)
		assert.Error(t, err)
	})

	t.Run("missing metric", func(t *testing.T) {
		a := &Alarm{
			Name:     "Valid Name",
			Metric:   "",
			Operator: "gt",
			Severity: "high",
		}
		err := ValidateAlarm(a)
		assert.Error(t, err)
	})

	t.Run("invalid operator", func(t *testing.T) {
		a := &Alarm{
			Name:     "Valid Name",
			Metric:   "cpu",
			Operator: "invalid_op",
			Severity: "high",
		}
		err := ValidateAlarm(a)
		assert.Error(t, err)
	})

	t.Run("missing severity", func(t *testing.T) {
		a := &Alarm{
			Name:     "Valid Name",
			Metric:   "cpu",
			Operator: "gt",
			Severity: "",
		}
		err := ValidateAlarm(a)
		assert.Error(t, err)
	})

	t.Run("negative duration", func(t *testing.T) {
		a := &Alarm{
			Name:            "Valid Name",
			Metric:          "cpu",
			Operator:        "gt",
			Severity:        "high",
			DurationSeconds: -10,
		}
		err := ValidateAlarm(a)
		assert.Error(t, err)
	})

	t.Run("valid alarm", func(t *testing.T) {
		a := &Alarm{
			Name:            "CPU Alert",
			Metric:          "cpu",
			Operator:        "gt",
			Threshold:       "80",
			DurationSeconds: 120,
			Severity:        "high",
			ClearedSeverity: "info",
			Destinations:    []string{"soc-bell"},
			Recipients:      []string{"admin"},
			Note:            "High CPU load detected",
		}
		err := ValidateAlarm(a)
		assert.NoError(t, err)
	})
}

func TestNormalizeOperator(t *testing.T) {
	assert.Equal(t, AlarmOperatorGT, NormalizeOperator(">"))
	assert.Equal(t, AlarmOperatorGT, NormalizeOperator("gt"))
	assert.Equal(t, AlarmOperatorGTE, NormalizeOperator(">="))
	assert.Equal(t, AlarmOperatorGTE, NormalizeOperator("gte"))
	assert.Equal(t, AlarmOperatorLT, NormalizeOperator("<"))
	assert.Equal(t, AlarmOperatorLT, NormalizeOperator("lt"))
	assert.Equal(t, AlarmOperatorLTE, NormalizeOperator("<="))
	assert.Equal(t, AlarmOperatorLTE, NormalizeOperator("lte"))
	assert.Equal(t, AlarmOperatorEQ, NormalizeOperator("=="))
	assert.Equal(t, AlarmOperatorEQ, NormalizeOperator("="))
	assert.Equal(t, AlarmOperatorEQ, NormalizeOperator("eq"))
	assert.Equal(t, AlarmOperatorNEQ, NormalizeOperator("!="))
	assert.Equal(t, AlarmOperatorNEQ, NormalizeOperator("<>"))
	assert.Equal(t, AlarmOperatorNEQ, NormalizeOperator("ne"))
	assert.Equal(t, AlarmOperatorContains, NormalizeOperator("contains"))
}

func TestIsValidAlarmID(t *testing.T) {
	assert.True(t, IsValidAlarmID("abc-123_456.789"))
	assert.False(t, IsValidAlarmID(""))
	assert.False(t, IsValidAlarmID("invalid id with spaces"))
	assert.False(t, IsValidAlarmID(strings.Repeat("a", MAX_ALARM_ID_LEN+1)))
}

func TestUnmarshalAlarms(t *testing.T) {
	alarms, err := UnmarshalAlarms("")
	assert.NoError(t, err)
	assert.Empty(t, alarms)

	raw := `[{"id":"1","name":"Alarm 1","metric":"cpu","operator":"gt","threshold":"80","severity":"high"}]`
	alarms, err = UnmarshalAlarms(raw)
	assert.NoError(t, err)
	assert.Len(t, alarms, 1)
	assert.Equal(t, "Alarm 1", alarms[0].Name)

	_, err = UnmarshalAlarms("invalid json")
	assert.Error(t, err)
}
