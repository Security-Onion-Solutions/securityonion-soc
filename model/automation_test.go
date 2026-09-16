// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutomationTaskJSON(t *testing.T) {
	disabled := false
	created := time.Date(2026, 9, 15, 15, 3, 22, 0, time.UTC)

	task := &Automation{
		Name:            "Nightly Alert Triage",
		Kind:            "alert_triage",
		Enabled:         disabled,
		IntervalSeconds: 3600,
		Owner:           "8beae4b5-275b-4669-b678-8cff894911b5",
		Params:          json.RawMessage(`{"sampleSize":5,"query":"tags:alert"}`),
		CreateTime:      &created,
	}

	raw, err := json.Marshal(task)
	require.NoError(t, err)

	var round Automation
	require.NoError(t, json.Unmarshal(raw, &round))

	assert.Equal(t, task.Name, round.Name)
	assert.Equal(t, task.Kind, round.Kind)
	assert.Equal(t, task.IntervalSeconds, round.IntervalSeconds)
	assert.Equal(t, task.Owner, round.Owner)
	assert.False(t, round.Enabled)

	// Params is stored exactly as submitted, so a kind that changes a default
	// reaches existing tasks rather than finding its old default baked in.
	assert.JSONEq(t, string(task.Params), string(round.Params))

	assert.NotContains(t, string(raw), "updateTime")
	assert.NotContains(t, string(raw), "lastRunTime")
}

func TestAutomationKindJSON(t *testing.T) {
	kind := AutomationKindDefinition{
		Name:        "alert_triage",
		DisplayName: "Alert Triage",
		Description: "Groups, samples and triages alerts",
		ParamSchema: JSONSchema{
			Json: &ToolSchema{
				Type: "object",
				Properties: map[string]ToolSchemaProperty{
					"sample_size": {Type: "integer", Description: "Alerts sampled per group", Default: 5},
				},
				Required: []string{"sample_size"},
			},
		},
	}

	raw, err := json.Marshal(kind)
	require.NoError(t, err)

	// The JSONSchema{Json: *ToolSchema} wrapper is the surprising part of this
	// payload, so the nesting the form has to walk is pinned here.
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))

	schema, ok := decoded["paramSchema"].(map[string]any)
	require.True(t, ok)

	inner, ok := schema["json"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "object", inner["type"])

	props, ok := inner["properties"].(map[string]any)
	require.True(t, ok)

	sampleSize, ok := props["sample_size"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "integer", sampleSize["type"])
	assert.Equal(t, float64(5), sampleSize["default"])
}
