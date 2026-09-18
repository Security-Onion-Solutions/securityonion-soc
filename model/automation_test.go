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
	created := time.Date(2026, 9, 15, 15, 3, 22, 0, time.UTC)

	automation := &Automation{
		Auditable: Auditable{
			Id:         "5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90",
			UserId:     "8beae4b5-275b-4669-b678-8cff894911b5",
			CreateTime: &created,
		},
		DisplayName:     "Nightly Alert Triage",
		AutomationKind:  "alert_triage",
		Enabled:         false,
		IntervalSeconds: 3600,
		Params:          json.RawMessage(`{"sampleSize":5,"query":"tags:alert"}`),
	}

	raw, err := json.Marshal(automation)
	require.NoError(t, err)

	var round Automation
	require.NoError(t, json.Unmarshal(raw, &round))

	assert.Equal(t, automation.Id, round.Id)
	assert.Equal(t, "Nightly Alert Triage", round.DisplayName)
	assert.Equal(t, automation.UserId, round.UserId)
	assert.Equal(t, automation.IntervalSeconds, round.IntervalSeconds)
	assert.False(t, round.Enabled)

	// AutomationKind must not collide with Auditable.Kind, which is the entity kind.
	assert.Equal(t, "alert_triage", round.AutomationKind)
	assert.Contains(t, string(raw), `"automationKind":"alert_triage"`)

	// Params is stored exactly as submitted, so a kind that changes a default
	// reaches existing automations rather than finding its old default baked in.
	assert.JSONEq(t, string(automation.Params), string(round.Params))

	// An automation that has never been edited carries no updateTime; last run is derived
	// from the run history rather than stored, so it is not a field at all.
	assert.NotContains(t, string(raw), "updateTime")
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
