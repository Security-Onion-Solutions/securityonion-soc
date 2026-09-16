// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"time"
)

// AutomationKindDefinition is one registered automation type as published to the browser.
// The backend owns the catalog; the Agent Studio renders ParamSchema as the "new
// automation" form in addition to name and interval fields.
type AutomationKindDefinition struct {
	Name        string     `json:"name" example:"alert_triage"`
	DisplayName string     `json:"displayName" example:"Alert Triage"`
	Description string     `json:"description" example:"Groups, samples and triages alerts"`
	ParamSchema JSONSchema `json:"paramSchema"`
}

// Automation is one scheduled automation, as persisted and as sent to the task
// save endpoint. Params is opaque here: only the named kind can validate it.
type Automation struct {
	Name            string `json:"name" example:"Nightly Alert Triage"`
	Kind            string `json:"kind" example:"alert_triage"`
	Enabled         bool   `json:"enabled" example:"true"`
	IntervalSeconds int    `json:"intervalSeconds" example:"300"`
	// The user each run's sessions execute as, so unattended tool calls carry that
	// user's RBAC
	Owner       string          `json:"owner" example:"8beae4b5-275b-4669-b678-8cff894911b5"`
	Params      json.RawMessage `json:"params" swaggertype:"object"`
	CreateTime  *time.Time      `json:"createTime,omitempty" example:"2026-09-15T15:03:22Z"`
	UpdateTime  *time.Time      `json:"updateTime,omitempty" example:"2026-09-15T15:33:02Z"`
	LastRunTime *time.Time      `json:"lastRunTime,omitempty" example:"2026-09-15T16:03:02Z"`
}
