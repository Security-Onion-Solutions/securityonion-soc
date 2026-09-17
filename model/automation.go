// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"encoding/json"
	"time"
)

// @Description One type of automation this grid can run, and the schema of the settings it accepts.
type AutomationKindDefinition struct {
	// The stable identifier for this kind, recorded on every automation that runs it.
	Name string `json:"name" example:"alert_triage"`
	// The label shown when choosing a kind.
	DisplayName string `json:"displayName" example:"Alert Triage"`
	// A summary of what this kind does, shown alongside the label.
	Description string `json:"description" example:"Groups, samples and triages alerts"`
	// The settings this kind accepts, one property per form field. Name, interval and
	// owner belong to the automation rather than the kind, so they are absent here.
	ParamSchema JSONSchema `json:"paramSchema"`
}

// @Description A task the grid runs on a schedule, with an agent doing the work and no user driving it.
type Automation struct {
	// The unique name of this automation.
	Name string `json:"name" example:"Nightly Alert Triage"`
	// The kind that runs this automation. Fixed once created, since the params are
	// only meaningful to the kind that validated them.
	Kind string `json:"kind" example:"alert_triage"`
	// Indicates whether the scheduler runs this automation.
	Enabled bool `json:"enabled" example:"true"`
	// How often this automation comes due, in seconds.
	IntervalSeconds int `json:"intervalSeconds" example:"300"`
	// The user each run's sessions execute as, so unattended tool calls carry that
	// user's RBAC.
	Owner string `json:"owner" example:"8beae4b5-275b-4669-b678-8cff894911b5"`
	// The settings for this automation, matching its kind's paramSchema. Opaque to
	// everything but that kind.
	Params json.RawMessage `json:"params" swaggertype:"object"`
	// The time this automation was created.
	CreateTime *time.Time `json:"createTime,omitempty" example:"2026-09-15T15:03:22Z"`
	// The time this automation was last modified.
	UpdateTime *time.Time `json:"updateTime,omitempty" example:"2026-09-15T15:33:02Z"`
	// The time this automation last finished a run; absent until the first run ends.
	LastRunTime *time.Time `json:"lastRunTime,omitempty" example:"2026-09-15T16:03:02Z"`
}
