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
	// The settings this kind accepts, one property per form field. Interval and owning
	// user belong to the automation rather than the kind, so they are absent here.
	ParamSchema JSONSchema `json:"paramSchema"`
}

// @Description A task the grid runs on a schedule, with an agent doing the work and no user driving it.
type Automation struct {
	Auditable
	// What this automation is called in the UI.
	DisplayName string `json:"displayName" example:"Nightly Alert Triage"`
	// The kind that runs this automation.
	AutomationKind string `json:"automationKind" example:"alert_triage"`
	// Indicates whether the scheduler runs this automation.
	Enabled bool `json:"enabled" example:"true"`
	// How often this automation comes due, in seconds.
	IntervalSeconds int `json:"intervalSeconds" example:"300"`
	// The settings for this automation, matching its kind's paramSchema. Opaque to
	// everything but that kind.
	Params json.RawMessage `json:"params" swaggertype:"object"`
}

// AutomationRunState is the lifecycle of one run.
type AutomationRunState string

const (
	// Unwritten today, but inside the in-flight index predicate so a run admitted before
	// it executes still blocks a second run of the same automation.
	AutomationRunQueued    AutomationRunState = "queued"
	AutomationRunRunning   AutomationRunState = "running"
	AutomationRunSucceeded AutomationRunState = "succeeded"
	AutomationRunFailed    AutomationRunState = "failed"
)

// IsTerminal reports whether this state indicates the automation has completed.
func (s AutomationRunState) IsTerminal() bool {
	return s == AutomationRunSucceeded || s == AutomationRunFailed
}

// AutomationWorkItemState is the lifecycle of one unit of automation work.
type AutomationWorkItemState string

const (
	AutomationWorkItemPending  AutomationWorkItemState = "pending"
	AutomationWorkItemRunning  AutomationWorkItemState = "running"
	AutomationWorkItemApplying AutomationWorkItemState = "applying"
	AutomationWorkItemDone     AutomationWorkItemState = "done"
	AutomationWorkItemFailed   AutomationWorkItemState = "failed"
)

// IsTerminal reports whether this item is finished.
func (s AutomationWorkItemState) IsTerminal() bool {
	return s == AutomationWorkItemDone || s == AutomationWorkItemFailed
}

// @Description One execution of one automation: opened before its kind runs, closed when it stops.
type AutomationRunRecord struct {
	// The unique id of this run, stamped on the sessions it creates.
	Id string `json:"id" example:"3f1a7c0e-9b21-4d8a-bc55-2e77a1f0c934"`
	// The automation this run belongs to.
	AutomationId string `json:"automationId" example:"5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90"`
	// The current state of this run.
	State AutomationRunState `json:"state" example:"running"`
	// The time this run started.
	StartTime *time.Time `json:"startTime,omitempty" example:"2026-09-15T16:00:02Z"`
	// The time this run stopped; absent while it is in flight.
	EndTime *time.Time `json:"endTime,omitempty" example:"2026-09-15T16:03:02Z"`
	// Why this run failed; absent unless it did.
	Error string `json:"error,omitempty"`
}

// @Description One unit of work inside an automation: what a kind enqueues, claims, runs a session for, and applies the outcome of.
type AutomationWorkItem struct {
	// The unique id of this work item.
	Id string `json:"id" example:"8c2e5b91-4a03-47f6-9d18-6b0e2c7d4a15"`
	// The automation this item belongs to.
	AutomationId string `json:"automationId" example:"5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90"`
	// The run that last worked this item: the one that enqueued it until another claims
	// it. Absent once that run is gone; items outlive their runs so a later run can
	// finish them.
	RunId string `json:"runId,omitempty"`
	// Identifies what this item is about, in whatever terms its kind uses. Only one item
	// per group is ever in flight.
	GroupKey string `json:"groupKey" example:"rule.name:Suspicious PowerShell"`
	// The kind's description of the work. Opaque to everything but that kind.
	Payload json.RawMessage `json:"payload" swaggertype:"object"`
	// The current state of this item.
	State AutomationWorkItemState `json:"state" example:"pending"`
	// How many times this item has been claimed, including attempts that died with the
	// process. Bounds retries so a payload that cannot succeed stops being retried.
	Attempts int `json:"attempts" example:"1"`
	// One root session per attempt, in attempt order. Each root reaches its own delegated
	// children.
	SessionIds []string `json:"sessionIds,omitempty"`
	// The kind's conclusion, stored in the same statement that moves the item to applying,
	// so a process that dies after that point resumes at the apply step.
	Result json.RawMessage `json:"result,omitempty" swaggertype:"object"`
	// Why this item failed; absent unless it did.
	Error string `json:"error,omitempty"`
	// The time this item was created.
	CreateTime *time.Time `json:"createTime,omitempty" example:"2026-09-15T16:00:05Z"`
	// The time this item last changed state.
	UpdateTime *time.Time `json:"updateTime,omitempty" example:"2026-09-15T16:02:41Z"`
}
