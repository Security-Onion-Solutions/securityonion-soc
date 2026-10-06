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
	// The settings this kind accepts, one property per form field. Interval and creator
	// belong to the automation rather than the kind, so they are absent here.
	ParamSchema JSONSchema `json:"paramSchema"`
}

// @Description A task the grid runs on a schedule, with an agent doing the work and no user driving it.
type Automation struct {
	Auditable
	// What this automation is called in the UI.
	DisplayName string `json:"displayName" example:"Nightly Alert Triage"`
	// The kind that runs this automation.
	AutomationKind string `json:"automationKind" example:"alert_triage"`
	// The agent whose sessions do this automation's work.
	Agent string `json:"agent" example:"Investigator"`
	// Indicates whether the scheduler runs this automation.
	Enabled bool `json:"enabled" example:"true"`
	// How often this automation comes due, in seconds.
	IntervalSeconds int `json:"intervalSeconds" example:"60"`
	// Ships with the product: only enabled and agent can be changed, and it cannot be deleted.
	IsSystem bool `json:"isSystem" example:"false"`
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
	// process.
	Attempts int `json:"attempts" example:"1"`
	// One root session per attempt, in attempt order. Each root reaches its own delegated
	// children.
	SessionIds []string `json:"sessionIds,omitempty"`
	// Every run that failed this item, in failure order. A run never claims an item it
	// failed, and the kind gives the item up once this reaches its budget.
	FailedRunIds []string `json:"failedRunIds,omitempty"`
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

// @Description Open work items an automation still has to finish, by state.
type AutomationBacklog struct {
	Pending  int `json:"pending" example:"3"`
	Running  int `json:"running" example:"1"`
	Applying int `json:"applying" example:"0"`
}

// @Description One run in an automation's history, with its work items counted by state.
type AutomationRunSummary struct {
	AutomationRunRecord
	// Items this run last worked or failed, counted by state; one it failed counts as failed.
	ItemCounts map[AutomationWorkItemState]int `json:"itemCounts"`
}

// @Description A page of one automation's runs plus what it still has queued.
type AutomationRunHistory struct {
	// The automation these runs belong to, echoed even when it no longer exists.
	AutomationId string `json:"automationId" example:"5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90"`
	// The automation's current name; empty once it has been deleted or without config/read.
	DisplayName string `json:"displayName" example:"Nightly Alert Triage"`
	// Indicates the automation has been deleted and only its history remains.
	AutomationDeleted bool `json:"automationDeleted" example:"false"`
	// Work still open for this automation, whichever run enqueued it.
	Backlog AutomationBacklog `json:"backlog"`
	// The requested page, newest first.
	Runs []*AutomationRunSummary `json:"runs"`
	// Indicates more runs exist past this page.
	HasMore bool `json:"hasMore" example:"true"`
}

const (
	// The session whose report the automation recorded.
	AutomationRunOutcomeReport = "report"
	// A session that produced no report, or an attempt superseded by a later one.
	AutomationRunOutcomeFailed = "failed"
	// A session still being driven.
	AutomationRunOutcomeRunning = "running"

	AutomationRunStepThought = "thought"
	AutomationRunStepTool    = "tool"

	AutomationToolStatusOk       = "ok"
	AutomationToolStatusError    = "error"
	AutomationToolStatusRejected = "rejected"
	AutomationToolStatusPending  = "pending"
)

// @Description One thing a session did, in transcript order: a stretch of thinking or a tool call.
type AutomationRunStep struct {
	// thought or tool.
	Kind string `json:"kind" example:"tool"`
	// The tool called; absent on a thought.
	Name string `json:"name,omitempty" example:"query_events"`
	// ok, error, rejected, or pending while the result is outstanding; absent on a thought.
	Status string `json:"status,omitempty" example:"ok"`
	// The start of the thinking; absent on a tool call. The session holds the full text.
	Text string `json:"text,omitempty"`
	// Indicates text was cut short.
	Truncated bool `json:"truncated,omitempty" example:"true"`
}

// @Description One session a run drove, summarized from its stored messages.
type AutomationRunSession struct {
	SessionId string `json:"sessionId" example:"9b7c1d2e-3f40-4a5b-8c6d-7e8f9a0b1c2d"`
	// The work item this session was an attempt at.
	ItemId string `json:"itemId" example:"8c2e5b91-4a03-47f6-9d18-6b0e2c7d4a15"`
	// The run that made this attempt, best effort: a run that failed before opening a session shifts the mapping.
	RunId string `json:"runId,omitempty" example:"3f1a7c0e-9b21-4d8a-bc55-2e77a1f0c934"`
	// report, failed or running, derived from the item's state, the attempt's position and whether its session is live.
	Outcome string `json:"outcome" example:"report"`
	// The agent that drove this session.
	Agent string `json:"agent,omitempty" example:"Investigator"`
	// Indicates the session is no longer stored; only its id remains on the work item.
	Missing      bool       `json:"missing,omitempty" example:"false"`
	CreateTime   *time.Time `json:"createTime,omitempty" example:"2026-09-15T16:00:05Z"`
	UpdateTime   *time.Time `json:"updateTime,omitempty" example:"2026-09-15T16:02:41Z"`
	MessageCount int        `json:"messageCount" example:"14"`
	// What the session did, in order.
	Steps []AutomationRunStep `json:"steps"`
}

// @Description Everything one run left behind: its row, its work items, the sessions they drove and the alerts they recorded on.
type AutomationRunDetails struct {
	Run *AutomationRunRecord `json:"run"`
	// The automation this run belongs to, echoed even when it no longer exists.
	AutomationId string `json:"automationId" example:"5c0b1f2e-0c6d-4a71-9f3e-1b8a2d4c6e90"`
	// The automation's current name; empty once it has been deleted or without config/read.
	DisplayName string `json:"displayName" example:"Nightly Alert Triage"`
	// Indicates the automation has been deleted and only its history remains.
	AutomationDeleted bool `json:"automationDeleted" example:"false"`
	// The items this run last worked or failed, oldest first.
	Items []*AutomationWorkItem `json:"items"`
	// Every attempt on those items, in item then attempt order, other runs' attempts included.
	Sessions []*AutomationRunSession `json:"sessions"`
	// The alerts carrying this run's id, newest first, up to the requested limit.
	Alerts []*AlertTriageAlert `json:"alerts"`
	// How many alerts carry this run's id.
	AlertTotal int `json:"alertTotal" example:"120"`
	// Indicates the run recorded on alerts that have since aged out of the alert indices.
	// A best effort: nothing distinguishes a partly expired list from a complete one.
	AlertsExpired bool `json:"alertsExpired" example:"false"`
	// The automation's failure cap when it is still defined; 0 when unknown.
	MaxFailures int `json:"maxFailures" example:"3"`
	// Alerts of this run whose group has failed maxFailures times; 0 when the cap is unknown.
	GivenUpAlerts int `json:"givenUpAlerts" example:"12"`
}

// @Description What agents are doing right now: every automation run in flight with its automation's open work, what each live session is doing, and the load on the pool that runs agent work.
type AutomationActivity struct {
	// Indicates the automation scheduler is running; it stays stopped when agents are off, on airgapped grids and without a database.
	SchedulerRunning bool `json:"schedulerRunning" example:"true"`
	// The pool that runs agent work, interactive turns included.
	Pool AgentPoolActivity `json:"pool"`
	// Runs queued or running, newest first.
	Runs []*AutomationRunActivity `json:"runs"`
	// When this view was built, so a client can drop one older than what it shows.
	GeneratedAt time.Time `json:"generatedAt" example:"2026-10-02T16:00:02Z"`
}

// @Description Load on the pool that runs agent work, interactive turns included.
type AgentPoolActivity struct {
	// Jobs waiting for a slot.
	Queued int `json:"queued" example:"21"`
	// Jobs holding a slot.
	Running int `json:"running" example:"4"`
	// The most jobs started from the queue at once; interactive turns count toward it but can run past it. 0 means unlimited.
	MaxConcurrent int `json:"maxConcurrent" example:"4"`
	// The most jobs allowed to wait; 0 means unlimited.
	MaxQueueDepth int `json:"maxQueueDepth" example:"0"`
	// The most jobs ever waiting at once since the server started.
	PeakQueued int `json:"peakQueued" example:"25"`
	// The most jobs ever running at once since the server started.
	PeakRunning int `json:"peakRunning" example:"4"`
	// Jobs refused because the queue was full, since the server started.
	Rejected uint64 `json:"rejected" example:"0"`
	// Jobs refused because the same work was already queued or running, since the server started.
	Deduped uint64 `json:"deduped" example:"2"`
	// Interactive turns refused because their agent was at its limit, since the server started.
	Busy uint64 `json:"busy" example:"1"`
	// Each agent with work queued or running, by name.
	Agents []*AgentPoolLoad `json:"agents"`
}

// @Description One agent's share of the pool.
type AgentPoolLoad struct {
	// The agent's name, or the model selector of an interactive turn that names no agent.
	Name    string `json:"name" example:"Investigator"`
	Queued  int    `json:"queued" example:"21"`
	Running int    `json:"running" example:"2"`
	// The agent's maxConcurrentInstances; 0 means unlimited.
	MaxConcurrentInstances int `json:"maxConcurrentInstances" example:"2"`
}

// @Description One run in flight and the work its automation still has open.
type AutomationRunActivity struct {
	AutomationRunSummary
	// The automation's current name; empty once it has been deleted or without config/read.
	DisplayName string `json:"displayName" example:"Nightly Alert Triage"`
	// Indicates the automation has been deleted and this run is finishing without it.
	AutomationDeleted bool `json:"automationDeleted" example:"false"`
	// The automation's unfinished items, oldest first, whichever run enqueued them.
	Items []*AutomationWorkItemActivity `json:"items"`
}

// @Description One unfinished work item and what is happening to it. A running item that is neither queued nor has phases is preparing its session.
type AutomationWorkItemActivity struct {
	AutomationWorkItem
	// Indicates the item's job is waiting for a pool slot.
	Queued bool `json:"queued" example:"false"`
	// The item's live session first, then each child it delegated to; empty while no session runs for it.
	Phases []AgentSessionPhase `json:"phases"`
}
