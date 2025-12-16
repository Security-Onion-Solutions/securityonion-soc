// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

type Status struct {
	// The grid ID for this status update, can be '' for local grids
	GridId     string            `json:"gridId" example:"my_subgrid_a"`
	Grid       *GridStatus       `json:"grid"`
	Alerts     *AlertsStatus     `json:"alerts"`
	Detections *DetectionsStatus `json:"detections"`
}

type GridStatus struct {
	// The total number of nodes that have checked-in to the grid manager since the manager SOC process was last restarted
	TotalNodeCount int `json:"totalNodeCount" example:"4"`
	// The number of nodes that are not in a healthy state, typically due to a fault.
	UnhealthyNodeCount int `json:"unhealthyNodeCount" example:"0"`
	// The number of nodes that are awaiting reboot for kernel updates
	AwaitingRebootNodeCount int `json:"awaitingRebootNodeCount" example:"1"`
	// The current Events Per Second ingest rate for this grid
	Eps int `json:"eps" example:"2311"`
}

type AlertsStatus struct {
	// The number of new alerts (currently unused)
	NewCount int `json:"newCount" example:"132"`
}

type DetectionsStatus struct {
	// The state of the ElastAlert 2 detection engine
	ElastAlert *EngineState `json:"elastalert"`
	// The state of the Suricata detection engine
	Suricata *EngineState `json:"suricata"`
	// The state of the Strelka detection engine
	Strelka *EngineState `json:"strelka"`
}

type EngineState struct {
	// True if this engine has failed the detection integrity check. This indicates a mismatch between running detections and the backend detection store.
	IntegrityFailure bool `json:"integrityFailure" example:"false"`
	// True if the detections are currently being migrated from an older release.
	Migrating bool `json:"migrating" example:"false"`
	// True if there was a migration failure during the most recent migration attempt.
	MigrationFailure bool `json:"migrationFailure" example:"false"`
	// True if new detections are currently being imported into the engine.
	Importing bool `json:"importing" example:"false"`
	// True if the detection engine is currently syncing the backend detection store with the running detection process.
	Syncing bool `json:"syncing" example:"true"`
	// True if a failure occurred during the most recent sync attempt.
	SyncFailure bool `json:"syncFailure" example:"false"`
	// True if sync operations are currently blocked (e.g., during migrations).
	Blocked bool `json:"blocked" example:"false"`
}

func (state *EngineState) IsFailureState() bool {
	return state.IntegrityFailure || state.MigrationFailure || state.SyncFailure
}

func NewStatus(gridId string) *Status {
	newStatus := &Status{
		GridId: gridId,
		Grid:   &GridStatus{},
		Alerts: &AlertsStatus{},
		Detections: &DetectionsStatus{
			ElastAlert: &EngineState{},
			Strelka:    &EngineState{},
			Suricata:   &EngineState{},
		},
	}
	return newStatus
}
