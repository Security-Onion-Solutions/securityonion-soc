// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

type Status struct {
	Grid       *GridStatus       `json:"grid"`
	Alerts     *AlertsStatus     `json:"alerts"`
	Detections *DetectionsStatus `json:"detections"`
}

type GridStatus struct {
	TotalNodeCount     int `json:"totalNodeCount"`
	UnhealthyNodeCount int `json:"unhealthyNodeCount"`
	Eps                int `json:"eps"`
}

type AlertsStatus struct {
	NewCount int `json:"newCount"`
}

type DetectionsStatus struct {
	ElastAlertIntegrityCheckPass bool `json:"elastalert"`
	SuricataIntegrityCheckPass   bool `json:"suricata"`
	StrelkaIntegrityCheckPass    bool `json:"strelka"`
}

func NewStatus() *Status {
	newStatus := &Status{
		Grid:       &GridStatus{},
		Alerts:     &AlertsStatus{},
		Detections: &DetectionsStatus{},
	}
	return newStatus
}
