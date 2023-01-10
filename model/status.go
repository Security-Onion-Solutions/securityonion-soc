// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import ()

type Status struct {
  Grid   *GridStatus   `json:"grid"`
  Alerts *AlertsStatus `json:"alerts"`
}

type GridStatus struct {
  TotalNodeCount     int `json:"totalNodeCount"`
  UnhealthyNodeCount int `json:"unhealthyNodeCount"`
  Eps                int `json:"eps"`
}

type AlertsStatus struct {
  NewCount int `json:"newCount"`
}

func NewStatus() *Status {
  newStatus := &Status{
    Grid:   &GridStatus{},
    Alerts: &AlertsStatus{},
  }
  return newStatus
}
