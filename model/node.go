// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package model

import (
	"time"
)

const NodeStatusUnknown = "unknown"
const NodeStatusOk = "ok"
const NodeStatusFault = "fault"

type Node struct {
	Id               string    `json:"id"`
	OnlineTime       time.Time `json:"onlineTime"`
	UpdateTime       time.Time `json:"updateTime"`
	EpochTime        time.Time `json:"epochTime"`
	UptimeSeconds    int       `json:"uptimeSeconds"`
	Description      string    `json:"description"`
	Address          string    `json:"address"`
	Role             string    `json:"role"`
	Model            string    `json:"model"`
	ImageFront       string    `json:"imageFront"`
	ImageBack        string    `json:"imageBack"`
	Status           string    `json:"status"`
	Version          string    `json:"version"`
	ConnectionStatus string    `json:"connectionStatus"`
	RaidStatus       string    `json:"raidStatus"`
	ProcessStatus    string    `json:"processStatus"`
	ProductionEps    int       `json:"productionEps"`
	ConsumptionEps   int       `json:"consumptionEps"`
	FailedEvents     int       `json:"failedEvents"`
	MetricsEnabled   bool      `json:"metricsEnabled"`
}

func NewNode(id string) *Node {
	return &Node{
		Id:               id,
		Status:           NodeStatusUnknown,
		ConnectionStatus: NodeStatusUnknown,
		RaidStatus:       NodeStatusUnknown,
		ProcessStatus:    NodeStatusUnknown,
		OnlineTime:       time.Now(),
		UpdateTime:       time.Now(),
	}
}

func (node *Node) SetModel(model string) {
	node.Model = model
	switch model {
	case "SOSMN", "SOS500", "SOS1000":
		node.ImageFront = "sos-1u-front-thumb.jpg"
		node.ImageBack = "sos-1u-ethernet-back-thumb.jpg"
	case "SOS1000F", "SOS10K", "SOSSNNV":
		node.ImageFront = "sos-1u-front-thumb.jpg"
		node.ImageBack = "sos-1u-sfp-back-thumb.jpg"
	case "SOS4000", "SOSSN7200":
		node.ImageFront = "sos-2u-front-thumb.jpg"
		node.ImageBack = "sos-2u-back-thumb.jpg"
	case "SO2AMI01":
		node.ImageFront = "so-cloud-aws.jpg"
	case "SO2AZI01":
		node.ImageFront = "so-cloud-azure.jpg"
	case "SO2GCI01":
		node.ImageFront = "so-cloud-gcp.jpg"
	default:
		node.Model = "N/A"
	}
}

func (node *Node) updateStatusComponent(currentState string, newState string) string {
	if newState != NodeStatusUnknown {
		if currentState == NodeStatusOk || currentState == NodeStatusUnknown {
			currentState = newState
		}
	}

	return currentState
}

func (node *Node) UpdateOverallStatus(enhancedStatusEnabled bool) bool {
	newStatus := NodeStatusUnknown
	newStatus = node.updateStatusComponent(newStatus, node.ConnectionStatus)
	if enhancedStatusEnabled {
		newStatus = node.updateStatusComponent(newStatus, node.RaidStatus)
		newStatus = node.updateStatusComponent(newStatus, node.ProcessStatus)
	}

	// Special case: If either process or connection status is unknown then show node in error state.
	if (enhancedStatusEnabled && node.ProcessStatus == NodeStatusUnknown) ||
		node.ConnectionStatus == NodeStatusUnknown {
		newStatus = NodeStatusFault
	}

	oldStatus := node.Status
	node.Status = newStatus
	node.MetricsEnabled = enhancedStatusEnabled
	return oldStatus != node.Status
}
