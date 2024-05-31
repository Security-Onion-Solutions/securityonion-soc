// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"time"
)

const NodeRoleDesktop = "so-desktop"
const NodeStatusUnknown = "unknown"
const NodeStatusOk = "ok"
const NodeStatusFault = "fault"
const NodeStatusPending = "pending"
const NodeStatusRestart = "restart"

type Node struct {
	Id                   string    `json:"id"`
	OnlineTime           time.Time `json:"onlineTime"`
	UpdateTime           time.Time `json:"updateTime"`
	EpochTime            time.Time `json:"epochTime"`
	UptimeSeconds        int       `json:"uptimeSeconds"`
	Description          string    `json:"description"`
	Address              string    `json:"address"`
	Role                 string    `json:"role"`
	Model                string    `json:"model"`
	ImageFront           string    `json:"imageFront"`
	ImageBack            string    `json:"imageBack"`
	Status               string    `json:"status"`
	Version              string    `json:"version"`
	ConnectionStatus     string    `json:"connectionStatus"`
	RaidStatus           string    `json:"raidStatus"`
	ProcessStatus        string    `json:"processStatus"`
	ProcessJson          string    `json:"processJson"`
	ProductionEps        int       `json:"productionEps"`
	ConsumptionEps       int       `json:"consumptionEps"`
	FailedEvents         int       `json:"failedEvents"`
	EventstoreStatus     string    `json:"eventstoreStatus"`
	OsNeedsRestart       int       `json:"osNeedsRestart"`
	OsUptimeSeconds      int       `json:"osUptimeSeconds"`
	MetricsEnabled       bool      `json:"metricsEnabled"`
	NonCriticalNode      bool      `json:"nonCriticalNode"`
	DiskTotalRootGB      float64   `json:"diskTotalRootGB"`
	DiskUsedRootPct      float64   `json:"diskUsedRootPct"`
	DiskTotalNsmGB       float64   `json:"diskTotalNsmGB"`
	DiskUsedNsmPct       float64   `json:"diskUsedNsmPct"`
	CpuUsedPct           float64   `json:"cpuUsedPct"`
	MemoryTotalGB        float64   `json:"memoryTotalGB"`
	MemoryUsedPct        float64   `json:"memoryUsedPct"`
	SwapTotalGB          float64   `json:"swapTotalGB"`
	SwapUsedPct          float64   `json:"swapUsedPct"`
	PcapDays             float64   `json:"pcapDays"`
	StenoLossPct         float64   `json:"stenoLossPct"`
	SuriLossPct          float64   `json:"suriLossPct"`
	ZeekLossPct          float64   `json:"zeekLossPct"`
	CaptureLossPct       float64   `json:"captureLossPct"`
	TrafficMonInMbs      float64   `json:"trafficMonInMbs"`
	TrafficMonInDropsMbs float64   `json:"trafficMonInDropsMbs"`
	TrafficManInMbs      float64   `json:"trafficManInMbs"`
	TrafficManOutMbs     float64   `json:"trafficManOutMbs"`
	RedisQueueSize       int       `json:"redisQueueSize"`
	IoWaitPct            float64   `json:"ioWaitPct"`
	Load1m               float64   `json:"load1m"`
	Load5m               float64   `json:"load5m"`
	Load15m              float64   `json:"load15m"`
	DiskUsedElasticGB    float64   `json:"diskUsedElasticGB"`
	DiskUsedInfluxDbGB   float64   `json:"diskUsedInfluxDbGB"`
	HighstateAgeSeconds  int       `json:"highstateAgeSeconds"`
	GmdEnabled           int       `json:"gmdEnabled"`
	LksEnabled           int       `json:"lksEnabled"`
	FpsEnabled           int       `json:"fpsEnabled"`
}

func NewNode(id string) *Node {
	return &Node{
		Id:               id,
		Status:           NodeStatusUnknown,
		ConnectionStatus: NodeStatusUnknown,
		RaidStatus:       NodeStatusUnknown,
		ProcessStatus:    NodeStatusUnknown,
		ProcessJson:      "",
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
	node.NonCriticalNode = node.Role == NodeRoleDesktop
	newStatus := NodeStatusUnknown
	newStatus = node.updateStatusComponent(newStatus, node.ConnectionStatus)
	if enhancedStatusEnabled {
		newStatus = node.updateStatusComponent(newStatus, node.RaidStatus)
		newStatus = node.updateStatusComponent(newStatus, node.ProcessStatus)
		newStatus = node.updateStatusComponent(newStatus, node.EventstoreStatus)

		if node.OsNeedsRestart == 1 && newStatus == NodeStatusOk {
			newStatus = NodeStatusRestart
		}
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
