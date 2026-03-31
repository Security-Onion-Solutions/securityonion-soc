// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"time"

	"github.com/security-onion-solutions/securityonion-soc/json"
)

const NodeRoleDesktop = "so-desktop"
const NodeStatusUnknown = "unknown"
const NodeStatusOk = "ok"
const NodeStatusFault = "fault"
const NodeStatusPending = "pending"
const NodeStatusRestart = "restart"

type Node struct {
	// The node ID
	Id string `json:"id" example:"sensor-001"`
	// The date and time when this node first came online; best estimate based on the node's apparent file system age
	OnlineTime time.Time `json:"onlineTime" example:"2024-01-26T21:17:25Z"`
	// The date and time when this node was most recently updated"
	UpdateTime time.Time `json:"updateTime" example:"2024-12-03T15:42:21.723166638Z"`
	// The node's data epoch; this is the date and time of the oldest known PCAP data available to the node
	EpochTime time.Time `json:"epochTime" example:"2024-12-01T03:24:01Z"`
	// The number of seconds since this node first came online and joined the grid
	UptimeSeconds int `json:"uptimeSeconds" example:"26936696"`
	// The node's optional description
	Description string `json:"description" example:"East coast sensor"`
	// The MAC address assigned to this node's management NIC
	MgmtMac string `json:"mgmtMac" example:"AA:BB:CC:11:22:33"`
	// The IP address of this node
	Address string `json:"address" example:"4.3.2.1"`
	// The node's assigned role; assigned during node setup
	Role string `json:"role" example:"so-standalone"`
	// The Seurity Onion appliance model, or N/A if this is not an official Security Onion appliance
	Model string `json:"model" example:"SOS5000-DE02"`
	// The Security Onion appliance front image, if available
	ImageFront string `json:"imageFront" example:"5000v2_front_thumb.jpg"`
	// The Security Onion appliance back image, if available
	ImageBack string `json:"imageBack" example:"5000v2_back_thumb.jpg"`
	// The current state of the node: unknown, ok, fault, pending, restart
	Status string `json:"status" example:"ok"`
	// The version of Security Onion installed on this node
	Version string `json:"version" example:"2.4.110"`
	// The connectivity status between this node and the manager node: unknown, ok, fault
	ConnectionStatus string `json:"connectionStatus" example:"fault"`
	// The raid status, if applicable: unknown, ok, fault
	RaidStatus string `json:"raidStatus" example:"unknown"`
	// The overall status of the node's Security Onion processes: unknown, ok, fault
	ProcessStatus string `json:"processStatus" example:"ok"`
	// The status of each individual process on the node, in JSON format
	ProcessJson string `json:"processJson" example:"{\"status_code\":0, \"containers\":[{\"Name\":\"so-dockerregistry\", \"Status\":\"running\",\"Details\":\"Up 2 weeks\"}, ... ]}"`
	// The events per second (EPS) produced by this node (not currently populated)
	ProductionEps int `json:"productionEps" example:"0"`
	// The events per second (EPS) consumed by this node
	ConsumptionEps int `json:"consumptionEps" example:"110"`
	// The count of failed events (currently not in use)"
	FailedEvents int `json:"failedEvents" example:"0"`
	// The event storage status; this refers to the backend status, such as Elasticsearch: unknown, ok, fault
	EventstoreStatus string `json:"eventstoreStatus" example:"ok"`
	// Indicates whether the node needs to be restarted to apply kernel updates: 0 = no restart needed, 1 = needs restarted
	OsNeedsRestart int `json:"osNeedsRestart" example:"1"`
	// The number of seconds that the operating system has been "up" since its last reboot
	OsUptimeSeconds int `json:"osUptimeSeconds" example:"1384801"`
	// Indicates whether the metric subsytem is available
	MetricsEnabled bool `json:"metricsEnabled" example:"true"`
	// Indicates whether this node is a non-critical node of the overall grid. An examples of a non-critical nodes is a desktop node
	NonCriticalNode bool `json:"nonCriticalNode" example:"false"`
	// Total size, in gigabytes, of the root operating system disk/partition
	DiskTotalRootGB float64 `json:"diskTotalRootGB" example:"314.41920000000005"`
	// Percentage usage of the root system disk/partition
	DiskUsedRootPct float64 `json:"diskUsedRootPct" example:"20.944604461814038"`
	// Total size, in gigabytes, of the NSM data disk/partition
	DiskTotalNsmGB float64 `json:"diskTotalNsmGB" example:"772.7962808320001"`
	// Percentage usage of the NSM data disk/partition
	DiskUsedNsmPct float64 `json:"diskUsedNsmPct" example:"84.28509193998036"`
	// The current CPU usage of the node, across all cores
	CpuUsedPct float64 `json:"cpuUsedPct" example:"5.0035165275079265"`
	// Total size, in gigabytes, of the system memory, or RAM
	MemoryTotalGB float64 `json:"memoryTotalGB" example:"33.176731648"`
	// Percentage usage of the system memory, or RAM
	MemoryUsedPct float64 `json:"memoryUsedPct" example:"60.66793353109983"`
	// Total size, in gigabytes, of the system swap memory
	SwapTotalGB float64 `json:"swapTotalGB" example:"8.589930496000001"`
	// Percentage usage of the system swap memory
	SwapUsedPct float64 `json:"swapUsedPct" example:"63.27341235800379"`
	// The number of days of PCAP storage available to this node
	PcapDays float64 `json:"pcapDays" example:"1.8762268518518517"`
	// The current percentage packet loss experienced by Suricata, if applicable to this node
	SuriLossPct float64 `json:"suriLossPct" example:"1.1345"`
	// The number of Suricata rules currently loaded, if applicable to this node
	SuriRulesLoaded int `json:"suriRulesLoaded" example:"45879"`
	// The number of Suricata rules that failed to load, if applicable to this node
	SuriRulesFailed int `json:"suriRulesFailed" example:"0"`
	// The timestamp of the last Suricata rule reload, if applicable to this node
	SuriRulesReloadTime string `json:"suriRulesReloadTime" example:"2025-12-04T01:04:07.994734+0000"`
	// The status of Suricata rule loading: ok, unknown
	SuriRulesStatus string `json:"suriRulesStatus" example:"ok"`
	// The current percentage packet loss experienced by Zeek, if applicable to this node
	ZeekLossPct float64 `json:"zeekLossPct" example:"0"`
	// The current percentage capture loss experienced by the network, if applicable to this node
	CaptureLossPct float64 `json:"captureLossPct" example:"24.0605"`
	// The inbound traffic rate, in megabytes per second, to this node's monitor network interface
	TrafficMonInMbs float64 `json:"trafficMonInMbs" example:"1.6864359999999998"`
	// The inbound traffic packet drop rate, in megabytes per second, to this node's monitor network interface
	TrafficMonInDropsMbs float64 `json:"trafficMonInDropsMbs" example:"0"`
	// The inbound traffic rate, in megabytes per second, to this node's management network interface
	TrafficManInMbs float64 `json:"trafficManInMbs" example:"0.031592"`
	// The outbound traffic rate, in megabytes per second, from this node's management network interface
	TrafficManOutMbs float64 `json:"trafficManOutMbs" example:"0.030966666666666667"`
	// The backlog of events waiting to be processed
	RedisQueueSize int `json:"redisQueueSize" example:"0"`
	// The IO wait percentage for this node
	IoWaitPct float64 `json:"ioWaitPct" example:"0.21099"`
	// The node's 1-minute load metric
	Load1m float64 `json:"load1m" example:"0.43"`
	// The node's 5-minute load metric
	Load5m float64 `json:"load5m" example:"0.96"`
	// The node's 15-minute load metric
	Load15m float64 `json:"load15m" example:"1.09"`
	// The disk space used, in gigabytes, on the backend data store system (Elasticsearch)
	DiskUsedElasticGB float64 `json:"diskUsedElasticGB" example:"386.948"`
	// The disk space used, in gigabytes, on the metrics data store system (InfluxDB)
	DiskUsedInfluxDbGB float64 `json:"diskUsedInfluxDbGB" example:"1.922272"`
	// How long ago, in seconds, the last highstate completed on this node
	HighstateAgeSeconds int `json:"highstateAgeSeconds" example:"220"`
	// Indicates whether guaranteed message delivery is enabled on this node
	GmdEnabled int `json:"gmdEnabled" example:"0"`
	// Indicates whether disk encryption is enabled on this node
	LksEnabled int `json:"lksEnabled" example:"1"`
	// Indicates whether federal information processing standards are enabled on this node
	FpsEnabled int `json:"fpsEnabled" example:"0"`
	// Grid ID, used for subgrids
	GridId string `json:"gridId" example:"so1"`
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
	case "SOS500-DE02":
		node.ImageFront = "500v2_front_thumb.jpg"
		node.ImageBack = "500v2_back_thumb.jpg"
	case "SOSMN-DE02", "SOS1000-DE02", "SOS2000-DE02":
		node.ImageFront = "MNv2_front_thumb.jpg"
		node.ImageBack = "MNv2_back_thumb.jpg"
	case "SOS5000-DE02", "SOSSN7200-DE02":
		node.ImageFront = "5000v2_front_thumb.jpg"
		node.ImageBack = "5000v2_back_thumb.jpg"
	case "SOSSNNV-DE02", "SOS10K-DE02", "SOS10KNV-DE02":
		node.ImageFront = "NVv2_front_thumb.jpg"
		node.ImageBack = "NVv2_back_thumb.jpg"
	case "SOS-GOFAST-LT-DE02", "SOS-GOFAST-MD-DE02", "SOS-GOFAST-HV-DE02":
		node.ImageFront = "GOFASTv2_front_thumb.jpg"
		node.ImageBack = "GOFASTv2_back_thumb.jpg"
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

func (node *Node) IsProcessRunning(match string) bool {
	nodeStatus := NodeStatus{}
	err := json.LoadJson([]byte(node.ProcessJson), &nodeStatus)
	if err != nil {
		return false
	}
	for _, process := range nodeStatus.Containers {
		if process.Name == match {
			return process.Status == "running"
		}
	}
	return false
}

func (node *Node) IsManager() bool {
	return node.Role == "so-standalone" || node.Role == "so-manager" || node.Role == "so-eval" || node.Role == "so-import" || node.Role == "so-managersearch"
}

type NodeStatus struct {
	StatusCode int             `json:"status_code"`
	Containers []ProcessStatus `json:"containers"`
}

type ProcessStatus struct {
	Name    string `json:"Name"`
	Status  string `json:"Status"`
	Details string `json:"Details"`
}
