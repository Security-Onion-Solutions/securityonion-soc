// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

// EventsHealth section names used as keys in its Errors map.
const (
	HEALTH_SECTION_SETTINGS          = "settings"
	HEALTH_SECTION_NODES             = "nodes"
	HEALTH_SECTION_UNASSIGNED_SHARDS = "unassignedShards"
)

// EventsHealth is a point-in-time diagnostic snapshot of the event datastore.
// An absent optional section means nothing to report, unless named in Errors.
type EventsHealth struct {
	Status           string                `json:"status" example:"yellow"`
	Indicators       []HealthIndicator     `json:"indicators"`
	Nodes            []EventsHealthNode    `json:"nodes,omitempty"`
	Settings         *EventsHealthSettings `json:"settings,omitempty"`
	UnassignedShards *UnassignedShards     `json:"unassignedShards,omitempty"`
	Errors           map[string]string     `json:"errors,omitempty" example:"nodes:unavailable"`
}

// Ids are an open set; clients must tolerate unknown ids.
type HealthIndicator struct {
	Id      string                 `json:"id" example:"shards_availability"`
	Status  string                 `json:"status" example:"red"`
	Symptom string                 `json:"symptom,omitempty" example:"This cluster has 1 unavailable primary shard."`
	Causes  []HealthIndicatorCause `json:"causes,omitempty"`
	// Diagnosed problems for this indicator, most severe first
	Findings []HealthFinding `json:"findings,omitempty"`
}

// Severities reported by HealthFinding.Severity; clients should treat
// unrecognized values as warnings.
const (
	FINDING_SEVERITY_CRITICAL = "critical"
	FINDING_SEVERITY_WARNING  = "warning"
	FINDING_SEVERITY_INFO     = "info"
)

// Decider names and allocation verdicts come from the datastore and are an open
// set; clients fall back to Detail for unknown conditions.
const (
	FINDING_NO_VALID_SHARD_COPY = "no_valid_shard_copy"
	FINDING_DISK_THRESHOLD      = "disk_threshold"
	FINDING_SAME_SHARD          = "same_shard"
	FINDING_THROTTLING          = "throttling"
	FINDING_UNEXPLAINED         = "unexplained"
	FINDING_INDICES_READONLY    = "indices_readonly"
)

// Detail carries the datastore's own prose, the only description available for
// unknown conditions.
type HealthFinding struct {
	Severity  string        `json:"severity" example:"critical"`
	Condition string        `json:"condition" example:"disk_threshold"`
	Scope     *FindingScope `json:"scope,omitempty"`
	Detail    string        `json:"detail,omitempty" example:"the node is above the low watermark cluster setting"`
	Count     int           `json:"count,omitempty" example:"3"`
	Nodes     []string      `json:"nodes,omitempty" example:"so-node-01"`
}

// Mirrors UnassignedShardGroup so clients can label both the same way.
type FindingScope struct {
	Reason  string `json:"reason" example:"NODE_LEFT"`
	Count   int    `json:"count" example:"2"`
	Primary bool   `json:"primary" example:"true"`
}

type HealthIndicatorCause struct {
	Cause   string   `json:"cause" example:"A node has recently left the cluster."`
	Nodes   []string `json:"nodes" example:"so-node-01"`
	Indices []string `json:"indices" example:"so-logs-2026.07.21"`
}

// EventsHealthNode stats are display strings; an unavailable stat is "".
type EventsHealthNode struct {
	Name            string `json:"name" example:"so-node-01"`
	Ip              string `json:"ip" example:"10.0.0.5"`
	Roles           string `json:"roles" example:"dhimrst"`
	Master          string `json:"master" example:"*"`
	Version         string `json:"version" example:"8.14.3"`
	HeapPercent     string `json:"heapPercent" example:"62"`
	RamPercent      string `json:"ramPercent" example:"88"`
	Cpu             string `json:"cpu" example:"12"`
	Load1m          string `json:"load1m" example:"1.42"`
	DiskTotal       string `json:"diskTotal" example:"1.5tb"`
	DiskUsedPercent string `json:"diskUsedPercent" example:"85.5"`
	Uptime          string `json:"uptime" example:"42d"`
}

// Settings overridden from defaults, keyed by flattened name; values are opaque.
type EventsHealthSettings struct {
	Persistent map[string]interface{} `json:"persistent"`
	Transient  map[string]interface{} `json:"transient"`
}

type UnassignedShards struct {
	Total     int                    `json:"total" example:"14"`
	Primaries int                    `json:"primaries" example:"2"`
	Replicas  int                    `json:"replicas" example:"12"`
	Groups    []UnassignedShardGroup `json:"groups"`
}

// Only an explained group carries sample and allocation details.
const (
	SAMPLE_STATUS_EXPLAINED = "explained"
	SAMPLE_STATUS_CAPPED    = "capped"
	SAMPLE_STATUS_FAILED    = "failed"
)

// One shard per group is sampled for an allocation explanation.
type UnassignedShardGroup struct {
	Reason       string `json:"reason" example:"NODE_LEFT"`
	Primary      bool   `json:"primary" example:"true"`
	Count        int    `json:"count" example:"2"`
	SampleStatus string `json:"sampleStatus" example:"explained"`
	SampleIndex  string `json:"sampleIndex,omitempty" example:"so-logs-2026.07.21"`
	SampleShard  int64  `json:"sampleShard" example:"0"`
	Since        string `json:"since,omitempty" example:"2026-07-21T20:48:02.943Z"`

	// Present when the sampled shard became unassigned due to an allocation failure.
	FailureDetails string              `json:"failureDetails,omitempty" example:"failed shard on node [abc]: shard failure, reason [corrupt file]"`
	CanAllocate    string              `json:"canAllocate,omitempty" example:"no"`
	Deciders       []AllocationDecider `json:"deciders,omitempty"`
}

type AllocationDecider struct {
	Name        string   `json:"name" example:"disk_threshold"`
	Explanation string   `json:"explanation" example:"the node is above the low watermark cluster setting"`
	Nodes       []string `json:"nodes" example:"so-node-01"`
}
