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
	// The overall datastore health: green, yellow, red, or unknown.
	Status string `json:"status" example:"yellow"`
	// The per-subsystem health checks reported by the datastore, most severe first.
	Indicators []HealthIndicator `json:"indicators"`
	// The nodes making up the datastore cluster.
	Nodes []EventsHealthNode `json:"nodes,omitempty"`
	// The cluster settings that have been overridden from their defaults.
	Settings *EventsHealthSettings `json:"settings,omitempty"`
	// A summary of the shards that the datastore has been unable to assign to a node.
	UnassignedShards *UnassignedShards `json:"unassignedShards,omitempty"`
	// The sections that could not be collected, keyed by section name, with the reason for each failure.
	Errors map[string]string `json:"errors,omitempty" example:"nodes:unavailable"`
}

// Ids are an open set; clients must tolerate unknown ids.
type HealthIndicator struct {
	// The datastore's identifier for the subsystem being checked.
	Id string `json:"id" example:"shards_availability"`
	// The health of this subsystem: green, yellow, red, or unknown.
	Status string `json:"status" example:"red"`
	// The datastore's summary of what is wrong with this subsystem.
	Symptom string `json:"symptom,omitempty" example:"This cluster has 1 unavailable primary shard."`
	// The datastore's diagnoses of the symptom, along with the resources each affects.
	Causes []HealthIndicatorCause `json:"causes,omitempty"`
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

// Conditions are an open set minted by each backend; this one is backend-neutral.
const FINDING_UNEXPLAINED = "unexplained"

// Detail carries the datastore's own prose, the only description available for
// unknown conditions.
type HealthFinding struct {
	// The importance of this finding: critical, warning, or info.
	Severity string `json:"severity" example:"critical"`
	// The identifier for the problem that was diagnosed.
	Condition string `json:"condition" example:"disk_threshold"`
	// The group of shards this finding was diagnosed from, when it came from the shard inventory.
	Scope *FindingScope `json:"scope,omitempty"`
	// The datastore's own explanation of the condition.
	Detail string `json:"detail,omitempty" example:"the node is above the low watermark cluster setting"`
	// The number of affected resources, when the condition is counted rather than scoped.
	Count int `json:"count,omitempty" example:"3"`
	// The names of the nodes affected by this condition.
	Nodes []string `json:"nodes,omitempty" example:"so-node-01"`
}

// Mirrors UnassignedShardGroup so clients can label both the same way.
type FindingScope struct {
	// The datastore's reason code for why the shards became unassigned.
	Reason string `json:"reason" example:"NODE_LEFT"`
	// The number of shards in the group.
	Count int `json:"count" example:"2"`
	// Whether the group contains primary shards rather than replicas.
	Primary bool `json:"primary" example:"true"`
}

type HealthIndicatorCause struct {
	// The datastore's description of the cause.
	Cause string `json:"cause" example:"A node has recently left the cluster."`
	// The names of the nodes affected by this cause.
	Nodes []string `json:"nodes" example:"so-node-01"`
	// The names of the indices affected by this cause.
	Indices []string `json:"indices" example:"so-logs-2026.07.21"`
}

// EventsHealthNode stats are display strings; an unavailable stat is "".
type EventsHealthNode struct {
	// The node name.
	Name string `json:"name" example:"so-node-01"`
	// The IP address the node is bound to.
	Ip string `json:"ip" example:"10.0.0.5"`
	// The abbreviated roles the node performs in the cluster.
	Roles string `json:"roles" example:"dhimrst"`
	// An asterisk if the node is the elected master, otherwise a dash.
	Master string `json:"master" example:"*"`
	// The datastore version the node is running.
	Version string `json:"version" example:"8.14.3"`
	// The percentage of the node's heap in use.
	HeapPercent string `json:"heapPercent" example:"62"`
	// The percentage of the node's memory in use.
	RamPercent string `json:"ramPercent" example:"88"`
	// The percentage of the node's CPU in use.
	Cpu string `json:"cpu" example:"12"`
	// The node's one minute load average.
	Load1m string `json:"load1m" example:"1.42"`
	// The total size of the node's data storage.
	DiskTotal string `json:"diskTotal" example:"1.5tb"`
	// The percentage of the node's data storage in use.
	DiskUsedPercent string `json:"diskUsedPercent" example:"85.5"`
	// How long the node has been running.
	Uptime string `json:"uptime" example:"42d"`
}

// Settings overridden from defaults, keyed by flattened name; values are opaque.
type EventsHealthSettings struct {
	// The settings that survive a cluster restart.
	Persistent map[string]interface{} `json:"persistent"`
	// The settings that are discarded on a cluster restart.
	Transient map[string]interface{} `json:"transient"`
}

type UnassignedShards struct {
	// The total number of unassigned shards.
	Total int `json:"total" example:"14"`
	// The number of unassigned shards that are primaries.
	Primaries int `json:"primaries" example:"2"`
	// The number of unassigned shards that are replicas.
	Replicas int `json:"replicas" example:"12"`
	// The unassigned shards grouped by reason, primaries first.
	Groups []UnassignedShardGroup `json:"groups"`
}

// Only an explained group carries sample and allocation details.
const (
	SAMPLE_STATUS_EXPLAINED = "explained"
	SAMPLE_STATUS_CAPPED    = "capped"
	SAMPLE_STATUS_FAILED    = "failed"
)

// One shard per group is sampled for an allocation explanation.
type UnassignedShardGroup struct {
	// The datastore's reason code for why these shards became unassigned.
	Reason string `json:"reason" example:"NODE_LEFT"`
	// Whether this group contains primary shards rather than replicas.
	Primary bool `json:"primary" example:"true"`
	// The number of shards in this group.
	Count int `json:"count" example:"2"`
	// Whether the sampled shard was explained, capped before being explained, or failed to be explained.
	SampleStatus string `json:"sampleStatus" example:"explained"`
	// The index of the sampled shard.
	SampleIndex string `json:"sampleIndex,omitempty" example:"so-logs-2026.07.21"`
	// The number of the sampled shard within its index.
	SampleShard int64 `json:"sampleShard" example:"0"`
	// The date and time that the sampled shard became unassigned.
	Since string `json:"since,omitempty" example:"2026-07-21T20:48:02.943Z"`

	// Present when the sampled shard became unassigned due to an allocation failure.
	FailureDetails string `json:"failureDetails,omitempty" example:"failed shard on node [abc]: shard failure, reason [corrupt file]"`
	// The datastore's verdict on whether the sampled shard can currently be allocated.
	CanAllocate string `json:"canAllocate,omitempty" example:"no"`
	// The allocation rules that rejected or throttled the sampled shard.
	Deciders []AllocationDecider `json:"deciders,omitempty"`
}

type AllocationDecider struct {
	// The name of the allocation rule.
	Name string `json:"name" example:"disk_threshold"`
	// The datastore's explanation of why the rule rejected or throttled the shard.
	Explanation string `json:"explanation" example:"the node is above the low watermark cluster setting"`
	// The names of the nodes the rule rejected or throttled the shard on.
	Nodes []string `json:"nodes" example:"so-node-01"`
}
