// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import "encoding/json"

// EventstoreHealth aggregates live eventstore diagnostics. HealthReport is
// always present; the remaining fields are best-effort.
type EventstoreHealth struct {
	HealthReport     json.RawMessage   `json:"healthReport" swaggertype:"object"`
	ClusterSettings  json.RawMessage   `json:"clusterSettings,omitempty" swaggertype:"object"`
	CatNodes         json.RawMessage   `json:"catNodes,omitempty" swaggertype:"object"`
	UnassignedShards *UnassignedShards `json:"unassignedShards,omitempty"`
}

// UnassignedShards groups the cluster's unassigned shards by primary/replica
// and unassigned reason.
type UnassignedShards struct {
	Total     int                     `json:"total"`
	Primaries int                     `json:"primaries"`
	Replicas  int                     `json:"replicas"`
	Groups    []*UnassignedShardGroup `json:"groups"`
}

// UnassignedShardGroup is one group of unassigned shards. CanAllocate and
// Deciders digest one sampled shard's allocation explanation; the raw
// Explanation is retained for support.
type UnassignedShardGroup struct {
	Reason      string               `json:"reason"`
	Primary     bool                 `json:"primary"`
	Count       int                  `json:"count"`
	CanAllocate string               `json:"canAllocate,omitempty"`
	Deciders    []*AllocationDecider `json:"deciders,omitempty"`
	Explanation json.RawMessage      `json:"explanation,omitempty" swaggertype:"object"`
}

// AllocationDecider is one distinct allocation decider that returned a NO
// decision for the sampled shard, along with the nodes it rejected.
type AllocationDecider struct {
	Name        string   `json:"name"`
	Explanation string   `json:"explanation"`
	Nodes       []string `json:"nodes"`
}
