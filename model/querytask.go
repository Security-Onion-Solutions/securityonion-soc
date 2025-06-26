// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

type QueryTask struct {
	// Grid ID on which this task is running, or empty for the local grid
	GridId string `json:"gridId" example:"SubgridA"`
	// Unique Task ID representing this active task
	TaskId string `json:"taskId" example:"jSliTqa12bOPhdW195TuuZ:443"`
	// Details of the task
	Details string `json:"details" example:"transport (cluster:monitor/tasks/lists)"`
	// Start time of this task
	StartTime time.Time `json:"startTime" example:"2024-10-06T19:29:39.332211Z"`
	// Elapsed runtime of this task
	ElapsedMs int64 `json:"elapsedMs" example:"100023"`
	// True if this task can be cancelled
	Cancellable bool `json:"cancellable" example:"true"`
	// Internally used elasticsearch client
	EsClient *elasticsearch.Client `json:"-"`
}
