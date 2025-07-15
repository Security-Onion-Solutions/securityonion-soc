// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import "time"

type ToolResult struct {
	ToolName       string
	Parameters     any
	Result         any
	TimeToExecute  time.Duration
	OnBehalfOfUser string
}
