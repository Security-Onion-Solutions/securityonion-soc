// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsFailureState(tester *testing.T) {
	status := NewStatus()
	assert.False(tester, status.Detections.ElastAlert.IsFailureState())
	assert.False(tester, status.Detections.Strelka.IsFailureState())
	assert.False(tester, status.Detections.Suricata.IsFailureState())

	status.Detections.ElastAlert.IntegrityFailure = true
	status.Detections.Strelka.MigrationFailure = true
	status.Detections.Suricata.SyncFailure = true
	assert.True(tester, status.Detections.ElastAlert.IsFailureState())
	assert.True(tester, status.Detections.Strelka.IsFailureState())
	assert.True(tester, status.Detections.Suricata.IsFailureState())
}
