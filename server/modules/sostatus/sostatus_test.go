// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sostatus

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func NewTestStatus() (*SoStatus, error) {
	status := NewSoStatus(server.NewFakeUnauthorizedServer())
	cfg := make(map[string]interface{})
	cfg["refreshIntervalMs"] = float64(1000)
	cfg["offlineThresholdMs"] = float64(2000)
	err := status.Init(cfg)
	return status, err
}

func TestSoStatusInit(tester *testing.T) {
	status, err := NewTestStatus()
	if assert.Nil(tester, err) {
		assert.Equal(tester, 1000, status.refreshIntervalMs)
		assert.Equal(tester, 2000, status.offlineThresholdMs)
	}
}

func TestRefreshGrid_LicensedNodes(tester *testing.T) {
	status, _ := NewTestStatus()

	// 0 = unlimited nodes
	licensing.Test("foo", 0, 0, "", "")
	status.refreshGrid(context.Background())
	assert.Equal(tester, licensing.LICENSE_STATUS_ACTIVE, licensing.GetStatus())

	// FakeServer has 2 fake critical nodes, since 2 > 1 the license will be exceeded
	licensing.Test("foo", 0, 1, "", "")
	status.refreshGrid(context.Background())
	assert.Equal(tester, licensing.LICENSE_STATUS_EXCEEDED, licensing.GetStatus())
}

func TestRefreshGrid(tester *testing.T) {
	status, _ := NewTestStatus()

	status.refreshGrid(context.Background())
	assert.Equal(tester, 2, status.currentStatus.Grid.UnhealthyNodeCount)
	assert.Equal(tester, 3, status.currentStatus.Grid.TotalNodeCount)
	assert.Equal(tester, 0, status.currentStatus.Grid.AwaitingRebootNodeCount)
	assert.Equal(tester, 12, status.currentStatus.Grid.Eps)
}

func TestCheckDetectionEngineStatus(tester *testing.T) {
	status, _ := NewTestStatus()
	bad := &model.EngineState{
		SyncFailure: true,
	}
	good := &model.EngineState{}
	assert.Equal(tester, bad, status.checkDetectionEngineStatus("foo", good, bad))
}
