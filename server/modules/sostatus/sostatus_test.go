// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sostatus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/json"
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
	assert.Equal(tester, 2, status.statusByGridId[model.LOCAL_GRID_ID].Grid.UnhealthyNodeCount)
	assert.Equal(tester, 3, status.statusByGridId[model.LOCAL_GRID_ID].Grid.TotalNodeCount)
	assert.Equal(tester, 0, status.statusByGridId[model.LOCAL_GRID_ID].Grid.AwaitingRebootNodeCount)
	assert.Equal(tester, 12, status.statusByGridId[model.LOCAL_GRID_ID].Grid.Eps)
}

func TestRefreshGrid_SubgridNodes(t *testing.T) {
	status, _ := NewTestStatus()

	// Define the mock subgrid nodes
	subgridNodes := []*model.Node{
		{
			Id:              "subgrid-node-1",
			Status:          model.NodeStatusOk,
			NonCriticalNode: false,
		},
		{
			Id:              "subgrid-node-2",
			Status:          model.NodeStatusFault,
			NonCriticalNode: false,
		},
	}

	// Simple server mock that returns JSON of the above subgridNodes
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		bytes, _ := json.WriteJson(subgridNodes)
		rw.Write(bytes)
	}))
	defer server.Close()

	grid := &model.Subgrid{
		ManagerUrl:      server.URL,
		ClientId:        "socl_test",
		ClientSecret:    "test-secret",
		AccessToken:     "new-access-token", // Assume token is already refreshed
		TokenExpiration: time.Now().Add(time.Hour),
	}

	status.server.Config.Subgrids = []*model.Subgrid{grid}

	status.refreshGrid(context.Background())

	assert.Equal(t, 3, status.statusByGridId[model.LOCAL_GRID_ID].Grid.TotalNodeCount)
	assert.Equal(t, 2, status.statusByGridId[model.LOCAL_GRID_ID].Grid.UnhealthyNodeCount)
}

func TestCheckDetectionEngineStatus(tester *testing.T) {
	status, _ := NewTestStatus()
	bad := &model.EngineState{
		SyncFailure: true,
	}
	good := &model.EngineState{}
	assert.Equal(tester, bad, status.checkDetectionEngineStatus("foo", good, bad))
}
