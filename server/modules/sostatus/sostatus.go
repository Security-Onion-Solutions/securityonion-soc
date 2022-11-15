// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sostatus

import (
	"context"
	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"time"
)

const DEFAULT_REFRESH_INTERVAL_MS = 30000
const DEFAULT_OFFLINE_THRESHOLD_MS = 60000

type SoStatus struct {
	config             module.ModuleConfig
	server             *server.Server
	stopChannel        chan int
	refreshTicker      *time.Ticker
	running            bool
	refreshIntervalMs  int
	offlineThresholdMs int
	currentStatus      *model.Status
	ctx                context.Context
}

func NewSoStatus(srv *server.Server) *SoStatus {
	return &SoStatus{
		server: srv,
	}
}

func (status *SoStatus) PrerequisiteModules() []string {
	return nil
}

func (status *SoStatus) newServerContext() context.Context {
	return status.server.Context
}

func (status *SoStatus) Init(cfg module.ModuleConfig) error {
	status.config = cfg
	status.refreshIntervalMs = module.GetIntDefault(cfg, "refreshIntervalMs", DEFAULT_REFRESH_INTERVAL_MS)
	status.offlineThresholdMs = module.GetIntDefault(cfg, "offlineThresholdMs", DEFAULT_OFFLINE_THRESHOLD_MS)
	status.currentStatus = model.NewStatus()
	status.ctx = status.newServerContext()
	return nil
}

func (status *SoStatus) Start() error {
	status.stopChannel = make(chan int)
	go status.refresher()
	return nil
}

func (status *SoStatus) refresher() {
	status.refreshTicker = time.NewTicker(time.Duration(status.refreshIntervalMs) * time.Millisecond)
	status.running = true

	for {
		select {
		case <-status.refreshTicker.C:
			status.Refresh(status.ctx)
		case <-status.stopChannel:
			status.refreshTicker.Stop()
			return
		}
	}
	status.running = false
}

func (status *SoStatus) Stop() error {
	close(status.stopChannel)
	return nil
}

func (status *SoStatus) IsRunning() bool {
	return status.running
}

func (status *SoStatus) Refresh(ctx context.Context) {
	log.Debug("Updating grid status")
	status.refreshGrid(ctx)
	status.server.Host.Broadcast("status", "nodes", status.currentStatus)
}

func (status *SoStatus) refreshGrid(ctx context.Context) {
	unhealthyNodes := 0

	nodes := status.server.Datastore.GetNodes(ctx)
	for _, node := range nodes {

		staleMs := int(time.Now().Sub(node.UpdateTime) / time.Millisecond)
		if staleMs > status.offlineThresholdMs {
			if node.ConnectionStatus != model.NodeStatusFault {
				log.WithFields(log.Fields{
					"nodeId":             node.Id,
					"staleMs":            staleMs,
					"offlineThresholdMs": status.offlineThresholdMs,
				}).Warn("Node has gone offline")
				node.ConnectionStatus = model.NodeStatusFault
			}
		}

		updated := status.server.Metrics.UpdateNodeMetrics(ctx, node)

		log.WithFields(log.Fields{
			"Id":               node.Id,
			"processStatus":    node.ProcessStatus,
			"raidStatus":       node.RaidStatus,
			"connectionStatus": node.ConnectionStatus,
			"overallStatus":    node.Status,
			"updated":          updated,
		}).Debug("Node Status")

		if updated {
			status.server.Host.Broadcast("node", "nodes", node)
		}

		if node.Status != model.NodeStatusOk {
			unhealthyNodes++
		}
	}
	status.currentStatus.Grid.TotalNodeCount = len(nodes)
	status.currentStatus.Grid.UnhealthyNodeCount = unhealthyNodes
	status.currentStatus.Grid.Eps = status.server.Metrics.GetGridEps(ctx)
}
