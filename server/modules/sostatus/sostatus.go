// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package sostatus

import (
	"context"
	"time"

	"github.com/apex/log"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
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
	statusByGridId     map[string]*model.Status
	ctx                context.Context
}

func NewSoStatus(srv *server.Server) *SoStatus {
	status := &SoStatus{
		server:         srv,
		statusByGridId: make(map[string]*model.Status),
	}
	srv.Statusstore = status
	return status
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
	status.statusByGridId[model.LOCAL_GRID_ID] = model.NewStatus(model.LOCAL_GRID_ID)
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
}

func (status *SoStatus) Stop() error {
	close(status.stopChannel)
	return nil
}

func (status *SoStatus) IsRunning() bool {
	return status.running
}

func (status *SoStatus) Refresh(ctx context.Context) {
	logger := log.FromContext(ctx)

	logger.Debug("Updating grid status")
	status.refreshGrid(ctx)
	status.refreshDetections(ctx)

	localGridStatus := status.statusByGridId[model.LOCAL_GRID_ID]
	status.server.Host.Broadcast("status", "nodes", localGridStatus)
}

func (status *SoStatus) refreshGrid(ctx context.Context) {
	logger := log.FromContext(ctx)

	unhealthyNodes := 0
	nonCriticalNodes := 0
	awaitingRebootCount := 0

	// Process local grid nodes.
	localNodes := status.server.Datastore.GetNodes(ctx)
	if status.server.Metrics != nil {
		for _, node := range localNodes {
			staleMs := int(time.Since(node.UpdateTime) / time.Millisecond)
			if staleMs > status.offlineThresholdMs {
				if node.ConnectionStatus != model.NodeStatusFault {
					logger.WithFields(log.Fields{
						"nodeId":             node.Id,
						"staleMs":            staleMs,
						"offlineThresholdMs": status.offlineThresholdMs,
					}).Warn("Node has gone offline")
					node.ConnectionStatus = model.NodeStatusFault
				}
			}

			updated := status.server.Metrics.UpdateNodeMetrics(ctx, node)
			logger.WithFields(log.Fields{
				"Id":               node.Id,
				"processStatus":    node.ProcessStatus,
				"raidStatus":       node.RaidStatus,
				"connectionStatus": node.ConnectionStatus,
				"nonCriticalNode":  node.NonCriticalNode,
				"overallStatus":    node.Status,
				"updated":          updated,
			}).Debug("Node Status")

			if updated {
				status.server.MarkEventsHealthAvailable(node)
				status.server.Host.Broadcast("node", "nodes", node)
			}

			if node.NonCriticalNode {
				nonCriticalNodes++
			}

			if node.Status != model.NodeStatusOk && node.Status != model.NodeStatusRestart && !node.NonCriticalNode {
				unhealthyNodes++
			}

			if node.OsNeedsRestart == 1 {
				awaitingRebootCount++
			}

		}

		localGridStatus := status.statusByGridId[model.LOCAL_GRID_ID]
		if localGridStatus.Grid.UnhealthyNodeCount == 0 && unhealthyNodes > 0 {
			logger.WithFields(log.Fields{
				"unhealthyNodes": unhealthyNodes,
				"totalNodes":     len(localNodes),
			}).Warn("Grid has entered an unhealthy state")
		} else if localGridStatus.Grid.UnhealthyNodeCount > 0 && unhealthyNodes == 0 {
			logger.WithFields(log.Fields{
				"unhealthyNodes": unhealthyNodes,
				"totalNodes":     len(localNodes),
			}).Info("Grid has returned to a healthy state")
		}
		localGridStatus.Grid.UnhealthyNodeCount = unhealthyNodes
		if localGridStatus.Grid.AwaitingRebootNodeCount == 0 && awaitingRebootCount > 0 {
			logger.WithFields(log.Fields{
				"awaitingRebootCount": awaitingRebootCount,
				"totalNodes":          len(localNodes),
			}).Info("Grid nodes are awaiting reboot")
		}
		localGridStatus.Grid.AwaitingRebootNodeCount = awaitingRebootCount
		localGridStatus.Grid.TotalNodeCount = len(localNodes)

		localGridStatus.Grid.Eps = status.server.Metrics.GetGridEps(ctx)
	}
	licensing.ValidateNodeCount(len(localNodes) - nonCriticalNodes)
	licensing.ValidateSubgridCount(len(status.server.Config.Subgrids))

	// Collect subgrid nodes and status from remote subgrids
	for _, subgrid := range status.server.Config.Subgrids {
		log.WithField("subgridId", subgrid.Id).Info("fetching subgrid status")
		subnodes, err := subgrid.GetGridNodes()
		if err != nil {
			log.WithField("subgridId", subgrid.Id).WithError(err).Error("failed to fetch subgrid nodes, skipping subgrid")
		} else {
			for _, node := range subnodes {
				status.server.Host.Broadcast("node", "nodes", node)
			}
		}

		subgridStatus, err := subgrid.GetGridStatus()
		if err != nil {
			log.WithField("subgridId", subgrid.Id).WithError(err).Error("failed to fetch subgrid status, skipping subgrid")
		} else {
			status.statusByGridId[subgrid.Id] = subgridStatus
			status.server.Host.Broadcast("status", "nodes", subgridStatus)
		}
	}
}

func (status *SoStatus) refreshDetections(ctx context.Context) {
	localGridStatus := status.statusByGridId[model.LOCAL_GRID_ID]

	eng, exists := status.server.DetectionEngines.Load(model.EngineNameElastAlert)
	if exists {
		localGridStatus.Detections.ElastAlert = status.checkDetectionEngineStatus("ElastAlert2",
			localGridStatus.Detections.ElastAlert,
			eng.(server.DetectionEngine).GetState())
	}

	eng, exists = status.server.DetectionEngines.Load(model.EngineNameSuricata)
	if exists {
		localGridStatus.Detections.Suricata = status.checkDetectionEngineStatus("Suricata",
			localGridStatus.Detections.Suricata,
			eng.(server.DetectionEngine).GetState())
	}

	eng, exists = status.server.DetectionEngines.Load(model.EngineNameStrelka)
	if exists {
		localGridStatus.Detections.Strelka = status.checkDetectionEngineStatus("Strelka",
			localGridStatus.Detections.Strelka,
			eng.(server.DetectionEngine).GetState())
	}
}

func (status *SoStatus) checkDetectionEngineStatus(engineName string, oldState *model.EngineState, newState *model.EngineState) *model.EngineState {
	if !oldState.IsFailureState() && newState.IsFailureState() {
		log.WithFields(log.Fields{
			"currentStateIntegrityFailure": oldState.IntegrityFailure,
			"currentStateMigrationFailure": oldState.MigrationFailure,
			"currentStateSyncFailure":      oldState.SyncFailure,
			"newStateIntegrityFailure":     newState.IntegrityFailure,
			"newStateMigrationFailure":     newState.MigrationFailure,
			"newStateSyncFailure":          newState.SyncFailure,
			"engineName":                   engineName,
		}).Warn("Detection engine has entered a failure state")
	} else if oldState.IsFailureState() && !newState.IsFailureState() {
		log.WithFields(log.Fields{
			"currentStateIntegrityFailure": oldState.IntegrityFailure,
			"currentStateMigrationFailure": oldState.MigrationFailure,
			"currentStateSyncFailure":      oldState.SyncFailure,
			"newStateIntegrityFailure":     newState.IntegrityFailure,
			"newStateMigrationFailure":     newState.MigrationFailure,
			"newStateSyncFailure":          newState.SyncFailure,
			"engineName":                   engineName,
		}).Warn("Detection engine has returned to a healthy state")
	}

	return newState
}

func (status *SoStatus) GetStatusSummary(ctx context.Context) (*model.Status, error) {
	if err := status.server.CheckAuthorized(ctx, "read", "grid"); err != nil {
		return nil, err
	}

	localGridStatus := status.statusByGridId[model.LOCAL_GRID_ID]
	return localGridStatus, nil
}
