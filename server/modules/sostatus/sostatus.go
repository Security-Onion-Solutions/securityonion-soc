// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package sostatus

import (
	"time"
	"github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "github.com/security-onion-solutions/securityonion-soc/server"
)

const DEFAULT_REFRESH_INTERVAL_MS  = 30000
const DEFAULT_OFFLINE_THRESHOLD_MS = 60000 

type SoStatus struct {
  config							module.ModuleConfig
  server							*server.Server
  stopChannel					chan int
  refreshTicker				*time.Ticker
  running							bool
  refreshIntervalMs		int
  offlineThresholdMs	int
  currentStatus				*model.Status
}

func NewSoStatus(srv *server.Server) *SoStatus {
  return &SoStatus {
    server: srv,
  }
}

func (status *SoStatus) PrerequisiteModules() []string {
  return nil
}

func (status *SoStatus) Init(cfg module.ModuleConfig) error {
  status.config = cfg
  status.refreshIntervalMs = module.GetIntDefault(cfg, "refreshIntervalMs", DEFAULT_REFRESH_INTERVAL_MS)
  status.offlineThresholdMs = module.GetIntDefault(cfg, "offlineThresholdMs", DEFAULT_OFFLINE_THRESHOLD_MS)
  status.currentStatus = model.NewStatus()
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
		case <- status.refreshTicker.C:
			status.Refresh()
		case <- status.stopChannel:
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

func (status *SoStatus) Refresh() {
	log.Debug("Refreshing SO Status")
	status.refreshGrid()
	status.server.Host.Broadcast("status", status.currentStatus)
}

func (status *SoStatus) refreshGrid() {
	unhealthyNodes := 0
	nodes := status.server.Datastore.GetNodes()
	for _, node := range nodes {
		staleMs := int(time.Now().Sub(node.UpdateTime) / time.Millisecond)
		if staleMs > status.offlineThresholdMs {
			unhealthyNodes++
			if node.Status != model.NodeStatusOffline {
				log.WithFields(log.Fields {
					"nodeId": node.Id,
					"staleMs": staleMs,
					"offlineThresholdMs": status.offlineThresholdMs,
				}).Warn("Node has gone offline")
				node.Status = model.NodeStatusOffline
	      status.server.Host.Broadcast("node", node)
			}
		}
	}
	status.currentStatus.Grid.TotalNodeCount = len(nodes)
	status.currentStatus.Grid.UnhealthyNodeCount = unhealthyNodes
}