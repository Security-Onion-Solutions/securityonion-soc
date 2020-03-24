// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package agent

import (
  "github.com/apex/log"
  "github.com/sensoroni/sensoroni/config"
  "github.com/sensoroni/sensoroni/web"
)

type Agent struct {
  Client			*web.Client
  Config 			*config.AgentConfig
  JobMgr			*JobManager
  stoppedChan	chan bool
  Version			string
}

func NewAgent(cfg *config.AgentConfig, version string) *Agent {
  agent := &Agent{
    Config: cfg,
    Client: web.NewClient(cfg.ServerUrl, cfg.VerifyCert),
    stoppedChan: make(chan bool, 1),
    Version: version,
  }
  agent.JobMgr = NewJobManager(agent)
  return agent
}

func (agent *Agent) Start() {
  log.Info("Starting agent")
  agent.JobMgr.Start()
  agent.stoppedChan <- true
}

func (agent *Agent) Stop() {
  log.Info("Stopping agent")
  agent.JobMgr.Stop()
}

func (agent *Agent) Wait() {
  <- agent.stoppedChan
}