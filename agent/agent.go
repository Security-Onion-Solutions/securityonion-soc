// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package agent

import (
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/config"
  "github.com/security-onion-solutions/securityonion-soc/web"
)

type Agent struct {
  Client      *web.Client
  Config      *config.AgentConfig
  JobMgr      *JobManager
  stoppedChan chan bool
  Version     string
}

func NewAgent(cfg *config.AgentConfig, version string) *Agent {
  agent := &Agent{
    Config:      cfg,
    Client:      web.NewClient(cfg.ServerUrl, cfg.VerifyCert),
    stoppedChan: make(chan bool, 1),
    Version:     version,
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
  <-agent.stoppedChan
}
