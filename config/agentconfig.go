// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package config

import (
  "errors"
  "os"
  "github.com/security-onion-solutions/securityonion-soc/module"
)

const DEFAULT_POLL_INTERVAL_MS = 1000

type AgentConfig struct {
  NodeId                          string                            `json:"nodeId"`
  Role                            string                            `json:"role"`
  Description                     string                            `json:"description"`
  Address                         string                            `json:"address"`
  ServerUrl                       string                            `json:"serverUrl"`
  VerifyCert                      bool                              `json:"verifyCert"`
  PollIntervalMs                  int                               `json:"pollIntervalMs"`
  Modules                         module.ModuleConfigMap            `json:"modules"`
  ModuleFailuresIgnored           bool                              `json:"moduleFailuresIgnored"`
}

func (config *AgentConfig) Verify() error {
  var err error
  if err == nil && config.PollIntervalMs <= 0 {
    config.PollIntervalMs = DEFAULT_POLL_INTERVAL_MS
  }
  if err == nil && config.NodeId == "" {
    config.NodeId, err = os.Hostname()
  }
  if err == nil && config.ServerUrl == "" {
    err = errors.New("Agent.ServerUrl configuration value is required")
  }
  return err
}