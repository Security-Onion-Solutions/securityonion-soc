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
  "time"
  "github.com/sensoroni/sensoroni/json"
)

type Config struct {
  Filename                  			string
  Version													string
  BuildTime                       time.Time
  LoadTime                  			time.Time
  LogLevel                  			string    												`json:"logLevel"`
  LogFilename               			string    												`json:"logFilename"`
  ShutdownGracePeriodMs						int																`json:"shutdownGracePeriodMs"`
  Server													*ServerConfig											`json:"server"`
  Agent														*AgentConfig											`json:"agent"`
}

func LoadConfig(filename string, version string, buildTime time.Time) (*Config, error) {
  cfg := &Config{
    Version: version,
    BuildTime: buildTime,
    Filename: filename,
    LoadTime: time.Now(),
    LogLevel: "info",
    LogFilename: filename + ".log",
    ShutdownGracePeriodMs: 10000,
  }
  err := json.LoadJsonFile(cfg.Filename, cfg)
  if err == nil {
    if cfg.Agent != nil {
      err = cfg.Agent.Verify()
    }
    if err == nil && cfg.Server != nil {
      err = cfg.Server.Verify()
    }
  }
  return cfg, err
}
