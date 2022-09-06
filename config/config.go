// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
  "github.com/security-onion-solutions/securityonion-soc/json"
  "time"
)

type Config struct {
  Filename              string
  Version               string
  BuildTime             time.Time
  LoadTime              time.Time
  LogLevel              string        `json:"logLevel"`
  LogFilename           string        `json:"logFilename"`
  ShutdownGracePeriodMs int           `json:"shutdownGracePeriodMs"`
  Server                *ServerConfig `json:"server"`
  Agent                 *AgentConfig  `json:"agent"`
}

func LoadConfig(filename string, version string, buildTime time.Time) (*Config, error) {
  cfg := &Config{
    Version:               version,
    BuildTime:             buildTime,
    Filename:              filename,
    LoadTime:              time.Now(),
    LogLevel:              "info",
    LogFilename:           filename + ".log",
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
