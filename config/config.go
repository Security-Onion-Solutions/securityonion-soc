// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package config

import (
	"time"

	"github.com/security-onion-solutions/securityonion-soc/json"
)

type Config struct {
	Filename              string
	Version               string
	BuildTime             time.Time
	LoadTime              time.Time
	LogLevel              string        `json:"logLevel"`
	LogFilename           string        `json:"logFilename"`
	LicenseKey            string        `json:"licenseKey"`
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

	// TODO: remove when put in config file
	cfg.Server.Modules["suricataengine"] = map[string]interface{}{
		"communityRulesFile":   "/nsm/rules/suricata/emerging-all.rules",
		"rulesFingerprintFile": "/tmp/socdev/so/conf/soc/emerging-all.fingerprint", // "/opt/so/conf/soc/emerging-all.fingerprint",
	}

	cfg.Server.Modules["elastalertengine"] = map[string]interface{}{
		"communityRulesImportFrequencySeconds": float64(61), // not a recommended value, I'm impatient
		"elastAlertRulesFolder":                "/tmp/socdev/so/rules/elastalert",
		"rulesFingerprintFile":                 "/tmp/socdev/so/conf/soc/sigma.fingerprint",
		"sigmaRulePackages":                    "all",
		"sigconverterUrl":                      "http://localhost:8000/sigma",
	}

	return cfg, err
}
