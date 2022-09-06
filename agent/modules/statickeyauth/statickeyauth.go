// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package statickeyauth

import (
  "errors"
  "github.com/security-onion-solutions/securityonion-soc/agent"
  "github.com/security-onion-solutions/securityonion-soc/module"
  "net/http"
)

type StaticKeyAuth struct {
  config module.ModuleConfig
  apiKey string
  agent  *agent.Agent
}

func NewStaticKeyAuth(agt *agent.Agent) *StaticKeyAuth {
  return &StaticKeyAuth{
    agent: agt,
  }
}

func (skmodule *StaticKeyAuth) PrerequisiteModules() []string {
  return nil
}

func (skmodule *StaticKeyAuth) Init(cfg module.ModuleConfig) error {
  skmodule.config = cfg
  key, err := module.GetString(cfg, "apiKey")
  if err == nil {
    skmodule.apiKey = key
    if skmodule.agent == nil {
      err = errors.New("Unable to set client auth due to nil agent")
    } else {
      skmodule.agent.Client.Auth = skmodule
    }
  }
  return err
}

func (skmodule *StaticKeyAuth) Start() error {
  return nil
}

func (skmodule *StaticKeyAuth) Stop() error {
  return nil
}

func (skmodule *StaticKeyAuth) IsRunning() bool {
  return false
}

func (skmodule *StaticKeyAuth) Authorize(request *http.Request) error {
  request.Header.Add("Authorization", skmodule.apiKey)
  return nil
}
