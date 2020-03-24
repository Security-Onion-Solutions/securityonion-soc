// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package statickeyauth

import (
  "errors"
  "net/http"
  "github.com/sensoroni/sensoroni/agent"
  "github.com/sensoroni/sensoroni/module"
)

type StaticKeyAuth struct {
  config			module.ModuleConfig
  apiKey			string
  agent				*agent.Agent
}

func NewStaticKeyAuth(agt *agent.Agent) *StaticKeyAuth {
  return &StaticKeyAuth {
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
