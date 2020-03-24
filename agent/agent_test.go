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
  "testing"
  "github.com/sensoroni/sensoroni/config"
)

func TestNewAgent(tester *testing.T) {
  cfg := &config.AgentConfig{}
  cfg.ServerUrl = "http://some.where"
  agent := NewAgent(cfg, "")
  if agent.Client == nil {
    tester.Errorf("expected non-nil agent.Client")
  }
  if agent.JobMgr == nil {
    tester.Errorf("expected non-nil agent.JobMgr")
  }
  if agent.stoppedChan == nil {
    tester.Errorf("expected non-nil agent.stoppedChan")
  }
}
