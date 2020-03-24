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
  "testing"
)

func TestVerifyAgent(tester *testing.T) {
  cfg := &AgentConfig{}
  err := cfg.Verify()
  if cfg.PollIntervalMs != DEFAULT_POLL_INTERVAL_MS {
    tester.Errorf("expected PollIntervalMs %d but got %d", DEFAULT_POLL_INTERVAL_MS, cfg.PollIntervalMs)
  }
  if cfg.SensorId == "" {
    tester.Errorf("expected non-empty SensorId")
  }
  if cfg.VerifyCert == true {
    tester.Errorf("expected VerifyCert to be false")
  }
  if err == nil {
    tester.Errorf("expected ServerUrl error")
  }

  cfg.PollIntervalMs = 123
  cfg.ServerUrl = "http://some.where"
  err = cfg.Verify()
  if cfg.PollIntervalMs != 123 {
    tester.Errorf("expected PollIntervalMs %d but got %d", 123, cfg.PollIntervalMs)
  }
  if err != nil {
    tester.Errorf("expected no error")
  }
}
