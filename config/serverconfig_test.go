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

func TestVerifyServer(tester *testing.T) {
  cfg := &ServerConfig{}
  err := cfg.Verify()
  if cfg.MaxPacketCount != DEFAULT_MAX_PACKET_COUNT {
    tester.Errorf("expected MaxPacketCount %d but got %d", DEFAULT_MAX_PACKET_COUNT, cfg.MaxPacketCount)
  }
  if err == nil {
    tester.Errorf("expected bind address error")
  }

  cfg.BindAddress = "http://some.where"
  cfg.MaxPacketCount = 123
  err = cfg.Verify()
  if cfg.MaxPacketCount != 123 {
    tester.Errorf("expected PollIntervalMs %d but got %d", 123, cfg.MaxPacketCount)
  }
  if err != nil {
    tester.Errorf("expected no error")
  }
}
