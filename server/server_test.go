// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
  "testing"
  "github.com/sensoroni/sensoroni/config"
)

func TestNewServer(tester *testing.T) {
  cfg := &config.ServerConfig{}
  srv := NewServer(cfg, "")
  if srv.Host == nil {
    tester.Errorf("expected non-nil Host")
  }
  if srv.stoppedChan == nil {
    tester.Errorf("expected non-nil stoppedChan")
  }
}
