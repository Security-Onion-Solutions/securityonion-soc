// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package importer

import (
  "testing"
  "time"
)

func TestInitImporter(tester *testing.T) {
  cfg := make(map[string]interface{})
  sq := NewImporter(nil)
  err := sq.Init(cfg)
  if err == nil {
    tester.Errorf("expected non-nil error during init")
  }
  if sq.executablePath != DEFAULT_EXECUTABLE_PATH {
    tester.Errorf("expected executablePath of %s but got %s", DEFAULT_EXECUTABLE_PATH, sq.executablePath)
  }
  if sq.pcapOutputPath != DEFAULT_PCAP_OUTPUT_PATH {
    tester.Errorf("expected pcapOutputPath of %s but got %s", DEFAULT_PCAP_OUTPUT_PATH, sq.pcapOutputPath)
  }
  if sq.pcapInputPath != DEFAULT_PCAP_INPUT_PATH {
    tester.Errorf("expected pcapInputPath of %s but got %s", DEFAULT_PCAP_INPUT_PATH, sq.pcapInputPath)
  }
  if sq.timeoutMs != DEFAULT_TIMEOUT_MS {
    tester.Errorf("expected timeoutMs of %d but got %d", DEFAULT_TIMEOUT_MS, sq.timeoutMs)
  }
}

func TestDataLag(tester *testing.T) {
  cfg := make(map[string]interface{})
  sq := NewImporter(nil)
  sq.Init(cfg)
  epoch := sq.GetDataEpoch()
  if epoch.After(time.Now()) {
    tester.Errorf("expected epoch date to be before or equal to current date")
  }
}
