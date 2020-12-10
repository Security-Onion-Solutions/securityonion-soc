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
  "github.com/security-onion-solutions/securityonion-soc/model"
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

func validateQuery(tester *testing.T, actual string, expected string) {
  if actual != expected {
    tester.Errorf("expected '%s' but got '%s'", expected, actual)
  }
}

func TestBuildQuery(tester *testing.T) {
  importer := NewImporter(nil)
  job := model.NewJob()

  query := importer.buildQuery(job)
  validateQuery(tester, query, "")

  job.Filter.SrcIp = "1.2.3.4"
  query = importer.buildQuery(job)
  validateQuery(tester, query, " host 1.2.3.4")

  job.Filter.DstIp = "4.3.2.1"
  query = importer.buildQuery(job)
  validateQuery(tester, query, " host 1.2.3.4 and host 4.3.2.1")

  job.Filter.DstPort = 53
  query = importer.buildQuery(job)
  validateQuery(tester, query, " host 1.2.3.4 and host 4.3.2.1 and port 53")

  job.Filter.SrcPort = 33
  query = importer.buildQuery(job)
  validateQuery(tester, query, " host 1.2.3.4 and host 4.3.2.1 and port 33 and port 53")
}