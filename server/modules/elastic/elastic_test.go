// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package elastic

import (
  "testing"
  "time"
  "github.com/security-onion-solutions/securityonion-soc/module"
)

func TestElasticInit(tester *testing.T) {
  elastic := NewElastic(nil)
  cfg := make(module.ModuleConfig)
  err := elastic.Init(cfg)
  if err != nil {
    tester.Errorf("unexpected Init error: %s", err)
  }
  if len(elastic.store.hostUrls) != 1 || elastic.store.hostUrls[0] != "elasticsearch" {
    tester.Errorf("expected host %s but got %s", "elasticsearch", elastic.store.hostUrls[0])
  }
  if len(elastic.store.esRemoteClients) != 0 {
    tester.Errorf("expected no remote hosts but got %v", elastic.store.esRemoteClients)
  }
  if len(elastic.store.esAllClients) != 1 {
    tester.Errorf("expected no remote hosts but got %v", elastic.store.esAllClients)
  }
  if elastic.store.timeShiftMs != DEFAULT_TIME_SHIFT_MS {
    tester.Errorf("expected timeShiftMs %d but got %d", DEFAULT_TIME_SHIFT_MS, elastic.store.timeShiftMs)
  }
  if elastic.store.defaultDurationMs != DEFAULT_DURATION_MS {
    tester.Errorf("expected defaultDurationMs %d but got %d", DEFAULT_DURATION_MS, elastic.store.defaultDurationMs)
  }
  if elastic.store.esSearchOffsetMs != DEFAULT_ES_SEARCH_OFFSET_MS {
    tester.Errorf("expected esSearchOffsetMs %d but got %d", DEFAULT_ES_SEARCH_OFFSET_MS, elastic.store.esSearchOffsetMs)
  }
  if elastic.store.timeoutMs != time.Duration(DEFAULT_TIMEOUT_MS) * time.Millisecond {
    tester.Errorf("expected timeoutMs %d but got %d", DEFAULT_TIMEOUT_MS, elastic.store.timeoutMs)
  }
  if elastic.store.cacheMs != time.Duration(DEFAULT_CACHE_MS) * time.Millisecond {
    tester.Errorf("expected cacheMs %d but got %d", DEFAULT_CACHE_MS, elastic.store.cacheMs)
  }
  if elastic.store.index != DEFAULT_INDEX {
    tester.Errorf("expected index %s but got %s", DEFAULT_INDEX, elastic.store.index)
  }
}
