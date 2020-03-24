// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package securityonion

import (
  "net/http"
  "testing"
  "github.com/sensoroni/sensoroni/module"
)

func TestSecurityOnionInit(tester *testing.T) {
  so := NewSecurityOnion(nil)
  cfg := make(module.ModuleConfig)
  err := so.Init(cfg)
  if err != nil {
    tester.Errorf("unexpected Init error: %s", err)
  }
  if len(so.elastic.esConfig.Addresses) != 1 || so.elastic.esConfig.Addresses[0] != "elasticsearch" {
    tester.Errorf("expected host %s but got %s", "elasticsearch", so.elastic.esConfig.Addresses)
  }
  if so.elastic.esConfig.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify != false {
    tester.Errorf("expected verifyCert %t but got %t", false, so.elastic.esConfig.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify)
  }
  if so.elastic.esConfig.Username != "" {
    tester.Errorf("expected username %s but got %s", "", so.elastic.esConfig.Username)
  }
  if so.elastic.esConfig.Password != "" {
    tester.Errorf("expected password %s but got %s", "", so.elastic.esConfig.Password)
  }
  if so.elastic.timeShiftMs != DEFAULT_TIME_SHIFT_MS {
    tester.Errorf("expected timeShiftMs %d but got %d", DEFAULT_TIME_SHIFT_MS, so.elastic.timeShiftMs)
  }
}
