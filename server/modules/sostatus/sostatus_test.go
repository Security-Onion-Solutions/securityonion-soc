// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package sostatus

import (
	"testing"
)

func TestSoStatusInit(tester *testing.T) {
	status := NewSoStatus(nil)
	cfg := make(map[string]interface{})
	cfg["refreshIntervalMs"] = float64(1000)
	cfg["offlineThresholdMs"] = float64(2000)
	err := status.Init(cfg)
	if err != nil {
		tester.Errorf("unexpected Init error")
	}
	if status.refreshIntervalMs != 1000 {
		tester.Errorf("Unexpected refresh interval value %d", status.refreshIntervalMs)
	}
	if status.offlineThresholdMs != 2000 {
		tester.Errorf("Unexpected threshold value %d", status.offlineThresholdMs)
	}
}
