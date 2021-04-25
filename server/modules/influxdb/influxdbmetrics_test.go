// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package influxdb

import (
	"github.com/security-onion-solutions/securityonion-soc/model"
	"testing"
	"time"
)

func TestConvertValuesToString(tester *testing.T) {
	metrics := NewInfluxDBMetrics()
	values := make(map[string]interface{})
	values["foo"] = "bar"
	values["bar"] = 1
	strValues := metrics.convertValuesToString(values)
	if strValues["foo"] != "bar" {
		tester.Errorf("Expected bar string but got %v", strValues["foo"])
	}
}

func TestConvertValuesToInt(tester *testing.T) {
	metrics := NewInfluxDBMetrics()
	values := make(map[string]interface{})
	values["foo"] = 1234
	values["bar"] = 9876.1
	values["zoo"] = "garbage"
	intValues := metrics.convertValuesToInt(values)
	if intValues["foo"] != 1234 {
		tester.Errorf("Expected 1234 int but got %v", intValues["foo"])
	}
	if intValues["bar"] != 9876 {
		tester.Errorf("Expected 9876 int but got %v", intValues["bar"])
	}
}

func TestGetRaidStatus(tester *testing.T) {
	metrics := NewInfluxDBMetrics()
	metrics.lastRaidUpdateTime = time.Now()
	metrics.raidStatus["foo"] = 0
	metrics.raidStatus["bar"] = 1

	if metrics.getRaidStatus("foo") != model.NodeStatusOk {
		tester.Errorf("Expected ok status but got %s", metrics.getRaidStatus("foo"))
	}
	if metrics.getRaidStatus("bar") != model.NodeStatusFault {
		tester.Errorf("Expected fault status but got %s", metrics.getRaidStatus("foo"))
	}
	if metrics.getRaidStatus("no") != model.NodeStatusUnknown {
		tester.Errorf("Expected unknown status but got %s", metrics.getRaidStatus("foo"))
	}
}

func TestGetProcessStatus(tester *testing.T) {
	metrics := NewInfluxDBMetrics()
	metrics.lastProcessUpdateTime = time.Now()
	metrics.processStatus["foo"] = 0
	metrics.processStatus["bar"] = 1

	if metrics.getProcessStatus("foo") != model.NodeStatusOk {
		tester.Errorf("Expected ok status but got %s", metrics.getProcessStatus("foo"))
	}
	if metrics.getProcessStatus("bar") != model.NodeStatusFault {
		tester.Errorf("Expected fault status but got %s", metrics.getProcessStatus("foo"))
	}
	if metrics.getProcessStatus("no") != model.NodeStatusUnknown {
		tester.Errorf("Expected unknown status but got %s", metrics.getProcessStatus("foo"))
	}
}

func TestGetProductionEps(tester *testing.T) {
	metrics := NewInfluxDBMetrics()
	metrics.lastEpsUpdateTime = time.Now()
	metrics.productionEps["foo"] = 0
	metrics.productionEps["bar"] = 1
	metrics.productionEps["zoo"] = 2

	if metrics.getProductionEps("foo") != 0 {
		tester.Errorf("Expected 0 but got %d", metrics.getProductionEps("foo"))
	}
	if metrics.getProductionEps("bar") != 1 {
		tester.Errorf("Expected 1 but got %d", metrics.getProductionEps("bar"))
	}
	if metrics.getProductionEps("zoo") != 2 {
		tester.Errorf("Expected 2 but got %d", metrics.getProductionEps("zoo"))
	}
}

func TestGetConsumptionEps(tester *testing.T) {
	metrics := NewInfluxDBMetrics()
	metrics.lastEpsUpdateTime = time.Now()
	metrics.consumptionEps["foo"] = 0
	metrics.consumptionEps["bar"] = 1
	metrics.consumptionEps["zoo"] = 2

	if metrics.getConsumptionEps("foo") != 0 {
		tester.Errorf("Expected 0 but got %d", metrics.getConsumptionEps("foo"))
	}
	if metrics.getConsumptionEps("bar") != 1 {
		tester.Errorf("Expected 1 but got %d", metrics.getConsumptionEps("bar"))
	}
	if metrics.getConsumptionEps("zoo") != 2 {
		tester.Errorf("Expected 2 but got %d", metrics.getConsumptionEps("zoo"))
	}
	if metrics.GetGridEps() != 3 {
		tester.Errorf("Expected 3 but got %d", metrics.GetGridEps())
	}
}

func TestGetFailedEvents(tester *testing.T) {
	metrics := NewInfluxDBMetrics()
	metrics.lastEpsUpdateTime = time.Now()
	metrics.failedEvents["foo"] = 0
	metrics.failedEvents["bar"] = 1
	metrics.failedEvents["zoo"] = 2

	if metrics.getFailedEvents("foo") != 0 {
		tester.Errorf("Expected 0 but got %d", metrics.getFailedEvents("foo"))
	}
	if metrics.getFailedEvents("bar") != 1 {
		tester.Errorf("Expected 1 but got %d", metrics.getFailedEvents("bar"))
	}
	if metrics.getFailedEvents("zoo") != 2 {
		tester.Errorf("Expected 2 but got %d", metrics.getFailedEvents("zoo"))
	}
}
