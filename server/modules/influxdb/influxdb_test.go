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
	"github.com/security-onion-solutions/securityonion-soc/module"
	"testing"
)

func TestInfluxDBInit(tester *testing.T) {
	influxdb := NewInfluxDB(nil)
	cfg := make(module.ModuleConfig)
	cfg["hostUrl"] = "http://some.where"
	cfg["org"] = "testorg"
	cfg["bucket"] = "testbucket"
	cfg["cacheExpirationMs"] = float64(12345)
	err := influxdb.Init(cfg)
	if err != nil {
		tester.Errorf("unexpected Init error: %s", err)
	}
	if influxdb.metrics.org != "testorg" {
		tester.Errorf("Expected testorg")
	}
	if influxdb.metrics.bucket != "testbucket" {
		tester.Errorf("Expected testbucket")
	}
	if influxdb.metrics.cacheExpirationMs != 12345 {
		tester.Errorf("Expected cacheExpirationMs to be overriden")
	}
	if influxdb.metrics.queryApi == nil {
		tester.Errorf("Expected constructed queryApi")
	}
}

func TestInfluxDBInitNoUrl(tester *testing.T) {
	influxdb := NewInfluxDB(nil)
	cfg := make(module.ModuleConfig)
	cfg["org"] = "testorg"
	cfg["bucket"] = "testbucket"
	cfg["cacheExpirationMs"] = float64(12345)
	err := influxdb.Init(cfg)
	if err != nil {
		tester.Errorf("unexpected Init error: %s", err)
	}
	if influxdb.metrics.org != "testorg" {
		tester.Errorf("Expected testorg")
	}
	if influxdb.metrics.bucket != "testbucket" {
		tester.Errorf("Expected testbucket")
	}
	if influxdb.metrics.cacheExpirationMs != 12345 {
		tester.Errorf("Expected cacheExpirationMs to be overriden")
	}
	if influxdb.metrics.queryApi != nil {
		tester.Errorf("Expected unconstructed queryApi")
	}
}

func TestInfluxDBInitDefaults(tester *testing.T) {
	influxdb := NewInfluxDB(nil)
	cfg := make(module.ModuleConfig)
	cfg["hostUrl"] = "http://some.where"
	err := influxdb.Init(cfg)
	if err != nil {
		tester.Errorf("unexpected Init error: %s", err)
	}
	if influxdb.metrics.org != DEFAULT_ORG {
		tester.Errorf("Expected default org")
	}
	if influxdb.metrics.bucket != DEFAULT_BUCKET {
		tester.Errorf("Expected default bucket but got %s", influxdb.metrics.bucket)
	}
	if influxdb.metrics.cacheExpirationMs != DEFAULT_CACHE_EXPIRATION_MS {
		tester.Errorf("Expected default cacheExpirationMs")
	}
	if influxdb.metrics.queryApi == nil {
		tester.Errorf("Expected constructed queryApi")
	}
}

func TestInfluxDBStop(tester *testing.T) {
	influxdb := NewInfluxDB(nil)
	cfg := make(module.ModuleConfig)
	cfg["hostUrl"] = "http://some.where"
	influxdb.Init(cfg)
	if !influxdb.IsRunning() {
		tester.Errorf("Expected IsRunning = true")
	}
	influxdb.Stop()
	if influxdb.IsRunning() {
		tester.Errorf("Expected IsRunning = false")
	}
}
