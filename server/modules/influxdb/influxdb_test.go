// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package influxdb

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/stretchr/testify/assert"
)

func TestInfluxDBInit(tester *testing.T) {
	influxdb := NewInfluxDB(nil)
	cfg := make(module.ModuleConfig)
	cfg["hostUrl"] = "http://some.where"
	cfg["org"] = "testorg"
	cfg["bucket"] = "testbucket"
	cfg["cacheExpirationMs"] = float64(12345)
	err := influxdb.Init(cfg)
	if assert.Nil(tester, err) {
		assert.Equal(tester, cfg["org"], influxdb.metrics.org)
		assert.Equal(tester, cfg["bucket"], influxdb.metrics.bucket)
		excpectedCacheExpirationMs := int(cfg["cacheExpirationMs"].(float64))
		assert.Equal(tester, excpectedCacheExpirationMs, influxdb.metrics.cacheExpirationMs)
		assert.NotNil(tester, influxdb.metrics.queryApi)
	}
}

func TestInfluxDBInitNoUrl(tester *testing.T) {
	influxdb := NewInfluxDB(nil)
	cfg := make(module.ModuleConfig)
	cfg["org"] = "testorg"
	cfg["bucket"] = "testbucket"
	cfg["cacheExpirationMs"] = float64(12345)
	err := influxdb.Init(cfg)
	if assert.Nil(tester, err) {
		assert.Equal(tester, cfg["org"], influxdb.metrics.org)
		assert.Equal(tester, cfg["bucket"], influxdb.metrics.bucket)
		excpectedCacheExpirationMs := int(cfg["cacheExpirationMs"].(float64))
		assert.Equal(tester, excpectedCacheExpirationMs, influxdb.metrics.cacheExpirationMs)
		assert.Nil(tester, influxdb.metrics.queryApi)
	}
}

func TestInfluxDBInitDefaults(tester *testing.T) {
	influxdb := NewInfluxDB(nil)
	cfg := make(module.ModuleConfig)
	cfg["hostUrl"] = "http://some.where"
	err := influxdb.Init(cfg)
	if assert.Nil(tester, err) {
		assert.Equal(tester, DEFAULT_ORG, influxdb.metrics.org)
		assert.Equal(tester, DEFAULT_BUCKET, influxdb.metrics.bucket)
		assert.Equal(tester, DEFAULT_CACHE_EXPIRATION_MS, influxdb.metrics.cacheExpirationMs)
		assert.NotNil(tester, influxdb.metrics.queryApi)
	}
}

func TestInfluxDBStop(tester *testing.T) {
	influxdb := NewInfluxDB(nil)
	cfg := make(module.ModuleConfig)
	cfg["hostUrl"] = "http://some.where"
	influxdb.Init(cfg)
	assert.True(tester, influxdb.IsRunning())
	influxdb.Stop()
	assert.False(tester, influxdb.IsRunning())
}
