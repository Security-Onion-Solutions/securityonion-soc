// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package influxdb

import (
	"context"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func newContext() context.Context {
	return context.Background()
}

func TestConvertValuesToString(tester *testing.T) {
	metrics := NewInfluxDBMetrics(server.NewFakeAuthorizedServer(nil))
	values := make(map[string]interface{})
	values["foo"] = "bar"
	values["bar"] = 1
	strValues := metrics.convertValuesToString(values)
	assert.Equal(tester, values["foo"], strValues["foo"])
}

func TestConvertValuesToInt(tester *testing.T) {
	metrics := NewInfluxDBMetrics(server.NewFakeAuthorizedServer(nil))
	values := make(map[string]interface{})
	values["foo"] = 1234
	values["bar"] = 9876.1
	values["zoo"] = "garbage"
	intValues := metrics.convertValuesToInt(values)
	assert.Equal(tester, values["foo"], intValues["foo"])
	expectedBarVal := int(values["bar"].(float64))
	assert.Equal(tester, expectedBarVal, intValues["bar"], "float64 should be cast to int")
}

func TestGetRaidStatus(tester *testing.T) {
	metrics := NewInfluxDBMetrics(server.NewFakeAuthorizedServer(nil))
	metrics.lastRaidUpdateTime = time.Now()
	metrics.raidStatus["foo"] = 0
	metrics.raidStatus["bar"] = 1

	assert.Equal(tester, model.NodeStatusOk, metrics.getRaidStatus("foo"))
	assert.Equal(tester, model.NodeStatusFault, metrics.getRaidStatus("bar"))
	assert.Equal(tester, model.NodeStatusUnknown, metrics.getRaidStatus("missing"))
}

func TestGetProcessJson(tester *testing.T) {
	metrics := NewInfluxDBMetrics(server.NewFakeAuthorizedServer(nil))
	metrics.lastProcessUpdateTime = time.Now()
	metrics.processJson["foo"] = `{"some":"value"}`
	metrics.processJson["bar"] = `{"some":"other"}`

	assert.Equal(tester, `{"some":"value"}`, metrics.getProcessJson("foo"))
	assert.Equal(tester, `{"some":"other"}`, metrics.getProcessJson("bar"))
	assert.Equal(tester, ``, metrics.getProcessJson("missing"))
}

func TestGetProcessStatus(tester *testing.T) {
	metrics := NewInfluxDBMetrics(server.NewFakeAuthorizedServer(nil))
	metrics.lastProcessUpdateTime = time.Now()
	metrics.processStatus["foo"] = 0
	metrics.processStatus["bar"] = 1

	assert.Equal(tester, model.NodeStatusOk, metrics.getProcessStatus("foo"))
	assert.Equal(tester, model.NodeStatusFault, metrics.getProcessStatus("bar"))
	assert.Equal(tester, model.NodeStatusUnknown, metrics.getProcessStatus("missing"))
}

func TestGetProductionEps(tester *testing.T) {
	metrics := NewInfluxDBMetrics(server.NewFakeAuthorizedServer(nil))
	metrics.lastEpsUpdateTime = time.Now()
	metrics.productionEps["foo"] = 0
	metrics.productionEps["bar"] = 1
	metrics.productionEps["zoo"] = 2

	assert.Equal(tester, 0, metrics.getProductionEps("foo"))
	assert.Equal(tester, 1, metrics.getProductionEps("bar"))
	assert.Equal(tester, 2, metrics.getProductionEps("zoo"))
	assert.Equal(tester, 0, metrics.getProductionEps("missing"))
}

func TestGetConsumptionEps(tester *testing.T) {
	metrics := NewInfluxDBMetrics(server.NewFakeAuthorizedServer(nil))
	metrics.lastEpsUpdateTime = time.Now()
	metrics.consumptionEps["foo"] = 0
	metrics.consumptionEps["bar"] = 1
	metrics.consumptionEps["zoo"] = 2

	assert.Equal(tester, 0, metrics.getConsumptionEps("foo"))
	assert.Equal(tester, 1, metrics.getConsumptionEps("bar"))
	assert.Equal(tester, 2, metrics.getConsumptionEps("zoo"))
	assert.Equal(tester, 0, metrics.getConsumptionEps("missing"))
	assert.Equal(tester, 3, metrics.GetGridEps(newContext()))
}

func TestGetFailedEvents(tester *testing.T) {
	metrics := NewInfluxDBMetrics(server.NewFakeAuthorizedServer(nil))
	metrics.lastEpsUpdateTime = time.Now()
	metrics.failedEvents["foo"] = 0
	metrics.failedEvents["bar"] = 1
	metrics.failedEvents["zoo"] = 2

	assert.Equal(tester, 0, metrics.getFailedEvents("foo"))
	assert.Equal(tester, 1, metrics.getFailedEvents("bar"))
	assert.Equal(tester, 2, metrics.getFailedEvents("zoo"))
	assert.Equal(tester, 0, metrics.getFailedEvents("missing"))
}
