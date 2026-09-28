// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics_test

import (
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/postgresmetrics"
	"github.com/stretchr/testify/assert"
)

func TestEvaluateCondition(t *testing.T) {
	// Numeric comparisons
	assert.True(t, postgresmetrics.EvaluateCondition("gt", "80", 85.5))
	assert.False(t, postgresmetrics.EvaluateCondition("gt", "80", 75.5))
	assert.True(t, postgresmetrics.EvaluateCondition("gte", "80", 80.0))
	assert.True(t, postgresmetrics.EvaluateCondition("lt", "20", 15.0))
	assert.False(t, postgresmetrics.EvaluateCondition("lt", "20", 25.0))
	assert.True(t, postgresmetrics.EvaluateCondition("lte", "20", 20.0))
	assert.True(t, postgresmetrics.EvaluateCondition("eq", "80", 80))
	assert.True(t, postgresmetrics.EvaluateCondition("ne", "80", 85))

	// String comparisons
	assert.True(t, postgresmetrics.EvaluateCondition("eq", "fault", "fault"))
	assert.True(t, postgresmetrics.EvaluateCondition("eq", "FAULT", "fault"))
	assert.False(t, postgresmetrics.EvaluateCondition("eq", "fault", "ok"))
	assert.True(t, postgresmetrics.EvaluateCondition("ne", "ok", "fault"))
	assert.True(t, postgresmetrics.EvaluateCondition("contains", "disk", "disk_used_root"))

	// Boolean comparisons
	assert.True(t, postgresmetrics.EvaluateCondition("eq", "true", true))
	assert.False(t, postgresmetrics.EvaluateCondition("eq", "false", true))
}

func TestExtractMetricValue(t *testing.T) {
	node := &model.Node{
		Id:              "node-1",
		CpuUsedPct:      75.5,
		MemoryUsedPct:   60.0,
		Load1m:          1.5,
		Load5m:          2.0,
		Load15m:         2.5,
		SwapUsedPct:     10.0,
		IoWaitPct:       0.5,
		DiskUsedRootPct: 45.0,
		DiskUsedNsmPct:  80.0,
		Status:          "ok",
		ProcessStatus:   "fault",
		OsNeedsRestart:  1,
	}

	val, found := postgresmetrics.ExtractMetricValue(node, "cpu", "")
	assert.True(t, found)
	assert.Equal(t, 75.5, val)

	val, found = postgresmetrics.ExtractMetricValue(node, "memory", "")
	assert.True(t, found)
	assert.Equal(t, 60.0, val)

	val, found = postgresmetrics.ExtractMetricValue(node, "load", "load5")
	assert.True(t, found)
	assert.Equal(t, 2.0, val)

	val, found = postgresmetrics.ExtractMetricValue(node, "disk", "disk_used_nsm")
	assert.True(t, found)
	assert.Equal(t, 80.0, val)

	val, found = postgresmetrics.ExtractMetricValue(node, "node_status", "")
	assert.True(t, found)
	assert.Equal(t, "ok", val)

	val, found = postgresmetrics.ExtractMetricValue(node, "process_status", "")
	assert.True(t, found)
	assert.Equal(t, "fault", val)

	val, found = postgresmetrics.ExtractMetricValue(node, "os_needs_restart", "")
	assert.True(t, found)
	assert.Equal(t, true, val)

	node.SuriRulesLoaded = 100
	node.SuriRulesFailed = 5
	node.SuriRulesStatus = "ok"
	node.SuriRulesReloadTime = "2026-09-28"
	node.HighstateAgeSeconds = 300
	node.GmdEnabled = 1
	node.LksEnabled = 1
	node.FpsEnabled = 1
	node.FailedEvents = 10
	node.DiskUsedInfluxDbGB = 2.5

	val, found = postgresmetrics.ExtractMetricValue(node, "suri_rules_loaded", "")
	assert.True(t, found)
	assert.Equal(t, float64(100), val)

	val, found = postgresmetrics.ExtractMetricValue(node, "suri_rules_failed", "")
	assert.True(t, found)
	assert.Equal(t, float64(5), val)

	val, found = postgresmetrics.ExtractMetricValue(node, "suri_rules_status", "")
	assert.True(t, found)
	assert.Equal(t, "ok", val)

	val, found = postgresmetrics.ExtractMetricValue(node, "suri_rules_reload_time", "")
	assert.True(t, found)
	assert.Equal(t, "2026-09-28", val)

	val, found = postgresmetrics.ExtractMetricValue(node, "highstate_age", "")
	assert.True(t, found)
	assert.Equal(t, float64(300), val)

	val, found = postgresmetrics.ExtractMetricValue(node, "gmd_enabled", "")
	assert.True(t, found)
	assert.Equal(t, true, val)

	val, found = postgresmetrics.ExtractMetricValue(node, "lks_enabled", "")
	assert.True(t, found)
	assert.Equal(t, true, val)

	val, found = postgresmetrics.ExtractMetricValue(node, "fps_enabled", "")
	assert.True(t, found)
	assert.Equal(t, true, val)

	val, found = postgresmetrics.ExtractMetricValue(node, "failed_events", "")
	assert.True(t, found)
	assert.Equal(t, float64(10), val)

	val, found = postgresmetrics.ExtractMetricValue(node, "influxdb_size", "")
	assert.True(t, found)
	assert.Equal(t, 2.5, val)

	_, found = postgresmetrics.ExtractMetricValue(node, "unknown_metric", "")
	assert.False(t, found)
}

func TestIsContainerMetric(t *testing.T) {
	assert.True(t, postgresmetrics.IsContainerMetric("container_cpu"))
	assert.True(t, postgresmetrics.IsContainerMetric("container_mem"))
	assert.True(t, postgresmetrics.IsContainerMetric("container_net_in"))
	assert.True(t, postgresmetrics.IsContainerMetric("container_uptime"))
	assert.False(t, postgresmetrics.IsContainerMetric("cpu"))
	assert.False(t, postgresmetrics.IsContainerMetric("memory"))
}
