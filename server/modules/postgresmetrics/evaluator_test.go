// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics_test

import (
	"math"
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

func TestFormatMetricValue(t *testing.T) {
	// Default precision
	assert.Equal(t, "5.6", postgresmetrics.FormatMetricValue(5.604744403578607, "80"))
	assert.Equal(t, "85.44", postgresmetrics.FormatMetricValue(85.4351, "80"))
	assert.Equal(t, "100", postgresmetrics.FormatMetricValue(99.999, "80"))
	assert.Equal(t, "86400", postgresmetrics.FormatMetricValue(float64(86400), "80"))
	assert.Equal(t, "0", postgresmetrics.FormatMetricValue(0.001, "80"))
	assert.Equal(t, "0", postgresmetrics.FormatMetricValue(-0.001, "80"))
	assert.Equal(t, "-1.5", postgresmetrics.FormatMetricValue(-1.5, "0"))
	assert.Equal(t, "2.5", postgresmetrics.FormatMetricValue(float32(2.5), "0"))
	assert.Equal(t, "85.44", postgresmetrics.FormatMetricValue(85.4351, "80.5"))
	assert.Equal(t, "85.44", postgresmetrics.FormatMetricValue(85.4351, "fault"))
	assert.Equal(t, "85.44", postgresmetrics.FormatMetricValue(85.4351, ""))

	// One more place than the threshold, when that exceeds the default
	assert.Equal(t, "85.441", postgresmetrics.FormatMetricValue(85.441, "85.44"))
	assert.Equal(t, "0.0014", postgresmetrics.FormatMetricValue(0.00144, "0.001"))
	assert.Equal(t, "85.4351", postgresmetrics.FormatMetricValue(85.4351, " 85.4350 "))
	assert.Equal(t, "85.5", postgresmetrics.FormatMetricValue(85.5, "85.4350"))

	// Exponent thresholds count the places of their expanded form
	assert.Equal(t, "0.0012", postgresmetrics.FormatMetricValue(0.0012, "1e-3"))
	assert.Equal(t, "1500.25", postgresmetrics.FormatMetricValue(1500.254, "1.5e3"))

	// Extra places when the value differs from the threshold but would render equal to it
	assert.Equal(t, "80.004", postgresmetrics.FormatMetricValue(80.004, "80"))
	assert.Equal(t, "99.999", postgresmetrics.FormatMetricValue(99.999, "100"))
	assert.Equal(t, "0.001", postgresmetrics.FormatMetricValue(0.001, "0"))
	assert.Equal(t, "-0.001", postgresmetrics.FormatMetricValue(-0.001, "0"))
	assert.Equal(t, "85.44001", postgresmetrics.FormatMetricValue(85.44001, "85.44"))
	assert.Equal(t, "80", postgresmetrics.FormatMetricValue(float64(80), "80"))
	assert.Equal(t, "85.44", postgresmetrics.FormatMetricValue(85.4351, "NaN"))

	// Non-finite and non-float values
	assert.Equal(t, "NaN", postgresmetrics.FormatMetricValue(math.NaN(), "80"))
	assert.Equal(t, "+Inf", postgresmetrics.FormatMetricValue(math.Inf(1), "80"))
	assert.Equal(t, "fault", postgresmetrics.FormatMetricValue("fault", "fault"))
	assert.Equal(t, "42", postgresmetrics.FormatMetricValue(42, "80"))
	assert.Equal(t, "<nil>", postgresmetrics.FormatMetricValue(nil, "80"))
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

func TestDefaultAlarmMetrics(t *testing.T) {
	metrics := postgresmetrics.DefaultAlarmMetrics()
	assert.NotEmpty(t, metrics)

	info, found := postgresmetrics.GetAlarmMetricInfo("cpu")
	assert.True(t, found)
	assert.NotNil(t, info)
	assert.Equal(t, "cpu", info.Metric)
	assert.Equal(t, "numeric", info.Type)
	assert.Equal(t, "node", info.Scope)

	info, found = postgresmetrics.GetAlarmMetricInfo("container_cpu")
	assert.True(t, found)
	assert.NotNil(t, info)
	assert.Equal(t, "container_cpu", info.Metric)
	assert.Equal(t, "container", info.Scope)

	_, found = postgresmetrics.GetAlarmMetricInfo("non_existent_metric")
	assert.False(t, found)
}

func TestValidateAlarmThreshold(t *testing.T) {
	// Numeric
	assert.NoError(t, postgresmetrics.ValidateAlarmThreshold("cpu", "80"))
	assert.NoError(t, postgresmetrics.ValidateAlarmThreshold("cpu", "80.5"))
	assert.Error(t, postgresmetrics.ValidateAlarmThreshold("cpu", "80%"))
	assert.Error(t, postgresmetrics.ValidateAlarmThreshold("cpu", "invalid"))
	assert.Error(t, postgresmetrics.ValidateAlarmThreshold("cpu", ""))

	// Boolean
	assert.NoError(t, postgresmetrics.ValidateAlarmThreshold("os_needs_restart", "true"))
	assert.NoError(t, postgresmetrics.ValidateAlarmThreshold("os_needs_restart", "false"))
	assert.NoError(t, postgresmetrics.ValidateAlarmThreshold("os_needs_restart", "1"))
	assert.NoError(t, postgresmetrics.ValidateAlarmThreshold("os_needs_restart", "0"))
	assert.Error(t, postgresmetrics.ValidateAlarmThreshold("os_needs_restart", "maybe"))
	assert.Error(t, postgresmetrics.ValidateAlarmThreshold("os_needs_restart", "80"))

	// String
	assert.NoError(t, postgresmetrics.ValidateAlarmThreshold("node_status", "fault"))
	assert.NoError(t, postgresmetrics.ValidateAlarmThreshold("node_status", "OK"))
	assert.Error(t, postgresmetrics.ValidateAlarmThreshold("node_status", ""))
}
