// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgresmetrics

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

var defaultAlarmMetrics = []model.AlarmMetricInfo{
	{Metric: "cpu", TitleKey: "metricsCpuUsage", Keys: []string{"cpu_used"}, LabelKeys: []string{"cpuUsageAbbr"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeNode},
	{Metric: "memory", TitleKey: "metricsMemUsage", Keys: []string{"memory_used"}, LabelKeys: []string{"memUsageAbbr"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeNode},
	{Metric: "load", TitleKey: "metricsLoadAverage", Keys: []string{"load1", "load5", "load15"}, LabelKeys: []string{"metricsLoad1", "metricsLoad5", "metricsLoad15"}, Type: model.AlarmMetricTypeNumeric, Scope: model.AlarmMetricScopeNode},
	{Metric: "swap", TitleKey: "swapUsage", Keys: []string{"swap_used"}, LabelKeys: []string{"swapUsage"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeNode},
	{Metric: "io_wait", TitleKey: "metricsIoWait", Keys: []string{"io_wait"}, LabelKeys: []string{"metricsIoWait"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeNode},
	{Metric: "disk", TitleKey: "metricsDiskUsage", Keys: []string{"disk_used_root", "disk_used_nsm"}, LabelKeys: []string{"diskUsageRootAbbr", "diskUsageNsmAbbr"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeNode},
	{Metric: "system_uptime", TitleKey: "metricsSystemUptime", Keys: []string{"system_uptime"}, LabelKeys: []string{"metricsUptimeDays"}, Type: model.AlarmMetricTypeNumeric, Units: "seconds", Scope: model.AlarmMetricScopeNode},
	{Metric: "elasticsearch_size", TitleKey: "metricsElasticsearchSize", Keys: []string{"elasticsearch_size"}, LabelKeys: []string{"metricsStorageSize"}, Type: model.AlarmMetricTypeNumeric, Units: "gb", Scope: model.AlarmMetricScopeNode},
	{Metric: "influxdb_size", TitleKey: "diskUsageInfluxDb", Keys: []string{"influxdb_size"}, LabelKeys: []string{"metricsStorageSize"}, Type: model.AlarmMetricTypeNumeric, Units: "gb", Scope: model.AlarmMetricScopeNode},
	{Metric: "redis_queue", TitleKey: "metricsRedisQueue", Keys: []string{"redis_queue"}, LabelKeys: []string{"metricsQueueSize"}, Type: model.AlarmMetricTypeNumeric, Scope: model.AlarmMetricScopeNode},
	{Metric: "pcap_retention", TitleKey: "metricsPcapRetention", Keys: []string{"pcap_retention"}, LabelKeys: []string{"metricsRetentionDays"}, Type: model.AlarmMetricTypeNumeric, Units: "days", Scope: model.AlarmMetricScopeNode},
	{Metric: "eps", TitleKey: "eps", Keys: []string{"consumption_eps", "production_eps"}, LabelKeys: []string{"metricsConsumptionEps", "metricsProductionEps"}, Type: model.AlarmMetricTypeNumeric, Scope: model.AlarmMetricScopeNode},
	{Metric: "failed_events", TitleKey: "failedEvents", Keys: []string{"failed_events"}, LabelKeys: []string{"failedEvents"}, Type: model.AlarmMetricTypeNumeric, Scope: model.AlarmMetricScopeNode},
	{Metric: "loss", TitleKey: "metricsLoss", Keys: []string{"suricata_loss", "zeek_loss"}, LabelKeys: []string{"suricataLoss", "zeekLoss"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeNode},
	{Metric: "capture_loss", TitleKey: "metricsCaptureLoss", Keys: []string{"zeek_capture_loss"}, LabelKeys: []string{"metricsLoss"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeNode},
	{Metric: "net", TitleKey: "metricsNetTraffic", Keys: []string{"traffic_man_in", "traffic_man_out", "traffic_mon_in"}, LabelKeys: []string{"metricsTrafficManIn", "metricsTrafficManOut", "metricsTrafficMonIn"}, Type: model.AlarmMetricTypeNumeric, Units: "mbs", Scope: model.AlarmMetricScopeNode},
	{Metric: "net_drops", TitleKey: "metricsMonitorDrops", Keys: []string{"traffic_mon_drops"}, LabelKeys: []string{"metricsDrops"}, Type: model.AlarmMetricTypeNumeric, Units: "mbs", Scope: model.AlarmMetricScopeNode},
	{Metric: "container_cpu", TitleKey: "metricsContainerCpu", Keys: []string{"container_cpu"}, LabelKeys: []string{"metricsCpuPct"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeContainer},
	{Metric: "container_mem", TitleKey: "metricsContainerMem", Keys: []string{"container_mem"}, LabelKeys: []string{"metricsMemPct"}, Type: model.AlarmMetricTypeNumeric, Units: "percent", Scope: model.AlarmMetricScopeContainer},
	{Metric: "container_net_in", TitleKey: "metricsContainerNetIn", Keys: []string{"container_net_in"}, LabelKeys: []string{"metricsTrafficMonIn"}, Type: model.AlarmMetricTypeNumeric, Units: "bits", Scope: model.AlarmMetricScopeContainer},
	{Metric: "container_uptime", TitleKey: "metricsContainerUptime", Keys: []string{"container_uptime"}, LabelKeys: []string{"metricsUptime"}, Type: model.AlarmMetricTypeNumeric, Units: "seconds", Scope: model.AlarmMetricScopeContainer},
	{Metric: "node_status", TitleKey: "nodeStatus", Keys: []string{"status"}, LabelKeys: []string{"status"}, Type: model.AlarmMetricTypeString, Scope: model.AlarmMetricScopeNode},
	{Metric: "connection_status", TitleKey: "nodeStatusConnection", Keys: []string{"connectionStatus"}, LabelKeys: []string{"connectionStatus"}, Type: model.AlarmMetricTypeString, Scope: model.AlarmMetricScopeNode},
	{Metric: "raid_status", TitleKey: "nodeStatusRaid", Keys: []string{"raidStatus"}, LabelKeys: []string{"raidStatus"}, Type: model.AlarmMetricTypeString, Scope: model.AlarmMetricScopeNode},
	{Metric: "process_status", TitleKey: "nodeStatusProcess", Keys: []string{"processStatus"}, LabelKeys: []string{"processStatus"}, Type: model.AlarmMetricTypeString, Scope: model.AlarmMetricScopeNode},
	{Metric: "eventstore_status", TitleKey: "eventstoreStatus", Keys: []string{"eventstoreStatus"}, LabelKeys: []string{"eventstoreStatus"}, Type: model.AlarmMetricTypeString, Scope: model.AlarmMetricScopeNode},
	{Metric: "os_needs_restart", TitleKey: "restartRequired", Keys: []string{"osNeedsRestart"}, LabelKeys: []string{"restartRequired"}, Type: model.AlarmMetricTypeBool, Scope: model.AlarmMetricScopeNode},
	{Metric: "suri_rules_loaded", TitleKey: "suriRulesLoaded", Keys: []string{"suriRulesLoaded"}, LabelKeys: []string{"suriRulesLoaded"}, Type: model.AlarmMetricTypeNumeric, Scope: model.AlarmMetricScopeNode},
	{Metric: "suri_rules_failed", TitleKey: "suriRulesFailed", Keys: []string{"suriRulesFailed"}, LabelKeys: []string{"suriRulesFailed"}, Type: model.AlarmMetricTypeNumeric, Scope: model.AlarmMetricScopeNode},
	{Metric: "suri_rules_status", TitleKey: "suriRulesStatus", Keys: []string{"suriRulesStatus"}, LabelKeys: []string{"suriRulesStatus"}, Type: model.AlarmMetricTypeString, Scope: model.AlarmMetricScopeNode},
	{Metric: "suri_rules_reload_time", TitleKey: "suriRulesReloadTime", Keys: []string{"suriRulesReloadTime"}, LabelKeys: []string{"suriRulesReloadTime"}, Type: model.AlarmMetricTypeString, Scope: model.AlarmMetricScopeNode},
	{Metric: "highstate_age", TitleKey: "lastHighstate", Keys: []string{"highstateAgeSeconds"}, LabelKeys: []string{"lastHighstate"}, Type: model.AlarmMetricTypeNumeric, Units: "seconds", Scope: model.AlarmMetricScopeNode},
	{Metric: "gmd_enabled", TitleKey: "gmd", Keys: []string{"gmdEnabled"}, LabelKeys: []string{"gmd"}, Type: model.AlarmMetricTypeBool, Scope: model.AlarmMetricScopeNode},
	{Metric: "lks_enabled", TitleKey: "lks", Keys: []string{"lksEnabled"}, LabelKeys: []string{"lks"}, Type: model.AlarmMetricTypeBool, Scope: model.AlarmMetricScopeNode},
	{Metric: "fps_enabled", TitleKey: "fps", Keys: []string{"fpsEnabled"}, LabelKeys: []string{"fps"}, Type: model.AlarmMetricTypeBool, Scope: model.AlarmMetricScopeNode},
}

// DefaultAlarmMetrics returns available grid metric metadata for alarm configurations.
func DefaultAlarmMetrics() []model.AlarmMetricInfo {
	res := make([]model.AlarmMetricInfo, len(defaultAlarmMetrics))
	copy(res, defaultAlarmMetrics)
	return res
}

// GetAlarmMetricInfo returns the AlarmMetricInfo for a given metric name.
func GetAlarmMetricInfo(metric string) (*model.AlarmMetricInfo, bool) {
	name := strings.ToLower(strings.TrimSpace(metric))
	for i := range defaultAlarmMetrics {
		if strings.ToLower(defaultAlarmMetrics[i].Metric) == name {
			return &defaultAlarmMetrics[i], true
		}
	}
	return nil, false
}

// IsContainerMetric returns true if the metric targets container-level metrics across a node.
func IsContainerMetric(metric string) bool {
	if info, found := GetAlarmMetricInfo(metric); found {
		return info.Scope == model.AlarmMetricScopeContainer
	}
	return false
}

// ValidateAlarmThreshold checks that the threshold is valid for the given metric type.
func ValidateAlarmThreshold(metric, threshold string) error {
	trimmed := strings.TrimSpace(threshold)
	if trimmed == "" {
		return errors.New("alarm threshold is required")
	}
	if len(trimmed) > model.MAX_ALARM_THRESHOLD_LEN {
		return errors.New("alarm threshold exceeds maximum allowed length")
	}

	info, found := GetAlarmMetricInfo(metric)
	if !found {
		return nil
	}

	switch info.Type {
	case model.AlarmMetricTypeBool:
		if trimmed != "true" && trimmed != "false" && trimmed != "1" && trimmed != "0" {
			return errors.New("alarm threshold must be a boolean value (true/false)")
		}
	case model.AlarmMetricTypeString:
		return nil
	default:
		if _, err := strconv.ParseFloat(trimmed, 64); err != nil {
			return errors.New("alarm threshold must be a valid number")
		}
	}
	return nil
}

// EvaluateCondition evaluates whether an actual metric value breaches the configured threshold.
func EvaluateCondition(op string, thresholdStr string, actualVal any) bool {
	normOp := model.NormalizeOperator(op)
	actualStr := fmt.Sprintf("%v", actualVal)

	// Try numeric comparison first
	thresholdNum, errThresh := strconv.ParseFloat(strings.TrimSpace(thresholdStr), 64)
	actualNum, errActual := strconv.ParseFloat(strings.TrimSpace(actualStr), 64)

	if errThresh == nil && errActual == nil {
		switch normOp {
		case model.AlarmOperatorGT:
			return actualNum > thresholdNum
		case model.AlarmOperatorGTE:
			return actualNum >= thresholdNum
		case model.AlarmOperatorLT:
			return actualNum < thresholdNum
		case model.AlarmOperatorLTE:
			return actualNum <= thresholdNum
		case model.AlarmOperatorEQ:
			return math.Abs(actualNum-thresholdNum) < 1e-9
		case model.AlarmOperatorNEQ:
			return math.Abs(actualNum-thresholdNum) >= 1e-9
		}
	}

	// String / Boolean comparisons
	tLower := strings.ToLower(strings.TrimSpace(thresholdStr))
	aLower := strings.ToLower(strings.TrimSpace(actualStr))

	switch normOp {
	case model.AlarmOperatorEQ:
		return aLower == tLower
	case model.AlarmOperatorNEQ:
		return aLower != tLower
	case model.AlarmOperatorContains:
		return strings.Contains(aLower, tLower)
	case model.AlarmOperatorGT:
		return actualStr > thresholdStr
	case model.AlarmOperatorGTE:
		return actualStr >= thresholdStr
	case model.AlarmOperatorLT:
		return actualStr < thresholdStr
	case model.AlarmOperatorLTE:
		return actualStr <= thresholdStr
	default:
		return false
	}
}

// ExtractMetricValue extracts the metric value from a Node model struct.
func ExtractMetricValue(node *model.Node, metric, key string) (any, bool) {
	if node == nil {
		return nil, false
	}
	switch metric {
	case "cpu":
		return node.CpuUsedPct, true
	case "memory":
		return node.MemoryUsedPct, true
	case "load":
		switch key {
		case "load5":
			return node.Load5m, true
		case "load15":
			return node.Load15m, true
		default:
			return node.Load1m, true
		}
	case "swap":
		return node.SwapUsedPct, true
	case "io_wait":
		return node.IoWaitPct, true
	case "disk":
		if key == "disk_used_nsm" {
			return node.DiskUsedNsmPct, true
		}
		return node.DiskUsedRootPct, true
	case "system_uptime":
		return float64(node.OsUptimeSeconds), true
	case "elasticsearch_size":
		return node.DiskUsedElasticGB, true
	case "influxdb_size":
		return node.DiskUsedInfluxDbGB, true
	case "redis_queue":
		return float64(node.RedisQueueSize), true
	case "pcap_retention":
		return node.PcapDays, true
	case "eps":
		if key == "production_eps" {
			return float64(node.ProductionEps), true
		}
		return float64(node.ConsumptionEps), true
	case "failed_events":
		return float64(node.FailedEvents), true
	case "loss":
		if key == "zeek_loss" {
			return node.ZeekLossPct, true
		}
		return node.SuriLossPct, true
	case "capture_loss":
		return node.CaptureLossPct, true
	case "net":
		switch key {
		case "traffic_man_in":
			return node.TrafficManInMbs, true
		case "traffic_man_out":
			return node.TrafficManOutMbs, true
		default:
			return node.TrafficMonInMbs, true
		}
	case "net_drops":
		return node.TrafficMonInDropsMbs, true
	case "node_status":
		return node.Status, true
	case "connection_status":
		return node.ConnectionStatus, true
	case "raid_status":
		return node.RaidStatus, true
	case "process_status":
		return node.ProcessStatus, true
	case "eventstore_status":
		return node.EventstoreStatus, true
	case "os_needs_restart":
		return node.OsNeedsRestart == 1, true
	case "suri_rules_loaded":
		return float64(node.SuriRulesLoaded), true
	case "suri_rules_failed":
		return float64(node.SuriRulesFailed), true
	case "suri_rules_status":
		return node.SuriRulesStatus, true
	case "suri_rules_reload_time":
		return node.SuriRulesReloadTime, true
	case "highstate_age":
		return float64(node.HighstateAgeSeconds), true
	case "gmd_enabled":
		return node.GmdEnabled == 1, true
	case "lks_enabled":
		return node.LksEnabled == 1, true
	case "fps_enabled":
		return node.FpsEnabled == 1, true
	default:
		return nil, false
	}
}
