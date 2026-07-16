// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package database

import (
	"context"
	"encoding/json"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

type MetricPanel struct {
	ID        string   `json:"id"`
	Title     string   `json:"title,omitempty"`
	TitleKey  string   `json:"titleKey,omitempty"`
	Type      string   `json:"type"`
	Metric    string   `json:"metric"`
	Keys      []string `json:"keys"`
	Labels    []string `json:"labels,omitempty"`
	LabelKeys []string `json:"labelKeys,omitempty"`
	Colors    []string `json:"colors"`
	Width     int      `json:"width"`
	Height    int      `json:"height"`
	Units     string   `json:"units,omitempty"`
}

type MetricsDashboard struct {
	Panels []MetricPanel `json:"panels"`
}

type MetricConfig struct {
	Tables        []string
	Fields        []string
	Keys          []string
	Filters       []string
	Factor        float64
	Aggregate     string
	CustomHandler func(ctx context.Context, s *Store, nodeId string, hostFilter, startPlaceholder, endPlaceholder string, args []interface{}) (map[string][]model.MetricSample, error)
	TitleKey      string
	LabelKeys     []string
	Units         string
}

var defaultColors = []string{
	"#4dc9f6",
	"#f67019",
	"#f53794",
	"#acc236",
	"#537bc4",
	"#00a950",
	"#58595b",
	"#8549ba",
	"#ebcc34",
	"#166a8f",
}

var DashboardMetricOrder = []string{
	"cpu", "memory", "load", "swap", "io_wait", "system_uptime", "disk", "net", "net_drops", "pcap_retention",
	"eps", "elasticsearch_size", "elasticsearch_docs", "elastic_ingest_time", "loss", "capture_loss",
	"container_uptime", "container_cpu", "container_mem", "container_net_in", "redis_queue", "logstash_eps",
	"kafka_eps", "kafka_controllers", "kafka_brokers", "kafka_under_replicated",
}

var MetricConfigs = map[string]MetricConfig{
	"cpu": {
		Tables:    []string{"cpu"},
		Fields:    []string{"usage_idle"},
		Keys:      []string{"cpu_used"},
		Filters:   []string{"tag.tags->>'cpu' = 'cpu-total'"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsCpuUsage",
		LabelKeys: []string{"cpuUsageAbbr"},
		Units:     "percent",
	},
	"memory": {
		Tables:    []string{"mem"},
		Fields:    []string{"used_percent"},
		Keys:      []string{"memory_used"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsMemUsage",
		LabelKeys: []string{"memUsageAbbr"},
		Units:     "percent",
	},
	"load": {
		Tables:    []string{"system"},
		Fields:    []string{"load1", "load5", "load15"},
		Keys:      []string{"load1", "load5", "load15"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsLoadAverage",
		LabelKeys: []string{"metricsLoad1", "metricsLoad5", "metricsLoad15"},
	},
	"swap": {
		Tables:    []string{"swap"},
		Fields:    []string{"used_percent"},
		Keys:      []string{"swap_used"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "swapUsage",
		LabelKeys: []string{"swapUsage"},
		Units:     "percent",
	},
	"io_wait": {
		Tables:    []string{"cpu"},
		Fields:    []string{"usage_iowait"},
		Keys:      []string{"io_wait"},
		Filters:   []string{"tag.tags->>'cpu' = 'cpu-total'"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsIoWait",
		LabelKeys: []string{"metricsIoWait"},
		Units:     "percent",
	},
	"elasticsearch_size": {
		Tables:    []string{"elasticsearch_indices"},
		Fields:    []string{"store_size_in_bytes"},
		Keys:      []string{"elasticsearch_size"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsElasticsearchSize",
		LabelKeys: []string{"metricsStorageSize"},
		Units:     "byte",
	},
	"elasticsearch_docs": {
		Tables:    []string{"elasticsearch_indices"},
		Fields:    []string{"docs_count"},
		Keys:      []string{"elasticsearch_docs"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsElasticsearchDocs",
		LabelKeys: []string{"metricsDocsCount"},
	},
	"redis_queue": {
		Tables:    []string{"redisqueue"},
		Fields:    []string{"unparsed"},
		Keys:      []string{"redis_queue"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsRedisQueue",
		LabelKeys: []string{"metricsQueueSize"},
	},
	"pcap_retention": {
		Tables:    []string{"pcapage"},
		Fields:    []string{"seconds"},
		Keys:      []string{"pcap_retention"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsPcapRetention",
		LabelKeys: []string{"metricsRetentionDays"},
		Units:     "second",
	},
	"system_uptime": {
		Tables:    []string{"system"},
		Fields:    []string{"uptime"},
		Keys:      []string{"system_uptime"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsSystemUptime",
		LabelKeys: []string{"metricsUptimeDays"},
		Units:     "second",
	},
	"kafka_eps": {
		Tables:    []string{"kafka_topic"},
		Fields:    []string{"MessagesInPerSec.Count"},
		Keys:      []string{"kafka_eps"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsKafkaEps",
		LabelKeys: []string{"metricsKafkaEps"},
	},
	"container_uptime": {
		Tables:    []string{"docker_container_status"},
		Fields:    []string{"uptime_ns"},
		Keys:      []string{"container_uptime"},
		Factor:    1.0 / 86400000000000.0,
		Aggregate: "AVG",
		TitleKey:  "metricsContainerUptime",
		LabelKeys: []string{"metricsUptime"},
	},
	"kafka_controllers": {
		Tables:    []string{"kafka_controller"},
		Fields:    []string{"ActiveControllerCount.Value"},
		Keys:      []string{"kafka_controllers"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsKafkaControllers",
		LabelKeys: []string{"metricsControllers"},
	},
	"kafka_brokers": {
		Tables:    []string{"kafka_controller"},
		Fields:    []string{"ActiveBrokerCount.Value"},
		Keys:      []string{"kafka_brokers"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsKafkaBrokers",
		LabelKeys: []string{"metricsBrokers"},
	},
	"container_cpu": {
		Tables:    []string{"docker_container_cpu"},
		Fields:    []string{"usage_percent"},
		Keys:      []string{"container_cpu"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsContainerCpu",
		LabelKeys: []string{"metricsCpuPct"},
		Units:     "percent",
	},
	"container_mem": {
		Tables:    []string{"docker_container_mem"},
		Fields:    []string{"usage_percent"},
		Keys:      []string{"container_mem"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsContainerMem",
		LabelKeys: []string{"metricsMemPct"},
		Units:     "percent",
	},
	"elastic_ingest_time": {
		Tables:    []string{"elasticsearch_clusterstats_nodes"},
		Fields:    []string{"ingest_processor_stats_grok_time_in_millis"},
		Keys:      []string{"elastic_ingest_time"},
		Factor:    1.0 / 1000.0,
		Aggregate: "AVG",
		TitleKey:  "metricsElasticIngestTime",
		LabelKeys: []string{"metricsTimeMs"},
		Units:     "seconds",
	},
	"logstash_eps": {
		Tables:    []string{"logstash_events"},
		Fields:    []string{"in"},
		Keys:      []string{"logstash_eps"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsLogstashEps",
		LabelKeys: []string{"metricsEps"},
	},
	"kafka_under_replicated": {
		Tables:    []string{"kafka_partition"},
		Fields:    []string{"UnderReplicatedPartitions"},
		Keys:      []string{"kafka_under_replicated"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsKafkaUnderReplicated",
		LabelKeys: []string{"metricsPartitions"},
	},
	"capture_loss": {
		Tables:    []string{"zeekcaptureloss"},
		Fields:    []string{"loss"},
		Keys:      []string{"zeek_capture_loss"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsCaptureLoss",
		LabelKeys: []string{"metricsLoss"},
		Units:     "percent",
	},
	"disk": {
		Tables:    []string{"disk", "disk"},
		Fields:    []string{"used_percent", "used_percent"},
		Keys:      []string{"disk_used_root", "disk_used_nsm"},
		Filters:   []string{"tag.tags->>'path' = '/'", "tag.tags->>'path' = '/nsm'"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsDiskUsage",
		LabelKeys: []string{"diskUsageRootAbbr", "diskUsageNsmAbbr"},
		Units:     "percent",
	},
	"eps": {
		Tables:    []string{"consumptioneps", "fbstats"},
		Fields:    []string{"eps", "eps"},
		Keys:      []string{"consumption_eps", "production_eps"},
		Factor:    1.0,
		Aggregate: "SUM",
		TitleKey:  "eps",
		LabelKeys: []string{"metricsConsumptionEps", "metricsProductionEps"},
	},
	"loss": {
		Tables:    []string{"suridrop", "zeekdrop"},
		Fields:    []string{"drop", "drop"},
		Keys:      []string{"suricata_loss", "zeek_loss"},
		Factor:    1.0,
		Aggregate: "AVG",
		TitleKey:  "metricsLoss",
		LabelKeys: []string{"suricataLoss", "zeekLoss"},
		Units:     "percent",
	},
	"net": {
		Keys:          []string{"traffic_man_in", "traffic_man_out", "traffic_mon_in"},
		CustomHandler: queryNetMetric,
		TitleKey:      "metricsNetTraffic",
		LabelKeys:     []string{"metricsTrafficManIn", "metricsTrafficManOut", "metricsTrafficMonIn"},
		Units:         "bits",
	},
	"net_drops": {
		Keys:          []string{"traffic_mon_drops"},
		CustomHandler: queryNetDropsMetric,
		TitleKey:      "metricsMonitorDrops",
		LabelKeys:     []string{"metricsDrops"},
	},
	"container_net_in": {
		Keys:          []string{"container_net_in"},
		CustomHandler: queryContainerNetInMetric,
		TitleKey:      "metricsContainerNetIn",
		LabelKeys:     []string{"metricsTrafficMonIn"},
		Units:         "bits",
	},
}

func GenerateDefaultMetricsDashboard() ([]byte, error) {
	panels := make([]MetricPanel, 0, len(DashboardMetricOrder))
	for _, mType := range DashboardMetricOrder {
		if cfg, ok := MetricConfigs[mType]; ok {
			colors := make([]string, len(cfg.Keys))
			for idx := range cfg.Keys {
				colors[idx] = defaultColors[idx%len(defaultColors)]
			}
			panels = append(panels, MetricPanel{
				ID:        mType,
				TitleKey:  cfg.TitleKey,
				Type:      "line_chart",
				Metric:    mType,
				Keys:      cfg.Keys,
				LabelKeys: cfg.LabelKeys,
				Colors:    colors,
				Width:     6,
				Height:    250,
				Units:     cfg.Units,
			})
		}
	}
	db := MetricsDashboard{Panels: panels}
	return json.Marshal(db)
}
