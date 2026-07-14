// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./grid.js');
require('./grid_metrics.js');

let comp;

const DEFAULT_MOCK_DASHBOARD = {
	panels: [
		{ id: "cpu", titleKey: "metricsCpuUsage", type: "line_chart", metric: "cpu", keys: ["cpu_used"], labelKeys: ["cpuUsageAbbr"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "memory", titleKey: "metricsMemUsage", type: "line_chart", metric: "memory", keys: ["memory_used"], labelKeys: ["memUsageAbbr"], colors: ["#f67019"], width: 6, height: 250 },
		{ id: "load", titleKey: "metricsLoadAverage", type: "line_chart", metric: "load", keys: ["load1", "load5", "load15"], labelKeys: ["metricsLoad1", "metricsLoad5", "metricsLoad15"], colors: ["#4dc9f6", "#f67019", "#f53794"], width: 6, height: 250 },
		{ id: "swap", titleKey: "swapUsage", type: "line_chart", metric: "swap", keys: ["swap_used"], labelKeys: ["swapUsage"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "io_wait", titleKey: "metricsIoWait", type: "line_chart", metric: "io_wait", keys: ["io_wait"], labelKeys: ["metricsIoWait"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "system_uptime", titleKey: "metricsSystemUptime", type: "line_chart", metric: "system_uptime", keys: ["system_uptime"], labelKeys: ["metricsUptimeDays"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "disk", titleKey: "metricsDiskUsage", type: "line_chart", metric: "disk", keys: ["disk_used_root", "disk_used_nsm"], labelKeys: ["diskUsageRootAbbr", "diskUsageNsmAbbr"], colors: ["#4dc9f6", "#f67019"], width: 6, height: 250 },
		{ id: "net", titleKey: "metricsNetTraffic", type: "line_chart", metric: "net", keys: ["traffic_man_in", "traffic_man_out", "traffic_mon_in"], labelKeys: ["metricsTrafficManIn", "metricsTrafficManOut", "metricsTrafficMonIn"], colors: ["#4dc9f6", "#f67019", "#f53794"], width: 6, height: 250 },
		{ id: "net_drops", titleKey: "metricsMonitorDrops", type: "line_chart", metric: "net_drops", keys: ["traffic_mon_drops"], labelKeys: ["metricsDrops"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "pcap_retention", titleKey: "metricsPcapRetention", type: "line_chart", metric: "pcap_retention", keys: ["pcap_retention"], labelKeys: ["metricsRetentionDays"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "eps", titleKey: "eps", type: "line_chart", metric: "eps", keys: ["consumption_eps", "production_eps"], labelKeys: ["metricsConsumptionEps", "metricsProductionEps"], colors: ["#4dc9f6", "#f67019"], width: 6, height: 250 },
		{ id: "elasticsearch_size", titleKey: "metricsElasticsearchSize", type: "line_chart", metric: "elasticsearch_size", keys: ["elasticsearch_size"], labelKeys: ["metricsStorageSize"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "elasticsearch_docs", titleKey: "metricsElasticsearchDocs", type: "line_chart", metric: "elasticsearch_docs", keys: ["elasticsearch_docs"], labelKeys: ["metricsDocsCount"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "elastic_ingest_time", titleKey: "metricsElasticIngestTime", type: "line_chart", metric: "elastic_ingest_time", keys: ["elastic_ingest_time"], labelKeys: ["metricsTimeMs"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "loss", titleKey: "metricsLoss", type: "line_chart", metric: "loss", keys: ["suricata_loss", "zeek_loss"], labelKeys: ["suricataLoss", "zeekLoss"], colors: ["#4dc9f6", "#f67019"], width: 6, height: 250 },
		{ id: "capture_loss", titleKey: "metricsCaptureLoss", type: "line_chart", metric: "capture_loss", keys: ["zeek_capture_loss"], labelKeys: ["metricsLoss"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "kafka_eps", titleKey: "metricsKafkaEps", type: "line_chart", metric: "kafka_eps", keys: ["kafka_eps"], labelKeys: ["metricsKafkaEps"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "kafka_controllers", titleKey: "metricsKafkaControllers", type: "line_chart", metric: "kafka_controllers", keys: ["kafka_controllers"], labelKeys: ["metricsControllers"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "kafka_brokers", titleKey: "metricsKafkaBrokers", type: "line_chart", metric: "kafka_brokers", keys: ["kafka_brokers"], labelKeys: ["metricsBrokers"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "kafka_under_replicated", titleKey: "metricsKafkaUnderReplicated", type: "line_chart", metric: "kafka_under_replicated", keys: ["kafka_under_replicated"], labelKeys: ["metricsPartitions"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "container_uptime", titleKey: "metricsContainerUptime", type: "line_chart", metric: "container_uptime", keys: ["container_uptime"], labelKeys: ["metricsUptime"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "container_cpu", titleKey: "metricsContainerCpu", type: "line_chart", metric: "container_cpu", keys: ["container_cpu"], labelKeys: ["metricsCpuPct"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "container_mem", titleKey: "metricsContainerMem", type: "line_chart", metric: "container_mem", keys: ["container_mem"], labelKeys: ["metricsMemPct"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "container_net_in", titleKey: "metricsContainerNetIn", type: "line_chart", metric: "container_net_in", keys: ["container_net_in"], labelKeys: ["metricsTrafficMonIn"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "redis_queue", titleKey: "metricsRedisQueue", type: "line_chart", metric: "redis_queue", keys: ["redis_queue"], labelKeys: ["metricsQueueSize"], colors: ["#4dc9f6"], width: 6, height: 250 },
		{ id: "logstash_eps", titleKey: "metricsLogstashEps", type: "line_chart", metric: "logstash_eps", keys: ["logstash_eps"], labelKeys: ["metricsEps"], colors: ["#4dc9f6"], width: 6, height: 250 }
	]
};

beforeEach(() => {
	comp = getComponent("grid");
	if (comp.$root) {
		comp.$root.parameters = {
			grid: {
				metricsDashboard: JSON.stringify(DEFAULT_MOCK_DASHBOARD)
			}
		};
	}
});

test('initMetricsCharts with default dashboard', () => {
	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.initMetricsCharts();
	expect(comp.metricPanels).toBeDefined();
	expect(comp.metricPanels.length).toBe(26);
	expect(comp.metricPanels[0].id).toBe('cpu');
});

test('initMetricsCharts with custom dashboard', () => {
	comp.$root.parameters = {
		grid: {
			metricsDashboard: JSON.stringify({
				panels: [
					{ id: 'custom_stat', title: 'Custom Stat', type: 'single_stat', metric: 'cpu', key: 'cpu_used' }
				]
			})
		}
	};
	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.initMetricsCharts();
	expect(comp.metricPanels).toBeDefined();
	expect(comp.metricPanels.length).toBe(1);
	expect(comp.metricPanels[0].id).toBe('custom_stat');
	expect(comp.metricPanels[0].type).toBe('single_stat');
});

test('getMetricPanelCardHeight', () => {
	expect(comp.getMetricPanelCardHeight({ height: 250 })).toBe('310px');
	expect(comp.getMetricPanelCardHeight(null)).toBe('310px');
	expect(comp.getMetricPanelCardHeight({ height: 100 })).toBe('160px');
});

test('setupMetricsAutoRefresh', () => {
	comp.metricsAutoRefresh = 30;
	comp.loadHistoricalMetrics = jest.fn();
	comp.setupMetricsAutoRefresh();
	expect(comp.metricsRefreshInterval).not.toBeNull();
	clearInterval(comp.metricsRefreshInterval);
});

test('populateMetricsChart', () => {
	const chart = { key: 0, datasets: [{ data: [] }] };
	const data = { cpu_used: [{ timestamp: '2026-06-30T00:00:00Z', value: 45.6 }] };
	comp.populateMetricsChart(chart, data, ['cpu_used']);
	expect(chart.key).toBe(1);
	expect(chart.datasets[0].data[0].y).toBe(45.6);
});

test('loadHistoricalMetrics', async () => {
	resetPapi();
	comp.$root.showError = console.error;
	comp.metricsLoading = false;
	comp.metricsTimeRange = '1h';
	comp.metricsNodeId = 'host1';
	comp.zone = 'UTC';

	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.initMetricsCharts();

	comp.$root.papi.get = jest.fn().mockResolvedValue({ data: { cpu_used: [] } });

	await comp.loadHistoricalMetrics();

	expect(comp.$root.papi.get).toHaveBeenCalledTimes(26);
	expect(comp.metricsLoading).toBe(false);
});
