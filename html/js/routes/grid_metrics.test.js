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
		{ id: "elastic_ingest_time", titleKey: "metricsElasticIngestTime", type: "line_chart", metric: "elastic_ingest_time", keys: ["elastic_ingest_time"], labelKeys: ["metricsTimeMs"], colors: ["#4dc9f6"], width: 6, height: 250, units: "ms" },
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
		{ id: "logstash_eps", titleKey: "metricsLogstashEps", type: "line_chart", metric: "logstash_eps", keys: ["logstash_eps"], labelKeys: ["metricsEventsReceived"], colors: ["#4dc9f6"], width: 6, height: 250 }
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
	expect(comp.metricPanels[0].chartData.datasets[0].borderWidth).toBe(1);
	expect(comp.metricPanels[0].chartData.datasets[0].pointRadius).toBe(0);
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
	comp.populateMetricsChart(chart, data, ['cpu_used'], ['#123456']);
	expect(chart.key).toBe(1);
	expect(chart.datasets[0].data[0].y).toBe(45.6);
});

test('populateMetricsChart with container metrics', () => {
	const chart = { key: 0, datasets: [] };
	const data = { "so-kafka": [{ timestamp: '2026-06-30T00:00:00Z', value: 12.3 }] };
	comp.populateMetricsChart(chart, data, ['container_cpu'], ['#4dc9f6']);
	expect(chart.key).toBe(1);
	expect(chart.datasets.length).toBe(1);
	expect(chart.datasets[0].label).toBe("so-kafka");
	expect(chart.datasets[0].data[0].y).toBe(12.3);
	expect(chart.datasets[0].borderWidth).toBe(1);
	expect(chart.datasets[0].pointRadius).toBe(0);
});

test('populateMetricsChart with elastic ingest time function breakdown', () => {
	const chart = { key: 0, datasets: [] };
	const data = {
		"grok": [{ timestamp: '2026-06-30T00:00:00Z', value: 454.4 }],
		"set": [{ timestamp: '2026-06-30T00:00:00Z', value: 240.3 }],
		"script": [{ timestamp: '2026-06-30T00:00:00Z', value: 92.8 }]
	};
	comp.populateMetricsChart(chart, data, ['elastic_ingest_time'], ['#4dc9f6', '#f67019', '#f53794']);
	expect(chart.key).toBe(1);
	expect(chart.datasets.length).toBe(3);
	expect(chart.datasets[0].label).toBe("grok");
	expect(chart.datasets[0].data[0].y).toBe(454.4);
	expect(chart.datasets[1].label).toBe("script");
	expect(chart.datasets[1].data[0].y).toBe(92.8);
	expect(chart.datasets[2].label).toBe("set");
	expect(chart.datasets[2].data[0].y).toBe(240.3);
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
	expect(comp.$root.papi.get).toHaveBeenCalledWith('grid/metrics', {
		params: {
			nodeId: 'host1',
			container: 'all',
			range: 'now-1h:now',
			format: 'local',
			zone: 'UTC',
			metric: 'cpu'
		}
	});
	expect(comp.metricsLoading).toBe(false);
});

test('loadHistoricalMetrics with custom timezone', async () => {
	resetPapi();
	comp.$root.showError = console.error;
	comp.metricsLoading = false;
	comp.metricsTimeRange = '1h';
	comp.metricsNodeId = 'host1';
	comp.zone = 'America/New_York';

	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.initMetricsCharts();

	comp.$root.papi.get = jest.fn().mockResolvedValue({ data: { cpu_used: [] } });

	await comp.loadHistoricalMetrics();

	expect(comp.$root.papi.get).toHaveBeenCalledTimes(26);
	expect(comp.$root.papi.get).toHaveBeenCalledWith('grid/metrics', {
		params: {
			nodeId: 'host1',
			container: 'all',
			range: 'now-1h:now',
			format: 'local',
			zone: 'America/New_York',
			metric: 'cpu'
		}
	});
	expect(comp.metricsLoading).toBe(false);
});

test('loadHistoricalMetrics populates panels as individual metric API calls return', async () => {
	resetPapi();
	comp.$root.showError = console.error;
	comp.metricsLoading = false;
	comp.metricsTimeRange = '1h';
	comp.metricsNodeId = 'host1';
	comp.zone = 'UTC';

	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.initMetricsCharts();

	// Ensure there are at least CPU and Memory panels
	expect(comp.metricPanels[0].id).toBe('cpu');
	expect(comp.metricPanels[1].id).toBe('memory');

	let resolveCpu;
	const cpuPromise = new Promise(resolve => { resolveCpu = resolve; });
	let resolveMem;
	const memPromise = new Promise(resolve => { resolveMem = resolve; });

	comp.$root.papi.get = jest.fn().mockImplementation((url, config) => {
		const m = config.params.metric;
		if (m === 'cpu') {
			return cpuPromise;
		} else if (m === 'memory') {
			return memPromise;
		}
		return Promise.resolve({ data: {} });
	});

	const loadPromise = comp.loadHistoricalMetrics();

	// Verify CPU and Memory charts are initially empty and loading state is true
	expect(comp.metricPanels[0].chartData.datasets[0].data).toEqual([]);
	expect(comp.metricPanels[1].chartData.datasets[0].data).toEqual([]);
	expect(comp.metricPanels[0].loading).toBe(true);
	expect(comp.metricPanels[1].loading).toBe(true);

	// Resolve CPU metric
	resolveCpu({ data: { cpu_used: [{ timestamp: '2026-06-30T00:00:00Z', value: 50 }] } });
	await Promise.resolve(); // Allow CPU promise handler to run
	await Promise.resolve();


	// CPU should now have data and loading is false, but Memory should still be empty and loading is true
	expect(comp.metricPanels[0].chartData.datasets[0].data.length).toBe(1);
	expect(comp.metricPanels[0].chartData.datasets[0].data[0].y).toBe(50);
	expect(comp.metricPanels[0].loading).toBe(false);
	expect(comp.metricPanels[1].chartData.datasets[0].data).toEqual([]);
	expect(comp.metricPanels[1].loading).toBe(true);

	// Resolve Memory metric
	resolveMem({ data: { memory_used: [{ timestamp: '2026-06-30T00:00:00Z', value: 80 }] } });
	await Promise.resolve(); // Allow Memory promise handler to run
	await Promise.resolve();


	await loadPromise; // Wait for loadHistoricalMetrics to fully finish

	// Both should now have data and loading should be false
	expect(comp.metricPanels[0].chartData.datasets[0].data.length).toBe(1);
	expect(comp.metricPanels[1].chartData.datasets[0].data.length).toBe(1);
	expect(comp.metricPanels[1].chartData.datasets[0].data[0].y).toBe(80);
	expect(comp.metricPanels[0].loading).toBe(false);
	expect(comp.metricPanels[1].loading).toBe(false);
});

test('socGraphing.formatAxisValue handles default auto-sizing and custom units', () => {
	const graphing = window.socGraphing;
	expect(graphing).toBeDefined();

	// Non-numbers should return unmodified
	expect(graphing.formatAxisValue('hello')).toBe('hello');
	expect(graphing.formatAxisValue(null)).toBeNull();

	// Default auto-sizing (K, M, B, T)
	expect(graphing.formatAxisValue(500)).toBe(500);
	expect(graphing.formatAxisValue(1500)).toBe('1.5k');
	expect(graphing.formatAxisValue(2500000)).toBe('2.5m');
	expect(graphing.formatAxisValue(45656234524)).toBe('45.7B');
	expect(graphing.formatAxisValue(1200000000000)).toBe('1.2T');

	// Custom 'byte' units auto-sizing
	expect(graphing.formatAxisValue(0, 'byte')).toBe('0 B');
	expect(graphing.formatAxisValue(512, 'byte')).toBe('512 B');
	expect(graphing.formatAxisValue(1024, 'byte')).toBe('1 KB');
	expect(graphing.formatAxisValue(1536, 'byte')).toBe('1.5 KB');
	expect(graphing.formatAxisValue(1048576, 'byte')).toBe('1 MB');
	expect(graphing.formatAxisValue(45656234524, 'byte')).toBe('42.5 GB');

	// Custom 'percent' units
	expect(graphing.formatAxisValue(45.6, 'percent')).toBe('45.6%');
	expect(graphing.formatAxisValue(100, 'percent')).toBe('100%');

	// Custom 'second'/'seconds' units
	expect(graphing.formatAxisValue(0, 'second')).toBe('0s');
	expect(graphing.formatAxisValue(10, 'seconds')).toBe('10s');
	expect(graphing.formatAxisValue(90, 'seconds')).toBe('1.5m');
	expect(graphing.formatAxisValue(12240, 'second')).toBe('3.4h');
	expect(graphing.formatAxisValue(388800, 'seconds')).toBe('4.5d');

	// Custom 'bits'/'bit' units
	expect(graphing.formatAxisValue(0, 'bits')).toBe('0 b/s');
	expect(graphing.formatAxisValue(0.005, 'bits')).toBe('5 Kb/s');
	expect(graphing.formatAxisValue(1.5, 'bits')).toBe('1.5 Mb/s');
	expect(graphing.formatAxisValue(12.5, 'bit')).toBe('12.5 Mb/s');
	expect(graphing.formatAxisValue(1500, 'bits')).toBe('1.5 Gb/s');

	// Split methods direct calls
	expect(graphing.formatPercent(99.4)).toBe('99.4%');
	expect(graphing.formatSeconds(10)).toBe('10s');
	expect(graphing.formatBytes(1024)).toBe('1 KB');
	expect(graphing.formatBits(1000000)).toBe('1 Mb/s');
	expect(graphing.formatDefaultNumber(1500)).toBe('1.5k');
});

test('loadUrlParameters parses tab and metrics parameters correctly', () => {
	comp.$route.query = {
		tab: 'metrics',
		host: 'host123',
		container: 'so-suricata',
		timeRange: '3h',
		autoRefresh: '30'
	};
	comp.loadUrlParameters();
	expect(comp.activeTab).toBe('metrics');
	expect(comp.metricsNodeId).toBe('host123');
	expect(comp.metricsContainerId).toBe('so-suricata');
	expect(comp.metricsTimeRange).toBe('3h');
	expect(comp.metricsAutoRefresh).toBe(30);
});

test('updateRoute calls replace only when route parameters differ', () => {
	comp.$router.replace = jest.fn().mockResolvedValue({});
	comp.$route.query = {
		tab: 'metrics',
		host: 'host123',
		container: 'so-suricata',
		timeRange: '3h',
		autoRefresh: '30'
	};
	comp.activeTab = 'metrics';
	comp.metricsNodeId = 'host123';
	comp.metricsContainerId = 'so-suricata';
	comp.metricsTimeRange = '3h';
	comp.metricsAutoRefresh = 30;

	// Call updateRoute where parameters are identical
	comp.updateRoute();
	expect(comp.$router.replace).not.toHaveBeenCalled();

	// Change container and check replace call
	comp.metricsContainerId = 'so-zeek';
	comp.updateRoute();
	expect(comp.$router.replace).toHaveBeenCalledWith({
		name: 'grid',
		query: {
			tab: 'metrics',
			host: 'host123',
			container: 'so-zeek',
			timeRange: '3h',
			autoRefresh: 30
		}
	});
});

test('watchers trigger updateRoute', () => {
	comp.updateRoute = jest.fn();
	
	comp.watch.metricsNodeId.call(comp);
	expect(comp.updateRoute).toHaveBeenCalledTimes(1);

	comp.watch.metricsContainerId.call(comp);
	expect(comp.updateRoute).toHaveBeenCalledTimes(2);

	comp.watch.metricsTimeRange.call(comp);
	expect(comp.updateRoute).toHaveBeenCalledTimes(3);

	comp.watch.metricsAutoRefresh.call(comp);
	expect(comp.updateRoute).toHaveBeenCalledTimes(4);

	comp.watch.activeTab.call(comp, 'metrics');
	expect(comp.updateRoute).toHaveBeenCalledTimes(5);
});

test('$route watcher behavior', () => {
	comp.loadData = jest.fn();
	comp.loadUrlParameters = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.activeTab = 'nodes';

	// Same path, same gridId, different metric parameter query should call loadUrlParameters but not loadData
	comp.watch['$route'].call(comp, { path: '/grid', query: { tab: 'metrics', gridId: 'grid1' } }, { path: '/grid', query: { gridId: 'grid1' } });
	expect(comp.loadUrlParameters).toHaveBeenCalled();
	expect(comp.loadData).not.toHaveBeenCalled();

	// Same path, different gridId should call loadUrlParameters AND loadData
	comp.loadUrlParameters.mockClear();
	comp.loadData.mockClear();
	comp.watch['$route'].call(comp, { path: '/grid', query: { gridId: 'grid2' } }, { path: '/grid', query: { gridId: 'grid1' } });
	expect(comp.loadUrlParameters).toHaveBeenCalled();
	expect(comp.loadData).toHaveBeenCalled();

	// Different path should call loadUrlParameters AND loadData
	comp.loadUrlParameters.mockClear();
	comp.loadData.mockClear();
	comp.watch['$route'].call(comp, { path: '/grid', query: {} }, { path: '/other', query: {} });
	expect(comp.loadUrlParameters).toHaveBeenCalled();
	expect(comp.loadData).toHaveBeenCalled();
});

test('initGrid initializes metrics when activeTab is metrics', () => {
	comp.activeTab = 'metrics';
	comp.initMetricsCharts = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.setupMetricsAutoRefresh = jest.fn();
	comp.loadData = jest.fn();

	comp.initGrid({});

	expect(comp.initMetricsCharts).toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).toHaveBeenCalled();
	expect(comp.setupMetricsAutoRefresh).toHaveBeenCalled();
});

test('activeTab watcher defers metrics initialization when parameters are not loaded', () => {
	comp.$root.parametersLoaded = false;
	comp.initMetricsCharts = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.setupMetricsAutoRefresh = jest.fn();
	comp.updateRoute = jest.fn();

	comp.watch.activeTab.call(comp, 'metrics');

	expect(comp.initMetricsCharts).not.toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).not.toHaveBeenCalled();
	expect(comp.setupMetricsAutoRefresh).not.toHaveBeenCalled();

	// Now set parametersLoaded = true and check that it triggers
	comp.$root.parametersLoaded = true;
	comp.watch.activeTab.call(comp, 'metrics');

	expect(comp.initMetricsCharts).toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).toHaveBeenCalled();
	expect(comp.setupMetricsAutoRefresh).toHaveBeenCalled();
});

test('activeTab watcher does not reload metrics if already initialized and params are unchanged', () => {
	comp.$root.parametersLoaded = true;
	comp.initMetricsCharts = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.setupMetricsAutoRefresh = jest.fn();
	comp.updateRoute = jest.fn();

	comp.metricPanels = [{ id: 'cpu' }];
	comp.metricsNodeId = 'host123';
	comp.metricsContainerId = 'all';
	comp.metricsTimeRange = '1h';
	comp.zone = 'UTC';
	comp.lastLoadedMetricsParams = { nodeId: 'host123', container: 'all', timeRange: '1h', zone: 'UTC' };

	comp.watch.activeTab.call(comp, 'metrics');

	expect(comp.initMetricsCharts).not.toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).not.toHaveBeenCalled();
	expect(comp.setupMetricsAutoRefresh).toHaveBeenCalled();
});

test('activeTab watcher reloads metrics if already initialized but params have changed', () => {
	comp.$root.parametersLoaded = true;
	comp.initMetricsCharts = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.setupMetricsAutoRefresh = jest.fn();
	comp.updateRoute = jest.fn();

	comp.metricPanels = [{ id: 'cpu' }];
	comp.metricsNodeId = 'host456'; // Node ID changed
	comp.metricsContainerId = 'all';
	comp.metricsTimeRange = '1h';
	comp.zone = 'UTC';
	comp.lastLoadedMetricsParams = { nodeId: 'host123', container: 'all', timeRange: '1h', zone: 'UTC' };

	comp.watch.activeTab.call(comp, 'metrics');

	expect(comp.initMetricsCharts).toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).toHaveBeenCalled();
	expect(comp.setupMetricsAutoRefresh).toHaveBeenCalled();
});

test('logstash_eps panel resolves title to Logstash Events Received and labelKeys to metricsEventsReceived', () => {
	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.initMetricsCharts();
	const logstashPanel = comp.metricPanels.find(p => p.id === 'logstash_eps');
	expect(logstashPanel).toBeDefined();
	expect(logstashPanel.titleKey).toBe('metricsLogstashEps');
	expect(comp.$root.i18n.metricsLogstashEps).toBe('Logstash Events Received');
	expect(logstashPanel.labelKeys).toEqual(['metricsEventsReceived']);
});

test('populateMetricsChart clears leftover host datasets when single host response is received', () => {
	const chart = {
		key: 0,
		datasets: [
			{ label: 'host1', data: [{ x: new Date(), y: 10 }] },
			{ label: 'host2', data: [{ x: new Date(), y: 20 }] }
		]
	};
	const data = { memory_used: [{ timestamp: '2026-06-30T00:00:00Z', value: 45.6 }] };
	comp.populateMetricsChart(chart, data, ['memory_used'], ['#f67019'], ['Memory Usage']);
	expect(chart.key).toBe(1);
	expect(chart.datasets.length).toBe(1);
	expect(chart.datasets[0].label).toBe('Memory Usage');
	expect(chart.datasets[0].data[0].y).toBe(45.6);
});




