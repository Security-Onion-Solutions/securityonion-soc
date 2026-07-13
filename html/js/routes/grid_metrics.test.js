// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./grid.js');
require('./grid_metrics.js');

let comp;

beforeEach(() => {
	comp = getComponent("grid");
	if (comp.$root) {
		delete comp.$root.parameters;
	}
});

test('initMetricsCharts with default dashboard', () => {
	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.initMetricsCharts();
	expect(comp.metricPanels).toBeDefined();
	expect(comp.metricPanels.length).toBe(6);
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

	expect(comp.$root.papi.get).toHaveBeenCalledTimes(6);
	expect(comp.metricsLoading).toBe(false);
});
