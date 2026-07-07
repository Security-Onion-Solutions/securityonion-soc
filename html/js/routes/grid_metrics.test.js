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
});

test('initMetricsCharts', () => {
	comp.setupMetricsChart = jest.fn();
	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.initMetricsCharts();
	expect(comp.setupMetricsChart).toHaveBeenCalledTimes(6);
});

test('setupMetricsChart', () => {
	comp.$root.getColor = jest.fn().mockReturnValue('#123456');
	comp.setupMetricsChart('cpu', 'CPU', ['cpu'], ['#123456']);
	expect(comp.chartCpuOptions).toBeDefined();
	expect(comp.chartCpuData).toBeDefined();
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
	comp.populateMetricsChart = jest.fn();

	comp.$root.papi.get = jest.fn().mockResolvedValue({ data: { cpu_used: [] } });

	await comp.loadHistoricalMetrics();

	expect(comp.$root.papi.get).toHaveBeenCalledTimes(6);
	expect(comp.populateMetricsChart).toHaveBeenCalledTimes(6);
	expect(comp.metricsLoading).toBe(false);
});
