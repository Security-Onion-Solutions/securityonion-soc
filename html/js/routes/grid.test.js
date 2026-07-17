// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./grid.js');
require('./grid_metrics.js');

const comp = getComponent("grid");

test('created', () => {
	comp.$root.initializeCharts = jest.fn();
	comp.created();
	expect(comp.$root.initializeCharts).toHaveBeenCalled();
});

test('updateStatus', () => {
	const status = { gridId: 'abc', grid: { eps: 12 }};

	expect(comp.gridEps).toBe(0);

	// Update for an alternate (non-selected) grid
	comp.updateStatus(status);
	expect(comp.gridEps).toBe(0);

	// Update for the selected grid
	comp.$root.selectedGridId = 'abc';
	comp.updateStatus(status);
	expect(comp.gridEps).toBe(12);
});

test('updateMetricsEnabled', () => {
	testUpdateMetricsEnabled(true, false, true, false, true, false, true);
	testUpdateMetricsEnabled(false, false, false, false, false, false, false);
	testUpdateMetricsEnabled(true, true, true, false, true, true, true);
	testUpdateMetricsEnabled(true, false, true, true, true, false, true);
	testUpdateMetricsEnabled(false, false, false, false, false, false, false);
	testUpdateMetricsEnabled(true, true, true, true, true, true, true);
});

function testUpdateMetricsEnabled(node1MetricsEnabled, node2MetricsEnabled, expectedMetricsEnabled, moreColumnsEnabled, node1HistoricalEnabled, node2HistoricalEnabled, expectedHistoricalEnabled) {
	const node1 = { metricsEnabled: node1MetricsEnabled, historicalMetricsEnabled: node1HistoricalEnabled };
	const node2 = { metricsEnabled: node2MetricsEnabled, historicalMetricsEnabled: node2HistoricalEnabled };
	comp.nodes = [node1, node2];
	comp.moreColumns = moreColumnsEnabled;

	comp.updateMetricsEnabled();

	expect(comp.metricsEnabled).toBe(expectedMetricsEnabled);
	expect(comp.historicalMetricsEnabled).toBe(expectedHistoricalEnabled);

	const validateColumn = (label, size, moreCols) => {
		const trans = comp.i18n[label];
		const column = comp.headers.find(function(item) {
			return item.title == trans;
		});
		if (!expectedMetricsEnabled || (moreCols && !moreColumnsEnabled)) {
			expect(column.align).toBe(' d-none');
		} else {
			expect(column.align).toBe(' d-none d-' + size + '-table-cell');
		}
	}

	validateColumn('eps', 'lg', false);
	validateColumn('memUsageAbbr', 'xl', false);
	validateColumn('diskUsageRootAbbr', 'xl', false);
	validateColumn('diskUsageNsmAbbr', 'xl', false);
	validateColumn('cpuUsageAbbr', 'xl', false);
	validateColumn('trafficManInAbbr', 'xl', false);
	validateColumn('trafficManOutAbbr', 'xl', false);
	validateColumn('trafficMonInAbbr', 'xl', true);
	validateColumn('trafficMonInDropsAbbr', 'xl', true);
	validateColumn('captureLossAbbr', 'xl', true);
	validateColumn('zeekLossAbbr', 'xl', true);
	validateColumn('suricataLossAbbr', 'xl', true);
	validateColumn('pcapRetentionAbbr', 'xl', true);
}

test('colorNodeStatus', () => {
	expect(comp.colorNodeStatus("ok")).toBe("success");
	expect(comp.colorNodeStatus("fault")).toBe("error");
	expect(comp.colorNodeStatus("fault", true)).toBe("warning");
	expect(comp.colorNodeStatus("unknown")).toBe("warning");
	expect(comp.colorNodeStatus("pending")).toBe("warning");
	expect(comp.colorNodeStatus("pending", true)).toBe("warning");
	expect(comp.colorNodeStatus("unknown", true)).toBe("warning");
	expect(comp.colorNodeStatus("restart", false)).toBe("info");
	expect(comp.colorNodeStatus("restart", true)).toBe("info");
});

test('colorContainerDetails', () => {
	expect(comp.colorContainerDetails("Up 2 hours")).toBe("normal");
	expect(comp.colorContainerDetails("Up 3 minutes")).toBe("info");
	expect(comp.colorContainerDetails("Up 5 seconds", true)).toBe("warning");
	expect(comp.colorContainerDetails("Up Less than a second", true)).toBe("warning");
});

test('formatLinearColor', () => {
	expect(comp.formatLinearColor(0, 1, 2, 3)).toBe("success");
	expect(comp.formatLinearColor(0.99, 1, 2, 3)).toBe("success");
	expect(comp.formatLinearColor(1.0, 1, 2, 3)).toBe("info");
	expect(comp.formatLinearColor(1.99, 1, 2, 3)).toBe("info");
	expect(comp.formatLinearColor(2.0, 1, 2, 3)).toBe("warning");
	expect(comp.formatLinearColor(2.99, 1, 2, 3)).toBe("warning");
	expect(comp.formatLinearColor(3.0, 1, 2, 3)).toBe("error");
	expect(comp.formatLinearColor(5, 1, 2, 3)).toBe("error");
});

test('iconNodeStatus', () => {
	expect(comp.iconNodeStatus("fault")).toBe("fa-triangle-exclamation");
	expect(comp.iconNodeStatus("pending")).toBe("fa-circle-exclamation");
	expect(comp.iconNodeStatus("ok")).toBe("fa-circle-check");
	expect(comp.iconNodeStatus("other")).toBe("fa-circle-question");
	expect(comp.iconNodeStatus("restart")).toBe("fa-circle-info");
});

test('colorContainerStatus', () => {
	expect(comp.colorContainerStatus("running")).toBe("success");
	expect(comp.colorContainerStatus("broken")).toBe("error");
});

test('formatNode', () => {
	node = {
		processJson: '{"containers": [{ "Name": "a" },{ "Name": "c" },{ "Name": "b" }]}',
		role: 'standalone',
	}

	node = comp.formatNode(node);

	expect(node.containers).toStrictEqual([{"Name": "a"}, {"Name": "b"}, {"Name": "c"}]);
});

test('formatNode_MissingContainers', () => {
	node = {
		processJson: '{}',
		role: 'standalone',
	}

	node = comp.formatNode(node);

	expect(node.containers).toStrictEqual([]);
});

test('testConfirmDialog', () => {
	expect(comp.gridMemberTestConfirmDialog).toBe(false);
	expect(comp.selectedNode).toBe(null);

	const testNode = { id: 't2', role: '', gridId: ''};
	comp.showTestConfirm(testNode);
	expect(comp.gridMemberTestConfirmDialog).toBe(true);
	expect(comp.selectedNode).toBe(testNode);

	comp.hideTestConfirm();
	expect(comp.gridMemberTestConfirmDialog).toBe(false);
	expect(comp.selectedNode).toBe(null);
});

test('canTest', () => {
	const node = {};
	expect(comp.canTest(node)).toBe(false);

	node['keywords'] = "Foo Bar";
	expect(comp.canTest(node)).toBe(false);

	node['keywords'] = "Foo Sensor Bar";
	comp.$root.user = { roles: ['superuser'] };
	expect(comp.canTest(node)).toBe(true);

	// Case: Admin user, but node is not a sensor
	node['keywords'] = "Foo Bar";
	expect(comp.canTest(node)).toBe(false);

	// Case: Non-admin user, but node is a sensor
	node['keywords'] = "Foo Sensor Bar";
	comp.$root.user = { roles: ['user'] };
	expect(comp.canTest(node)).toBe(false);
});


test('testRestartConfirmDialog', () => {
	expect(comp.gridMemberRestartConfirmDialog).toBe(false);
	expect(comp.selectedNode).toBe(null);

	const testNode = { id: 't2', role: '', gridId: ''};
	comp.showRestartConfirm(testNode);
	expect(comp.gridMemberRestartConfirmDialog).toBe(true);
	expect(comp.selectedNode).toStrictEqual(testNode);

	comp.hideRestartConfirm();
	expect(comp.gridMemberRestartConfirmDialog).toBe(false);
	expect(comp.selectedNode).toBe(null);
});

test('testUploadDialog', () => {
	expect(comp.gridMemberUploadConfirmDialog).toBe(false);
	expect(comp.selectedNode).toBe(null);

	const node = { keywords: 'Sensor Manager'};

	comp.showUploadConfirm(node);
	expect(comp.gridMemberUploadConfirmDialog).toBe(true);
	expect(comp.selectedNode).toBe(node);

	comp.hideUploadConfirm();
	expect(comp.gridMemberUploadConfirmDialog).toBe(false);
	expect(comp.selectedNode).toBe(null);
});

test('canUpload', () => {
	const node = {};

	const table = [
		{ keywords: "", canUploadPCAP: false, canUploadEvtx: false, accept: '' },
		{ keywords: "Foo Bar", canUploadPCAP: false, canUploadEvtx: false, accept: '' },
		{ keywords: "Foo Sensor Bar", canUploadPCAP: true, canUploadEvtx: false, accept: '.pcap' },
		{ keywords: "Foo Import Bar", canUploadPCAP: true, canUploadEvtx: false, accept: '.pcap' },
		{ keywords: "Foo Manager Bar", canUploadPCAP: false, canUploadEvtx: true, accept: '.evtx' },
		{ keywords: "Foo Sensor Manager Bar", canUploadPCAP: true, canUploadEvtx: true, accept: '.pcap,.evtx' },
	];

	expect(comp.selectedNode).toBe(null);
	expect(comp.pickUploadDialogAccept()).toBe('*.*');

	table.forEach((t) => {
		node['keywords'] = t.keywords;

		expect(comp.canUploadPCAP(node)).toBe(t.canUploadPCAP);
		expect(comp.canUploadEvtx(node)).toBe(t.canUploadEvtx);
		expect(comp.canUpload(node)).toBe(t.canUploadPCAP || t.canUploadEvtx);

		comp.selectedNode = node;
		expect(comp.pickUploadDialogAccept()).toBe(t.accept);

		if (t.canUploadPCAP || t.canUploadEvtx) {
			const title = comp.pickUploadDialogTitle();
			if (t.canUploadPCAP) {
				expect(title).toMatch('PCAP');
			} else {
				expect(title).not.toMatch('PCAP');
			}

			if (t.canUploadEvtx) {
				expect(title).toMatch('EVTX');
			} else {
				expect(title).not.toMatch('EVTX');
			}
		}
	});
});

test('canNotUploadPCAPToHeavyNode', () => {
	const node = { role: 'so-heavynode', keywords: 'Sensor' }
	expect(comp.canUploadPCAP(node)).toBe(false);
});

test('canConfigureMaxUploadSize', () => {
	const skip = comp.loadData;

	comp.loadData = () => {};

	let params = {};
	const orig = comp.maxUploadSizeBytes;

	comp.initGrid(params);
	expect(comp.maxUploadSizeBytes).toBe(orig);

	params = { maxUploadSize: 0 };
	comp.initGrid(params);
	expect(comp.maxUploadSizeBytes).toBe(orig);

	params = { maxUploadSize: 100 * 1024 * 1024 };
	comp.initGrid(params);
	expect(comp.maxUploadSizeBytes).toBe(params.maxUploadSize);

	comp.loadData = skip;
});

test('gridMemberTest', async () => {
	resetPapi();
	const mock = mockPapi("post");
	comp.selectedNode = { id: 'fwd01', role: 'so-sensor', gridId: ''};
	await comp.gridMemberTest();
	expect(mock).toHaveBeenCalledWith('gridmembers/fwd01_sensor/test', null, {params: { gridId: ''}});
});

test('gridMemberRestart', async () => {
	resetPapi();
	const mock = mockPapi("post");
	comp.selectedNode = { id: 'fwd01', role: 'so-sensor', gridId: 'abc'};
	await comp.gridMemberRestart();
	expect(mock).toHaveBeenCalledWith('gridmembers/fwd01_sensor/restart', null, {params: { gridId: 'abc'}});
});

test('hasEventstore', () => {
	var item = {containers: [{Name: 'so-something'}, {Name: 'so-elasticsearch'}, {Name: 'so-another'}]};
	expect(comp.hasEventstore(item)).toBe(true);

	item = {containers: [{Name: 'so-something'}, {Name: 'so-nope'}, {Name: 'so-another'}]};
	expect(comp.hasEventstore(item)).toBe(false);
});

test('hasMetricstore', () => {
	var item = {containers: [{Name: 'so-something'}, {Name: 'so-influxdb'}, {Name: 'so-another'}]};
	expect(comp.hasMetricstore(item)).toBe(true);

	item = {containers: [{Name: 'so-something'}, {Name: 'so-nope'}, {Name: 'so-another'}]};
	expect(comp.hasMetricstore(item)).toBe(false);
});

test('hasQueuestore', () => {
	var item = {containers: [{Name: 'so-something'}, {Name: 'so-redis'}, {Name: 'so-another'}]};
	expect(comp.hasQueuestore(item)).toBe(true);

	item = {containers: [{Name: 'so-something'}, {Name: 'so-nope'}, {Name: 'so-another'}]};
	expect(comp.hasQueuestore(item)).toBe(false);
});

test('hasSuri', () => {
	var item = {containers: [{Name: 'so-something'}, {Name: 'so-suricata'}, {Name: 'so-another'}]};
	expect(comp.hasSuri(item)).toBe(true);

	item = {containers: [{Name: 'so-something'}, {Name: 'so-nope'}, {Name: 'so-another'}]};
	expect(comp.hasQueuestore(item)).toBe(false);
});

test('hasZeek', () => {
	var item = {containers: [{Name: 'so-something'}, {Name: 'so-zeek'}, {Name: 'so-another'}]};
	expect(comp.hasZeek(item)).toBe(true);

	item = {containers: [{Name: 'so-something'}, {Name: 'so-nope'}, {Name: 'so-another'}]};
	expect(comp.hasQueuestore(item)).toBe(false);
});

test('setInterval and clearInterval', () => {
  jest.useFakeTimers();
  const setIntervalSpy = jest.spyOn(window, 'setInterval');
  const clearIntervalSpy = jest.spyOn(window, 'clearInterval');
  const loadDataSpy = jest.spyOn(comp, 'loadData').mockImplementation(() => {});

  comp.initGrid({});
  expect(setIntervalSpy).toHaveBeenCalledTimes(1);
  expect(setIntervalSpy).toHaveBeenCalledWith(comp.checkStaleness, 30000);

  comp.unmounted();
  expect(clearIntervalSpy).toHaveBeenCalledTimes(1);
  expect(clearIntervalSpy).toHaveBeenCalledWith(comp.stalenessInterval);

  setIntervalSpy.mockRestore();
  clearIntervalSpy.mockRestore();
  loadDataSpy.mockRestore();
});

test('saveLocalSettings', () => {
  comp.sortBy = [{ key: 'model', order: 'desc' }];
  comp.itemsPerPage = 50;
  comp.saveLocalSettings();
  expect(localStorage['settings.grid.sortBy']).toBe('model');
  expect(localStorage['settings.grid.sortDesc']).toBe('desc');
  expect(localStorage['settings.grid.itemsPerPage']).toBe('50');
});

test('loadLocalSettings', () => {
  localStorage['settings.grid.sortBy'] = 'role';
  localStorage['settings.grid.sortDesc'] = 'asc';
  localStorage['settings.grid.itemsPerPage'] = '250';
  comp.loadLocalSettings();
  expect(comp.sortBy).toEqual([{ key: 'role', order: 'asc' }]);
  expect(comp.itemsPerPage).toBe(250);
});

test('loadLocalSettings_defaults', () => {
  delete localStorage['settings.grid.sortBy'];
  delete localStorage['settings.grid.itemsPerPage'];
  comp.sortBy = [{ key: 'id', order: 'asc' }];
  comp.itemsPerPage = 10;
  comp.loadLocalSettings();
  expect(comp.sortBy).toEqual([{ key: 'id', order: 'asc' }]);
  expect(comp.itemsPerPage).toBe(10);
});

test('showNodeMetrics', () => {
	comp.$root.papi.get = jest.fn().mockResolvedValue({ data: {} });
	comp.$root.getColor = jest.fn().mockReturnValue('#123456');

	expect(comp.activeTab).toBe('nodes');
	comp.showNodeMetrics('host123');
	expect(comp.activeTab).toBe('metrics');
	expect(comp.metricsNodeId).toBe('host123');
});

test('refresh on nodes tab', () => {
	comp.loadData = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.activeTab = 'nodes';

	comp.refresh();

	expect(comp.loadData).toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).not.toHaveBeenCalled();
});

test('refresh on metrics tab', () => {
	comp.loadData = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.activeTab = 'metrics';

	comp.refresh();

	expect(comp.loadData).toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).toHaveBeenCalledWith(true);
});

test('zone watcher on nodes tab', () => {
	comp.saveTimezone = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.activeTab = 'nodes';

	comp.watch.zone.call(comp, 'America/New_York');

	expect(comp.saveTimezone).toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).not.toHaveBeenCalled();
});

test('zone watcher on metrics tab', () => {
	comp.saveTimezone = jest.fn();
	comp.loadHistoricalMetrics = jest.fn();
	comp.activeTab = 'metrics';

	comp.watch.zone.call(comp, 'America/New_York');

	expect(comp.saveTimezone).toHaveBeenCalled();
	expect(comp.loadHistoricalMetrics).toHaveBeenCalledWith(true);
});

