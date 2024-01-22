// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./grid.js');

const comp = getComponent("grid");

test('updateStatus', () => {
	const status = { grid: { eps: 12 }};

	expect(comp.gridEps).toBe(0);
	comp.updateStatus(status);
	expect(comp.gridEps).toBe(12);
});

test('updateMetricsEnabled', () => {
	testUpdateMetricsEnabled(true, false, true);
	testUpdateMetricsEnabled(false, false, false);
	testUpdateMetricsEnabled(true, true, true);
	testUpdateMetricsEnabled(true, false, true, true);
	testUpdateMetricsEnabled(false, false, false, false);
	testUpdateMetricsEnabled(true, true, true, true);
});

function testUpdateMetricsEnabled(node1MetricsEnabled, node2MetricsEnabled, expectedMetricsEnabled, moreColumnsEnabled) {
	const node1 = { metricsEnabled: node1MetricsEnabled };
	const node2 = { metricsEnabled: node2MetricsEnabled };
	comp.nodes = [node1, node2];
	comp.moreColumns = moreColumnsEnabled;

	comp.updateMetricsEnabled();

	expect(comp.metricsEnabled).toBe(expectedMetricsEnabled);

	const validateColumn = (label, size, moreCols) => {
		const column = comp.headers.find(function(item) {
			const trans = comp.i18n[label]
			return item.text == trans;
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
	validateColumn('stenoLossAbbr', 'xl', true);
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
	expect(comp.selectedId).toBe(null);

	comp.showTestConfirm('t2');
	expect(comp.gridMemberTestConfirmDialog).toBe(true);
	expect(comp.selectedId).toBe('t2');

	comp.hideTestConfirm();
	expect(comp.gridMemberTestConfirmDialog).toBe(false);
	expect(comp.selectedId).toBe(null);
});

test('canTest', () => {
	const node = {};
	expect(comp.canTest(node)).toBe(false);

	node['keywords'] = "Foo Bar";
	expect(comp.canTest(node)).toBe(false);

	node['keywords'] = "Foo Sensor Bar";
	expect(comp.canTest(node)).toBe(true);
});


test('testRestartConfirmDialog', () => {
	expect(comp.gridMemberRestartConfirmDialog).toBe(false);
	expect(comp.selectedId).toBe(null);

	comp.showRestartConfirm('t2');
	expect(comp.gridMemberRestartConfirmDialog).toBe(true);
	expect(comp.selectedId).toBe('t2');

	comp.hideRestartConfirm();
	expect(comp.gridMemberRestartConfirmDialog).toBe(false);
	expect(comp.selectedId).toBe(null);
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
	comp.selectedId = 'fwd01_so-sensor';
	await comp.gridMemberTest();
	expect(mock).toHaveBeenCalledWith('gridmembers/fwd01_sensor/test');
});

test('gridMemberRestart', async () => {
	resetPapi();
	const mock = mockPapi("post");
	comp.selectedId = 'fwd01_so-sensor';
	await comp.gridMemberRestart();
	expect(mock).toHaveBeenCalledWith('gridmembers/fwd01_sensor/restart');
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
