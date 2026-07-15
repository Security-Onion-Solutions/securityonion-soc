// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./grid.js');

const comp = getComponent("grid");

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

function buildEsHealth() {
  return {
    healthReport: {
      status: 'red',
      cluster_name: 'securityonion',
      indicators: {
        master_is_stable: { status: 'green', symptom: 'The cluster has a stable master node' },
        shards_availability: {
          status: 'red',
          symptom: 'This cluster has 17 unavailable primary shards, 6 unavailable replica shards.',
          diagnosis: [{
            cause: 'A node has recently left the cluster.',
            action: 'Restart the node.',
            affected_resources: {
              nodes: [{ id: 'abc', name: 'mgr' }],
              indices: ['so-logs', 'so-case'],
            },
          }],
        },
        disk: {
          status: 'yellow',
          symptom: 'Disk usage exceeds the low watermark.',
          details: { indices_with_readonly_block: 2 },
          diagnosis: [{}],
        },
      },
    },
    clusterSettings: { persistent: { 'cluster.routing.allocation.enable': 'all' }, transient: {} },
    catNodes: [{
      name: 'node-1', ip: '10.0.0.5', 'node.role': 'dhimrt', master: '*', version: '9.3.3',
      'heap.percent': '49', 'ram.percent': '97', cpu: '2', load_1m: '1.68',
      'disk.total': '124.5gb', 'disk.used_percent': '85.57', uptime: '1.6h',
    }],
    unassignedShards: {
      total: 23,
      primaries: 17,
      replicas: 6,
      groups: [
        {
          reason: 'CLUSTER_RECOVERED', primary: true, count: 17,
          canAllocate: 'no_valid_shard_copy',
          explanation: {
            index: 'so-logs',
            shard: 0,
            primary: true,
            can_allocate: 'no_valid_shard_copy',
            unassigned_info: { reason: 'CLUSTER_RECOVERED', at: '2026-07-06T16:15:02.915Z' },
          },
        },
        {
          reason: 'CLUSTER_RECOVERED', primary: false, count: 6,
          canAllocate: 'no',
          deciders: [
            { name: 'same_shard', explanation: 'a copy of this shard is already allocated to this node [[so-case][0], node[ZMxh271FT32], [P], s[STARTED], a[id=BiFvj57ZQi], failed_attempts[0]]', nodes: ['sa-tshoot-jb'] },
            { name: 'disk_threshold', explanation: 'the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]', nodes: ['sa-tshoot-jb'] },
          ],
          explanation: {
            index: 'so-case',
            shard: 0,
            primary: false,
            can_allocate: 'no',
            unassigned_info: { reason: 'CLUSTER_RECOVERED' },
            node_allocation_decisions: [{
              node_name: 'sa-tshoot-jb',
              node_decision: 'no',
              deciders: [
                { decider: 'same_shard', decision: 'NO', explanation: 'a copy of this shard is already allocated to this node [[so-case][0], node[ZMxh271FT32], [P], s[STARTED], a[id=BiFvj57ZQi], failed_attempts[0]]' },
                { decider: 'disk_threshold', decision: 'NO', explanation: 'the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]' },
              ],
            }],
          },
        },
      ],
    },
  };
}

test('loadEsHealth', async () => {
  const mock = mockPapi("get", { data: buildEsHealth() });
  comp.esHealthExpanded = { disk: true };
  await comp.loadEsHealth('subgrid1');
  expect(mock).toHaveBeenCalledWith('eshealth', expect.objectContaining({ params: { gridId: 'subgrid1' } }));
  expect(comp.esHealth.healthReport.status).toBe('red');
  expect(comp.esHealthExpanded).toEqual({});
  expect(comp.esHealthLoading).toBe(false);
  // View data is derived once per load
  expect(comp.esHealthIssues.map(i => i.id)).toEqual(['shards_availability', 'disk']);
});

test('loadEsHealthSupersededRequestAborted', async () => {
  let rejectSlow;
  const slow = new Promise(function(resolve, reject) { rejectSlow = reject; });
  const mock = mockPapi("get", slow);
  mock.mockReturnValueOnce({ data: buildEsHealth() });

  const slowLoad = comp.loadEsHealth('subgrid1');
  const slowSignal = mock.mock.calls[0][1].signal;
  const fastLoad = comp.loadEsHealth('');

  // The newer request aborts the superseded one (cancelling its backend work)
  expect(slowSignal.aborted).toBe(true);
  await fastLoad;
  expect(comp.esHealth.healthReport.status).toBe('red');
  expect(comp.esHealthLoading).toBe(false);

  // Axios rejects aborted requests; the late rejection must not clear the
  // newer request's data or show an error
  const showErrorMock = mockShowError();
  rejectSlow({ name: 'CanceledError', message: 'canceled' });
  await slowLoad;
  expect(comp.esHealth.healthReport.status).toBe('red');
  expect(comp.esHealthLoading).toBe(false);
  expect(showErrorMock).not.toHaveBeenCalled();
});

test('loadEsHealthError', async () => {
  mockPapi("get", null, new Error("something bad"));
  const showErrorMock = mockShowError();
  comp.esHealth = buildEsHealth();
  comp.digestEsHealth();
  await comp.loadEsHealth();
  expect(comp.esHealth).toBe(null);
  expect(comp.esHealthIndicators).toEqual([]);
  expect(comp.esHealthLoading).toBe(false);
  // The dialog renders its own unavailable message; no global error popup
  expect(showErrorMock).not.toHaveBeenCalled();
});

test('canShowEsHealth', () => {
  expect(comp.canShowEsHealth({ role: 'so-manager' })).toBe(true);
  expect(comp.canShowEsHealth({ role: 'so-standalone' })).toBe(true);
  expect(comp.canShowEsHealth({ role: 'so-heavynode' })).toBe(false);
});

test('showHideEsHealth', () => {
  const loadSpy = jest.spyOn(comp, 'loadEsHealth').mockImplementation(() => {});
  comp.showEsHealth({ id: 'mgr', gridId: 'subgrid1' });
  expect(comp.esHealthDialog).toBe(true);
  expect(loadSpy).toHaveBeenCalledWith('subgrid1');

  comp.hideEsHealth();
  expect(comp.esHealthDialog).toBe(false);
  loadSpy.mockRestore();
});

test('esHealthDialogCloseAborts', () => {
  // Every close path (Close button, ESC, outside-click) funnels through the
  // v-model watcher, which aborts any in-flight request
  const abort = { abort: jest.fn() };
  comp.esHealthAbort = abort;
  comp.onEsHealthDialogChanged(false);
  expect(abort.abort).toHaveBeenCalled();
  expect(comp.esHealthAbort).toBe(null);

  // Opening must not abort the load that showEsHealth just started
  const abort2 = { abort: jest.fn() };
  comp.esHealthAbort = abort2;
  comp.onEsHealthDialogChanged(true);
  expect(abort2.abort).not.toHaveBeenCalled();
  comp.esHealthAbort = null;
});

test('colorEsHealthStatus', () => {
  expect(comp.colorEsHealthStatus('green')).toBe('success');
  expect(comp.colorEsHealthStatus('yellow')).toBe('warning');
  expect(comp.colorEsHealthStatus('red')).toBe('error');
  expect(comp.colorEsHealthStatus('unknown')).toBe('secondary');
});

test('iconEsHealthStatus', () => {
  expect(comp.iconEsHealthStatus('green')).toBe('fa-circle-check');
  expect(comp.iconEsHealthStatus('yellow')).toBe('fa-circle-exclamation');
  expect(comp.iconEsHealthStatus('red')).toBe('fa-triangle-exclamation');
  expect(comp.iconEsHealthStatus('unknown')).toBe('fa-circle-question');
});

test('formatEsIndicatorName', () => {
  expect(comp.formatEsIndicatorName('shards_availability')).toBe('Shards availability');
  expect(comp.formatEsIndicatorName('disk')).toBe('Disk');
  expect(comp.formatEsIndicatorName('ilm')).toBe('ILM');
  expect(comp.formatEsIndicatorName('slm')).toBe('SLM');
});

test('esHealthIndicators', () => {
  comp.esHealth = null;
  comp.digestEsHealth();
  expect(comp.esHealthIndicators).toEqual([]);

  comp.esHealth = buildEsHealth();
  comp.digestEsHealth();
  const indicators = comp.esHealthIndicators;
  expect(indicators.length).toBe(3);

  // Sorted worst-first: red, yellow, green
  expect(indicators[0].id).toBe('shards_availability');
  expect(indicators[0].name).toBe('Shards availability');
  expect(indicators[0].status).toBe('red');
  expect(indicators[0].symptom).toBe('This cluster has 17 unavailable primary shards, 6 unavailable replica shards.');
  expect(indicators[0].causes).toEqual([{
    cause: 'A node has recently left the cluster.',
    nodes: ['mgr'],
    indices: ['so-logs', 'so-case'],
  }]);
  expect(indicators[1].id).toBe('disk');
  expect(indicators[1].causes).toEqual([]);
  expect(indicators[2].id).toBe('master_is_stable');
});

test('esHealthIssuesAndHealthy', () => {
  comp.esHealth = null;
  comp.digestEsHealth();
  expect(comp.esHealthIssues).toEqual([]);
  expect(comp.esHealthHealthy).toEqual([]);

  comp.esHealth = buildEsHealth();
  comp.digestEsHealth();
  expect(comp.esHealthIssues.map(i => i.id)).toEqual(['shards_availability', 'disk']);
  expect(comp.esHealthHealthy.map(i => i.id)).toEqual(['master_is_stable']);
});

test('toggleEsHealthDetails', () => {
  comp.esHealthExpanded = { disk: true };
  comp.toggleEsHealthDetails('shards_availability');
  expect(comp.esHealthExpanded.shards_availability).toBe(true);
  comp.toggleEsHealthDetails('shards_availability');
  expect(comp.esHealthExpanded.shards_availability).toBe(false);
  expect(comp.esHealthExpanded.disk).toBe(true);
});

test('hasEsHealthDetails', () => {
  comp.esHealth = buildEsHealth();
  comp.digestEsHealth();
  const byId = {};
  comp.esHealthIndicators.forEach(i => byId[i.id] = i);

  // Blocking reasons and causes
  expect(comp.hasEsHealthDetails(byId.shards_availability)).toBe(true);
  // Disk findings
  expect(comp.hasEsHealthDetails(byId.disk)).toBe(true);
  // No details of any kind
  expect(comp.hasEsHealthDetails(byId.master_is_stable)).toBe(false);

  // Shards indicator with no blocking reasons, causes remain as details
  delete comp.esHealth.unassignedShards;
  comp.digestEsHealth();
  expect(comp.hasEsHealthDetails(byId.shards_availability)).toBe(true);
  byId.shards_availability.causes = [];
  expect(comp.hasEsHealthDetails(byId.shards_availability)).toBe(false);
});

test('esAllocationLines', () => {
  expect(comp.esAllocationLines(null)).toEqual([]);
  expect(comp.esAllocationLines(buildEsHealth().unassignedShards.groups[0].explanation)).toEqual([
    'Shard: so-logs[0] (primary)',
    'Unassigned reason: CLUSTER_RECOVERED, since 2026-07-06T16:15:02.915Z',
    'Can allocate: no_valid_shard_copy',
  ]);
  expect(comp.esAllocationLines(buildEsHealth().unassignedShards.groups[1].explanation)).toEqual([
    'Shard: so-case[0] (replica)',
    'Unassigned reason: CLUSTER_RECOVERED',
    'Can allocate: no',
    '  * Node sa-tshoot-jb: no',
    '    - same_shard: a copy of this shard is already allocated to this node [[so-case][0], node[ZMxh271FT32], [P], s[STARTED], a[id=BiFvj57ZQi], failed_attempts[0]]',
    '    - disk_threshold: the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]',
  ]);
});

test('esShardVerdicts', () => {
  comp.esHealth = null;
  comp.digestEsHealth();
  expect(comp.esShardVerdicts).toEqual([]);

  comp.esHealth = buildEsHealth();
  comp.digestEsHealth();
  const verdicts = comp.esShardVerdicts;
  expect(verdicts.length).toBe(3);

  // Severity order: lost primaries, then actionable deciders, then expected conditions
  expect(verdicts[0].scope).toBe('17 primary (CLUSTER_RECOVERED)');
  expect(verdicts[0].summary).toBe(comp.i18n.esHealthVerdictNoValidShardCopy);
  expect(verdicts[0].decider).toBe(null);
  expect(verdicts[0].color).toBe('error');
  expect(verdicts[0].icon).toBe('fa-triangle-exclamation');

  expect(verdicts[1].scope).toBe('6 replica (CLUSTER_RECOVERED)');
  expect(verdicts[1].decider).toBe('disk_threshold');
  expect(verdicts[1].summary).toBe(comp.i18n.esHealthVerdictDiskThreshold);
  expect(verdicts[1].detail).toBe('the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]');
  expect(verdicts[1].nodes).toEqual(['sa-tshoot-jb']);
  expect(verdicts[1].color).toBe('warning');

  expect(verdicts[2].decider).toBe('same_shard');
  expect(verdicts[2].summary).toBe(comp.i18n.esHealthVerdictSameShard);
  expect(verdicts[2].color).toBe('info');
  expect(verdicts[2].icon).toBe('fa-circle-info');

  // Unknown deciders surface ES's explanation verbatim at warning severity
  comp.esHealth.unassignedShards.groups[1].deciders.push({ name: 'awareness', explanation: 'too many copies of the shard allocated to nodes with attribute [zone]', nodes: [] });
  comp.digestEsHealth();
  const withUnknown = comp.esShardVerdicts;
  expect(withUnknown.length).toBe(4);
  const unknown = withUnknown.find(v => v.decider == 'awareness');
  expect(unknown.summary).toBe('awareness: too many copies of the shard allocated to nodes with attribute [zone]');
  expect(unknown.detail).toBe(null);
  expect(unknown.color).toBe('warning');

  // Groups with a transient outcome and no NO deciders still get a verdict row
  comp.esHealth.unassignedShards.groups[1].deciders = [];
  comp.esHealth.unassignedShards.groups[1].canAllocate = 'throttled';
  comp.digestEsHealth();
  const fallback = comp.esShardVerdicts;
  expect(fallback.length).toBe(2);
  expect(fallback[1].scope).toBe('6 replica (CLUSTER_RECOVERED)');
  expect(fallback[1].summary).toBe('Elasticsearch reports no blocking deciders for this group; allocation outcome: throttled.');
  expect(fallback[1].color).toBe('info');
});

test('formatEsReportList', () => {
  expect(comp.formatEsReportList('Affected indices', ['a', 'b'])).toBe('Affected indices (2): a, b');
  const many = Array.from({ length: 14 }, (x, i) => 'idx-' + i);
  expect(comp.formatEsReportList('Affected indices', many))
      .toBe('Affected indices (14): idx-0, idx-1, idx-2, idx-3, idx-4, idx-5, idx-6, idx-7, idx-8, idx-9, ... (+4 more)');
});

test('esDiskFindings', () => {
  comp.esHealth = null;
  comp.digestEsHealth();
  expect(comp.esDiskFindings).toEqual([]);

  comp.esHealth = buildEsHealth();
  comp.digestEsHealth();
  expect(comp.esDiskFindings).toEqual(['Write-blocked (read-only) indices: 2. Writes to these indices are rejected; Elasticsearch typically applies this block when disk usage exceeds the flood stage watermark.']);

  comp.esHealth.healthReport.indicators.disk.status = 'green';
  comp.digestEsHealth();
  expect(comp.esDiskFindings).toEqual([]);
});

test('buildEsHealthReport', () => {
  comp.esHealth = null;
  comp.digestEsHealth();
  expect(comp.buildEsHealthReport()).toBe('');

  comp.esHealth = buildEsHealth();
  comp.digestEsHealth();
  comp.$root.version = '2.4.999';
  const report = comp.buildEsHealthReport();
  expect(report).toContain('ELASTICSEARCH HEALTH REPORT');
  expect(report).toContain('Security Onion: 2.4.999');

  // Sections are ordered: nodes, cluster settings, indicators, unassigned shards
  const sections = ['--- Nodes', '--- Cluster Settings', '--- Indicators', '--- Unassigned Shards'];
  const positions = sections.map(s => report.indexOf(s));
  expect(positions.every(p => p >= 0)).toBe(true);
  expect(positions).toEqual([...positions].sort((a, b) => a - b));
  expect(report).toContain('[RED] Shards availability - This cluster has 17 unavailable primary shards, 6 unavailable replica shards.');
  expect(report).toContain('  * A node has recently left the cluster.');
  expect(report).toContain('    Affected nodes (1): mgr');
  expect(report).toContain('    Affected indices (2): so-logs, so-case');
  expect(report).toContain('[YELLOW] Disk - Disk usage exceeds the low watermark.');
  expect(report).toContain('  * Write-blocked (read-only) indices: 2.');
  expect(report).toContain('[GREEN] Master is stable - The cluster has a stable master node');
  expect(report).toContain('--- Unassigned Shards (_cat/shards, _cluster/allocation/explain) ---');
  expect(report).toContain('Total: 23 unassigned (17 primary, 6 replica)');
  // The curated verdicts are dialog-only; the report carries the full sampled-shard dumps
  expect(report).not.toContain(comp.i18n.esHealthVerdictNoValidShardCopy);
  expect(report).toContain('Sampled shard for 17 primary (CLUSTER_RECOVERED):');
  expect(report).toContain('  Shard: so-logs[0] (primary)');
  expect(report).toContain('  Unassigned reason: CLUSTER_RECOVERED, since 2026-07-06T16:15:02.915Z');
  expect(report).toContain('  Can allocate: no_valid_shard_copy');
  expect(report).toContain('Sampled shard for 6 replica (CLUSTER_RECOVERED):');
  expect(report).toContain('      - disk_threshold: the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]');
  expect(report).toContain('--- Cluster Settings (_cluster/settings) ---');
  expect(report).toContain('  cluster.routing.allocation.enable: "all"');
  expect(report).toContain('transient: (none)');
  expect(report).toContain('--- Nodes (_cat/nodes) ---');
  expect(report).toContain('  * node-1 (10.0.0.5) roles=dhimrt master=* version=9.3.3 heap=49% ram=97% cpu=2% load_1m=1.68 disk_used=85.57% of 124.5gb uptime=1.6h');
  // No raw JSON dumps in the report
  expect(report).not.toContain('{');

  // Unexplained groups (explain failed or beyond the sampling cap) are disclosed
  delete comp.esHealth.unassignedShards.groups[1].explanation;
  expect(comp.buildEsHealthReport()).toContain('No allocation explanation sampled for 6 replica (CLUSTER_RECOVERED)');

  // Optional sections are omitted when the backend could not collect them
  delete comp.esHealth.unassignedShards;
  delete comp.esHealth.clusterSettings;
  delete comp.esHealth.catNodes;
  const minimalReport = comp.buildEsHealthReport();
  expect(minimalReport).toContain('--- Indicators (_health_report) ---');
  expect(minimalReport).not.toContain('_cat/shards');
  expect(minimalReport).not.toContain('_cluster/settings');
  expect(minimalReport).not.toContain('_cat/nodes');
});

test('copyEsHealthReport', () => {
  comp.esHealth = buildEsHealth();
  comp.digestEsHealth();
  comp.$root.copyToClipboard = jest.fn();
  comp.$root.showTip = jest.fn();
  comp.copyEsHealthReport();
  expect(comp.$root.copyToClipboard).toHaveBeenCalledWith(comp.buildEsHealthReport());
  expect(comp.$root.showTip).toHaveBeenCalledWith(comp.i18n.esHealthCopied);
});
