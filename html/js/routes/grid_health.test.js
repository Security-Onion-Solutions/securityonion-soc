// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./grid.js');
require('./grid_health.js');

const comp = getComponent("grid");

beforeEach(() => {
  resetPapi();
});

function buildEsHealth() {
  return {
    status: 'red',
    // The server ranks indicators and their findings before responding
    indicators: [
      {
        id: 'shards_availability',
        status: 'red',
        symptom: 'This cluster has 17 unavailable primary shards, 6 unavailable replica shards.',
        causes: [{
          cause: 'A node has recently left the cluster.',
          nodes: ['mgr'],
          indices: ['so-logs', 'so-case'],
        }],
        findings: [
          {
            severity: 'critical', condition: 'no_valid_shard_copy',
            scope: { reason: 'CLUSTER_RECOVERED', count: 17, primary: true },
          },
          {
            severity: 'warning', condition: 'disk_threshold',
            scope: { reason: 'CLUSTER_RECOVERED', count: 6, primary: false },
            detail: 'the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]',
            nodes: ['sa-tshoot-jb'],
          },
          {
            severity: 'info', condition: 'same_shard',
            scope: { reason: 'CLUSTER_RECOVERED', count: 6, primary: false },
            detail: 'a copy of this shard is already allocated to this node [[so-case][0], node[ZMxh271FT32], [P], s[STARTED], a[id=BiFvj57ZQi], failed_attempts[0]]',
            nodes: ['sa-tshoot-jb'],
          },
        ],
      },
      {
        id: 'disk',
        status: 'yellow',
        symptom: 'Disk usage exceeds the low watermark.',
        findings: [{ severity: 'critical', condition: 'indices_readonly', count: 2 }],
      },
      { id: 'master_is_stable', status: 'green', symptom: 'The cluster has a stable master node' },
    ],
    settings: { persistent: { 'cluster.routing.allocation.enable': 'all' }, transient: {} },
    nodes: [{
      name: 'node-1', ip: '10.0.0.5', roles: 'dhimrt', master: '*', version: '9.3.3',
      heapPercent: '49', ramPercent: '97', cpu: '2', load1m: '1.68',
      diskTotal: '124.5gb', diskUsedPercent: '85.57', uptime: '1.6h',
    }],
    unassignedShards: {
      total: 23,
      primaries: 17,
      replicas: 6,
      groups: [
        {
          reason: 'CLUSTER_RECOVERED', primary: true, count: 17,
          sampleStatus: 'explained', sampleIndex: 'so-logs', sampleShard: 0, since: '2026-07-06T16:15:02.915Z',
          canAllocate: 'no_valid_shard_copy',
        },
        {
          reason: 'CLUSTER_RECOVERED', primary: false, count: 6,
          sampleStatus: 'explained', sampleIndex: 'so-case', sampleShard: 0,
          canAllocate: 'no',
          deciders: [
            { name: 'same_shard', explanation: 'a copy of this shard is already allocated to this node [[so-case][0], node[ZMxh271FT32], [P], s[STARTED], a[id=BiFvj57ZQi], failed_attempts[0]]', nodes: ['sa-tshoot-jb'] },
            { name: 'disk_threshold', explanation: 'the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]', nodes: ['sa-tshoot-jb'] },
          ],
        },
      ],
    },
  };
}

test('loadEsHealth', async () => {
  const mock = mockPapi("get", { data: buildEsHealth() });
  comp.esHealthExpanded = { disk: true };
  await comp.loadEsHealth('subgrid1');
  expect(mock).toHaveBeenCalledWith('events/health', expect.objectContaining({ params: { gridId: 'subgrid1' } }));
  expect(comp.esHealth.status).toBe('red');
  expect(comp.esHealthExpanded).toEqual({});
  expect(comp.esHealthLoading).toBe(false);
  expect(comp.esHealthIssues().map(i => i.id)).toEqual(['shards_availability', 'disk']);
});

test('loadEsHealthSupersededRequestAborted', async () => {
  let rejectSlow;
  const slow = new Promise(function(resolve, reject) { rejectSlow = reject; });
  const mock = mockPapi("get", slow);
  mock.mockReturnValueOnce({ data: buildEsHealth() });

  const slowLoad = comp.loadEsHealth();
  const slowSignal = mock.mock.calls[0][1].signal;
  const fastLoad = comp.loadEsHealth();

  // The newer request aborts the superseded one (cancelling its backend work)
  expect(slowSignal.aborted).toBe(true);
  await fastLoad;
  expect(comp.esHealth.status).toBe('red');
  expect(comp.esHealthLoading).toBe(false);

  // Axios rejects aborted requests; the late rejection must not clear the
  // newer request's data or show an error
  const showErrorMock = mockShowError();
  rejectSlow({ name: 'CanceledError', message: 'canceled' });
  await slowLoad;
  expect(comp.esHealth.status).toBe('red');
  expect(comp.esHealthLoading).toBe(false);
  expect(showErrorMock).not.toHaveBeenCalled();
});

test('loadEsHealthError', async () => {
  mockPapi("get", null, new Error("something bad"));
  const showErrorMock = mockShowError();
  comp.esHealth = buildEsHealth();
  await comp.loadEsHealth();
  expect(comp.esHealth).toBe(null);
  expect(comp.esHealthIndicators()).toEqual([]);
  expect(comp.esHealthLoading).toBe(false);
  // The dialog renders its own unavailable message; no global error popup
  expect(showErrorMock).not.toHaveBeenCalled();
});

test('canShowEsHealth', () => {
  expect(comp.canShowEsHealth({ eventsHealthAvailable: true })).toBe(true);
  expect(comp.canShowEsHealth({ eventsHealthAvailable: false })).toBe(false);
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
  expect(comp.esHealthIndicators()).toEqual([]);

  comp.esHealth = buildEsHealth();
  const indicators = comp.esHealthIndicators();
  expect(indicators.length).toBe(3);

  // Server-ranked order is preserved: red, yellow, green
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
  expect(comp.esHealthIssues()).toEqual([]);
  expect(comp.esHealthHealthy()).toEqual([]);

  comp.esHealth = buildEsHealth();
  expect(comp.esHealthIssues().map(i => i.id)).toEqual(['shards_availability', 'disk']);
  expect(comp.esHealthHealthy().map(i => i.id)).toEqual(['master_is_stable']);
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
  const byId = {};
  comp.esHealthIndicators().forEach(i => byId[i.id] = i);

  // Findings and causes
  expect(comp.hasEsHealthDetails(byId.shards_availability)).toBe(true);
  // Findings only
  expect(comp.hasEsHealthDetails(byId.disk)).toBe(true);
  // No details of any kind
  expect(comp.hasEsHealthDetails(byId.master_is_stable)).toBe(false);

  // Causes alone remain details
  byId.shards_availability.findings = [];
  expect(comp.hasEsHealthDetails(byId.shards_availability)).toBe(true);
  byId.shards_availability.causes = [];
  expect(comp.hasEsHealthDetails(byId.shards_availability)).toBe(false);
});

test('formatEsFinding', () => {
  comp.esHealth = buildEsHealth();
  const byId = {};
  comp.esHealthIndicators().forEach(i => byId[i.id] = i);
  const findings = byId.shards_availability.findings;
  expect(findings.length).toBe(3);

  // Severity drives the icon and color; the condition drives the explanation
  expect(findings[0].scope).toBe('17 primary (CLUSTER_RECOVERED)');
  expect(findings[0].summary).toBe(comp.i18n.esHealthVerdictNoValidShardCopy);
  expect(findings[0].detail).toBe('');
  expect(findings[0].color).toBe('error');
  expect(findings[0].icon).toBe('fa-triangle-exclamation');

  expect(findings[1].scope).toBe('6 replica (CLUSTER_RECOVERED)');
  expect(findings[1].summary).toBe(comp.i18n.esHealthVerdictDiskThreshold);
  expect(findings[1].detail).toBe('disk_threshold: the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]');
  expect(findings[1].nodes).toEqual(['sa-tshoot-jb']);
  expect(findings[1].color).toBe('warning');

  expect(findings[2].summary).toBe(comp.i18n.esHealthVerdictSameShard);
  expect(findings[2].color).toBe('info');
  expect(findings[2].icon).toBe('fa-circle-info');

  // Unscoped findings interpolate their own count
  expect(byId.disk.findings[0].summary).toBe('Write-blocked (read-only) indices: 2. Writes to these indices are rejected; Elasticsearch typically applies this block when disk usage exceeds the flood stage watermark.');
  expect(byId.disk.findings[0].scope).toBe('');

  // Unknown conditions surface the datastore's explanation verbatim
  const unknown = comp.formatEsFinding({
    severity: 'warning', condition: 'awareness',
    detail: 'too many copies of the shard allocated to nodes with attribute [zone]',
  });
  expect(unknown.summary).toBe('awareness: too many copies of the shard allocated to nodes with attribute [zone]');
  expect(unknown.detail).toBe('');
  expect(unknown.color).toBe('warning');

  // Absent detail and unrecognized severity degrade gracefully
  const bare = comp.formatEsFinding({ severity: 'catastrophic', condition: 'awareness' });
  expect(bare.summary).toBe('awareness');
  expect(bare.icon).toBe('fa-circle-exclamation');
  expect(bare.color).toBe('warning');

  // A group with a transient outcome interpolates it rather than repeating it
  const unexplained = comp.formatEsFinding({ severity: 'info', condition: 'unexplained', detail: 'throttled' });
  expect(unexplained.summary).toBe('Elasticsearch reports no blocking deciders for this group; allocation outcome: throttled.');
  expect(unexplained.detail).toBe('');
  expect(unexplained.color).toBe('info');
});

test('formatEsReportList', () => {
  expect(comp.formatEsReportList('Affected indices', ['a', 'b'])).toBe('Affected indices (2): a, b');
  const many = Array.from({ length: 14 }, (x, i) => 'idx-' + i);
  expect(comp.formatEsReportList('Affected indices', many))
      .toBe('Affected indices (14): idx-0, idx-1, idx-2, idx-3, idx-4, idx-5, idx-6, idx-7, idx-8, idx-9, ... (+4 more)');
});

test('buildEsHealthReport', () => {
  comp.esHealth = null;
  expect(comp.buildEsHealthReport()).toBe('');

  comp.esHealth = buildEsHealth();
  comp.$root.version = '2.4.999';
  const report = comp.buildEsHealthReport();
  expect(report).toContain('ELASTICSEARCH HEALTH REPORT');
  expect(report).toContain('Security Onion: 2.4.999');
  expect(report).toContain('Overall status: red');

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
  expect(report).toContain('  Shard: so-case[0] (replica)');
  expect(report).toContain('  Unassigned reason: CLUSTER_RECOVERED\n');
  expect(report).toContain('    - disk_threshold: the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]');
  expect(report).toContain('      Affected nodes (1): sa-tshoot-jb');
  expect(report).toContain('--- Cluster Settings (_cluster/settings) ---');
  expect(report).toContain('  cluster.routing.allocation.enable: "all"');
  expect(report).toContain('transient: (none)');
  expect(report).toContain('--- Nodes (_cat/nodes) ---');
  expect(report).toContain('  * node-1 (10.0.0.5) roles=dhimrt master=* version=9.3.3 heap=49% ram=97% cpu=2% load_1m=1.68 disk_used=85.57% of 124.5gb uptime=1.6h');
  // No raw JSON dumps in the report
  expect(report).not.toContain('{');

  comp.esHealth.unassignedShards.groups[0].details = 'failed shard on node [abc]: shard failure';
  expect(comp.buildEsHealthReport()).toContain('  Failure details: failed shard on node [abc]: shard failure');

  // A group left unexplained by the cap is distinguished from one whose
  // explain call failed
  comp.esHealth.unassignedShards.groups[1].sampleStatus = 'capped';
  expect(comp.buildEsHealthReport()).toContain('No allocation explanation sampled for 6 replica (CLUSTER_RECOVERED)');
  comp.esHealth.unassignedShards.groups[1].sampleStatus = 'failed';
  expect(comp.buildEsHealthReport()).toContain('Allocation explanation could not be retrieved for 6 replica (CLUSTER_RECOVERED)');

  // Failed collections omit their section and are disclosed with their reason
  delete comp.esHealth.unassignedShards;
  delete comp.esHealth.settings;
  delete comp.esHealth.nodes;
  comp.esHealth.errors = { nodes: 'connection refused', settings: 'denied', unassignedShards: 'timeout' };
  const minimalReport = comp.buildEsHealthReport();
  expect(minimalReport).toContain('--- Indicators (_health_report) ---');
  expect(minimalReport).not.toContain('_cat/shards');
  expect(minimalReport).not.toContain('_cluster/settings');
  expect(minimalReport).not.toContain('_cat/nodes');
  expect(minimalReport).toContain('Collection failed: nodes: connection refused');
  expect(minimalReport).toContain('Collection failed: settings: denied');
  expect(minimalReport).toContain('Collection failed: unassignedShards: timeout');
});

test('copyEsHealthReport', () => {
  comp.esHealth = buildEsHealth();
  comp.$root.copyToClipboard = jest.fn();
  comp.$root.showTip = jest.fn();
  comp.copyEsHealthReport();
  expect(comp.$root.copyToClipboard).toHaveBeenCalledWith(comp.buildEsHealthReport());
  expect(comp.$root.showTip).toHaveBeenCalledWith(comp.i18n.esHealthCopied);
});
