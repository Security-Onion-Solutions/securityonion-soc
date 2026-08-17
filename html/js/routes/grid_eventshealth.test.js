// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./grid.js');
require('./grid_eventshealth.js');

const comp = getComponent("grid");

beforeEach(() => {
  resetPapi();
});

function buildEventsHealth() {
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

test('loadEventsHealth', async () => {
  const mock = mockPapi("get", { data: buildEventsHealth() });
  comp.eventsHealthExpanded = { disk: true };
  await comp.loadEventsHealth('subgrid1');
  expect(mock).toHaveBeenCalledWith('events/health', expect.objectContaining({ params: { gridId: 'subgrid1' } }));
  expect(comp.eventsHealth.status).toBe('red');
  expect(comp.eventsHealthExpanded).toEqual({});
  expect(comp.eventsHealthLoading).toBe(false);
  expect(comp.eventsHealthIssueIndicators().map(i => i.id)).toEqual(['shards_availability', 'disk']);
});

test('loadEventsHealthSupersededRequestAborted', async () => {
  let rejectSlow;
  const slow = new Promise(function(resolve, reject) { rejectSlow = reject; });
  const mock = mockPapi("get", slow);
  mock.mockReturnValueOnce({ data: buildEventsHealth() });

  const slowLoad = comp.loadEventsHealth();
  const slowSignal = mock.mock.calls[0][1].signal;
  const fastLoad = comp.loadEventsHealth();

  // The newer request aborts the superseded one (cancelling its backend work)
  expect(slowSignal.aborted).toBe(true);
  await fastLoad;
  expect(comp.eventsHealth.status).toBe('red');
  expect(comp.eventsHealthLoading).toBe(false);

  // Axios rejects aborted requests; the late rejection must not clear the
  // newer request's data or show an error
  const showErrorMock = mockShowError();
  rejectSlow({ name: 'CanceledError', message: 'canceled' });
  await slowLoad;
  expect(comp.eventsHealth.status).toBe('red');
  expect(comp.eventsHealthLoading).toBe(false);
  expect(showErrorMock).not.toHaveBeenCalled();
});

test('loadEventsHealthError', async () => {
  mockPapi("get", null, new Error("something bad"));
  const showErrorMock = mockShowError();
  comp.eventsHealth = buildEventsHealth();
  await comp.loadEventsHealth();
  expect(comp.eventsHealth).toBe(null);
  expect(comp.digestEventsHealthIndicators()).toEqual([]);
  expect(comp.eventsHealthLoading).toBe(false);
  // The dialog renders its own unavailable message; no global error popup
  expect(showErrorMock).not.toHaveBeenCalled();
});

test('canShowEventsHealth', () => {
  expect(comp.canShowEventsHealth({ eventsHealthAvailable: true })).toBe(true);
  expect(comp.canShowEventsHealth({ eventsHealthAvailable: false })).toBe(false);
});

test('showHideEventsHealth', () => {
  const loadSpy = jest.spyOn(comp, 'loadEventsHealth').mockImplementation(() => {});
  comp.showEventsHealth({ id: 'mgr', gridId: 'subgrid1' });
  expect(comp.eventsHealthDialog).toBe(true);
  expect(loadSpy).toHaveBeenCalledWith('subgrid1');

  comp.hideEventsHealth();
  expect(comp.eventsHealthDialog).toBe(false);
  loadSpy.mockRestore();
});

test('eventsHealthDialogCloseAborts', () => {
  // Every close path (Close button, ESC, outside-click) funnels through the
  // v-model watcher, which aborts any in-flight request
  const abort = { abort: jest.fn() };
  comp.eventsHealthAbort = abort;
  comp.onEventsHealthDialogChanged(false);
  expect(abort.abort).toHaveBeenCalled();
  expect(comp.eventsHealthAbort).toBe(null);

  // Opening must not abort the load that showEventsHealth just started
  const abort2 = { abort: jest.fn() };
  comp.eventsHealthAbort = abort2;
  comp.onEventsHealthDialogChanged(true);
  expect(abort2.abort).not.toHaveBeenCalled();
  comp.eventsHealthAbort = null;
});

test('colorEventsHealthStatus', () => {
  expect(comp.colorEventsHealthStatus('green')).toBe('success');
  expect(comp.colorEventsHealthStatus('yellow')).toBe('warning');
  expect(comp.colorEventsHealthStatus('red')).toBe('error');
  expect(comp.colorEventsHealthStatus('unknown')).toBe('secondary');
});

test('iconEventsHealthStatus', () => {
  expect(comp.iconEventsHealthStatus('green')).toBe('fa-circle-check');
  expect(comp.iconEventsHealthStatus('yellow')).toBe('fa-circle-exclamation');
  expect(comp.iconEventsHealthStatus('red')).toBe('fa-triangle-exclamation');
  expect(comp.iconEventsHealthStatus('unknown')).toBe('fa-circle-question');
});

test('formatEventsHealthIndicatorName', () => {
  expect(comp.formatEventsHealthIndicatorName('shards_availability')).toBe('Shards availability');
  expect(comp.formatEventsHealthIndicatorName('disk')).toBe('Disk');
  expect(comp.formatEventsHealthIndicatorName('ilm')).toBe('ILM');
  expect(comp.formatEventsHealthIndicatorName('slm')).toBe('SLM');
});

test('digestEventsHealthIndicators', () => {
  comp.eventsHealth = null;
  expect(comp.digestEventsHealthIndicators()).toEqual([]);

  comp.eventsHealth = buildEventsHealth();
  const indicators = comp.digestEventsHealthIndicators();
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

test('eventsHealthIssueAndHealthyIndicators', () => {
  comp.eventsHealth = null;
  expect(comp.eventsHealthIssueIndicators()).toEqual([]);
  expect(comp.eventsHealthHealthyIndicators()).toEqual([]);

  comp.eventsHealth = buildEventsHealth();
  expect(comp.eventsHealthIssueIndicators().map(i => i.id)).toEqual(['shards_availability', 'disk']);
  expect(comp.eventsHealthHealthyIndicators().map(i => i.id)).toEqual(['master_is_stable']);
});

test('toggleEventsHealthDetails', () => {
  comp.eventsHealthExpanded = { disk: true };
  comp.toggleEventsHealthDetails('shards_availability');
  expect(comp.eventsHealthExpanded.shards_availability).toBe(true);
  comp.toggleEventsHealthDetails('shards_availability');
  expect(comp.eventsHealthExpanded.shards_availability).toBe(false);
  expect(comp.eventsHealthExpanded.disk).toBe(true);
});

test('hasEventsHealthDetails', () => {
  comp.eventsHealth = buildEventsHealth();
  const byId = {};
  comp.digestEventsHealthIndicators().forEach(i => byId[i.id] = i);

  // Findings and causes
  expect(comp.hasEventsHealthDetails(byId.shards_availability)).toBe(true);
  // Findings only
  expect(comp.hasEventsHealthDetails(byId.disk)).toBe(true);
  // No details of any kind
  expect(comp.hasEventsHealthDetails(byId.master_is_stable)).toBe(false);

  // Causes alone remain details
  byId.shards_availability.findings = [];
  expect(comp.hasEventsHealthDetails(byId.shards_availability)).toBe(true);
  byId.shards_availability.causes = [];
  expect(comp.hasEventsHealthDetails(byId.shards_availability)).toBe(false);
});

test('formatEventsHealthFinding', () => {
  comp.eventsHealth = buildEventsHealth();
  const byId = {};
  comp.digestEventsHealthIndicators().forEach(i => byId[i.id] = i);
  const findings = byId.shards_availability.findings;
  expect(findings.length).toBe(3);

  // Severity drives the icon and color; the condition drives the explanation
  expect(findings[0].scope).toBe('17 primary (CLUSTER_RECOVERED)');
  expect(findings[0].summary).toBe(comp.i18n.eventsHealthConditionNoValidShardCopy);
  expect(findings[0].detail).toBe('');
  expect(findings[0].color).toBe('error');
  expect(findings[0].icon).toBe('fa-triangle-exclamation');

  expect(findings[1].scope).toBe('6 replica (CLUSTER_RECOVERED)');
  expect(findings[1].summary).toBe(comp.i18n.eventsHealthConditionDiskThreshold);
  expect(findings[1].detail).toBe('disk_threshold: the node is above the low watermark cluster setting [cluster.routing.allocation.disk.watermark.low=80%]');
  expect(findings[1].nodes).toEqual(['sa-tshoot-jb']);
  expect(findings[1].color).toBe('warning');

  expect(findings[2].summary).toBe(comp.i18n.eventsHealthConditionSameShard);
  expect(findings[2].color).toBe('info');
  expect(findings[2].icon).toBe('fa-circle-info');

  // Unscoped findings interpolate their own count
  expect(byId.disk.findings[0].summary).toBe('Write-blocked (read-only) indices: 2. Writes to these indices are rejected; Elasticsearch typically applies this block when disk usage exceeds the flood stage watermark.');
  expect(byId.disk.findings[0].scope).toBe('');

  // Unknown conditions surface the datastore's explanation verbatim
  const unknown = comp.formatEventsHealthFinding({
    severity: 'warning', condition: 'awareness',
    detail: 'too many copies of the shard allocated to nodes with attribute [zone]',
  });
  expect(unknown.summary).toBe('awareness: too many copies of the shard allocated to nodes with attribute [zone]');
  expect(unknown.detail).toBe('');
  expect(unknown.color).toBe('warning');

  // Absent detail and unrecognized severity degrade gracefully
  const bare = comp.formatEventsHealthFinding({ severity: 'catastrophic', condition: 'awareness' });
  expect(bare.summary).toBe('awareness');
  expect(bare.icon).toBe('fa-circle-exclamation');
  expect(bare.color).toBe('warning');

  // A group with a transient outcome interpolates it rather than repeating it
  const unexplained = comp.formatEventsHealthFinding({ severity: 'info', condition: 'unexplained', detail: 'throttled' });
  expect(unexplained.summary).toBe('Elasticsearch reports no blocking deciders for this group; allocation outcome: throttled.');
  expect(unexplained.detail).toBe('');
  expect(unexplained.color).toBe('info');
});

test('formatEventsHealthReportList', () => {
  expect(comp.formatEventsHealthReportList('Affected indices', ['a', 'b'])).toBe('Affected indices (2): a, b');
  const many = Array.from({ length: 14 }, (x, i) => 'idx-' + i);
  expect(comp.formatEventsHealthReportList('Affected indices', many))
      .toBe('Affected indices (14): idx-0, idx-1, idx-2, idx-3, idx-4, idx-5, idx-6, idx-7, idx-8, idx-9, ... (+4 more)');
});

test('buildEventsHealthReport', () => {
  comp.eventsHealth = null;
  expect(comp.buildEventsHealthReport()).toBe('');

  comp.eventsHealth = buildEventsHealth();
  comp.$root.version = '2.4.999';
  const report = comp.buildEventsHealthReport();
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
  expect(report).not.toContain(comp.i18n.eventsHealthConditionNoValidShardCopy);
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

  comp.eventsHealth.unassignedShards.groups[0].failureDetails = 'failed shard on node [abc]: shard failure';
  expect(comp.buildEventsHealthReport()).toContain('  Failure details: failed shard on node [abc]: shard failure');

  // A group left unexplained by the cap is distinguished from one whose
  // explain call failed
  comp.eventsHealth.unassignedShards.groups[1].sampleStatus = 'capped';
  expect(comp.buildEventsHealthReport()).toContain('No allocation explanation sampled for 6 replica (CLUSTER_RECOVERED)');
  comp.eventsHealth.unassignedShards.groups[1].sampleStatus = 'failed';
  expect(comp.buildEventsHealthReport()).toContain('Allocation explanation could not be retrieved for 6 replica (CLUSTER_RECOVERED)');

  // Failed collections omit their section and are disclosed with their reason
  delete comp.eventsHealth.unassignedShards;
  delete comp.eventsHealth.settings;
  delete comp.eventsHealth.nodes;
  comp.eventsHealth.errors = { nodes: 'connection refused', settings: 'denied', unassignedShards: 'timeout' };
  const minimalReport = comp.buildEventsHealthReport();
  expect(minimalReport).toContain('--- Indicators (_health_report) ---');
  expect(minimalReport).not.toContain('_cat/shards');
  expect(minimalReport).not.toContain('_cluster/settings');
  expect(minimalReport).not.toContain('_cat/nodes');
  expect(minimalReport).toContain('Collection failed: nodes: connection refused');
  expect(minimalReport).toContain('Collection failed: settings: denied');
  expect(minimalReport).toContain('Collection failed: unassignedShards: timeout');
});

test('copyEventsHealthReport', () => {
  comp.eventsHealth = buildEventsHealth();
  comp.$root.copyToClipboard = jest.fn();
  comp.$root.showTip = jest.fn();
  comp.copyEventsHealthReport();
  expect(comp.$root.copyToClipboard).toHaveBeenCalledWith(comp.buildEventsHealthReport());
  expect(comp.$root.showTip).toHaveBeenCalledWith(comp.i18n.eventsHealthCopied);
});
