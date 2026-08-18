// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
// The rule view highlights with the same vendored Prism grammars the detection page uses.
require('../external/prism-custom-v1.30.0.js');
// Guided analysis shares its request sequence with the hunt screen.
require('../playbook.js');
// Method packs must load before simplealerts.js, which merges them into the component.
require('./simplealerts.data.js');
require('./simplealerts.grouping.js');
require('./simplealerts.details.js');
require('./simplealerts.rules.js');
require('./simplealerts.actions.js');
require('./simplealerts.pivots.js');
require('./simplealerts.playbook.js');
require('./simplealerts.js');

let comp;

beforeEach(() => {
  comp = getComponent("simple-alerts");
  resetPapi();
});

test('buildQuery', () => {
  comp.filterStatus = 'active';
  comp.filterSeverity = 'all';
  expect(comp.buildQuery()).toBe('tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true');

  comp.filterStatus = 'acknowledged';
  expect(comp.buildQuery()).toBe('tags:alert AND event.acknowledged:true');

  comp.filterStatus = 'escalated';
  expect(comp.buildQuery()).toBe('tags:alert AND event.escalated:true');

  comp.filterStatus = 'all';
  expect(comp.buildQuery()).toBe('tags:alert');

  comp.filterSeverity = 'high';
  expect(comp.buildQuery()).toBe('tags:alert AND event.severity_label:high');
});

test('getDateRange', () => {
  const parse = (range) => {
    const pieces = range.split(' - ');
    expect(pieces.length).toBe(2);
    return pieces.map(p => moment(p, comp.i18n.timePickerFormat));
  };

  comp.filterTimeRange = '1h';
  let [start, end] = parse(comp.getDateRange());
  expect(end.diff(start, 'hours')).toBe(1);

  comp.filterTimeRange = '24h';
  [start, end] = parse(comp.getDateRange());
  expect(end.diff(start, 'hours')).toBe(24);

  comp.filterTimeRange = '7d';
  [start, end] = parse(comp.getDateRange());
  expect(end.diff(start, 'days')).toBe(7);

  comp.filterTimeRange = '30d';
  [start, end] = parse(comp.getDateRange());
  expect(end.diff(start, 'days')).toBe(30);
});

test('getDateRangeDefaultsToOneDay', () => {
  comp.filterTimeRange = 'not-a-range';
  const pieces = comp.getDateRange().split(' - ');
  const start = moment(pieces[0], comp.i18n.timePickerFormat);
  const end = moment(pieces[1], comp.i18n.timePickerFormat);
  expect(end.diff(start, 'hours')).toBe(24);
});

test('processAlertsMergesFieldSources', () => {
  const alerts = comp.processAlerts([{
    id: 'fallback-id',
    timestamp: '2025-01-01T00:00:00Z',
    payload: { 'rule.name': 'ET MALWARE Something Bad', 'source.ip': '10.1.2.3' },
    fields: { 'destination.ip': '8.8.8.8', 'event.severity_label': 'high' },
    event_data: { 'soc_id': 'evt-1' },
  }]);

  expect(alerts.length).toBe(1);
  const alert = alerts[0];
  expect(alert.id).toBe('evt-1');
  expect(alert.ruleName).toBe('ET MALWARE Something Bad');
  expect(alert.sourceIp).toBe('10.1.2.3');
  expect(alert.destIp).toBe('8.8.8.8');
  expect(alert.severityLabel).toBe('high');
  expect(alert.isHostBased).toBe(false);
});

test('processAlertsDerivesCategoryAndOptions', () => {
  const alerts = comp.processAlerts([
    { payload: { 'rule.name': 'ET MALWARE One' } },
    { payload: { 'rule.name': 'GPL ATTACK_RESPONSE Two' } },
    { payload: { 'rule.name': 'ET MALWARE Three' } },
    { payload: { 'rule.name': 'Some Unprefixed Rule' } },
  ]);

  expect(alerts.map(a => a['rule.category'])).toEqual(['MALWARE', 'ATTACK_RESPONSE', 'MALWARE', '']);
  // deduplicated, sorted, and prefixed with the "all" option
  expect(comp.categoryOptions).toEqual([
    { value: 'all', title: 'All Categories' },
    { value: 'ATTACK_RESPONSE', title: 'ATTACK_RESPONSE' },
    { value: 'MALWARE', title: 'MALWARE' },
  ]);
});

test('processAlertsHandlesMissingFields', () => {
  const alerts = comp.processAlerts([{}]);
  expect(alerts[0].ruleName).toBe('Unknown Rule');
  expect(alerts[0].severityLabel).toBe('unknown');
  expect(alerts[0].acknowledged).toBe(false);
  expect(alerts[0].escalated).toBe(false);
  // no source or destination makes this a host-based alert
  expect(alerts[0].isHostBased).toBe(true);
});

test('processAlertsPrefersSocIdOverEventId', () => {
  expect(comp.processAlerts([{ id: 'evt', payload: { 'soc_id': 'soc' } }])[0].id).toBe('soc');
  expect(comp.processAlerts([{ id: 'evt', payload: {} }])[0].id).toBe('evt');
});

test('getSeverityLevel', () => {
  expect(comp.getSeverityLevel({ severityLabel: 'high' })).toBe('high');
  expect(comp.getSeverityLevel({ severityLabel: 'critical' })).toBe('high');
  expect(comp.getSeverityLevel({ severityLabel: 'HIGH' })).toBe('high');
  expect(comp.getSeverityLevel({ severityLabel: 'medium' })).toBe('medium');
  expect(comp.getSeverityLevel({ severityLabel: 'low' })).toBe('low');
  expect(comp.getSeverityLevel({ severityLabel: 'anything else' })).toBe('low');
  expect(comp.getSeverityLevel({})).toBe('low');
});

test('severityColor', () => {
  // theme tokens, never literal colors, so chips follow the active theme
  expect(comp.severityColor({ severityLabel: 'high' })).toBe('error');
  expect(comp.severityColor({ severityLabel: 'critical' })).toBe('error');
  expect(comp.severityColor({ severityLabel: 'medium' })).toBe('warning');
  expect(comp.severityColor({ severityLabel: 'low' })).toBe('info');
  expect(comp.severityColor({})).toBe('info');
});

test('isPrivateIP', () => {
  expect(comp.isPrivateIP('10.0.0.1')).toBe(true);
  expect(comp.isPrivateIP('172.16.0.1')).toBe(true);
  expect(comp.isPrivateIP('172.31.255.255')).toBe(true);
  expect(comp.isPrivateIP('192.168.1.1')).toBe(true);
  expect(comp.isPrivateIP('127.0.0.1')).toBe(true);

  expect(comp.isPrivateIP('8.8.8.8')).toBe(false);
  expect(comp.isPrivateIP('172.15.0.1')).toBe(false);
  expect(comp.isPrivateIP('172.32.0.1')).toBe(false);
  expect(comp.isPrivateIP('192.169.1.1')).toBe(false);

  expect(comp.isPrivateIP('')).toBe(false);
  expect(comp.isPrivateIP(null)).toBe(false);
  expect(comp.isPrivateIP(undefined)).toBe(false);
  // IPv6 and malformed input must not be reported as private
  expect(comp.isPrivateIP('::1')).toBe(false);
  expect(comp.isPrivateIP('not.an.ip.addr')).toBe(false);
});

test('formatCompactNumber', () => {
  expect(comp.formatCompactNumber(0)).toBe('0');
  expect(comp.formatCompactNumber(999)).toBe('999');
  expect(comp.formatCompactNumber(1000)).toBe('1K');
  expect(comp.formatCompactNumber(1500)).toBe('1.5K');
  expect(comp.formatCompactNumber(99999)).toBe('100K');
  expect(comp.formatCompactNumber(100000)).toBe('100K');
  expect(comp.formatCompactNumber(1000000)).toBe('1M');
  expect(comp.formatCompactNumber(2500000)).toBe('2.5M');
});

test('loadAlerts', async () => {
  const mock = mockPapi("get", { data: {
    events: [{ payload: { 'soc_id': 'a', 'rule.name': 'ET MALWARE One' } }],
    totalEvents: 5,
  }});

  comp.filterStatus = 'all';
  comp.filterSeverity = 'all';
  comp.filterTimeRange = '24h';
  comp.groupAlerts = false;
  await comp.loadAlerts();

  expect(mock).toHaveBeenCalled();
  const [route, options] = mock.mock.calls[0];
  expect(route).toBe('events/');
  expect(options.params.query).toBe('tags:alert | groupby event.severity_label');
  expect(options.params.format).toBe(comp.i18n.timePickerSample);
  expect(options.params.eventLimit).toBe(100);
  expect(options.params.metricLimit).toBe(10);
  // the events/ route has no "view" parameter; sending one would be silently ignored
  expect(options.params.view).toBeUndefined();

  expect(comp.alerts.length).toBe(1);
  expect(comp.totalAlerts).toBe(5);
  expect(comp.hasMore).toBe(true);
  expect(comp.loading).toBe(false);
});

test('loadAlertsRequestsSeverityAggregation', async () => {
  const mock = mockPapi("get", { data: { events: [], totalEvents: 0, metrics: {} } });
  comp.filterStatus = 'all';
  comp.filterSeverity = 'all';
  comp.groupAlerts = false;

  await comp.loadAlerts();

  // the aggregation rides along with the event page rather than costing extra requests
  expect(mock.mock.calls[0][1].params.query).toBe('tags:alert | groupby event.severity_label');
  expect(mock).toHaveBeenCalledTimes(1);
});

test('loadAlertsRaisesMetricLimitWhenGrouped', async () => {
  const mock = mockPapi("get", { data: { events: [], totalEvents: 0, metrics: {} } });

  comp.groupAlerts = false;
  await comp.loadAlerts();
  expect(mock.mock.calls[0][1].params.metricLimit).toBe(comp.metricLimit);

  resetPapi();
  const grouped = mockPapi("get", { data: { events: [], totalEvents: 0, metrics: {} } });
  comp.groupAlerts = true;
  comp.groupingMode = 'rule';
  await comp.loadAlerts();
  // the aggregation has to cover the groups the page shows, not just severity buckets
  expect(grouped.mock.calls[0][1].params.metricLimit).toBe(comp.groupLimit);
});

test('parseSeverityTotals', () => {
  const totals = comp.parseSeverityTotals({ 'groupby_0|event.severity_label': [
    { value: 10, keys: ['high'] },
    { value: 5, keys: ['critical'] },
    { value: 20, keys: ['medium'] },
    { value: 30, keys: ['low'] },
    { value: 1, keys: ['something-unmapped'] },
  ]});

  // critical folds into high, and anything unrecognized falls to low
  expect(totals).toEqual({ high: 15, medium: 20, low: 31 });
});

test('parseSeverityTotalsMissingAggregation', () => {
  expect(comp.parseSeverityTotals(undefined)).toBeNull();
  expect(comp.parseSeverityTotals({})).toBeNull();
  expect(comp.parseSeverityTotals({ 'groupby_0|other.field': [] })).toBeNull();
  expect(comp.parseSeverityTotals({ 'groupby_0|event.severity_label': [] })).toEqual({ high: 0, medium: 0, low: 0 });
});

test('severityCountsFallBackWhenAggregationMissing', async () => {
  mockPapi("get", { data: { events: [], totalEvents: 0, metrics: {} } });
  await comp.loadAlerts();

  expect(comp.severityTotals).toBeNull();
  // a dash, not a zero that would read as "none matched"
  expect(comp.highSeverityCount()).toBe('—');
  expect(comp.mediumSeverityCount()).toBe('—');
  expect(comp.lowSeverityCount()).toBe('—');
});

test('totalAlertsLabelTracksStatusFilter', () => {
  comp.filterStatus = 'active';
  expect(comp.totalAlertsLabel()).toBe('Active');
  comp.filterStatus = 'acknowledged';
  expect(comp.totalAlertsLabel()).toBe('Acknowledged');
  comp.filterStatus = 'escalated';
  expect(comp.totalAlertsLabel()).toBe('Escalated');
  comp.filterStatus = 'all';
  expect(comp.totalAlertsLabel()).toBe('All Statuses');
});

test('loadAlertsHandlesError', async () => {
  mockPapi("get", null, new Error("boom"));
  const showError = mockShowError();

  await comp.loadAlerts();

  expect(showError).toHaveBeenCalled();
  expect(comp.loading).toBe(false);
});

test('loadAlertsSkipsReverseLookupWhenDisabled', async () => {
  mockPapi("get", { data: { events: [{ payload: { 'source.ip': '1.1.1.1' } }], totalEvents: 1 } });
  comp.$root.enableReverseLookup = false;
  comp.$root.batchLookup = jest.fn();

  await comp.loadAlerts();

  expect(comp.$root.batchLookup).not.toHaveBeenCalled();
});

test('loadAlertsBatchesReverseLookupWhenEnabled', async () => {
  mockPapi("get", { data: { events: [
    { payload: { 'source.ip': '1.1.1.1', 'destination.ip': '2.2.2.2' } },
    { payload: { 'source.ip': '3.3.3.3' } },
  ], totalEvents: 2 } });
  comp.$root.enableReverseLookup = true;
  comp.$root.batchLookup = jest.fn();

  await comp.loadAlerts();

  expect(comp.$root.batchLookup).toHaveBeenCalledWith(['1.1.1.1', '2.2.2.2', '3.3.3.3'], comp);
});

test('processedAlertsFiltersByCategory', () => {
  comp.alerts = [
    { id: '1', 'rule.category': 'MALWARE' },
    { id: '2', 'rule.category': 'POLICY' },
    { id: '3', 'rule.category': 'MALWARE' },
  ];

  comp.filterCategory = 'all';
  expect(comp.processedAlerts().length).toBe(3);

  comp.filterCategory = 'MALWARE';
  expect(comp.processedAlerts().map(a => a.id)).toEqual(['1', '3']);

  comp.filterCategory = 'NONE';
  expect(comp.processedAlerts().length).toBe(0);
});

test('severityCountsRenderCompactAggregateTotals', () => {
  // these describe every matching alert, not just the loaded page
  comp.severityTotals = { high: 3623, medium: 2900, low: 1900 };

  expect(comp.highSeverityCount()).toBe('3.6K');
  expect(comp.mediumSeverityCount()).toBe('2.9K');
  expect(comp.lowSeverityCount()).toBe('1.9K');
});

// --- grouping ---------------------------------------------------------------

const RULE_METRIC_KEY = 'groupby_1|rule.name|event.severity_label|rule.uuid';
const SD_METRIC_KEY = 'groupby_1|source.ip|destination.ip';

test('buildFullQueryIncludesActiveGrouping', () => {
  comp.filterStatus = 'all';
  comp.filterSeverity = 'all';

  comp.groupAlerts = true;
  comp.groupingMode = 'rule';
  expect(comp.buildFullQuery()).toBe(
    'tags:alert | groupby event.severity_label | groupby rule.name event.severity_label rule.uuid');

  comp.groupingMode = 'source-dest';
  expect(comp.buildFullQuery()).toBe(
    'tags:alert | groupby event.severity_label | groupby source.ip destination.ip');

  comp.groupAlerts = false;
  expect(comp.buildFullQuery()).toBe('tags:alert | groupby event.severity_label');
});

test('parseRuleGroupsFoldsSeveritiesAndSumsExactCounts', () => {
  const groups = comp.parseRuleGroups([
    { value: 10, keys: ['ET MALWARE One', 'medium', 'uuid-1'] },
    { value: 5, keys: ['ET MALWARE One', 'high', 'uuid-1'] },
    { value: 40, keys: ['GPL ATTACK_RESPONSE Two', 'low', 'uuid-2'] },
  ]);

  // sorted by count desc
  expect(groups.map(g => g.ruleName)).toEqual(['GPL ATTACK_RESPONSE Two', 'ET MALWARE One']);

  const one = groups.find(g => g.ruleName === 'ET MALWARE One');
  // counts are summed, not extrapolated from a sampled ratio
  expect(one.count).toBe(15);
  // a rule spanning severities takes its highest
  expect(one.severityLabel).toBe('high');
  expect(one.ruleUuid).toBe('uuid-1');
  expect(one['rule.category']).toBe('MALWARE');
  expect(one.alertsLoaded).toBe(false);
});

test('parseRuleGroupsHandlesMissingSentinels', () => {
  const groups = comp.parseRuleGroups([
    { value: 3, keys: ['__missing__', '__missing__', '__missing__'] },
  ]);

  expect(groups[0].ruleName).toBe('Unknown Rule');
  expect(groups[0].severityLabel).toBe('unknown');
  // the sentinel must not leak through as a usable uuid
  expect(groups[0].ruleUuid).toBeNull();
});

test('parseSourceDestGroupsDropsPairlessRows', () => {
  const groups = comp.parseSourceDestGroups([
    { value: 7, keys: ['10.0.0.1', '8.8.8.8'] },
    { value: 99, keys: ['__missing__', '__missing__'] },
    { value: 20, keys: ['10.0.0.2', '1.1.1.1'] },
  ]);

  // host-based alerts have no pair and would otherwise form one meaningless group
  expect(groups.length).toBe(2);
  expect(groups[0].count).toBe(20);
  expect(groups[0].sourceIp).toBe('10.0.0.2');
});

test('applyGroupMetricsRoutesByMode', () => {
  const metrics = {
    [RULE_METRIC_KEY]: [{ value: 4, keys: ['ET MALWARE One', 'high', 'u1'] }],
    [SD_METRIC_KEY]: [{ value: 9, keys: ['10.0.0.1', '8.8.8.8'] }],
  };

  comp.groupAlerts = true;
  comp.groupingMode = 'rule';
  comp.applyGroupMetrics(metrics);
  expect(comp.alertGroups.length).toBe(1);
  expect(comp.sourceDestGroups.length).toBe(0);

  comp.groupingMode = 'source-dest';
  comp.applyGroupMetrics(metrics);
  expect(comp.sourceDestGroups.length).toBe(1);
  expect(comp.alertGroups.length).toBe(0);

  comp.groupAlerts = false;
  comp.applyGroupMetrics(metrics);
  expect(comp.alertGroups.length).toBe(0);
  expect(comp.sourceDestGroups.length).toBe(0);
});

test('applyGroupMetricsToleratesAbsentAggregation', () => {
  comp.groupAlerts = true;
  comp.groupingMode = 'rule';
  comp.applyGroupMetrics({});
  expect(comp.alertGroups).toEqual([]);
});

test('toggleGroupExpandsAndLazyLoadsOnce', async () => {
  const group = comp.newGroup('rule', 'ET MALWARE One', { ruleName: 'ET MALWARE One', count: 3 });
  comp.loadGroupAlerts = jest.fn();

  expect(comp.isGroupExpanded(group)).toBe(false);

  comp.toggleGroup(group);
  expect(comp.isGroupExpanded(group)).toBe(true);
  expect(comp.loadGroupAlerts).toHaveBeenCalledTimes(1);

  comp.toggleGroup(group);
  expect(comp.isGroupExpanded(group)).toBe(false);

  // collapsing and re-expanding must not refetch
  group.alertsLoaded = true;
  comp.toggleGroup(group);
  expect(comp.loadGroupAlerts).toHaveBeenCalledTimes(1);
});

test('groupTerms', () => {
  expect(comp.groupTerms({ kind: 'rule', ruleName: 'ET MALWARE One' }))
    .toEqual([{ field: 'rule.name', value: 'ET MALWARE One' }]);

  expect(comp.groupTerms({ kind: 'source-dest', sourceIp: '10.0.0.1', destIp: '8.8.8.8' }))
    .toEqual([
      { field: 'source.ip', value: '10.0.0.1' },
      { field: 'destination.ip', value: '8.8.8.8' },
    ]);

  // a pair missing one side only contributes the side it has
  expect(comp.groupTerms({ kind: 'source-dest', sourceIp: '10.0.0.1', destIp: null }))
    .toEqual([{ field: 'source.ip', value: '10.0.0.1' }]);
});

test('narrowQueryDelegatesEscapingToServer', async () => {
  const mock = mockPapi("get", { data: 'tags:alert AND rule.name:"ET MALWARE One"' });

  const result = await comp.narrowQuery('tags:alert', [{ field: 'rule.name', value: 'ET MALWARE One' }]);

  expect(mock).toHaveBeenCalledWith('query/filtered', { params: {
    query: 'tags:alert',
    field: 'rule.name',
    value: 'ET MALWARE One',
    scalar: false,
    mode: 'INCLUDE',
  }});
  expect(result).toBe('tags:alert AND rule.name:"ET MALWARE One"');
});

test('loadGroupAlertsFetchesNarrowedEvents', async () => {
  const group = comp.newGroup('rule', 'ET MALWARE One', { ruleName: 'ET MALWARE One', count: 900 });
  comp.narrowQuery = jest.fn().mockResolvedValue('narrowed-query');
  const mock = mockPapi("get", { data: { events: [
    { payload: { 'soc_id': 'a', 'rule.name': 'ET MALWARE One' } },
  ], totalEvents: 900 } });

  await comp.loadGroupAlerts(group);

  expect(mock.mock.calls[0][1].params.query).toBe('narrowed-query');
  expect(mock.mock.calls[0][1].params.eventLimit).toBe(comp.groupAlertLimit);
  expect(group.alerts.length).toBe(1);
  expect(group.alertsLoaded).toBe(true);
  expect(group.alertsLoading).toBe(false);
  // the exact total came from the aggregation; the fetched sample fell short of it
  expect(group.alertsTruncated).toBe(true);
});

test('loadGroupAlertsHandlesError', async () => {
  const group = comp.newGroup('rule', 'r', { ruleName: 'r' });
  comp.narrowQuery = jest.fn().mockRejectedValue(new Error('boom'));
  const showError = mockShowError();

  await comp.loadGroupAlerts(group);

  expect(showError).toHaveBeenCalled();
  expect(group.alertsLoading).toBe(false);
  expect(group.alertsLoaded).toBe(false);
});

test('displayLimitAndLoadMore', () => {
  const group = comp.newGroup('rule', 'r', { ruleName: 'r' });
  group.alerts = Array.from({ length: 120 }, (_, i) => ({ id: String(i) }));
  comp.subGroupDisplayLimit = 50;

  expect(comp.getDisplayedAlerts(group).length).toBe(50);
  expect(comp.shouldShowLoadMore(group)).toBe(true);
  expect(comp.getLoadMoreText(group)).toBe('Show all 120');

  comp.toggleLoadMore(group);
  expect(comp.getDisplayedAlerts(group).length).toBe(120);
  expect(comp.getLoadMoreText(group)).toBe('Show fewer');

  group.alerts = group.alerts.slice(0, 10);
  group.showAll = false;
  expect(comp.shouldShowLoadMore(group)).toBe(false);
  expect(comp.getDisplayedAlerts(group).length).toBe(10);
});

test('getGroupSummary', () => {
  const group = comp.newGroup('rule', 'r', { ruleName: 'r', severityLabel: 'high', count: 1500 });
  expect(comp.getGroupSummary(group)).toBe('1.5K alerts · high');

  group.alertsTruncated = true;
  group.alerts = Array.from({ length: 500 }, () => ({}));
  expect(comp.getGroupSummary(group)).toBe('1.5K alerts · high · showing first 500');

  const sd = comp.newGroup('source-dest', 'k', { sourceIp: '10.0.0.1', destIp: '8.8.8.8', count: 12 });
  expect(comp.getGroupSummary(sd)).toBe('12 alerts');
});

test('groupHeadersVaryByGroupKind', () => {
  expect(comp.groupHeaders({ kind: 'rule' }).map(h => h.value)).toEqual(['timestamp', 'sourceIp', 'destIp']);
  expect(comp.groupHeaders({ kind: 'source-dest' }).map(h => h.value)).toEqual(['timestamp', 'ruleName']);
});

test('setGroupingModeResetsExpansionAndReloads', () => {
  comp.loadAlerts = jest.fn();
  comp.expandedGroups = ['stale-key'];

  comp.setGroupingMode('source-dest');
  expect(comp.groupingMode).toBe('source-dest');
  expect(comp.groupAlerts).toBe(true);
  expect(comp.expandedGroups).toEqual([]);
  expect(comp.loadAlerts).toHaveBeenCalled();

  comp.setGroupingMode('none');
  expect(comp.groupAlerts).toBe(false);
});

test('visibleGroupsAppliesCategoryFilterOnlyWhereMeaningful', () => {
  comp.groupingMode = 'rule';
  comp.alertGroups = [
    { key: 'a', 'rule.category': 'MALWARE' },
    { key: 'b', 'rule.category': 'POLICY' },
  ];
  comp.filterCategory = 'MALWARE';
  expect(comp.categoryFilterEnabled()).toBe(true);
  expect(comp.visibleGroups().map(g => g.key)).toEqual(['a']);

  // source/destination groups carry no rule dimension, so the filter cannot apply
  comp.groupingMode = 'source-dest';
  comp.sourceDestGroups = [{ key: 'x' }, { key: 'y' }];
  expect(comp.categoryFilterEnabled()).toBe(false);
  expect(comp.visibleGroups().length).toBe(2);
});

test('localSettingsRoundTrip', () => {
  Object.keys(localStorage).filter(k => k.startsWith('settings.simplealerts.')).forEach(k => localStorage.removeItem(k));

  comp.groupingMode = 'source-dest';
  comp.filterStatus = 'acknowledged';
  comp.filterSeverity = 'high';
  comp.filterTimeRange = '7d';
  comp.saveLocalSettings();

  comp.groupingMode = 'rule';
  comp.groupAlerts = true;
  comp.filterStatus = 'active';
  comp.filterSeverity = 'all';
  comp.filterTimeRange = '24h';
  comp.loadLocalSettings();

  expect(comp.groupingMode).toBe('source-dest');
  expect(comp.groupAlerts).toBe(true);
  expect(comp.filterStatus).toBe('acknowledged');
  expect(comp.filterSeverity).toBe('high');
  expect(comp.filterTimeRange).toBe('7d');
});

test('localSettingsOmitsDefaults', () => {
  Object.keys(localStorage).filter(k => k.startsWith('settings.simplealerts.')).forEach(k => localStorage.removeItem(k));

  comp.groupingMode = 'rule';
  comp.filterStatus = 'active';
  comp.filterSeverity = 'all';
  comp.filterTimeRange = '24h';
  comp.saveLocalSettings();

  // defaults are not persisted, so a later change to the default survives an upgrade
  expect(localStorage['settings.simplealerts.groupingMode']).toBeUndefined();
  expect(localStorage['settings.simplealerts.filterStatus']).toBeUndefined();
});

test('localSettingsRestoresUngroupedMode', () => {
  localStorage['settings.simplealerts.groupingMode'] = 'none';
  comp.groupAlerts = true;

  comp.loadLocalSettings();

  expect(comp.groupingMode).toBe('none');
  expect(comp.groupAlerts).toBe(false);
  localStorage.removeItem('settings.simplealerts.groupingMode');
});

test('onFilterChangedPersistsAndReloads', () => {
  comp.loadAlerts = jest.fn();
  comp.saveLocalSettings = jest.fn();

  comp.onFilterChanged();

  expect(comp.saveLocalSettings).toHaveBeenCalled();
  expect(comp.loadAlerts).toHaveBeenCalled();
});

// --- details dialog ---------------------------------------------------------

test('extractGeoReadsEcsFields', () => {
  const geo = comp.extractGeo({
    'source.geo.city_name': 'Austin',
    'source.geo.region_iso_code': 'US-TX',
    'source.geo.country_name': 'United States',
    'source.as.organization.name': 'Example ISP',
  }, 'source');

  expect(geo).toEqual({
    city: 'Austin', regionCode: 'US-TX', regionName: undefined,
    country: 'United States', asOrg: 'Example ISP',
  });

  // a document with no geo at all yields null rather than a hollow object
  expect(comp.extractGeo({ 'source.ip': '1.1.1.1' }, 'source')).toBeNull();
});

test('processAlertsPopulatesGeo', () => {
  // the original hard-coded these to null because it requested a "simple" view
  const alert = comp.processAlerts([{ payload: {
    'source.ip': '8.8.8.8',
    'source.geo.country_name': 'United States',
    'destination.ip': '10.0.0.1',
  }}])[0];

  expect(alert.sourceGeo).not.toBeNull();
  expect(alert.sourceGeo.country).toBe('United States');
  expect(alert.destGeo).toBeNull();
});

test('formatGeoInfo', () => {
  expect(comp.formatGeoInfo(null, '10.0.0.1')).toBe('Private network (RFC1918)');
  // a private address takes precedence even when geo data happens to exist
  expect(comp.formatGeoInfo({ country: 'X' }, '192.168.1.1')).toBe('Private network (RFC1918)');

  expect(comp.formatGeoInfo(null, '8.8.8.8')).toBe('Location not available');

  expect(comp.formatGeoInfo({ city: 'Austin', regionCode: 'US-TX', country: 'United States' }, '8.8.8.8'))
    .toBe('Austin, US-TX, United States');
  // region name is the fallback when the ISO code is absent
  expect(comp.formatGeoInfo({ city: 'Austin', regionName: 'Texas', country: 'United States' }, '8.8.8.8'))
    .toBe('Austin, Texas, United States');
  expect(comp.formatGeoInfo({ country: 'Sweden', asOrg: 'Example AB' }, '8.8.8.8'))
    .toBe('Sweden · Example AB');
  expect(comp.formatGeoInfo({ asOrg: 'Example AB' }, '8.8.8.8')).toBe('Example AB');
});

test('showAndCloseDetails', () => {
  const alert = { id: 'a1', ruleName: 'r' };
  comp.showDetails(alert);
  expect(comp.detailsDialog).toBe(true);
  expect(comp.selectedAlertDetails).toBe(alert);

  comp.closeDetails();
  expect(comp.detailsDialog).toBe(false);
});

test('getDetailFieldsOmitsPromotedAndEmptyValues', () => {
  const fields = comp.getDetailFields({ payload: {
    'rule.name': 'promoted away',
    'source.ip': 'promoted away',
    'event.severity_label': 'promoted away',
    'zeta.field': 'z',
    'alpha.field': 'a',
    'empty.field': '',
    'null.field': null,
    'undefined.field': undefined,
    'zero.field': 0,
    'false.field': false,
  }});

  // sorted for a stable layout; zero and false are real values and must survive
  expect(fields).toEqual([
    { key: 'alpha.field', value: 'a' },
    { key: 'false.field', value: false },
    { key: 'zero.field', value: 0 },
    { key: 'zeta.field', value: 'z' },
  ]);
});

test('getDetailFieldsOmitsGeoRenderedByTheNetworkPanel', () => {
  const fields = comp.getDetailFields({ payload: {
    'destination.geo.city_name': 'Mountain View',
    'destination.geo.country_name': 'United States',
    'destination.as.organization.name': 'Google LLC',
    'network.protocol': 'dns',
  }});

  // the network panel already shows these as a formatted location
  expect(fields.map(f => f.key)).toEqual(['network.protocol']);
});

test('getDetailFieldsHandlesMissingPayload', () => {
  expect(comp.getDetailFields(null)).toEqual([]);
  expect(comp.getDetailFields({})).toEqual([]);
});

test('getEndpoints', () => {
  const endpoints = comp.getEndpoints({
    isHostBased: false,
    sourceIp: '10.0.0.1', sourcePort: 1234, sourceGeo: null,
    destIp: '8.8.8.8', destPort: 53, destGeo: { country: 'United States' },
  });

  expect(endpoints.length).toBe(2);
  expect(endpoints[0].role).toBe('Source');
  expect(endpoints[0].isPrivate).toBe(true);
  expect(endpoints[0].geo).toBe('Private network (RFC1918)');
  expect(endpoints[1].isPrivate).toBe(false);
  expect(endpoints[1].geo).toBe('United States');
});

test('getEndpointsSkipsHostBasedAndMissingSides', () => {
  // host-based alerts have no network dimension, so the panel is omitted entirely
  expect(comp.getEndpoints({ isHostBased: true, sourceIp: 'x', destIp: 'y' })).toEqual([]);
  expect(comp.getEndpoints(null)).toEqual([]);

  const oneSided = comp.getEndpoints({ isHostBased: false, sourceIp: '10.0.0.1', destIp: null });
  expect(oneSided.length).toBe(1);
  expect(oneSided[0].role).toBe('Source');
});

test('getHuntRouteEscapesTheAlertId', () => {
  const route = comp.getHuntRoute({ id: 'weird"id' });
  expect(route.path).toBe('/alerts');
  expect(route.query.q).toBe('tags:alert AND soc_id:"weird\\"id"');
  expect(route.query.z).toBe(comp.zone);
  expect(route.query.t).toContain(' - ');

  expect(comp.getHuntRoute(null)).toBeNull();
});

test('copyAlertId', async () => {
  const writeText = jest.fn().mockResolvedValue(undefined);
  global.navigator.clipboard = { writeText };
  comp.$root.showTip = jest.fn();

  await comp.copyAlertId({ id: 'abc' });

  expect(writeText).toHaveBeenCalledWith('abc');
  expect(comp.$root.showTip).toHaveBeenCalled();
});

test('copyAlertIdSurfacesFailure', async () => {
  global.navigator.clipboard = { writeText: jest.fn().mockRejectedValue(new Error('denied')) };
  const showError = mockShowError();

  await comp.copyAlertId({ id: 'abc' });

  expect(showError).toHaveBeenCalled();
});

// --- rule highlighting ------------------------------------------------------

test('ruleLanguageMapsEngineToGrammar', () => {
  expect(comp.ruleLanguage({ module: 'suricata' })).toBe('suricata');
  expect(comp.ruleLanguage({ module: 'Suricata' })).toBe('suricata');
  expect(comp.ruleLanguage({ module: 'sigma' })).toBe('yaml');
  expect(comp.ruleLanguage({ module: 'elastalert' })).toBe('yaml');
  expect(comp.ruleLanguage({ module: 'yara' })).toBe('yara');
  expect(comp.ruleLanguage({ module: 'strelka' })).toBe('yara');

  expect(comp.ruleLanguage({ module: 'ossec' })).toBeNull();
  expect(comp.ruleLanguage({})).toBeNull();
  expect(comp.ruleLanguage(null)).toBeNull();
});

test('ruleLanguageClass', () => {
  expect(comp.ruleLanguageClass({ module: 'suricata' })).toBe('language-suricata');
  expect(comp.ruleLanguageClass({ module: 'sigma' })).toBe('language-yaml');
  expect(comp.ruleLanguageClass({ module: 'ossec' })).toBe('');
});

test('hasRuleText', () => {
  expect(comp.hasRuleText({ ruleText: 'alert tcp any any -> any any (sid:1;)' })).toBe(true);
  expect(comp.hasRuleText({ ruleText: '' })).toBe(false);
  expect(comp.hasRuleText({})).toBe(false);
  expect(comp.hasRuleText(null)).toBe(false);
});

test('highlightRuleEscapesUntrustedContent', () => {
  // With no grammar the text renders literally, so markup is escaped rather than
  // sanitized; sanitizing would keep a stripped <img> tag and misreport the rule.
  const plain = comp.highlightRule({ module: 'ossec', ruleText: '<img src=x onerror="alert(1)">' });
  expect(plain).toBe('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');

  // The grammar path goes through Prism, which escapes its input as well.
  const highlighted = comp.highlightRule({ module: 'suricata', ruleText: '<script>alert(1)</script>' });
  expect(highlighted).not.toContain('<script');
  expect(highlighted).toContain('&lt;');

  expect(comp.highlightRule({ ruleText: '' })).toBe('');
  expect(comp.highlightRule(null)).toBe('');
});

test('highlightRuleProducesPrismMarkupForKnownGrammars', () => {
  const html = comp.highlightRule({
    module: 'suricata',
    ruleText: 'alert tcp any any -> any any (msg:"test"; sid:1;)',
  });
  // Prism emits token spans; the rule text itself must survive intact
  expect(html).toContain('<span');
  expect(html).toContain('sid');
});

// --- selection and actions --------------------------------------------------

function papiSpy(responses) {
  const calls = [];
  comp.$root.papi = {
    get: jest.fn((route, opts) => { calls.push(['get', route, opts]); return Promise.resolve({ data: '' }); }),
    post: jest.fn((route, body) => {
      calls.push(['post', route, body]);
      return Promise.resolve(responses[route] || { data: {} });
    }),
  };
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.showTip = jest.fn();
  comp.$root.showWarning = jest.fn();
  return calls;
}

test('selectionToggles', () => {
  comp.clearSelection();
  const alert = { id: 'a1' };
  expect(comp.isAlertSelected(alert)).toBe(false);

  comp.toggleAlertSelection(alert);
  expect(comp.isAlertSelected(alert)).toBe(true);
  comp.toggleAlertSelection(alert);
  expect(comp.isAlertSelected(alert)).toBe(false);

  const group = { key: 'g1' };
  comp.toggleGroupSelection(group);
  expect(comp.isGroupSelected(group)).toBe(true);
  comp.toggleGroupSelection(group);
  expect(comp.isGroupSelected(group)).toBe(false);
});

test('toggleSelectionModeClearsOnExit', () => {
  comp.clearSelection();
  comp.selectionMode = false;
  comp.toggleAlertSelection({ id: 'a1' });

  comp.toggleSelectionMode();
  expect(comp.selectionMode).toBe(true);
  expect(comp.hasSelection()).toBe(true);

  comp.toggleSelectionMode();
  expect(comp.selectionMode).toBe(false);
  expect(comp.hasSelection()).toBe(false);
});

test('selectionSummaryCountsWholeGroups', () => {
  comp.clearSelection();
  comp.groupingMode = 'rule';
  comp.alertGroups = [
    { key: 'g1', count: 1500, alerts: [] },
    { key: 'g2', count: 40, alerts: [] },
  ];
  comp.filterCategory = 'all';

  comp.toggleGroupSelection(comp.alertGroups[0]);
  comp.toggleAlertSelection({ id: 'a1' });

  // a selected group contributes its true count, not the rows on screen
  expect(comp.selectionSummary()).toEqual({ alerts: 1, groups: 1, total: 1501 });
});

test('buildCaseMatchesHuntShape', () => {
  const built = comp.buildCase({
    ruleName: 'ET MALWARE One',
    severity: 3,
    payload: { 'rule.case_template': 'tmpl' },
  });

  expect(built).toEqual({
    title: 'ET MALWARE One',
    description: comp.i18n.caseEscalatedDescription,
    severity: '3',
    template: 'tmpl',
  });

  // falls back to the shared escalation title, and truncates very long rule names
  expect(comp.buildCase({ payload: {} }).title).toBe(comp.i18n.eventCaseTitle);
  const long = comp.buildCase({ ruleName: 'x'.repeat(200), payload: {} });
  expect(long.title.length).toBe(100);
  expect(long.title.endsWith('...')).toBe(true);
});

test('acknowledgeAlertPostsFilterForThatAlert', async () => {
  const calls = papiSpy({});
  comp.filterStatus = 'all';
  comp.alerts = [];
  const alert = { id: 'evt-1', ruleName: 'r', payload: {} };

  await comp.acknowledgeAlert(alert);

  const ack = calls.find(c => c[1] === 'events/ack');
  expect(ack).toBeDefined();
  expect(ack[2].eventFilter).toEqual({ 'soc_id': 'evt-1' });
  expect(ack[2].acknowledge).toBe(true);
  expect(ack[2].escalate).toBe(false);
  // acknowledging must not create a case
  expect(calls.find(c => c[1] === 'case/')).toBeUndefined();
  expect(comp.detailsDialog).toBe(false);
});

test('escalateAlertCreatesCaseAttachesEventsThenAcks', async () => {
  const calls = papiSpy({ 'case/': { data: { id: 'case-9' } } });
  comp.filterStatus = 'all';
  comp.alerts = [];

  await comp.escalateAlert({ id: 'evt-1', ruleName: 'ET MALWARE One', severity: 3, payload: {} });

  const routes = calls.filter(c => c[0] === 'post').map(c => c[1]);
  expect(routes).toEqual(['case/', 'case/events', 'events/ack']);

  const attach = calls.find(c => c[1] === 'case/events');
  expect(attach[2].caseId).toBe('case-9');
  expect(attach[2].fields).toEqual({ 'soc_id': 'evt-1' });

  expect(calls.find(c => c[1] === 'events/ack')[2].escalate).toBe(true);
});

test('groupActionUsesTheGroupFilterNotTheLoadedRows', async () => {
  const calls = papiSpy({});
  comp.filterStatus = 'all';
  const group = { kind: 'rule', key: 'k', ruleName: 'ET MALWARE One', count: 5000, alerts: [] };

  await comp.applyGroupAction(group, true, false);

  const ack = calls.find(c => c[1] === 'events/ack');
  // one request covering every matching alert, including those never fetched
  expect(calls.filter(c => c[1] === 'events/ack').length).toBe(1);
  expect(ack[2].eventFilter).toEqual({ 'rule.name': 'ET MALWARE One' });
});

test('sourceDestGroupActionFiltersOnBothEndpoints', async () => {
  const calls = papiSpy({});
  const group = { kind: 'source-dest', key: 'k', sourceIp: '10.0.0.1', destIp: '8.8.8.8', count: 12, alerts: [] };

  await comp.applyGroupAction(group, true, false);

  expect(calls.find(c => c[1] === 'events/ack')[2].eventFilter)
    .toEqual({ 'source.ip': '10.0.0.1', 'destination.ip': '8.8.8.8' });
});

test('bulkAcknowledgeCoversGroupsAndIndividualAlerts', async () => {
  comp.clearSelection();
  comp.groupingMode = 'rule';
  comp.filterCategory = 'all';
  const alert = { id: 'evt-1', ruleName: 'r', payload: {} };
  comp.alerts = [alert];
  comp.alertGroups = [{ kind: 'rule', key: 'g1', ruleName: 'ET MALWARE One', count: 900, alerts: [] }];
  comp.sourceDestGroups = [];
  comp.toggleGroupSelection(comp.alertGroups[0]);
  comp.toggleAlertSelection(alert);

  const calls = papiSpy({});
  comp.loadAlerts = jest.fn();

  await comp.bulkAcknowledge();

  const acks = calls.filter(c => c[1] === 'events/ack');
  // one for the group as a whole, one for the individually picked alert
  expect(acks.length).toBe(2);
  expect(acks[0][2].eventFilter).toEqual({ 'rule.name': 'ET MALWARE One' });
  expect(acks[1][2].eventFilter).toEqual({ 'soc_id': 'evt-1' });

  expect(comp.hasSelection()).toBe(false);
  expect(comp.selectionMode).toBe(false);
  expect(comp.loadAlerts).toHaveBeenCalled();
});

test('bulkActionIsANoOpWithoutASelection', async () => {
  comp.clearSelection();
  const calls = papiSpy({});
  await comp.bulkAcknowledge();
  expect(calls.length).toBe(0);
});

test('actionErrorsSurfaceAndClearLoading', async () => {
  comp.$root.papi = { post: jest.fn().mockRejectedValue(new Error('boom')) };
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  const showError = mockShowError();

  await comp.applyAlertAction({ id: 'a', ruleName: 'r', payload: {} }, true, false);

  expect(showError).toHaveBeenCalled();
  expect(comp.actionLoading).toBe(false);
  expect(comp.$root.stopLoading).toHaveBeenCalled();
});

test('removeAlertFromViewDropsItEverywhere', () => {
  const alert = { id: 'a1' };
  comp.alerts = [alert, { id: 'a2' }];
  comp.alertGroups = [{ alerts: [alert] }];
  comp.sourceDestGroups = [{ alerts: [] }];
  comp.selectedAlertIds = { a1: true };

  comp.removeAlertFromView(alert);

  expect(comp.alerts.map(a => a.id)).toEqual(['a2']);
  expect(comp.alertGroups[0].alerts.length).toBe(0);
  expect(comp.selectedAlertIds.a1).toBeUndefined();
});

test('selectedAlertsResolvesFromEveryViewWithoutDuplicates', () => {
  const shared = { id: 'dup' };
  comp.alerts = [shared, { id: 'flat' }];
  comp.alertGroups = [{ alerts: [shared] }];
  comp.sourceDestGroups = [{ alerts: [{ id: 'sd' }] }];
  comp.selectedAlertIds = { dup: true, sd: true };

  expect(comp.selectedAlerts().map(a => a.id).sort()).toEqual(['dup', 'sd']);
});

test('categoryFilterEnabledIsAMethodNotAComputed', () => {
  // Vue exposes computeds as properties, so a computed calling another as a function
  // throws at runtime. The test harness flattens computeds to functions and would hide
  // that, so assert the shape directly: this must live in methods.
  const component = global.routes.find(r => r.name === 'simple-alerts').component;
  expect(typeof component.methods.categoryFilterEnabled).toBe('function');
  expect(component.computed.categoryFilterEnabled).toBeUndefined();
  expect(typeof component.methods.activeGroups).toBe('function');
});

test('visibleGroupsFiltersByCategoryWithoutThrowing', () => {
  comp.groupingMode = 'rule';
  comp.alertGroups = [
    { key: 'a', 'rule.category': 'MALWARE' },
    { key: 'b', 'rule.category': 'POLICY' },
  ];
  comp.sourceDestGroups = [];

  // the path that previously short-circuited before reaching categoryFilterEnabled
  comp.filterCategory = 'MALWARE';
  expect(comp.visibleGroups().map(g => g.key)).toEqual(['a']);

  comp.groupingMode = 'source-dest';
  comp.sourceDestGroups = [{ key: 'x' }, { key: 'y' }];
  expect(comp.visibleGroups().length).toBe(2);
});

test('bulkSelectionLabelUsesTheRightPlural', () => {
  comp.clearSelection();
  comp.groupingMode = 'rule';
  comp.filterCategory = 'all';
  comp.sourceDestGroups = [];
  comp.alertGroups = [
    { key: 'g1', count: 1915, alerts: [] },
    { key: 'g2', count: 85, alerts: [] },
  ];

  comp.toggleAlertSelection({ id: 'a1' });
  expect(comp.bulkSelectionLabel()).toBe('1 selected');

  comp.clearSelection();
  comp.toggleGroupSelection(comp.alertGroups[0]);
  expect(comp.bulkSelectionLabel()).toBe('1.9K selected across 1 group');

  comp.toggleGroupSelection(comp.alertGroups[1]);
  expect(comp.bulkSelectionLabel()).toBe('2K selected across 2 groups');
});

// --- pivots -----------------------------------------------------------------

test('tuneDetectionOpensTheDetectionTuningTab', async () => {
  const mock = mockPapi("get", { data: { id: 'det-1', engine: 'suricata' } });
  comp.$router.push = jest.fn();

  await comp.tuneDetection({ ruleUuid: 'uuid-1' });

  expect(mock).toHaveBeenCalledWith('detection/public/uuid-1');
  expect(comp.$router.push).toHaveBeenCalledWith({
    name: 'detection', params: { id: 'det-1' }, query: { tab: 'tuning' },
  });
});

test('tuneDetectionSendsStrelkaToTheSourceTab', async () => {
  mockPapi("get", { data: { id: 'det-2', engine: 'strelka' } });
  comp.$router.push = jest.fn();

  await comp.tuneDetection({ ruleUuid: 'uuid-2' });

  // strelka detections have no tuning tab; overrides live on source
  expect(comp.$router.push.mock.calls[0][0].query).toEqual({ tab: 'source' });
});

test('tuneDetectionReadsTheUuidFromEitherShape', async () => {
  const mock = mockPapi("get", { data: { id: 'det-3', engine: 'suricata' } });
  comp.$router.push = jest.fn();

  // an alert carries it on the payload, a group on the group itself
  await comp.tuneDetection({ payload: { 'rule.uuid': 'uuid-3' } });
  expect(mock).toHaveBeenCalledWith('detection/public/uuid-3');
});

test('tuneDetectionWarnsWhenThereIsNoDetection', async () => {
  comp.$root.showWarning = jest.fn();
  comp.$router.push = jest.fn();

  await comp.tuneDetection({ payload: {} });

  expect(comp.$root.showWarning).toHaveBeenCalled();
  expect(comp.$router.push).not.toHaveBeenCalled();
});

test('canRequestPcapNeedsBothEndpointsAndASensor', () => {
  const full = { sourceIp: '10.0.0.1', destIp: '8.8.8.8', payload: { 'observer.name': 'sensor1' } };
  expect(comp.canRequestPcap(full)).toBe(true);

  expect(comp.canRequestPcap({ sourceIp: '10.0.0.1', payload: { 'observer.name': 's' } })).toBe(false);
  expect(comp.canRequestPcap({ sourceIp: '10.0.0.1', destIp: '8.8.8.8', payload: {} })).toBe(false);
  expect(comp.canRequestPcap(null)).toBe(false);

  // agent.name is the fallback when the observer is not recorded
  expect(comp.pcapNodeId({ payload: { 'agent.name': 'agent1' } })).toBe('agent1');
  expect(comp.pcapNodeId({ payload: { 'observer.name': 'obs', 'agent.name': 'agent1' } })).toBe('obs');
});

test('requestPcapEnqueuesTheJobAndHandsOffToTheJobPage', async () => {
  const mock = mockPapi("post", { data: { id: 42 } });
  comp.$router.push = jest.fn();

  await comp.requestPcap({
    timestamp: '2026-01-01T12:00:00Z',
    sourceIp: '10.0.0.1', sourcePort: '1234',
    destIp: '8.8.8.8', destPort: '53',
    payload: { 'observer.name': 'sensor1' },
  });

  const [route, body] = mock.mock.calls[0];
  expect(route).toBe('job/');
  expect(body.nodeId).toBe('sensor1');
  expect(body.filter.srcIp).toBe('10.0.0.1');
  expect(body.filter.dstIp).toBe('8.8.8.8');
  // ports are sent as numbers, and the window brackets the alert
  expect(body.filter.srcPort).toBe(1234);
  expect(body.filter.dstPort).toBe(53);
  expect(moment(body.filter.endTime).diff(moment(body.filter.beginTime), 'seconds')).toBe(60);

  // packets are rendered by the job page rather than re-implemented here
  expect(comp.$router.push).toHaveBeenCalledWith({ name: 'job', params: { jobId: '42' } });
  expect(comp.detailsDialog).toBe(false);
  expect(comp.pcapLoading).toBe(false);
});

test('requestPcapRefusesWithoutEnoughInformation', async () => {
  const mock = mockPapi("post", { data: { id: 1 } });
  comp.$root.showWarning = jest.fn();

  await comp.requestPcap({ sourceIp: '10.0.0.1', payload: {} });

  expect(mock).not.toHaveBeenCalled();
  expect(comp.$root.showWarning).toHaveBeenCalled();
});

test('requestPcapSurfacesErrors', async () => {
  mockPapi("post", null, new Error('boom'));
  const showError = mockShowError();

  await comp.requestPcap({
    timestamp: '2026-01-01T12:00:00Z',
    sourceIp: '10.0.0.1', destIp: '8.8.8.8',
    payload: { 'observer.name': 'sensor1' },
  });

  expect(showError).toHaveBeenCalled();
  expect(comp.pcapLoading).toBe(false);
});

// --- guided analysis --------------------------------------------------------

function playbookAlert(extra) {
  return Object.assign({
    id: 'evt-1',
    timestamp: '2026-01-01T12:00:00Z',
    ruleUuid: 'uuid-1',
    payload: { 'soc_id': 'sid-1', 'soc_timestamp': '2026-01-01T11:59:00Z' },
  }, extra || {});
}

test('playbookTimestampPrefersTheAlertDocumentTime', () => {
  expect(comp.playbookTimestamp(playbookAlert())).toBe('2026-01-01T11:59:00Z');
  expect(comp.playbookTimestamp({ timestamp: 'evt-time', payload: {} })).toBe('evt-time');
});

test('loadAlertPlaybookFetchesSkeletonByDetectionAndAnswersQuestions', async () => {
  const skeleton = [{ id: 'pb1', questions: [
    { question: 'Ranged one?', range: '24h' },
    { question: 'Rangeless one?' },
  ]}];
  const converted = [{ id: 'pb1', questions: [
    { oqlQuery: 'oql-1', fields: ['source.ip'], isAggregate: false },
    {},
  ]}];

  const get = jest.fn((route) => {
    if (route.indexOf('stage=convert') !== -1) return Promise.resolve({ data: converted });
    return Promise.resolve({ data: skeleton });
  });
  const post = jest.fn(() => Promise.resolve({ data: { queryResults: [
    { payload: { 'source.ip': '10.0.0.1' }, timestamp: 't1' },
  ]}}));
  comp.$root.papi = { get: get, post: post };

  const alert = playbookAlert();
  await comp.loadAlertPlaybook(alert);

  // rule.uuid routes the skeleton to the cheaper detection endpoint
  expect(get).toHaveBeenCalledWith('playbook/detection/uuid-1');
  expect(get.mock.calls.some(c => c[0].indexOf('stage=convert') !== -1)).toBe(true);

  expect(alert.playbookErr).toBe(false);
  expect(alert.playbookNone).toBe(false);
  expect(alert.playbookLoading).toBe(false);
  expect(alert.questions.length).toBe(2);

  // the ranged question ran a query; its columns came from the conversion
  expect(alert.questions[0].status).toBe(PlaybookRunner.STATUS_DONE);
  expect(alert.questions[0].fields).toEqual(['@timestamp', 'source.ip']);
  expect(alert.questions[0].queryResults.length).toBe(1);

  // the rangeless question is answered by the alert itself, without a query
  expect(post).toHaveBeenCalledTimes(1);
  expect(alert.questions[1].status).toBe(PlaybookRunner.STATUS_DONE);
  expect(alert.questions[1].queryResults[0].payload['soc_id']).toBe('sid-1');
});

test('loadAlertPlaybookReportsNoPlaybookDistinctlyFromFailure', async () => {
  comp.$root.papi = { get: jest.fn(() => Promise.resolve({ data: [] })) };

  const alert = playbookAlert();
  await comp.loadAlertPlaybook(alert);

  expect(alert.playbookNone).toBe(true);
  expect(alert.playbookErr).toBe(false);
  expect(alert.playbooks).toBeNull();
});

test('loadAlertPlaybookReportsFailure', async () => {
  comp.$root.papi = { get: jest.fn(() => Promise.reject(new Error('boom'))) };

  const alert = playbookAlert();
  await comp.loadAlertPlaybook(alert);

  expect(alert.playbookErr).toBe(true);
  expect(alert.playbookNone).toBe(false);
  expect(alert.playbookLoading).toBe(false);
});

test('loadAlertPlaybookNeedsASocId', async () => {
  const get = jest.fn();
  comp.$root.papi = { get: get };

  const alert = { id: 'x', payload: {} };
  await comp.loadAlertPlaybook(alert);

  expect(alert.playbookErr).toBe(true);
  expect(get).not.toHaveBeenCalled();
});

test('loadAlertPlaybookRunsOnlyOncePerAlert', async () => {
  const get = jest.fn(() => Promise.resolve({ data: [] }));
  comp.$root.papi = { get: get };

  const alert = playbookAlert();
  await comp.loadAlertPlaybook(alert);
  const callsAfterFirst = get.mock.calls.length;

  await comp.loadAlertPlaybook(alert);
  expect(get.mock.calls.length).toBe(callsAfterFirst);
});

test('rangedQuestionWithoutAConvertedQueryIsMarkedFailed', async () => {
  const skeleton = [{ id: 'pb1', questions: [{ question: 'Ranged?', range: '24h' }] }];
  comp.$root.papi = {
    get: jest.fn((route) => route.indexOf('stage=convert') !== -1
      ? Promise.reject(new Error('convert failed'))
      : Promise.resolve({ data: skeleton })),
    post: jest.fn(),
  };

  const alert = playbookAlert();
  await comp.loadAlertPlaybook(alert);

  expect(alert.questions[0].status).toBe(PlaybookRunner.STATUS_ERROR);
  expect(alert.questions[0].queryResults).toEqual([]);
  expect(comp.$root.papi.post).not.toHaveBeenCalled();
});

test('questionPresentationHelpers', () => {
  expect(comp.hasPlaybook({ questions: [{}] })).toBe(true);
  expect(comp.hasPlaybook({ questions: [] })).toBe(false);
  expect(comp.hasPlaybook(null)).toBe(false);

  expect(comp.questionStatusColor({ status: PlaybookRunner.STATUS_ERROR })).toBe('error');
  expect(comp.questionStatusColor({ status: PlaybookRunner.STATUS_DONE, queryResults: [{}] })).toBe('success');
  // answered, but nothing matched
  expect(comp.questionStatusColor({ status: PlaybookRunner.STATUS_DONE, queryResults: [] })).toBe('info');
  expect(comp.isQuestionRunning({ status: PlaybookRunner.STATUS_RUNNING })).toBe(true);

  expect(comp.questionAnswerCount({ queryResults: [{}, {}] })).toBe(2);
  expect(comp.questionAnswerCount({})).toBe(0);

  expect(comp.questionColumns({ fields: ['a'] })).toEqual(['a']);
  expect(comp.questionColumns({})).toEqual([]);

  const answer = { payload: { 'source.ip': '1.1.1.1' }, timestamp: 'ts' };
  expect(comp.questionRowValue(answer, '@timestamp')).toBe('ts');
  expect(comp.questionRowValue(answer, 'source.ip')).toBe('1.1.1.1');
  expect(comp.questionRowValue(answer, 'missing')).toBe('');
  expect(comp.questionRowValue(null, 'x')).toBe('');
});
