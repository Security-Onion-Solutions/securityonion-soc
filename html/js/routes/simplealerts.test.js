// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
// Method packs must load before simplealerts.js, which merges them into the component.
require('./simplealerts.data.js');
require('./simplealerts.grouping.js');
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
