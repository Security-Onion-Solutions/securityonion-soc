// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
// Method packs must load before simplealerts.js, which merges them into the component.
require('./simplealerts.data.js');
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
  await comp.loadAlerts();

  expect(mock).toHaveBeenCalled();
  const [route, options] = mock.mock.calls[0];
  expect(route).toBe('events/');
  expect(options.params.query).toBe('tags:alert');
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

test('severityCounts', () => {
  comp.alerts = [
    { severityLabel: 'high', acknowledged: false, escalated: false },
    { severityLabel: 'critical', acknowledged: true, escalated: false },
    { severityLabel: 'medium', acknowledged: false, escalated: true },
    { severityLabel: 'low', acknowledged: false, escalated: false },
  ];

  expect(comp.highSeverityCount()).toBe(2);
  expect(comp.mediumSeverityCount()).toBe(1);
  expect(comp.lowSeverityCount()).toBe(1);
  expect(comp.activeAlertCount()).toBe(2);
});
