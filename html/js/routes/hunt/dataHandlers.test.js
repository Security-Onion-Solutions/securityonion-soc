// Copyright 2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
const { dataHandlerMethods } = require('./dataHandlers.js');

let comp;

beforeEach(() => {
  comp = {
    $root: {
      users: [],
      initializeCharts: () => {},
    },
    i18n: {
      __missing__: '*Missing',
      caseEscalatedDescription: 'Case Escalated Description',
      timePickerSample: 'YYYY-MM-DD HH:mm:ss',
    },
    totalEvents: 0,
    queryGroupByOptions: [],
    aggregationActionsEnabled: false,
    groupBys: [],
    eventData: [],
    eventCurrentItems: [],
    eventHeaders: [],
    queryTableFields: [],
    query: '',
    category: '',
    filterToggles: [],
    dateRange: '',
    zone: '',
    $router: [],
  };
  resetPapi();
});

test('removeDataFromView', () => {
  const a = {};
  const b = {};
  const c = { count: 10 };
  let data = [a, b, c];
  comp.totalEvents = 11;

  dataHandlerMethods.removeDataItemFromView.call(comp, data, a);
  expect(comp.totalEvents).toBe(10);
  expect(data.length).toBe(2);

  dataHandlerMethods.removeDataItemFromView.call(comp, data, c);
  expect(comp.totalEvents).toBe(0);
  expect(data.length).toBe(1);

  // Removing non-existent item should be no-op
  dataHandlerMethods.removeDataItemFromView.call(comp, data, a);
  expect(comp.totalEvents).toBe(0);
  expect(data.length).toBe(1);

  // Ensure totalEvents never drops below 0 (shouldn't, but double check)
  dataHandlerMethods.removeDataItemFromView.call(comp, data, b);
  expect(comp.totalEvents).toBe(0);
  expect(data.length).toBe(0);
});

test('sortEventsAscending', () => {
  const index = [ 'x' ];
  const desc = [ false ];
  const item1 = { 'x': 1 };
  const item2 = { 'x': 2 };
  const item3 = { 'x': 3 };
  const unsorted = [item1, item2, item3];
  const sorted = dataHandlerMethods.sortEvents.call(comp, unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[0]).toBe(item1);
  expect(sorted[1]).toBe(item2);
  expect(sorted[2]).toBe(item3);
});

test('sortEventsDescending', () => {
  const index = [ 'x' ];
  const desc = [ true ];
  const item1 = { 'x': 1 };
  const item2 = { 'x': 2 };
  const item3 = { 'x': 3 };
  const unsorted = [item1, item2, item3];
  const sorted = dataHandlerMethods.sortEvents.call(comp, unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[2]).toBe(item1);
  expect(sorted[1]).toBe(item2);
  expect(sorted[0]).toBe(item3);
});

test('sortAlertsAscending', () => {
  const index = [ 'x' ];
  const desc = [ false ];
  const item1 = { 'x': 1 };
  const item2 = { 'x': 2 };
  const item3 = { 'x': 3 };
  const unsorted = [item1, item2, item3];
  const sorted = dataHandlerMethods.sortEvents.call(comp, unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[0]).toBe(item1);
  expect(sorted[1]).toBe(item2);
  expect(sorted[2]).toBe(item3);
});

test('sortAlertsDescending', () => {
  const index = [ 'event.severity_label' ];
  const desc = [ false ];
  const item1 = { 'event.severity_label': 'low' };
  const item2 = { 'event.severity_label': 'medium' };
  const item3 = { 'event.severity_label': 'high' };
  const item4 = { 'event.severity_label': 'critical' };
  const unsorted = [item2, item3, item4, item1];
  const sorted = dataHandlerMethods.sortEvents.call(comp, unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[0]).toBe(item1);
  expect(sorted[1]).toBe(item2);
  expect(sorted[2]).toBe(item3);
  expect(sorted[3]).toBe(item4);
});

test('sortAlertsAscending', () => {
  const index = [ 'event.severity_label' ];
  const desc = [ true ];
  const item1 = { 'event.severity_label': 'low' };
  const item2 = { 'event.severity_label': 'medium' };
  const item3 = { 'event.severity_label': 'high' };
  const item4 = { 'event.severity_label': 'critical' };
  const unsorted = [item2, item3, item4, item1];
  const sorted = dataHandlerMethods.sortEvents.call(comp, unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[3]).toBe(item1);
  expect(sorted[2]).toBe(item2);
  expect(sorted[1]).toBe(item3);
  expect(sorted[0]).toBe(item4);
});

test('lookupSocIds', () => {
  comp.$root.users = [{id:'12345678-1234-5678-0123-123456789012', email:'test@test.invalid'}];
  var record = { 'so_case.assigneeId': '123'}; // invalid UUID
  dataHandlerMethods.lookupSocIds.call(comp, record);
  expect(record['so_case.assigneeId']).toBe('123');

  var record = { 'assigneeId': '12345678-1234-5678-0123-123456789012'}; // invalid key
  dataHandlerMethods.lookupSocIds.call(comp, record);
  expect(record['assigneeId']).toBe('12345678-1234-5678-0123-123456789012');

  var record = { 'so_case.assigneeId': '12345678-1234-5678-0123-123456789012'};
  dataHandlerMethods.lookupSocIds.call(comp, record);
  expect(record['so_case.assigneeId']).toBe('test@test.invalid');

  var record = { 'so_case.userId': '12345678-1234-5678-0123-123456789012'};
  dataHandlerMethods.lookupSocIds.call(comp, record);
  expect(record['so_case.userId']).toBe('test@test.invalid');
});

test('populateGroupByTables', () => {
  var metrics = {
    "groupby_0|foo": [{ value: 37, keys: ['moo'] }],
    "groupby_0|foo|bar": [{ value: 23, keys: ['moo', 'mar'] }],
    "groupby_1|car": [{ value: 9, keys: ['mis'] }],
  }

  comp.groupBySortBy = "foo";
  comp.groupBySortDesc = false;

  comp.queryGroupByOptions = [[],["maximize"]];
  var result = dataHandlerMethods.populateGroupByTables.call(comp, metrics);
  expect(comp.groupBys.length).toBe(2);
  expect(comp.groupBys[0].title).toBe("foo, bar");
  expect(comp.groupBys[0].fields.length).toBe(2);
  expect(comp.groupBys[0].data[0].count).toBe(23);
  expect(comp.groupBys[0].data[0].foo).toBe('moo');
  expect(comp.groupBys[0].data[0].bar).toBe('mar');
  expect(comp.groupBys[0].headers).toStrictEqual([{title: 'Count', value:'count'}, {title: 'foo', value: 'foo'}, {title: 'bar', value: 'bar'}]);
  expect(comp.groupBys[0].chart_metrics).toStrictEqual([{value: 23, keys:['moo, mar']}]);
  expect(comp.groupBys[0].sortBy).toStrictEqual([{ key: "foo", order: "asc" }]);
  expect(comp.groupBys[0].maximized).toBe(false);
  expect(comp.groupBys[1].title).toBe("car");
  expect(comp.groupBys[1].fields.length).toBe(1);
  expect(comp.groupBys[1].data[0].count).toBe(9);
  expect(comp.groupBys[1].data[0].car).toBe('mis');
  expect(comp.groupBys[1].headers).toStrictEqual([{title: 'Count', value:'count'}, {title: 'car', value: 'car'}]);
  expect(comp.groupBys[1].chart_metrics).toStrictEqual([{value: 9, keys:['mis']}]);
  expect(comp.groupBys[1].sortBy).toStrictEqual([{ key: "count", order: "desc" }]);
  expect(comp.groupBys[1].maximized).toBe(true);

  // Now include action column
  comp.aggregationActionsEnabled = true;
  result = dataHandlerMethods.populateGroupByTables.call(comp, metrics);
  expect(comp.groupBys[0].headers).toStrictEqual([{title: '', value: ''}, {title: 'Count', value:'count'}, {title: 'foo', value: 'foo'}, {title: 'bar', value: 'bar'}]);
  expect(comp.groupBys[1].headers).toStrictEqual([{title: '', value: ''}, {title: 'Count', value:'count'}, {title: 'car', value: 'car'}]);
});

test('lookupGroupByMetricKey', () => {
  var metrics = {
    "groupby_0|foo": [{ value: 37, keys: ['moo'] }],
    "groupby_0|foo|bar": [{ value: 23, keys: ['moo', 'mar'] }],
    "groupby_1|car": [{ value: 9, keys: ['mis'] }],
  }
  var result = dataHandlerMethods.lookupGroupByMetricKey.call(comp, metrics, 0, true);
  expect(result).toBe("groupby_0|foo|bar");

  result = dataHandlerMethods.lookupGroupByMetricKey.call(comp, metrics, 0, false);
  expect(result).toBe("groupby_0|foo");
});

test('populateEventHeaders', () => {
  const defs = ["x", "y"];
  dataHandlerMethods.populateEventHeaders.call(comp, defs);
  expect(comp.eventHeaders).toStrictEqual([{title:'x', value:'x'},{title:'y', value: 'y'}]);

  comp.queryTableFields = ['b', 'c'];
  dataHandlerMethods.populateEventHeaders.call(comp, defs);
  expect(comp.eventHeaders).toStrictEqual([{ title: 'b', value: 'b' }, { title: 'c', value: 'c' }]);

  comp.queryTableFields = ['a', 'b', 'so_detection.isEnabled', 'c'];
  dataHandlerMethods.populateEventHeaders.call(comp, defs);
  expect(comp.eventHeaders).toStrictEqual([{ title: 'a', value: 'a' }, { title: 'b', value: 'b' }, { title: 'Enabled', value: 'so_detection.isEnabled' }, { title: 'c', value: 'c' }]);

  comp.category = 'detections';
  dataHandlerMethods.populateEventHeaders.call(comp, defs);
  expect(comp.eventHeaders).toStrictEqual([{ title: 'a', value: 'a' }, { title: 'b', value: 'b' }, { title: 'Enabled', value: 'so_detection.isEnabled'}, { title: 'Overrides', value: 'override_count' }, { title: 'c', value: 'c' }]);
});

test('repopulateEventHeaders', () => {
  comp.queryTableFields = ["b", "c"];
  comp.query = 'foo: bar| table old';
  expect(comp.$router.length).toBe(0);
  expect(comp.disableRouteLoad).toBe(undefined);
  dataHandlerMethods.repopulateEventHeaders.call(comp);
  expect(comp.disableRouteLoad).toBe(true);
  expect(comp.eventHeaders).toStrictEqual([{"title":"b", "value":"b"},{"title":"c", "value": "c"}]);
  expect(comp.query).toBe('foo: bar | table b c');
  expect(comp.$router.length).toBe(1);
});

test('toggleColumnHeader', () => {
  expect(comp.eventHeaders).toStrictEqual([]);
  dataHandlerMethods.toggleColumnHeader.call(comp, 'x');
  expect(comp.eventHeaders).toStrictEqual([{value:'x', title:'x'}]);
  dataHandlerMethods.toggleColumnHeader.call(comp, 'x');
  expect(comp.eventHeaders).toStrictEqual([]);
  dataHandlerMethods.toggleColumnHeader.call(comp, 'x');
  expect(comp.eventHeaders).toStrictEqual([{value:'x', title:'x'}]);
  dataHandlerMethods.toggleColumnHeader.call(comp, 'y');
  expect(comp.eventHeaders).toStrictEqual([{value:'x', title:'x'},{value:'y', title:'y'}]);
  dataHandlerMethods.toggleColumnHeader.call(comp, 'x');
  expect(comp.eventHeaders).toStrictEqual([{value:'y', title:'y'}]);
});

test('moveColumnHeader', () => {
  dataHandlerMethods.moveColumnHeader.call(comp, 'x', true);
  expect(comp.queryTableFields).toStrictEqual([]);

  comp.queryTableFields = ['x', 'y', 'z'];
  dataHandlerMethods.moveColumnHeader.call(comp, 'x', true);
  expect(comp.queryTableFields).toStrictEqual(['x', 'y', 'z']);

  dataHandlerMethods.moveColumnHeader.call(comp, 'x', false);
  expect(comp.queryTableFields).toStrictEqual(['y', 'x', 'z']);

  dataHandlerMethods.moveColumnHeader.call(comp, 'x', false);
  expect(comp.queryTableFields).toStrictEqual(['y', 'z', 'x']);

  // double check that repopulateEventHeaders was invoked
  expect(comp.eventHeaders).toStrictEqual([{"title":"y", "value":"y"},{"title":"z", "value":"z"},{"title":"x", "value": "x"}]);

  dataHandlerMethods.moveColumnHeader.call(comp, 'x', false);
  expect(comp.queryTableFields).toStrictEqual(['y', 'z', 'x']);

  dataHandlerMethods.moveColumnHeader.call(comp, 'x', true);
  expect(comp.queryTableFields).toStrictEqual(['y', 'x', 'z']);

  dataHandlerMethods.moveColumnHeader.call(comp, 'x', true);
  expect(comp.queryTableFields).toStrictEqual(['x', 'y', 'z']);

  // double check that repopulateEventHeaders was invoked
  expect(comp.eventHeaders).toStrictEqual([{"title":"x", "value":"x"},{"title":"y", "value":"y"},{"title":"z", "value": "z"}]);
});

test('extractSocValues', () => {
  let obj = {
    payload: {
      a: 1,
      b: 2,
      c: 3,
    },
    id: 'abc',
    score: 0.947,
    type: 'type',
    timestamp: 'now',
    source: 'network',
  };

  const expected = {
    a: 1,
    b: 2,
    c: 3,
    soc_id: 'abc',
    soc_score: 0.947,
    soc_type: 'type',
    soc_timestamp: 'now',
    soc_source: 'network',
  };

  let actual = dataHandlerMethods.extractSocValues.call(comp, obj);

  expect(actual).toStrictEqual(expected);
});

test('getEventField', () => {
  let event = {
    a: 1,
    timestamp: 'now',
    'event_data.a': 2,
    'event_data.b': 3,
  };

  const a = dataHandlerMethods.getEventField.call(comp, event, 'a');
  const eventdataA = dataHandlerMethods.getEventField.call(comp, event, 'event_data.a');
  const b = dataHandlerMethods.getEventField.call(comp, event, 'b');
  const timestamp = dataHandlerMethods.getEventField.call(comp, event, 'timestamp');

  expect(a).toBe(1);
  expect(eventdataA).toBe(2);
  expect(b).toBe('');
  expect(timestamp).toBe('now');
});

test('fetchNewestEvent', async () => {
  const eventSearch = mockPapi('get', { data: { events: [{ id: '100', payload: { a: 1, b: "2", c: true } }] } });
  
  comp.filterToggles = [
    {
      name: 'acknowledged',
      enabled: false,
    },
    {
      name: 'escalated',
      enabled: false,
    },
  ];
  comp.dateRange = 'x - y';
  comp.zone = 'zone';

  var item = {
    a: 1,
    b: "2",
    'event_data.c': true,
    count: 10,
  };

  await dataHandlerMethods.fetchNewestEvent.call(comp, item);

  expect(item.newest.soc_id).toBe('100');
  
  expect(eventSearch).toHaveBeenCalledTimes(1);
  expect(eventSearch).toHaveBeenCalledWith('events/', {
    params: {
      query: 'a:"1" AND b:"2" AND c:"true" AND NOT event.acknowledged:true AND NOT event.escalated:true | sortby @timestamp',
      range: 'x - y',
      format: comp.i18n.timePickerSample,
      zone: 'zone',
      eventLimit: 1,
      metricLimit: 0,
    }
  });

  comp.filterToggles[0].enabled = true;
  comp.filterToggles[1].enabled = true;
  delete item.newest;
  resetPapi();
  const eventSearch2 = mockPapi('get', { data: { events: [{ id: '100', payload: { a: 1, b: "2", c: true } }] } });

  await dataHandlerMethods.fetchNewestEvent.call(comp, item);

  expect(item.newest.soc_id).toBe('100');
  
  expect(eventSearch2).toHaveBeenCalledTimes(1);
  expect(eventSearch2).toHaveBeenCalledWith('events/', {
    params: {
      query: 'a:"1" AND b:"2" AND c:"true" AND event.acknowledged:true AND event.escalated:true | sortby @timestamp',
      range: 'x - y',
      format: comp.i18n.timePickerSample,
      zone: 'zone',
      eventLimit: 1,
      metricLimit: 0,
    }
  });

  resetPapi();
});