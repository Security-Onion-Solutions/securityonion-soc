// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./hunt.js');

let comp;

beforeEach(() => {
  comp = getComponent("hunt");
  resetPapi();
  comp.$root.initializeCharts = () => { };
  comp.created();
});

test('localizeValue', () => {
  expect(comp.localizeValue('foo')).toBe('foo');
  expect(comp.localizeValue('__missing__')).toBe('*Missing');
  expect(comp.localizeValue(123)).toBe(123);
  expect(comp.localizeValue(null)).toBe(null);
});

test('removeDataFromView', () => {
  const a = {};
  const b = {};
  const c = { count: 10 };
  data = [a, b, c];
  comp.totalEvents = 11;

  comp.removeDataItemFromView(data, a);
  expect(comp.totalEvents).toBe(10);
  expect(data.length).toBe(2);

  comp.removeDataItemFromView(data, c);
  expect(comp.totalEvents).toBe(0);
  expect(data.length).toBe(1);

  // Removing non-existent item should be no-op
  comp.removeDataItemFromView(data, a);
  expect(comp.totalEvents).toBe(0);
  expect(data.length).toBe(1);

  // Ensure totalEvents never drops below 0 (shouldn't, but double check)
  comp.removeDataItemFromView(data, b);
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
  const sorted = comp.sortEvents(unsorted, index, desc);
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
  const sorted = comp.sortEvents(unsorted, index, desc);
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
  const sorted = comp.sortEvents(unsorted, index, desc);
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
  const sorted = comp.sortEvents(unsorted, index, desc);
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
  const sorted = comp.sortEvents(unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[3]).toBe(item1);
  expect(sorted[2]).toBe(item2);
  expect(sorted[1]).toBe(item3);
  expect(sorted[0]).toBe(item4);
});

test('saveTimezone', () => {
  comp.zone = "Foo/Bar";
  comp.saveTimezone();
  comp.zone = "Test";
  comp.loadLocalSettings();
  expect(comp.zone).toBe("Foo/Bar");
});

test('removeFilter', () => {
  comp.query = "abc def | groupby foo bar*";
  comp.removeFilter('def')
  expect(comp.query).toBe("abc  | groupby foo bar*");

  comp.removeFilter('abc')
  expect(comp.query).toBe("* | groupby foo bar*");

  // no-op
  comp.removeFilter('*')
  expect(comp.query).toBe("* | groupby foo bar*");
});

test('removeGroupBy', () => {
  comp.query = "abc | groupby foo bar*";
  comp.queryGroupBys = [['foo','bar*']];
  comp.removeGroupBy(0, 0)
  expect(comp.query).toBe("abc | groupby bar*");

  comp.query = "abc | groupby foo bar*";
  comp.queryGroupBys = [['foo','bar*']];
  comp.removeGroupBy(0, 1)
  expect(comp.query).toBe("abc | groupby foo");

  comp.query = "abc | groupby bar*";
  comp.queryGroupBys = [['bar*']];
  comp.removeGroupBy(0, 0)
  expect(comp.query).toBe("abc");

  // no-op
  comp.query = "abc";
  comp.queryGroupBys = [];
  comp.removeGroupBy(0, 0)
  expect(comp.query).toBe("abc");

  comp.query = "abc | groupby foo bar* | groupby a b";
  comp.queryGroupBys = [['foo','bar*'],['a','b']];
  comp.removeGroupBy(1, 1)
  expect(comp.query).toBe("abc | groupby foo bar* | groupby a");

  // Remove entire group
  comp.query = "abc | groupby foo bar* | groupby a b";
  comp.queryGroupBys = [['foo','bar*'],['a','b']];
  comp.removeGroupBy(1, -1)
  expect(comp.query).toBe("abc | groupby foo bar*");
});

test('removeSortBy', () => {
  comp.query = "abc | sortby foo bar^";
  comp.removeSortBy('foo')
  expect(comp.query).toBe("abc | sortby bar^");

  comp.removeSortBy('bar^')
  expect(comp.query).toBe("abc");

  // no-op
  comp.removeSortBy('bar^')
  expect(comp.query).toBe("abc");

  comp.query = "abc | sortby foo bar^ | groupby xyz";
  comp.removeSortBy('foo')
  expect(comp.query).toBe("abc | sortby bar^ | groupby xyz");

  comp.removeSortBy('bar^')
  expect(comp.query).toBe("abc | groupby xyz");

  // no-op
  comp.removeSortBy('bar^')
  expect(comp.query).toBe("abc | groupby xyz");
});

test('formatCaseSummary', () => {
  const caseObj = {id:"12", title:"This is a case title"};
  const summary = comp.formatCaseSummary(caseObj);
  expect(summary).toBe('This is a case title');
});

test('formatSafeString', () => {
  const longstr =  "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
  const expected = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567...";
  comp.safeStringMaxLength = 100;
  const actual = comp.formatSafeString(longstr);
  expect(actual).toBe(expected);
});

test('toggleEscalationMenu', () => {
  comp.escalateRelatedEventsEnabled = true;
  const domEvent = {target: 'target'};
  const event = {id:"33",foo:"bar"};
  comp.$nextTick = function(fn) { fn(); };
  comp.toggleEscalationMenu(domEvent, event, 2);
  expect(comp.escalationMenuTarget).toBe('target');
  expect(comp.escalationItem).toBe(event);
  expect(comp.escalationGroupIdx).toBe(2);
  expect(comp.escalationMenuVisible).toBe(true);
});

test('toggleEscalationMenuAlreadyOpen', () => {
  comp.escalateRelatedEventsEnabled = true;
  const domEvent = {clientX: 12, clientY: 34};
  const event = {id:"33",foo:"bar"};
  comp.quickActionVisible = true;
  comp.escalationMenuVisible = true;
  comp.toggleEscalationMenu(domEvent, event, 2);
  expect(comp.quickActionVisible).toBe(false);
  expect(comp.escalationMenuVisible).toBe(false);
});

function validateCase(
    name, template, mod, dataset, severity, message,
    expectedTitle, expectedDescription, expectedSeverity, expectedTemplate) {
  const item = {
    "rule.name": name,
    "rule.case_template": template,
    "event.module": mod,
    "event.dataset": dataset,
    "event.severity": severity,
    "message": message,
  };
  const caseObj = comp.buildCase(item)
  expect(caseObj.title).toBe(expectedTitle);
  expect(caseObj.description).toBe(expectedDescription);
  expect(caseObj.severity).toBe(expectedSeverity);
  expect(caseObj.template).toBe(expectedTemplate);
}

test('buildCase', () => {
  comp.escalateRelatedEventsEnabled = true;

  // has rule name and message, etc (happy path)
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'myTitle', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name, module, and dataset
  validateCase('', 'myTemplate', '', '', 'mySeverity', 'myMessage',
      'Event Escalation from SOC', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has module
  validateCase('', 'myTemplate', 'myModule', '', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has dataset
  validateCase('', 'myTemplate', '', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myDataset', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has module and dataset
  validateCase('', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule - myDataset', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');
  validateCase(null, 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule - myDataset', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing message
  comp.escalateRelatedEventsEnabled = false;
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', '',
      'myTitle', '{\"rule.name\":\"myTitle\",\"rule.case_template\":\"myTemplate\",\"event.module\":\"myModule\",\"event.dataset\":\"myDataset\",\"event.severity\":\"mySeverity\",\"message\":\"\"}', 'mySeverity', 'myTemplate');

  comp.escalateRelatedEventsEnabled = true;
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', '',
      'myTitle', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing severity
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', '', 'myMessage',
      'myTitle', comp.i18n.caseEscalatedDescription, '', 'myTemplate');

  // missing template
  validateCase('myTitle', '', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'myTitle', comp.i18n.caseEscalatedDescription, 'mySeverity', '');

});

test('applyQuerySubstitutions', () => {
  comp.$root.user = {id:'123'};
  const queries = [{ query: 'foo'}, { query: 'bar:{myId}' }];
  const newQueries = comp.applyQuerySubstitutions(queries);
  expect(newQueries).toBe(queries);
  expect(newQueries[0].query).toBe('foo');
  expect(newQueries[1].query).toBe('bar:123');
});

test('lookupSocIds', () => {
  comp.$root.users = [{id:'12345678-1234-5678-0123-123456789012', email:'test@test.invalid'}];
  var record = { 'so_case.assigneeId': '123'}; // invalid UUID
  comp.lookupSocIds(record);
  expect(record['so_case.assigneeId']).toBe('123');

  var record = { 'assigneeId': '12345678-1234-5678-0123-123456789012'}; // invalid key
  comp.lookupSocIds(record);
  expect(record['assigneeId']).toBe('12345678-1234-5678-0123-123456789012');

  var record = { 'so_case.assigneeId': '12345678-1234-5678-0123-123456789012'};
  comp.lookupSocIds(record);
  expect(record['so_case.assigneeId']).toBe('test@test.invalid');

  var record = { 'so_case.userId': '12345678-1234-5678-0123-123456789012'};
  comp.lookupSocIds(record);
  expect(record['so_case.userId']).toBe('test@test.invalid');
});

test('getQuery', async () => {
  comp.query = "a:1 OR b:2";
  comp.queryBaseFilter = "c:3";
  comp.filterToggles = [{ enabled: true, filter: "e:4" }, { enabled: false, filter: "f:5", exclusive: true }];
  mock = mockPapi("get", {'data':'(a:1 OR b:2) AND c:3 AND e:4 AND NOT f:5'});

  const newQuery = await comp.getQuery();
  const params = { params: { query: 'a:1 OR b:2', field: '', value: 'c:3 AND e:4 AND NOT f:5', scalar: true, mode: 'INCLUDE', condense: true } };
  expect(mock).toHaveBeenCalledWith('query/filtered', params);
  expect(newQuery).toBe("(a:1 OR b:2) AND c:3 AND e:4 AND NOT f:5");
});

test('buildGroupByNew', () => {
  comp.groupBys = ['foo', 'bar'];
  var route = comp.buildGroupByRoute('car');
  expect(route.query.groupByField).toBe('car');
  expect(route.query.groupByGroup).toBe(1);
});

test('buildGroupByNewRoute', () => {
  comp.groupBys = ['foo', 'bar'];
  var route = comp.buildGroupByNewRoute('car');
  expect(route.query.groupByField).toBe('car');
  expect(route.query.groupByGroup).toBe(-1);
});

test('constructGroupMetrics', () => {
  var data = [{value: 12, keys: ['foo', 'bar']}, {value:3, keys:['car']}];
  var records = comp.constructChartMetrics(data);
  expect(records.length).toBe(2);
  expect(records[0].value).toBe(12);
  expect(records[0].keys.length).toBe(1);
  expect(records[0].keys[0]).toBe('foo, bar');
  expect(records[1].value).toBe(3);
  expect(records[1].keys[0]).toBe('car');
  expect(records[1].keys.length).toBe(1);
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
  var result = comp.populateGroupByTables(metrics);
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
  result = comp.populateGroupByTables(metrics);
  expect(comp.groupBys[0].headers).toStrictEqual([{title: '', value: ''}, {title: 'Count', value:'count'}, {title: 'foo', value: 'foo'}, {title: 'bar', value: 'bar'}]);
  expect(comp.groupBys[1].headers).toStrictEqual([{title: '', value: ''}, {title: 'Count', value:'count'}, {title: 'car', value: 'car'}]);
});

test('displayTable', () => {
  var group = {chart_type: 'pie'};
  comp.groupBys = [group];
  comp.displayTable(group, 0);
  expect(group.chart_type).toBe('');
});

test('displayPieChart', () => {
  var group = {chart_type: ''};
  comp.groupBys = [group];
  comp.queryGroupByOptions = [[]];
  comp.displayPieChart(group, 0);
  expect(group.chart_type).toBe('pie');
});

test('displaySankeyChart', () => {
  var group = {chart_type: ''};
  group.data = [{ count: 10, foo: 'mog', bar: 'mop' }, { count: 1, foo: 'moo', bar: 'mar' }, { count: 12, foo: 'moo', bar: 'car' }, { count: 2, foo: 'moo', bar: 'mog' }, { count: 2, foo: 'mop', bar: 'moo' },{ count: 2, foo: 'moo', bar: 'moo' }, { count: 3, foo: 'mop', bar: 'baz' }]
  group.fields = ['foo', 'bar'];
  comp.groupBys = [group];
  comp.queryGroupByOptions = [[]];
  comp.displaySankeyChart(group, 0);
  expect(group.chart_type).toBe('sankey');
  expect(group.chart_data.flowMax).toBe(15);
  expect(group.chart_data.datasets[0].data).toStrictEqual([
    {
      "flow": 10,
      "from": "mog",
      "to": "mop",
    },
    {
      "flow": 1,
      "from": "moo",
      "to": "mar",
    },
    {
      "flow": 12,
      "from": "moo",
      "to": "car",
    },
    {
      "flow": 2,
      "from": "moo",
      "to": "mog",
    },
    {
      "flow": 3,
      "from": "mop",
      "to": "baz",
    },
  ]);
});

test('displayBarChart', () => {
  var group = {chart_type: ''};
  comp.groupBys = [group];
  comp.queryGroupByOptions = [[]];
  comp.displayBarChart(group, 0);
  expect(group.chart_type).toBe('bar');
});

test('lookupGroupByMetricKey', () => {
  var metrics = {
    "groupby_0|foo": [{ value: 37, keys: ['moo'] }],
    "groupby_0|foo|bar": [{ value: 23, keys: ['moo', 'mar'] }],
    "groupby_1|car": [{ value: 9, keys: ['mis'] }],
  }
  var result = comp.lookupGroupByMetricKey(metrics, 0, true);
  expect(result).toBe("groupby_0|foo|bar");

  result = comp.lookupGroupByMetricKey(metrics, 0, false);
  expect(result).toBe("groupby_0|foo");
});

test('setupPieChart', () => {
  var options = {};
  var data = {};
  comp.setupPieChart(options, data, 'some title');
  expect(options).toStrictEqual({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          position: 'left',
        },
        title: {
          display: true,
          text: 'some title',
        }
      }
    });
  expect(data).toStrictEqual({
      labels: [],
      datasets: [{
        backgroundColor: [
          'rgba(77, 201, 246, 1)',
          'rgba(246, 112, 25, 1)',
          'rgba(245, 55, 148, 1)',
          'rgba(83, 123, 196, 1)',
          'rgba(172, 194, 54, 1)',
          'rgba(22, 106, 143, 1)',
          'rgba(0, 169, 80, 1)',
          'rgba(88, 89, 91, 1)',
          'rgba(133, 73, 186, 1)',
          'rgba(235, 204, 52, 1)',
          "rgba(127, 127, 127, 1)",
        ],
        borderColor: 'rgba(255, 255, 255, 0.5)',
        data: [],
        label: 'Count',
      }],
    });
});

test('setupSankeyChart', () => {
  var options = {};
  var data = {};
  comp.setupSankeyChart(options, data, 'some title');
  expect(options).toStrictEqual({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false,
        },
        title: {
          display: true,
          text: 'some title',
        }
      }
    });
  expect(data.labels).toStrictEqual([]);
  expect(data.datasets[0].data).toStrictEqual([]);
  expect(data.datasets[0].label).toBe('Count');
  expect(data.datasets[0].color).toBe('black');
});

test('getSankeyColor', () => {
  var source = {};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('steelblue');

  var source = { parsed: { _custom: { foo: { bar: 100 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 91)).toBe('crimson');

  var source = { parsed: { _custom: { foo: { bar: 89 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('red');

  var source = { parsed: { _custom: { foo: { bar: 71 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('orangered');

  var source = { parsed: { _custom: { foo: { bar: 65 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('darkorange');

  var source = { parsed: { _custom: { foo: { bar: 54 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('orange');

  var source = { parsed: { _custom: { foo: { bar: 41 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('goldenrod');

  var source = { parsed: { _custom: { foo: { bar: 34 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('gold');

  var source = { parsed: { _custom: { foo: { bar: 26 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('yellow');

  var source = { parsed: { _custom: { foo: { bar: 21 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('yellowgreen');

  var source = { parsed: { _custom: { foo: { bar: 16 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('limegreen');

  var source = { parsed: { _custom: { foo: { bar: 12 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('green');

  var source = { parsed: { _custom: { foo: { bar: 6 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('aquamarine');

  var source = { parsed: { _custom: { foo: { bar: 5 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('cyan');

  var source = { parsed: { _custom: { foo: { bar: 4 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('darkturquoise');

  var source = { parsed: { _custom: { foo: { bar: 3 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('lightskyblue');

  var source = { parsed: { _custom: { foo: { bar: 2 }}}};
  expect(comp.getSankeyColor('foo', 'bar', source, 100)).toBe('royalblue');
});

test('applyLegendOption', () => {
  const group = {
    chart_options: {
      plugins: {
        legend: {
          display: true
        }
      }
    }
  };
  comp.queryGroupByOptions = [["bar"],["pie", "nolegend"]];
  comp.applyLegendOption(group, 1);
  expect(group.chart_options.plugins.legend.display).toBe(false);

  comp.queryGroupByOptions = [["bar"],["pie", "legend"]];
  comp.applyLegendOption(group, 1);
  expect(group.chart_options.plugins.legend.display).toBe(true);
});

test('buildGroupOptionRoute', () => {
  comp.query = "* | groupby -foo something | groupby something else";
  var route = comp.buildGroupOptionRoute(1, ["foo"], "bar");
  expect(route.query.q).toBe("* | groupby -foo something | groupby -bar something else");

  var route = comp.buildGroupOptionRoute(0, ["foo"], "bar");
  expect(route.query.q).toBe("* | groupby -bar something | groupby something else");
});

test('buildToggleLegendRoute', () => {
  var group = {
    chart_options: {
      plugins: {
        legend: {
          display: true
        }
      }
    }
  };
  comp.query = "* | groupby -pie -legend something | groupby something else";
  var route = comp.buildToggleLegendRoute(group, 0);
  expect(route.query.q).toBe("* | groupby -nolegend -pie something | groupby something else");

  var group = {
    chart_options: {
      plugins: {
        legend: {
          display: false
        }
      }
    }
  };
  comp.query = "* | groupby -pie -nolegend something | groupby something else";
  var route = comp.buildToggleLegendRoute(group, 0);
  expect(route.query.q).toBe("* | groupby -legend -pie something | groupby something else");
});

test('buildMaximizeRoute', () => {
  var group = {};
  comp.query = "* | groupby -pie something | groupby something else";
  var route = comp.buildMaximizeRoute(group, 0);
  expect(route.query.q).toBe("* | groupby -maximize -pie something | groupby something else");

  route = comp.buildNonMaximizedRoute(group, 0);
  expect(route.query.q).toBe("* | groupby -pie something | groupby something else");
});

test('buildGroupWithoutOptionsRoute', () => {
  comp.query = "* | groupby -maximize -pie something | groupby something else";
  var route = comp.buildGroupWithoutOptionsRoute(1);
  expect(route.query.q).toBe("* | groupby -maximize -pie something | groupby something else");

  var route = comp.buildGroupWithoutOptionsRoute(0);
  expect(route.query.q).toBe("* | groupby something | groupby something else");
});

test('isGroupSankeyCapable', () => {
  var group = {  };
  expect(comp.isGroupSankeyCapable(group)).toBe(false);

  var group = { fields: ['foo'] };
  expect(comp.isGroupSankeyCapable(group)).toBe(false);

  var group = { fields: ['foo', 'bar'] };
  expect(comp.isGroupSankeyCapable(group)).toBe(true);

  var group = { fields: ['foo', 'bar', 'car'] };
  expect(comp.isGroupSankeyCapable(group)).toBe(true);
});

test('getGroupByFieldStartIndex', () => {
  comp.aggregationActionsEnabled = false;
  expect(comp.getGroupByFieldStartIndex()).toBe(1);

  comp.aggregationActionsEnabled = true;
  expect(comp.getGroupByFieldStartIndex()).toBe(2);
});

test('obtainQueryDetails_blank', () => {
  comp.query = ""
  comp.obtainQueryDetails();
  expect(comp.queryName).toBe("");
  expect(comp.querySearch).toBe("");
  expect(comp.queryRemainder).toBe("");
  expect(comp.queryFilters).toStrictEqual([]);
  expect(comp.queryGroupBys).toStrictEqual([]);
  expect(comp.queryGroupByOptions).toStrictEqual([]);
  expect(comp.querySortBys).toStrictEqual([]);
});

test('obtainQueryDetails_queryOnly', () => {
  comp.query = "foo: bar AND x:1"
  comp.obtainQueryDetails();
  expect(comp.queryName).toBe("Custom");
  expect(comp.querySearch).toBe("foo: bar AND x:1");
  expect(comp.queryRemainder).toBe("");
  expect(comp.queryFilters).toStrictEqual(["foo: bar", "x:1"]);
  expect(comp.queryGroupBys).toStrictEqual([]);
  expect(comp.queryGroupByOptions).toStrictEqual([]);
  expect(comp.querySortBys).toStrictEqual([]);
});

test('obtainQueryDetails_queryGroupedOptionsTableSorted', () => {
  comp.query = "foo: bar AND x:1 | groupby -opt1 z | groupby -optB r^ | sortby y | table x y z"
  comp.obtainQueryDetails();
  expect(comp.queryName).toBe("Custom");
  expect(comp.querySearch).toBe("foo: bar AND x:1");
  expect(comp.queryRemainder).toBe("| groupby -opt1 z | groupby -optB r^ | sortby y | table x y z");
  expect(comp.queryFilters).toStrictEqual(["foo: bar", "x:1"]);
  expect(comp.queryGroupBys).toStrictEqual([["z"], ["r^"]]);
  expect(comp.queryGroupByOptions).toStrictEqual([["opt1"], ["optB"]]);
  expect(comp.querySortBys).toStrictEqual(["y"]);
  expect(comp.queryTableFields).toStrictEqual(["x", "y", "z"]);
});

test('obtainQueryDetails_queryGroupedFilterPipe', () => {
  comp.query = "foo: bar AND x:\"with | this\" | groupby z"
  comp.obtainQueryDetails();
  expect(comp.queryName).toBe("Custom");
  expect(comp.querySearch).toBe("foo: bar AND x:\"with | this\"");
  expect(comp.queryRemainder).toBe("| groupby z");
  expect(comp.queryFilters).toStrictEqual(["foo: bar", "x:\"with | this\""]);
  expect(comp.queryGroupBys).toStrictEqual([["z"]]);
  expect(comp.queryGroupByOptions).toStrictEqual([[]]);
  expect(comp.querySortBys).toStrictEqual([]);
});

test('obtainQueryDetails_trickyEscapeSequence', () => {
  comp.query = `process.working_directory:"C:\\\\Windows\\\\system32\\\\" | groupby host.name`;
  comp.obtainQueryDetails();
  expect(comp.queryName).toBe("Custom");
  expect(comp.querySearch).toBe(`process.working_directory:"C:\\\\Windows\\\\system32\\\\"`);
  expect(comp.queryRemainder).toBe("| groupby host.name");
  expect(comp.queryFilters).toStrictEqual([`process.working_directory:"C:\\\\Windows\\\\system32\\\\"`]);
  expect(comp.queryGroupBys).toStrictEqual([["host.name"]]);
  expect(comp.queryGroupByOptions).toStrictEqual([[]]);
  expect(comp.querySortBys).toStrictEqual([]);
});

test('query string filterToggles', () => {
  comp.$route = { path: "hunt", query: { socExcludeToggle: false } };
  comp.filterToggles = [{
    "enabled": true,
    "filter": "NOT _index:\"*:so-case*\"",
    "name": "caseExcludeToggle"
  },
  {
    "enabled": true,
    "filter": "NOT event.module:\"soc\"",
    "name": "socExcludeToggle"
  }];
  comp.parseUrlParameters();

  expect(comp.filterToggles[0].enabled).toBe(true);
  expect(comp.filterToggles[1].enabled).toBe(false);
});

test('buildGroupByRoute', () => {
  comp.query = "*"; // no groupBy clause results in hard coded response of 1
  let r = comp.buildGroupByRoute('x');
  expect(r.query.groupByGroup).toBe(1);

  comp.query = `* | groupby "log.level"`;
  r = comp.buildGroupByRoute('x');
  expect(r.query.groupByGroup).toBe(0);

  comp.query = `* | groupby "log.level" |GrOuPbY "field.groupBy" |   GROUPBY "@version"`;
  r = comp.buildGroupByRoute('x');
  expect(r.query.groupByGroup).toBe(2);
});

test('subMissing', () => {
  expect(comp.subMissing("")).toBe("");
  expect(comp.subMissing("foo")).toBe("foo");
  expect(comp.subMissing("Missing")).toBe("Missing");
  expect(comp.subMissing(comp.i18n.__missing__)).toBe("__missing__");
  expect(comp.subMissing(comp.i18n.__missing__ + " foo")).toBe(comp.i18n.__missing__ + " foo");
  expect(comp.subMissing(null)).toBe(null)
  expect(comp.subMissing(undefined)).toBe(undefined)
  expect(comp.subMissing(10)).toBe(10)
});

test('getRelativeTimeUnits', () => {
  comp.relativeTimeUnit = 10;
  expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.seconds);

  comp.relativeTimeUnit = 20;
  expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.minutes);

  comp.relativeTimeUnit = 30;
  expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.hours);

  comp.relativeTimeUnit = 40;
  expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.days);

  comp.relativeTimeUnit = 50;
  expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.weeks);

  comp.relativeTimeUnit = 60;
  expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.months);

  comp.relativeTimeUnit = -1;
  expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.hours);
});

test('setRelativeTimeUnits', () => {
  for (let i = 0; i < comp.relativeTimeUnits.length; i++) {
    comp.setRelativeTimeUnits(comp.relativeTimeUnits[i].title);
    expect(comp.relativeTimeUnit).toBe(comp.relativeTimeUnits[i].value);
  }

  comp.setRelativeTimeUnits("foo");
  expect(comp.relativeTimeUnit).toBe(30);
});

test('relative query string', () => {
  comp.$route = { path: "hunt", query: { rt: 24, rtu: 'hours' } };
  comp.parseUrlParameters();

  expect(comp.relativeTimeEnabled).toBe(true);
  expect(comp.relativeTimeUnit).toBe(30);
  expect(comp.relativeTimeValue).toBe(24);

  comp.$route = { path: "hunt", query: { rt: 10 } };
  comp.parseUrlParameters();

  expect(comp.relativeTimeEnabled).toBe(true);
  expect(comp.relativeTimeUnit).toBe(30);
  expect(comp.relativeTimeValue).toBe(10);

  comp.$route = { path: "hunt", query: { rt: 24, rtu: 'hours', t: '2021/07/03 01:01:57 PM - 2023/07/03 01:01:57 PM' } };
  comp.parseUrlParameters();

  expect(comp.relativeTimeEnabled).toBe(false);
  expect(comp.dateRange).toBe('2021/07/03 01:01:57 PM - 2023/07/03 01:01:57 PM');
});

test('autoRefresh query string', () => {
  comp.$route = { path: "hunt", query: { ar: 30 } };
  comp.parseUrlParameters();

  expect(comp.autoRefreshEnabled).toBe(true);
  expect(comp.autoRefreshInterval).toBe(30);

  comp.$route = { path: "hunt", query: { ar: 1 } };
  comp.parseUrlParameters();

  expect(comp.autoRefreshEnabled).toBe(false);
  expect(comp.autoRefreshInterval).toBe(0);

  comp.$route = { path: "hunt", query: {} };
  comp.parseUrlParameters();

  expect(comp.autoRefreshEnabled).toBe(false);
  expect(comp.autoRefreshInterval).toBe(0);
});

test('isNumeric', () => {
  let table = [
    { value: '', expected: false },
    { value: 'foo', expected: false },
    { value: '1', expected: true },
    { value: '1.9', expected: true },
    { value: '3.1.4', expected: false },
    { value: '6,8', expected: false },
    { value: '-32', expected: true },
    { value: '-0.7', expected: true },
    { value: '-1.2.3', expected: false },
    { value: '1-1', expected: false },
    { value: '6.4-5', expected: false },
    { value: '--0', expected: false },
    { value: NaN, expected: false },
  ];

  for (let i = 0; i < table.length; i++) {
    expect(comp.isNumeric(table[i].value)).toBe(table[i].expected);
  }
});

test('buildFilterRoute', () => {
  let route = comp.buildFilterRoute('@version', '1', 'INCLUDE');
  expect(route.query).toEqual(expect.not.objectContaining({scalar: expect.anything()}));

  route = comp.buildFilterRoute('@version', '1', 'INCLUDE', false);
  expect(route.query).toEqual(expect.objectContaining({scalar: expect.anything()}));

  route = comp.buildFilterRoute('@version', '1', 'INCLUDE', true);
  expect(route.query).toEqual(expect.objectContaining({scalar: expect.anything()}));
});

test('huntBetween', () => {
  let table = [
    { inputs: [1, false, false, 10], expErr: '', expQuery: {"el": 100, "filterField": "", "filterMode": "INCLUDE", "filterValue": "{1 TO 10}", "gl": 10, "q": "", "rt": 24, "rtu": "hours", "scalar": "true", "z": "" }},
    { inputs: [1, true, false, 10], expErr: '', expQuery: { "el": 100, "filterField": "", "filterMode": "INCLUDE", "filterValue": "[1 TO 10}", "gl": 10, "q": "", "rt": 24, "rtu": "hours", "scalar": "true", "z": "" }},
    { inputs: [1, false, true, 10], expErr: '', expQuery: {"el": 100, "filterField": "", "filterMode": "INCLUDE", "filterValue": "{1 TO 10]", "gl": 10, "q": "", "rt": 24, "rtu": "hours", "scalar": "true", "z": "" }},
    { inputs: [1, true, true, 10], expErr: '', expQuery: { "el": 100, "filterField": "", "filterMode": "INCLUDE", "filterValue": "[1 TO 10]", "gl": 10, "q": "", "rt": 24, "rtu": "hours", "scalar": "true", "z": "" } },
    { inputs: [1, false, false, 0], expErr: comp.i18n.startEndOrderErr },
    { inputs: ['x', true, true, 'y'], expErr: comp.i18n.startEndNumericErr },
  ];

  for (let i = 0; i < table.length; i++) {
    [comp.betweenStart, comp.betweenStartEquals, comp.betweenEndEquals, comp.betweenEnd] = table[i].inputs;
    comp.$router = [];

    comp.huntBetween();

    expect(comp.betweenError).toBe(table[i].expErr);

    if (table[i].expQuery || comp.$router.length !== 0) {
      expect(comp.$router[0].query).toEqual(table[i].expQuery);
    }
  }
});

test('filterVisibleFields', () => {
  comp.eventFields = {
    ':module:dataset': 'a',
    '::dataset': 'b',
    ':module:': 'c',
    'default': 'default',
  };

  expect(comp.filterVisibleFields('module', 'module.dataset', [])).toEqual('a');
  expect(comp.filterVisibleFields('', 'module.dataset', [])).toEqual('b');
  expect(comp.filterVisibleFields('module', 'otherData', [])).toEqual('c');
  expect(comp.filterVisibleFields('A', 'B', [])).toEqual('default');
});

test('handleChartClick', () => {
  const orig = comp.toggleQuickAction;
  comp.toggleQuickAction = jest.fn();

  let metrics = { "groupby_2|MyField": [] };
  let groupIdx = 2;
  comp.queryGroupByOptions = [[], [], ["bar"]]


  const result = comp.populateGroupByTable(metrics, groupIdx);
  comp.groupBys[2].chart_options.onClick(null, [{ index: 0 }], { data: {labels: ['value']} });

  expect(result).toBe(true);
  expect(comp.toggleQuickAction).toHaveBeenCalledTimes(1);
  expect(comp.toggleQuickAction).toHaveBeenCalledWith(null, {}, 'MyField', 'value');

  comp.toggleQuickAction = orig;
});

test('performAction', () => {
  const mock = jest.fn();
  comp.testFunc = mock;

  let action = { jsCall: 'nonExistentFunc' };

  let result = comp.performAction(undefined, action);

  expect(mock).toHaveBeenCalledTimes(0);
  expect(result).toBe(true); // true means allow the href property to navigate

  action.jsCall = 'testFunc';

  result = comp.performAction(undefined, action);

  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith(action);
  expect(result).toBe(false);

  delete comp.testFunc;
});

test('openAddToCaseDialog', () => {
  localStorage['settings.case.mruCases'] = `[{ "id": "1", "title": "Case 1" }, { "id": "2", "title": "Case 2" }]`;
  comp.$refs = {
    evidence: {
      resetValidation: jest.fn(),
    }
  };
  comp.openAddToCaseDialog();

  expect(comp.addToCaseDialogVisible).toBe(true);
  expect(comp.mruCases).toEqual([{ value: 'New Case', title: comp.i18n.createNewCase }, { value: { id: "1", title: 'Case 1' }, title: 'Case 1' }, { value: { id: "2", title: 'Case 2' }, title: 'Case 2' }]);
  expect(comp.selectedMruCase).toBe('New Case');
  expect(comp.$refs.evidence.resetValidation).toHaveBeenCalledTimes(1);
});

test('addToCase', () => {
  const origOpen = window.open;
  window.open = jest.fn();
  comp.$refs = {
    evidence: {
      validate: jest.fn(),
    }
  };
  comp.$refs.evidence.validate.mockReturnValue(true);

  comp.quickActionValue = 'test';
  comp.selectedMruCase = 'New Case';

  comp.addToCase(false);

  expect(window.open).toHaveBeenCalledTimes(1);
  expect(window.open).toHaveBeenCalledWith('http://localhost/#/case/create?type=evidence&value=test', '_self');
  expect(comp.addToCaseDialogVisible).toBe(false);

  comp.addToCase(true)

  expect(window.open).toHaveBeenCalledTimes(2);
  expect(window.open).toHaveBeenCalledWith('http://localhost/#/case/create?type=evidence&value=test', '_blank');
  expect(comp.addToCaseDialogVisible).toBe(false);

  comp.selectedMruCase = { id: '1', title: 'Case 1' };

  comp.addToCase(true);

  expect(window.open).toHaveBeenCalledTimes(3);
  expect(window.open).toHaveBeenCalledWith('http://localhost/#/case/1?type=evidence&value=test', '1');
  expect(comp.addToCaseDialogVisible).toBe(false);

  window.open = origOpen;
});

test('populateEventHeaders', () => {
  const defs = ["x", "y"];
  comp.populateEventHeaders(defs);
  expect(comp.eventHeaders).toStrictEqual([{title:'x', value:'x'},{title:'y', value: 'y'}]);

  comp.queryTableFields = ['b', 'c'];
  comp.populateEventHeaders(defs);
  expect(comp.eventHeaders).toStrictEqual([{ title: 'b', value: 'b' }, { title: 'c', value: 'c' }]);

  comp.queryTableFields = ['a', 'b', 'so_detection.isEnabled', 'c'];
  comp.populateEventHeaders(defs);
  expect(comp.eventHeaders).toStrictEqual([{ title: 'a', value: 'a' }, { title: 'b', value: 'b' }, { title: 'Enabled', value: 'so_detection.isEnabled' }, { title: 'c', value: 'c' }]);

  comp.category = 'detections';
  comp.populateEventHeaders(defs);
  expect(comp.eventHeaders).toStrictEqual([{ title: 'a', value: 'a' }, { title: 'b', value: 'b' }, { title: 'Enabled', value: 'so_detection.isEnabled'}, { title: 'Overrides', value: 'override_count' }, { title: 'c', value: 'c' }]);
});

test('repopulateEventHeaders', () => {
  comp.queryTableFields = ["b", "c"];
  comp.query = 'foo: bar| table old';
  expect(comp.$router.length).toBe(0);
  expect(comp.disableRouteLoad).toBe(false);
  comp.repopulateEventHeaders();
  expect(comp.disableRouteLoad).toBe(true);
  expect(comp.eventHeaders).toStrictEqual([{"title":"b", "value":"b"},{"title":"c", "value": "c"}]);
  expect(comp.query).toBe('foo: bar | table b c');
  expect(comp.$router.length).toBe(1);
});

test('toggleColumnHeader', () => {
  expect(comp.eventHeaders).toStrictEqual([]);
  comp.toggleColumnHeader('x');
  expect(comp.eventHeaders).toStrictEqual([{value:'x', title:'x'}]);
  comp.toggleColumnHeader('x');
  expect(comp.eventHeaders).toStrictEqual([]);
  comp.toggleColumnHeader('x');
  expect(comp.eventHeaders).toStrictEqual([{value:'x', title:'x'}]);
  comp.toggleColumnHeader('y');
  expect(comp.eventHeaders).toStrictEqual([{value:'x', title:'x'},{value:'y', title:'y'}]);
  comp.toggleColumnHeader('x');
  expect(comp.eventHeaders).toStrictEqual([{value:'y', title:'y'}]);
});

test('moveColumnHeader', () => {
  comp.moveColumnHeader('x', true);
  expect(comp.queryTableFields).toStrictEqual([]);

  comp.queryTableFields = ['x', 'y', 'z'];
  comp.moveColumnHeader('x', true);
  expect(comp.queryTableFields).toStrictEqual(['x', 'y', 'z']);

  comp.moveColumnHeader('x', false);
  expect(comp.queryTableFields).toStrictEqual(['y', 'x', 'z']);

  comp.moveColumnHeader('x', false);
  expect(comp.queryTableFields).toStrictEqual(['y', 'z', 'x']);

  // double check that repopulateEventHeaders was invoked
  expect(comp.eventHeaders).toStrictEqual([{"title":"y", "value":"y"},{"title":"z", "value":"z"},{"title":"x", "value": "x"}]);

  comp.moveColumnHeader('x', false);
  expect(comp.queryTableFields).toStrictEqual(['y', 'z', 'x']);

  comp.moveColumnHeader('x', true);
  expect(comp.queryTableFields).toStrictEqual(['y', 'x', 'z']);

  comp.moveColumnHeader('x', true);
  expect(comp.queryTableFields).toStrictEqual(['x', 'y', 'z']);

  // double check that repopulateEventHeaders was invoked
  expect(comp.eventHeaders).toStrictEqual([{"title":"x", "value":"x"},{"title":"y", "value":"y"},{"title":"z", "value": "z"}]);
});

test('updateBulkSelector', () => {
  const selected = { _isSelected: true };
  const unselected = { _isSelected: false };

  comp.totalEvents = 2;

  expect(comp.selectedCount).toBe(0);
  expect(comp.selectAllState).toBe(false);
  expect(comp.selectAllIndeterminate).toBe(false);

  comp.updateBulkSelector(selected);

  expect(comp.selectedCount).toBe(1);
  expect(comp.selectAllState).toBe(false);
  expect(comp.selectAllIndeterminate).toBe(true);

  comp.updateBulkSelector(selected);

  expect(comp.selectedCount).toBe(2);
  expect(comp.selectAllState).toBe(true);
  expect(comp.selectAllIndeterminate).toBe(false);

  comp.updateBulkSelector(unselected);

  expect(comp.selectedCount).toBe(1);
  expect(comp.selectAllState).toBe(false);
  expect(comp.selectAllIndeterminate).toBe(true);

  comp.updateBulkSelector(unselected);

  expect(comp.selectedCount).toBe(0);
  expect(comp.selectAllState).toBe(false);
  expect(comp.selectAllIndeterminate).toBe(false);
});

test('toggleSelectAll', () => {
  comp.totalEvents = 11;
  comp.eventData = [];
  comp.eventCurrentItems = [];

  for (let i = 0; i < comp.totalEvents; i++) {
    let obj = { _isSelected: i === 0 };
    comp.eventData.push(obj);
    if (comp.eventCurrentItems.length < 10) {
      comp.eventCurrentItems.push(obj);
    }
  }

  comp.selectAllState = 'indeterminate';
  comp.countSelected();

  expect(comp.selectedCount).toBe(1);
  expect(comp.isPageSelected()).toBe(false);

  // the comp has 11 eventData, the first 10 are in eventCurrentItems
  // eventData[0] is the only one selected

  // some selected => none selected
  comp.toggleSelectAll();

  expect(comp.selectAllState).toBe(false);
  expect(comp.selectAllIndeterminate).toBe(false);
  expect(comp.selectedCount).toBe(0);
  expect(comp.eventData[0]._isSelected).toBe(false);
  comp.countSelected();
  expect(comp.selectedCount).toBe(0);
  expect(comp.isPageSelected()).toBe(false);

  // none selected => page selected
  comp.toggleSelectAll();

  expect(comp.selectAllState).toBe(false);
  expect(comp.selectAllIndeterminate).toBe(true);
  expect(comp.selectedCount).toBe(10);
  expect(comp.eventData[10]._isSelected).toBe(false);
  comp.countSelected();
  expect(comp.selectedCount).toBe(10);
  expect(comp.isPageSelected()).toBe(true);

  // page selected => all selected
  comp.selectAllEvents(true, true);

  expect(comp.selectAllState).toBe(true);
  expect(comp.selectAllIndeterminate).toBe(false);
  expect(comp.selectedCount).toBe(11);
  expect(comp.eventData[10]._isSelected).toBe(true);
  comp.countSelected();
  expect(comp.selectedCount).toBe(11);
  expect(comp.isPageSelected()).toBe(true);

  // all selected => none selected
  comp.toggleSelectAll();

  expect(comp.selectAllState).toBe(false);
  expect(comp.selectAllIndeterminate).toBe(false);
  expect(comp.selectedCount).toBe(0);
  comp.countSelected();
  expect(comp.selectedCount).toBe(0);
  expect(comp.isPageSelected()).toBe(false);
});

test('bulkAction - delete - pre-confirm', async () => {
  comp.selectedAction = 'delete';
  comp.selectedCount = 2;

  await comp.bulkAction();

  expect(comp.showBulkDeleteConfirmDialog).toBe(true);
  expect(comp.selectedCount).toBe(2);
  expect(comp.$root.tip).toBe(false);
});

test('bulkAction - enable', async () => {
  comp.selectedAction = 'enable';
  comp.selectedCount = 2;
  comp.selectAllIndeterminate = true;
  comp.eventData = [{ _isSelected: true, soc_id: "1" }, { _isSelected: false, soc_id: "2" }, { _isSelected: true, soc_id: "3" }];
  comp.hunt = jest.fn();
  const mock = resetPapi().mockPapi('post', { data: { count: 2 }, }, null);

  await comp.bulkAction(true);

  expect(comp.showBulkDeleteConfirmDialog).toBe(false);
  expect(comp.selectAllState).toBe(false);
  expect(comp.selectedCount).toBe(0);
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith('detection/bulk/enable', { ids: ["1", "3"] });
  expect(comp.hunt).toHaveBeenCalledTimes(1);
  expect(comp.hunt).toHaveBeenCalledWith(false);
  expect(comp.$root.tip).toBe(true);
  expect(comp.$root.tipMessage).toBe('Updating 2 detections. This may take awhile.');
});

test('bulkAction - disable', async () => {
  comp.selectedAction = 'disable';
  comp.selectedCount = 2;
  comp.selectAllIndeterminate = true;
  comp.eventData = [{ _isSelected: true, soc_id: "1" }, { _isSelected: false, soc_id: "2" }, { _isSelected: true, soc_id: "3" }];
  comp.hunt = jest.fn();
  const mock = resetPapi().mockPapi('post', { data: { count: 2 } }, null);

  await comp.bulkAction(true);

  expect(comp.showBulkDeleteConfirmDialog).toBe(false);
  expect(comp.selectAllState).toBe(false);
  expect(comp.selectedCount).toBe(0);
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith('detection/bulk/disable', { ids: ["1", "3"] });
  expect(comp.hunt).toHaveBeenCalledTimes(1);
  expect(comp.hunt).toHaveBeenCalledWith(false);
  expect(comp.$root.tip).toBe(true);
  expect(comp.$root.tipMessage).toBe('Updating 2 detections. This may take awhile.');
});

test('bulkAction - delete - confirm - success', async () => {
  comp.selectedAction = 'delete';
  comp.showBulkDeleteConfirmDialog = true;
  comp.selectedCount = 2;
  comp.selectAllIndeterminate = true;
  comp.eventData = [{ _isSelected: true, soc_id: "1" }, { _isSelected: false, soc_id: "2" }, { _isSelected: true, soc_id: "3" }];
  comp.hunt = jest.fn();
  const mock = resetPapi().mockPapi('post', { data: { count: 2 } }, null);

  await comp.bulkAction(true);

  expect(comp.showBulkDeleteConfirmDialog).toBe(false);
  expect(comp.selectAllState).toBe(false);
  expect(comp.selectedCount).toBe(0);
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith('detection/bulk/delete', { ids: ["1", "3"] });
  expect(comp.hunt).toHaveBeenCalledTimes(1);
  expect(comp.hunt).toHaveBeenCalledWith(false);
  expect(comp.$root.tip).toBe(true);
  expect(comp.$root.tipMessage).toBe('Deleting 2 detections. This may take awhile.');
});

test('bulkAction - delete - confirm - failure', async () => {
  comp.selectedAction = 'delete';
  comp.showBulkDeleteConfirmDialog = true;
  comp.selectedCount = 2;
  comp.selectAllIndeterminate = true;
  comp.eventData = [{ _isSelected: true, soc_id: "1" }, { _isSelected: false, soc_id: "2" }, { _isSelected: true, soc_id: "3" }];
  const err = { response: { data: "ERROR_BULK_COMMUNITY" } }
  const mock = resetPapi().mockPapi('post', null, err);

  await comp.bulkAction(true);

  expect(comp.showBulkDeleteConfirmDialog).toBe(false);
  expect(comp.selectAllState).toBe(false);
  expect(comp.selectAllIndeterminate).toBe(true);
  expect(comp.selectedCount).toBe(2);
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith('detection/bulk/delete', { ids: ["1", "3"] });
  expect(comp.$root.error).toBe(true);
  expect(comp.$root.errorMessage).toBe(comp.i18n.ERROR_BULK_COMMUNITY);
});

test('reconstructQuery', () => {
  comp.query = "bar: 'hi' | groupby x"
  comp.obtainQueryDetails();
  comp.reconstructQuery();
  comp.querySearch = "foo: 1"

  // Advanced mode and showFullQuery false so should reconstruct query using new custom filter
  comp.advanced = true;
  comp.showFullQuery = false;
  comp.queryModified();
  expect(comp.query).toBe("foo: 1 | groupby x");
});

test('queryModified', () => {
  comp.$root.loading = true; // prevent any notification logic from running
  comp.query = "bar: 'hi' | groupby x"
  comp.obtainQueryDetails();
  comp.querySearch = "foo: 1"

  // Basic mode, should not reconstruct query
  comp.queryModified();
  expect(comp.query).toBe("bar: 'hi' | groupby x");

  // Advanced mode, but showFullQuery is true so should not reconstruct query
  comp.advanced = true;
  comp.showFullQuery = true;
  comp.queryModified();
  expect(comp.query).toBe("bar: 'hi' | groupby x");

  // Advanced mode and showFullQuery false so should reconstruct query using new custom filter
  comp.advanced = true;
  comp.showFullQuery = false;
  comp.queryModified();
  expect(comp.query).toBe("foo: 1 | groupby x");
});

test('getDisplayedQueryVar', () => {
  expect(comp.getDisplayedQueryVar()).toBe('queryName');

  comp.advanced = true;
  comp.showFullQuery = true;
  expect(comp.getDisplayedQueryVar()).toBe('query');

  comp.advanced = true;
  comp.showFullQuery = false;
  expect(comp.getDisplayedQueryVar()).toBe('querySearch');
});

test('bulkUpdateReport - error', () => {
  let stats = {
    error: 1,
  };

  comp.bulkUpdateReport(stats)

  expect(comp.$root.error).toBe(true);
  expect(comp.$root.errorMessage).toBe('1 of the detections during the last bulk update failed. Please check the SOC logs for more information.');
});

test('bulkUpdateReport - update success', () => {
  let stats = {
    time: 10,
    filtered: 0,
    verb: 'update',
    modified: 2,
    total: 2,
  };

  comp.bulkUpdateReport(stats)

  expect(comp.$root.info).toBe(true);
  expect(comp.$root.infoMessage).toBe('Bulk update successfully updated 2 of 2 events. (10s)');
});

test('bulkUpdateReport - delete success', () => {
  let stats = {
    time: 1000,
    filtered: 0,
    verb: 'delete',
    modified: 200,
    total: 200,
  };

  comp.bulkUpdateReport(stats)

  expect(comp.$root.info).toBe(true);
  expect(comp.$root.infoMessage).toBe('Bulk delete successfully deleted 200 of 200 events. (16m 40s)');
});

test('bulkUpdateReport - filtered success', () => {
  let stats = {
    time: 200,
    filtered: 1,
    verb: 'update',
    modified: 20,
    total: 20,
  };

  comp.bulkUpdateReport(stats)

  expect(comp.$root.warning).toBe(true);
  expect(comp.$root.warningMessage).toBe('Bulk update successfully updated 20 of 20 events. However, the statuses of 1 of the updated detections are controlled by the current regex filter settings and were reverted. <a href="/#/config?s=soc.config.server.modules.suricataengine" data-aid="warning_bulk_update_configure_filters">Click here to configure those filters.</a> (3m 20s)'
);
});

test('toggleQuickAction - Tune Detection, Yara => Source Tab, Other Engines => Tuning Tab', () => {
  comp.category = 'alerts';
  comp.escalationMenuVisible = comp.quickActionVisible = false;
  let event = { "rule.uuid": 'id' }

  let mockPromise = {
    then: (f) => {
      f({ data: { id: 'onionId', engine: 'elastalert' } });
    }
  };
  resetPapi().mockPapi('get', mockPromise, null);

  comp.toggleQuickAction({}, event, null, null);
  expect(comp.quickActionDetId).toBe('onionId');
  expect(comp.tuneDetectionTabTarget).toBe('tuning');

  mockPromise = {
    then: (f) => {
      f({ data: { id: 'onionId', engine: 'suricata' } });
    }
  };
  resetPapi().mockPapi('get', mockPromise, null);

  comp.toggleQuickAction({}, event, null, null);
  expect(comp.quickActionDetId).toBe('onionId');
  expect(comp.tuneDetectionTabTarget).toBe('tuning');

  mockPromise = {
    then: (f) => {
      f({ data: { id: 'onionId', engine: 'strelka' } });
    }
  };
  resetPapi().mockPapi('get', mockPromise, null);

  comp.toggleQuickAction({}, event, null, null);
  expect(comp.quickActionDetId).toBe('onionId');
  expect(comp.tuneDetectionTabTarget).toBe('source');
});

test('buildDetectionEngineHuntQuery', () => {
  comp.detectionEngineStatusQueries = {
    elastalert: {
      default: 'default',
      IntegrityFailure: 'IntegrityFailure',
    },
    suricata: {
      default: 'default',
      Healthy: 'Healthy',
    },
    strelka: {
      SyncFailure: 'SyncFailure',
    }
  };
  comp.$root.currentStatus = {
    detections: {
      elastalert: {
        syncFailure: 1,
      },
      suricata: {}, // Healthy
      strelka: {
        syncing: 1,
      },
    }
  };

  // miss, fallback to default
  let query = comp.buildDetectionEngineHuntQuery('elastalert');
  expect(query).toBe('default');

  // hit
  query = comp.buildDetectionEngineHuntQuery('suricata');
  expect(query).toBe('Healthy');

  // miss, no default specified, fallback to simple query
  query = comp.buildDetectionEngineHuntQuery('strelka');
  expect(query).toBe(`tags:so-soc AND strelka | groupby log.level | groupby event.action | groupby soc.fields.error`);
});