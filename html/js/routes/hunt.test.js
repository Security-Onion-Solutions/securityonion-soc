// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./hunt.js');

let comp;

beforeEach(() => {
  comp = getComponent("hunt");
  resetPapi();
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

test('toggleEscalationMenu', () => {
  comp.escalateRelatedEventsEnabled = true;
  const domEvent = {clientX: 12, clientY: 34};
  const event = {id:"33",foo:"bar"};
  comp.$nextTick = function(fn) { fn(); };
  comp.toggleEscalationMenu(domEvent, event, 2);
  expect(comp.escalationMenuX).toBe(12);
  expect(comp.escalationMenuY).toBe(34);
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
  comp.filterToggles = [{enabled: true, filter: "e:4"},{enabled: false, filter: "f:5", exclusive: true}];
  mock = mockPapi("get", {'data':'(a:1 OR b:2) AND c:3 AND e:4 AND NOT f:5'});

  const newQuery = await comp.getQuery();
  const params = { params: { query: 'a:1 OR b:2', field: '', value: 'c:3 AND e:4 AND NOT f:5', scalar: true, mode: 'INCLUDE', condense: true } };
  expect(mock).toHaveBeenCalledWith('query/filtered', params);
  expect(newQuery).toBe("(a:1 OR b:2) AND c:3 AND e:4 AND NOT f:5")
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
  expect(comp.groupBys[0].headers).toStrictEqual([{text: 'Count', value:'count'}, {text: 'foo', value: 'foo'}, {text: 'bar', value: 'bar'}]);
  expect(comp.groupBys[0].chart_metrics).toStrictEqual([{value: 23, keys:['moo, mar']}]);
  expect(comp.groupBys[0].sortBy).toBe('foo');
  expect(comp.groupBys[0].sortDesc).toBe(false);
  expect(comp.groupBys[0].maximized).toBe(false);
  expect(comp.groupBys[1].title).toBe("car");
  expect(comp.groupBys[1].fields.length).toBe(1);
  expect(comp.groupBys[1].data[0].count).toBe(9);
  expect(comp.groupBys[1].data[0].car).toBe('mis');
  expect(comp.groupBys[1].headers).toStrictEqual([{text: 'Count', value:'count'}, {text: 'car', value: 'car'}]);
  expect(comp.groupBys[1].chart_metrics).toStrictEqual([{value: 9, keys:['mis']}]);
  expect(comp.groupBys[1].sortBy).toBe('count');
  expect(comp.groupBys[1].sortDesc).toBe(true);
  expect(comp.groupBys[1].maximized).toBe(true);

  // Now include action column
  comp.aggregationActionsEnabled = true;
  result = comp.populateGroupByTables(metrics);
  expect(comp.groupBys[0].headers).toStrictEqual([{text: '', value: ''}, {text: 'Count', value:'count'}, {text: 'foo', value: 'foo'}, {text: 'bar', value: 'bar'}]);  
  expect(comp.groupBys[1].headers).toStrictEqual([{text: '', value: ''}, {text: 'Count', value:'count'}, {text: 'car', value: 'car'}]);
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
  expect(comp.queryFilters).toStrictEqual([]);
  expect(comp.queryGroupBys).toStrictEqual([]);
  expect(comp.queryGroupByOptions).toStrictEqual([]);
  expect(comp.querySortBys).toStrictEqual([]);
});

test('obtainQueryDetails_queryOnly', () => {
  comp.query = "foo: bar AND x:1"
  comp.obtainQueryDetails();
  expect(comp.queryName).toBe("Custom");
  expect(comp.queryFilters).toStrictEqual(["foo: bar", "x:1"]);
  expect(comp.queryGroupBys).toStrictEqual([]);
  expect(comp.queryGroupByOptions).toStrictEqual([]);
  expect(comp.querySortBys).toStrictEqual([]);
});

test('obtainQueryDetails_queryGroupedOptionsSorted', () => {
  comp.query = "foo: bar AND x:1 | groupby -opt1 z | groupby -optB r^ | sortby y"
  comp.obtainQueryDetails();
  expect(comp.queryName).toBe("Custom");
  expect(comp.queryFilters).toStrictEqual(["foo: bar", "x:1"]);
  expect(comp.queryGroupBys).toStrictEqual([["z"], ["r^"]]);
  expect(comp.queryGroupByOptions).toStrictEqual([["opt1"], ["optB"]]);
  expect(comp.querySortBys).toStrictEqual(["y"]);
});

test('obtainQueryDetails_queryGroupedFilterPipe', () => {
  comp.query = "foo: bar AND x:\"with | this\" | groupby z"
  comp.obtainQueryDetails();
  expect(comp.queryName).toBe("Custom");
  expect(comp.queryFilters).toStrictEqual(["foo: bar", "x:\"with | this\""]);
  expect(comp.queryGroupBys).toStrictEqual([["z"]]);
  expect(comp.queryGroupByOptions).toStrictEqual([[]]);
  expect(comp.querySortBys).toStrictEqual([]);
});
