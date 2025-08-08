// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { chartMethods } from './charts.js';

let comp;

beforeEach(() => {
  comp = {
    ...chartMethods,
    i18n: {
      __missing__: '*Missing',
    },
    $root: {
        debounce: (fn) => fn,
    },
    queryGroupByOptions: [],
    groupBys: [],
    toggleQuickAction: jest.fn(),
    debounceChartResize: jest.fn(),
    chartResizeTracker: {},
  };
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


test('setupPieChart', () => {
  var options = {};
  var data = {};
  comp.setupPieChart(options, data, 'some title');
  expect(options).toStrictEqual({
      responsive: true,
      maintainAspectRatio: false,
      onResize: comp.debounceChartResize,
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
      onResize: comp.debounceChartResize,
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

test('handleChartClick', () => {
  let metrics = { "groupby_2|MyField": [] };
  let groupIdx = 2;
  comp.queryGroupByOptions = [[], [], ["bar"]]
  comp.populateGroupByTable = jest.fn().mockReturnValue(true);
  comp.groupBys[2] = {
      chart_options: {
          onClick: () => {}
      }
  };


  const result = comp.populateGroupByTable(metrics, groupIdx);
  comp.groupBys[2].chart_options.onClick(null, [{ index: 0 }], { data: {labels: ['value']} });

  expect(result).toBe(true);
  expect(comp.toggleQuickAction).toHaveBeenCalledTimes(1);
  expect(comp.toggleQuickAction).toHaveBeenCalledWith(null, {}, 2, 'MyField', 'value');
});

test('debounceChartResize', () => {
  const chart = {
    options: {
      responsive: true
    }
  };
  comp.chartResizeTracker = {};

  // Initial call
  comp.debounceChartResize(chart, { width: 100 });
  expect(comp.chartResizeTracker[chart].length).toBe(1);
  expect(comp.chartResizeTracker[chart][0].size.width).toBe(100);

  // Second call with same size
  comp.debounceChartResize(chart, { width: 100 });
  expect(comp.chartResizeTracker[chart].length).toBe(2);

  // Simulate flapping
  for (let i = 0; i < 20; i++) {
    comp.debounceChartResize(chart, { width: 100 + (i % 2 === 0 ? 1 : -1) });
  }
  expect(chart.options.responsive).toBe(false);
});

test('debounceChartResize - no flapping', () => {
  const chart = {
    options: {
      responsive: true
    }
  };
  comp.chartResizeTracker = {};

  // Initial call
  comp.debounceChartResize(chart, { width: 100 });
  expect(comp.chartResizeTracker[chart].length).toBe(1);
  expect(comp.chartResizeTracker[chart][0].size.width).toBe(100);
  expect(chart.options.responsive).toBe(true);

  comp.debounceChartResize(chart, { width: 101 });
  expect(chart.options.responsive).toBe(true);

  comp.debounceChartResize(chart, { width: 101 });
  expect(chart.options.responsive).toBe(true);

  comp.debounceChartResize(chart, { width: 151 });
  expect(comp.chartResizeTracker[chart].length).toBe(4);
  expect(chart.options.responsive).toBe(true);
});