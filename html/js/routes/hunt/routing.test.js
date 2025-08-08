// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const { routingMethods } = require('../hunt-bundled.js');

let comp;

describe('Hunt Routing', () => {
  beforeEach(() => {
    comp = {
    ...routingMethods,
    query: '',
    zone: '',
    eventLimit: 100,
    groupByLimit: 10,
    relativeTimeEnabled: true,
    relativeTimeValue: 24,
    relativeTimeUnit: 30,
    autoRefreshInterval: 0,
    gridId: '',
    category: '',
    filterToggles: [],
    i18n: {
      seconds: 'seconds',
      minutes: 'minutes',
      hours: 'hours',
      days: 'days',
      weeks: 'weeks',
      months: 'months',
      startEndOrderErr: 'Start value must be less than end value.',
      startEndNumericErr: 'Start and end values must be numeric.',
      __missing__: '*Missing',
      timePickerSample: '2006/01/02 03:04:05 PM',
    },
    getRelativeTimeUnits: jest.fn().mockReturnValue('hours'),
    setRelativeTimeUnits: jest.fn(),
    subMissing: jest.fn((val) => val === '*Missing' ? '__missing__' : val),
    $route: {
      path: '/hunt',
      query: {}
    },
    $router: {
      push: jest.fn(),
    }
    };
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
  
  test('relative query string', async () => {
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
    const orig = comp.setupDateRangePicker;
    comp.setupDateRangePicker = jest.fn();
  
    comp.parseUrlParameters();
    await new Promise(resolve => setTimeout(resolve, 20)); // Let setTimeouts resolve
  
    expect(comp.relativeTimeEnabled).toBe(false);
    expect(comp.dateRange).toBe('2021/07/03 01:01:57 PM - 2023/07/03 01:01:57 PM');
    expect(comp.setupDateRangePicker).toHaveBeenCalled();
  
    comp.setupDateRangePicker = orig;
    });
  
  test('autoRefresh query string', () => {
    comp.autoRefreshIntervals = [{value: 30}];
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
  
  test('buildFilterRoute', () => {
    let route = comp.buildFilterRoute('@version', '1', 'INCLUDE');
    expect(route.query).toEqual(expect.not.objectContaining({scalar: expect.anything()}));
  
    route = comp.buildFilterRoute('@version', '1', 'INCLUDE', false);
    expect(route.query).toEqual(expect.objectContaining({scalar: expect.anything()}));
  
    route = comp.buildFilterRoute('@version', '1', 'INCLUDE', true);
    expect(route.query).toEqual(expect.objectContaining({scalar: expect.anything()}));
    });
  
  test('countDrilldown', () => {
    comp.filterRouteDrilldown = null;
  
    let event = {};
    event.count = 10;
  
    comp.countDrilldown(event);
    expect(comp.$router.push).toHaveBeenCalledTimes(0);
    expect(comp.filterRouteDrilldown).toBe(null);
  
    event.a = 'a';
  
    let expected = {
      path: '',
      query: {
        el: 100,
        filterField: 'a',
        filterMode: 'DRILLDOWN',
        filterValue: 'a',
        gl: 10,
        q: '',
        rt: 24,
        rtu: 'hours',
        z: ''
      }
    };
  
    comp.countDrilldown(event);
    expect(comp.$router.push).toHaveBeenCalledTimes(1);
    expect(comp.filterRouteDrilldown).toEqual(expected);
    expect(comp.$router.push).toHaveBeenCalledWith(expected);
  
    comp.$router.push.mockClear();
    comp.filterRouteDrilldown = null;
  
    event.b = 'b';
  
    comp.countDrilldown(event);
    expect(comp.$router.push).toHaveBeenCalledTimes(0);
    expect(comp.filterRouteDrilldown).toBe(null);
  
    event = {};
    event.count = 10;
    event["rule.name"] = 'rule_name';
    event["event.module"] = 'event_module';
    event["event.severity_label"] = 'event_severity_label';
    event["rule.uuid"] = 'rule_uuid';
  
    expected = {
      path: "",
      query: {
        el: 100,
        filterField: "rule.name",
        filterMode: "DRILLDOWN",
        filterValue: "rule_name",
        gl: 10,
        q: "",
        rt: 24,
        rtu: "hours",
        z: ""
      }
    };
  
    comp.countDrilldown(event);
    expect(comp.$router.push).toHaveBeenCalledTimes(1);
    expect(comp.filterRouteDrilldown).toEqual(expected);
  
    comp.$router.push.mockClear();
    comp.filterRouteDrilldown = null;
  
    event.a = 10;
  
    comp.countDrilldown(event);
    expect(comp.$router.push).toHaveBeenCalledTimes(0);
    expect(comp.filterRouteDrilldown).toBe(null);
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
});