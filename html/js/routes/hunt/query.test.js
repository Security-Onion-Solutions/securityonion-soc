// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import queryMethods from './query.js';

let comp;

beforeEach(() => {
  comp = {
    ...queryMethods,
    $root: {
      user: { id: '123' },
      papi: {
        get: jest.fn(),
      },
    },
    query: '',
    queryBaseFilter: '',
    filterToggles: [],
    queryName: '',
    querySearch: '',
    queryRemainder: '',
    queryFilters: [],
    queryGroupBys: [],
    queryGroupByOptions: [],
    querySortBys: [],
    queryTableFields: [],
    isAdvanced: () => comp.advanced,
    advanced: false,
    showFullQuery: false,
    notifyInputsChanged: jest.fn(),
    hunt: jest.fn(),
    detectionEngineStatusQueries: {},
  };
});

test('applyQuerySubstitutions', () => {
  const queries = [{ query: 'foo'}, { query: 'bar:{myId}' }];
  const newQueries = comp.applyQuerySubstitutions(queries);
  expect(newQueries).toBe(queries);
  expect(newQueries[0].query).toBe('foo');
  expect(newQueries[1].query).toBe('bar:123');
});

test('getQuery', async () => {
  comp.query = "a:1 OR b:2";
  comp.queryBaseFilter = "c:3";
  comp.filterToggles = [{ enabled: true, filter: "e:4" }, { enabled: false, filter: "f:5", exclusive: true }];
  comp.$root.papi.get.mockResolvedValue({data:'(a:1 OR b:2) AND c:3 AND e:4 AND NOT f:5'});

  const newQuery = await comp.getQuery();
  const params = { params: { query: 'a:1 OR b:2', field: '', value: 'c:3 AND e:4 AND NOT f:5', scalar: true, mode: 'INCLUDE', condense: true } };
  expect(comp.$root.papi.get).toHaveBeenCalledWith('query/filtered', params);
  expect(newQuery).toBe("(a:1 OR b:2) AND c:3 AND e:4 AND NOT f:5");
});

test('isComplexQuery', () => {
  expect(comp.isComplexQuery('')).toBe(false);
  expect(comp.isComplexQuery('*')).toBe(false);
  expect(comp.isComplexQuery('foo:bar')).toBe(false);
  expect(comp.isComplexQuery('foo:"bar"')).toBe(false);
  expect(comp.isComplexQuery('foo:"bar \\"car\\""')).toBe(false);
  expect(comp.isComplexQuery('foo:bar AND cat:dog')).toBe(false);
  expect(comp.isComplexQuery('foo:bar AND qry:"(cat:dog OR fish:bowl)"')).toBe(false);
  expect(comp.isComplexQuery('foo:bar AND qry:"this is a \\"test\\" (cat:dog OR fish:bowl)"')).toBe(false);
  expect(comp.isComplexQuery('foo:bar AND (cat:dog OR fish:bowl)')).toBe(true);
  expect(comp.isComplexQuery('foo:bar AND cat:(dog OR fish)')).toBe(true);
  expect(comp.isComplexQuery('foo:bar AND ((cat:(dog OR fish) OR some:thing))')).toBe(true);
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
  comp.$root.getDetectionEngineStatus = (engine) => {
    const statuses = {
      elastalert: 'IntegrityFailure',
      suricata: 'Healthy',
      strelka: 'Syncing',
    };
    return statuses[engine];
  }

  // miss, fallback to default
  let query = comp.buildDetectionEngineHuntQuery('elastalert');
  expect(query).toBe('IntegrityFailure');

  // hit
  query = comp.buildDetectionEngineHuntQuery('suricata');
  expect(query).toBe('Healthy');

  // miss, no default specified, fallback to simple query
  query = comp.buildDetectionEngineHuntQuery('strelka');
  expect(query).toBe(`tags:so-soc AND strelka | groupby log.level | groupby event.action | groupby soc.fields.error`);
});

test('reconstructQuery', () => {
    comp.querySearch = "foo: 1";
    comp.queryRemainder = "| groupby x";

    // Advanced mode and showFullQuery false so should reconstruct query using new custom filter
    comp.advanced = true;
    comp.showFullQuery = false;
    comp.reconstructQuery();
    expect(comp.query).toBe("foo: 1 | groupby x");
});

test('queryModified', () => {
    comp.querySearch = "foo: 1";
    comp.queryRemainder = "| groupby x";

    // Basic mode, should not reconstruct query
    comp.queryModified();
    expect(comp.query).toBe("");

    // Advanced mode, but showFullQuery is true so should not reconstruct query
    comp.advanced = true;
    comp.showFullQuery = true;
    comp.queryModified();
    expect(comp.query).toBe("");

    // Advanced mode and showFullQuery false so should reconstruct query using new custom filter
    comp.advanced = true;
    comp.showFullQuery = false;
    comp.queryModified();
    expect(comp.query).toBe("foo: 1 | groupby x");
});