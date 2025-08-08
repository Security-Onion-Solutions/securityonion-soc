// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./hunt-bundled.js');

let comp;

beforeEach(() => {
  comp = getComponent("hunt");
  resetPapi();
  comp.$root.initializeCharts = () => { };
  comp.created();
});

describe('Hunt Component Integration', () => {
  test('initializes correctly', () => {
    expect(comp).toBeDefined();
    expect(comp.query).toBeDefined();
    expect(comp.eventData).toBeDefined();
    expect(comp.groupBys).toBeDefined();
  });

  test('has query methods integrated', () => {
    // Test that query methods are available
    expect(comp.getQuery).toBeDefined();
    expect(comp.applyQuerySubstitutions).toBeDefined();
    expect(comp.submitQuery).toBeDefined();
    expect(comp.obtainQueryDetails).toBeDefined();
  });

  test('has routing methods integrated', () => {
    // Test that routing methods are available
    expect(comp.buildCurrentRoute).toBeDefined();
    expect(comp.buildFilterRoute).toBeDefined();
    expect(comp.parseUrlParameters).toBeDefined();
  });

  test('has dataHandler methods integrated', () => {
    // Test that dataHandler methods are available
    expect(comp.loadData).toBeDefined();
    expect(comp.populateEventTable).toBeDefined();
    expect(comp.populateGroupByTable).toBeDefined();
  });

  test('has action methods integrated', () => {
    // Test that action methods are available
    expect(comp.ack).toBeDefined();
    expect(comp.performAction).toBeDefined();
    expect(comp.buildCase).toBeDefined();
    expect(comp.bulkAction).toBeDefined();
  });

  test('has chart methods integrated', () => {
    // Test that chart methods are available
    expect(comp.setupCharts).toBeDefined();
    expect(comp.setupBarChart).toBeDefined();
    expect(comp.setupPieChart).toBeDefined();
  });

  test('can perform a basic query operation', () => {
    // Mock necessary properties
    comp.query = 'test query';
    comp.queryBaseFilter = '';
    comp.filterToggles = [];
    comp.$root.papi = {
      get: jest.fn().mockResolvedValue({ data: {} })
    };

    // Test getQuery method
    return comp.getQuery().then(result => {
      expect(result).toBe('test query');
    });
  });
});
