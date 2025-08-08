// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

describe('Hunt Component Integration', () => {
  test('initializes correctly', () => {
    expect(comp).toBeDefined();
    expect(comp.query).toBeDefined();
    expect(comp.results).toBeDefined();
  });

  test('imports and uses query module', () => {
    // Mock the query module's functions and verify they are called
    comp.queryModule.buildQuery = jest.fn().mockReturnValue('test query');
    comp.search();
    expect(comp.queryModule.buildQuery).toHaveBeenCalled();
    expect(comp.query).toBe('test query');
  });

  test('imports and uses routing module', () => {
    // Mock the routing module's functions and verify they are called
    comp.routingModule.updateUrl = jest.fn();
    comp.search();
    expect(comp.routingModule.updateUrl).toHaveBeenCalled();
  });

  test('imports and uses dataHandlers module', () => {
    // Mock the dataHandlers module's functions and verify they are called
    const mockResults = { events: [{'_id': '1', '_source': {}}]};
    comp.dataHandlersModule.processResults = jest.fn().mockReturnValue(mockResults);
    comp.handleResponse({data: {}});
    expect(comp.dataHandlersModule.processResults).toHaveBeenCalled();
    expect(comp.results).toEqual(mockResults);
  });

  test('imports and uses actions module', () => {
    // Mock the actions module's functions and verify they are called
    comp.actionsModule.performAction = jest.fn();
    comp.performAction(null, {id: 'testAction'});
    expect(comp.actionsModule.performAction).toHaveBeenCalledWith(expect.anything(), {id: 'testAction'});
  });

  test('imports and uses charts module', () => {
    // Mock the charts module's functions and verify they are called
    comp.chartsModule.initializeCharts = jest.fn();
    comp.initializeCharts();
    expect(comp.chartsModule.initializeCharts).toHaveBeenCalled();
  });

  test('modules work together on search', () => {
    const mockQuery = 'test query';
    const mockResults = { events: [{'_id': '1', '_source': {}}]};

    comp.queryModule.buildQuery = jest.fn().mockReturnValue(mockQuery);
    comp.routingModule.updateUrl = jest.fn();
    comp.dataHandlersModule.processResults = jest.fn().mockReturnValue(mockResults);
    getPromise.mockResolvedValue({ data: {} });

    comp.search();

    expect(comp.queryModule.buildQuery).toHaveBeenCalled();
    expect(comp.routingModule.updateUrl).toHaveBeenCalled();

    // Need to wait for the promise from search to resolve
    return Promise.resolve().then(() => {
        expect(comp.dataHandlersModule.processResults).toHaveBeenCalled();
        expect(comp.results).toEqual(mockResults);
    });
  });
});
