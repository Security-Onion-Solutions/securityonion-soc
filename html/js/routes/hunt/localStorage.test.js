// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import localStorageMethods from './localStorage.js';

describe('localStorage', () => {
  let mockThis;

  beforeEach(() => {
    // Mock the component's context (`this`)
    mockThis = {
      category: 'testCategory',
      zone: '',
      autohunt: false,
      advanced: false,
      relativeTimeValue: 24,
      relativeTimeUnit: 'hours',
      sortBy: 'timestamp',
      sortDesc: true,
      itemsPerPage: 50,
      eventLimit: 100,
      groupBySortBy: 'count',
      groupBySortDesc: true,
      groupByItemsPerPage: 10,
      groupByLimit: 10,
      mruQueries: [],
      queryTableFields: [],
      showDetailsPanel: true,
      aiInvestigations: {},
    };
    // Clear localStorage before each test
    localStorage.clear();
  });

  test('saveSetting', () => {
    localStorageMethods.saveSetting.call(mockThis, 'timezone', 'America/New_York');
    const settings = JSON.parse(localStorage['testCategorySettings']);
    expect(settings.timezone).toBe('America/New_York');
  });

  test('saveTimezone', () => {
    mockThis.zone = 'Foo/Bar';
    localStorageMethods.saveTimezone.call(mockThis);
    const settings = JSON.parse(localStorage['testCategorySettings']);
    expect(settings.timezone).toBe('Foo/Bar');
  });

  test('saveLocalSettings and loadLocalSettings', () => {
    // Modify some settings to test
    mockThis.autohunt = true;
    mockThis.itemsPerPage = 100;
    mockThis.zone = 'UTC';

    // Save the settings
    localStorageMethods.saveLocalSettings.call(mockThis);

    // Create a new context to load into
    const newContext = {
      category: 'testCategory',
      zone: '',
      autohunt: false,
      itemsPerPage: 50,
    };

    // Load the settings
    localStorageMethods.loadLocalSettings.call(newContext);

    // Check if the settings were loaded correctly
    expect(newContext.autohunt).toBe(true);
    expect(newContext.itemsPerPage).toBe(100);
    expect(newContext.zone).toBe('UTC');
  });

  test('loadLocalSettings with no saved settings', () => {
    const newContext = {
      category: 'testCategory',
      zone: 'Default/Zone',
      autohunt: false,
    };
    const originalContext = { ...newContext };

    localStorageMethods.loadLocalSettings.call(newContext);

    expect(newContext).toEqual(originalContext);
  });

  test('saveAIInvestigations and loadAIInvestigations', () => {
    const investigations = { 'investigation1': { status: 'complete' } };
    mockThis.aiInvestigations = investigations;

    localStorageMethods.saveAIInvestigations.call(mockThis);

    const newContext = {
      aiInvestigations: {},
    };

    localStorageMethods.loadAIInvestigations.call(newContext);

    expect(newContext.aiInvestigations).toEqual(investigations);
  });

  test('loadAIInvestigations with no saved investigations', () => {
    const newContext = {
      aiInvestigations: {},
    };
    const originalContext = { ...newContext };

    localStorageMethods.loadAIInvestigations.call(newContext);

    expect(newContext).toEqual(originalContext);
  });

  test('loadAIInvestigations with corrupted data', () => {
    localStorage['aiInvestigations'] = 'not a valid json';
    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const newContext = {
      aiInvestigations: { some: 'data' },
    };

    localStorageMethods.loadAIInvestigations.call(newContext);

    expect(newContext.aiInvestigations).toEqual({});
    expect(consoleErrorSpy).toHaveBeenCalled();

    consoleErrorSpy.mockRestore();
  });
});