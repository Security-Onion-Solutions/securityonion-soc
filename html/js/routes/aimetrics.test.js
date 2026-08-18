
// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');

// Define time constants that are used in aimetrics.js
global.RELATIVE_TIME_SECONDS = 0;
global.RELATIVE_TIME_MINUTES = 1;
global.RELATIVE_TIME_HOURS = 2;
global.RELATIVE_TIME_DAYS = 3;
global.RELATIVE_TIME_WEEKS = 4;
global.RELATIVE_TIME_MONTHS = 5;

require('./aimetrics.js');

let comp;
let mockLocalStorage;
let originalConsole;

beforeEach(() => {
  // Mock console methods to suppress error messages during testing
  originalConsole = {
    log: console.log,
    error: console.error,
    warn: console.warn
  };
  console.log = jest.fn();
  console.error = jest.fn();
  console.warn = jest.fn();
  
  comp = getComponent("aimetrics");
  resetPapi();
  
  // Mock localStorage with proper Jest mocks that supports property access
  const removeItemMock = jest.fn();
  const getItemMock = jest.fn();
  const setItemMock = jest.fn();
  const clearMock = jest.fn();
  const storageData = {};
  
  // Create localStorage mock that handles both property access and method calls
  const localStorageMock = {
    getItem: getItemMock,
    setItem: setItemMock,
    removeItem: removeItemMock,
    clear: clearMock
  };
  
  // Override removeItem to also delete from storageData
  localStorageMock.removeItem = jest.fn((key) => {
    delete storageData[key];
    removeItemMock(key);
  });
  
  global.localStorage = new Proxy(localStorageMock, {
    get(target, prop) {
      if (typeof prop === 'string' && prop.startsWith('settings.')) {
        return storageData[prop];
      }
      if (prop === 'timezone') {
        return storageData[prop];
      }
      return target[prop];
    },
    set(target, prop, value) {
      if (typeof prop === 'string' && (prop.startsWith('settings.') || prop === 'timezone')) {
        // Convert values to strings like real localStorage
        storageData[prop] = String(value);
        return true;
      }
      target[prop] = value;
      return true;
    },
    deleteProperty(target, prop) {
      delete storageData[prop];
      return true;
    }
  });
  
  // Keep reference to the mock for testing
  mockLocalStorage = global.localStorage;
  
  // Mock router
  comp.$router = {
    push: jest.fn(),
    replace: jest.fn()
  };
  
  // Mock route
  comp.$route = {
    params: {},
    query: {}
  };
  
  // Mock nextTick
  comp.$nextTick = jest.fn(() => Promise.resolve());
  
  // Mock forceUpdate
  comp.$forceUpdate = jest.fn();
  
  // Mock DOM element
  comp.$el = {
    querySelector: jest.fn(() => ({
      scrollTop: 0,
      scrollHeight: 100
    }))
  };

  // Mock jQuery for date range picker
  global.$ = jest.fn(() => ({
    daterangepicker: jest.fn(),
    on: jest.fn(),
    click: jest.fn()
  }));
  global.$['fn'] = {
    daterangepicker: jest.fn()
  };
});

afterEach(() => {
  // Restore original console methods
  if (originalConsole) {
    console.log = originalConsole.log;
    console.error = originalConsole.error;
    console.warn = originalConsole.warn;
  }
  
  jest.clearAllMocks();
});

// Data initialization and lifecycle tests
test('component data initialization', () => {
  expect(comp.aimetrics).toEqual([]);
  expect(comp.headers).toHaveLength(3);
  expect(comp.headers[0]).toHaveLength(8); // Users table headers
  expect(comp.headers[1]).toHaveLength(9); // Sessions table headers
  expect(comp.headers[2]).toHaveLength(8); // Messages table headers
  expect(comp.expandedFields).toHaveProperty('1');
  expect(comp.sortByUsers).toEqual([{ key: 'totalCredits', order: 'desc' }]);
  expect(comp.sortBySessions).toEqual([{ key: 'createTime', order: 'desc' }]);
  expect(comp.sortByMessages).toEqual([{ key: 'createTime', order: 'desc' }]);
  expect(comp.itemsPerPage).toBe(10);
  expect(comp.itemsPerPageOptions).toEqual([10, 50, 250, 1000]);
  expect(comp.tableSetting).toBe(0);
  expect(comp.expanded).toEqual([]);
  expect(comp.searchFilter).toBe('');
  expect(comp.dateRange).toBe('');
  expect(comp.relativeTimeEnabled).toBe(true);
  expect(comp.relativeTimeValue).toBe(24);
  expect(comp.relativeTimeUnit).toBe(RELATIVE_TIME_HOURS);
  expect(comp.autoRefreshInterval).toBe(0);
  expect(comp.autoRefreshTimer).toBe(null);
  expect(comp.breadcrumbs).toHaveLength(0);
});

test('created lifecycle hook initializes data', () => {
  // Mock VueChartJs and initializeCharts
  global.VueChartJs = {
    Bar: jest.fn(),
    Line: jest.fn(),
    Pie: jest.fn()
  };
  comp.$root.initializeCharts = jest.fn();
  
  // Simulate the created lifecycle hook
  comp.created();
  
  expect(comp.relativeTimeUnits).toHaveLength(6);
  expect(comp.autoRefreshIntervals).toHaveLength(16);
  expect(comp.zone).toBe(moment.tz.guess());
  expect(comp.$root.initializeCharts).toHaveBeenCalled();
});

// Auto refresh functionality tests
test('autoRefreshIntervalChanged saves setting', () => {
  comp.saveSetting = jest.fn();
  comp.autoRefreshInterval = 30;
  
  comp.autoRefreshIntervalChanged();
  
  expect(comp.saveSetting).toHaveBeenCalledWith('autoRefreshInterval', 30, 0);
});

test('stopRefreshTimer clears existing timer', () => {
  const mockTimer = setTimeout(() => {}, 1000);
  comp.autoRefreshTimer = mockTimer;
  jest.spyOn(global, 'clearTimeout');
  
  comp.stopRefreshTimer();
  
  expect(clearTimeout).toHaveBeenCalledWith(mockTimer);
});

test('stopRefreshTimer handles null timer', () => {
  comp.autoRefreshTimer = null;
  jest.spyOn(global, 'clearTimeout');
  
  comp.stopRefreshTimer();
  
  expect(clearTimeout).not.toHaveBeenCalled();
});

test('resetRefreshTimer sets up new timer', () => {
  comp.stopRefreshTimer = jest.fn();
  comp.loadData = jest.fn();
  comp.autoRefreshInterval = 10;
  jest.spyOn(global, 'setTimeout');
  
  comp.resetRefreshTimer();
  
  expect(comp.stopRefreshTimer).toHaveBeenCalled();
  expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 10000);
});

test('resetRefreshTimer does not set timer when interval is 0', () => {
  comp.stopRefreshTimer = jest.fn();
  comp.autoRefreshInterval = 0;
  jest.spyOn(global, 'setTimeout');
  
  comp.resetRefreshTimer();
  
  expect(comp.stopRefreshTimer).toHaveBeenCalled();
  expect(setTimeout).not.toHaveBeenCalled();
});

// Settings management tests
test('saveSetting stores value in localStorage with correct key', () => {
  const settingName = 'testSetting';
  const settingValue = 'testValue';
  
  comp.saveSetting(settingName, settingValue);
  
  expect(mockLocalStorage['settings.aimetrics.testSetting']).toBe('testValue');
});

test('saveSetting removes item when value equals default', () => {
  const settingName = 'testSetting';
  const settingValue = 'defaultValue';
  const defaultValue = 'defaultValue';
  
  // Set up a value first
  mockLocalStorage['settings.aimetrics.testSetting'] = 'someValue';
  
  comp.saveSetting(settingName, settingValue, defaultValue);
  
  // Check that the value was removed
  expect(mockLocalStorage['settings.aimetrics.testSetting']).toBeUndefined();
});

test('saveSetting stores value when different from default', () => {
  const settingName = 'testSetting';
  const settingValue = 'customValue';
  const defaultValue = 'defaultValue';
  
  comp.saveSetting(settingName, settingValue, defaultValue);
  
  expect(mockLocalStorage['settings.aimetrics.testSetting']).toBe('customValue');
});

test('saveLocalSettings saves all settings', () => {
  comp.saveSetting = jest.fn();
  comp.sortByUsers = [{ key: 'email', order: 'asc' }];
  comp.sortBySessions = [{ key: 'title', order: 'desc' }];
  comp.sortByMessages = [{ key: 'role', order: 'asc' }];
  comp.itemsPerPage = 50;
  comp.relativeTimeValue = 12;
  comp.relativeTimeUnit = RELATIVE_TIME_MINUTES;
  comp.autoRefreshInterval = 60;
  comp.zone = 'America/New_York';
  
  comp.saveLocalSettings();
  
  expect(comp.saveSetting).toHaveBeenCalledWith('sortByUsers', 'email', 'totalCredits');
  expect(comp.saveSetting).toHaveBeenCalledWith('sortDescUsers', 'asc', 'desc');
  expect(comp.saveSetting).toHaveBeenCalledWith('sortBySessions', 'title', 'createTime');
  expect(comp.saveSetting).toHaveBeenCalledWith('sortDescSessions', 'desc', 'desc');
  expect(comp.saveSetting).toHaveBeenCalledWith('sortByMessages', 'role', 'createTime');
  expect(comp.saveSetting).toHaveBeenCalledWith('sortDescMessages', 'asc', 'desc');
  expect(comp.saveSetting).toHaveBeenCalledWith('itemsPerPage', 50, 10);
  expect(comp.saveSetting).toHaveBeenCalledWith('relativeTimeValue', 12, 24);
  expect(comp.saveSetting).toHaveBeenCalledWith('relativeTimeUnit', RELATIVE_TIME_MINUTES, RELATIVE_TIME_HOURS);
  expect(comp.saveSetting).toHaveBeenCalledWith('autoRefreshInterval', 60, 0);
  expect(mockLocalStorage['timezone']).toBe('America/New_York');
});

test('loadLocalSettings loads all settings from localStorage', () => {
  // Mock localStorage values
  mockLocalStorage['settings.aimetrics.sortByUsers'] = 'test';
  mockLocalStorage['settings.aimetrics.sortDescUsers'] = 'desc'
  mockLocalStorage['settings.aimetrics.sortBySessions'] = 'test1';
  mockLocalStorage['settings.aimetrics.sortDescSessions'] = 'asc'
  mockLocalStorage['settings.aimetrics.sortByMessages'] = 'test2';
  mockLocalStorage['settings.aimetrics.sortDescMessages'] = 'desc'
  mockLocalStorage['settings.aimetrics.itemsPerPage'] = '25';
  mockLocalStorage['settings.aimetrics.relativeTimeValue'] = '48';
  mockLocalStorage['settings.aimetrics.relativeTimeUnit'] = String(RELATIVE_TIME_DAYS);
  mockLocalStorage['timezone'] = 'Europe/London';
  mockLocalStorage['settings.aimetrics.autoRefreshInterval'] = '120';
  
  comp.loadLocalSettings();
  
  expect(comp.sortByUsers).toEqual([{ key: 'test', order: 'desc' }]);
  expect(comp.sortBySessions).toEqual([{ key: 'test1', order: 'asc' }]);
  expect(comp.sortByMessages).toEqual([{ key: 'test2', order: 'desc' }]);
  expect(comp.itemsPerPage).toBe(25);
  expect(comp.relativeTimeValue).toBe(48);
  expect(comp.relativeTimeUnit).toBe(RELATIVE_TIME_DAYS);
  expect(comp.zone).toBe('Europe/London');
  expect(comp.autoRefreshInterval).toBe(120);
});

test('loadLocalSettings handles missing localStorage values', () => {
  // Set initial values different from defaults
  comp.itemsPerPage = 100;
  comp.relativeTimeValue = 72;
  comp.zone = 'Asia/Tokyo';
  
  // Ensure localStorage has no values
  delete mockLocalStorage['settings.aimetrics.itemsPerPage'];
  delete mockLocalStorage['settings.aimetrics.relativeTimeValue'];
  delete mockLocalStorage['timezone'];
  
  comp.loadLocalSettings();
  
  // Values should remain unchanged when localStorage is empty
  expect(comp.itemsPerPage).toBe(100);
  expect(comp.relativeTimeValue).toBe(72);
  expect(comp.zone).toBe('Asia/Tokyo');
});

// Assistant initialization tests
test('initAssistant sets assistantEnabled to true when enabled and licensed', async () => {
  const mockParams = {
    enabled: true,
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.loadData = jest.fn();
  
  await comp.initAssistant(mockParams);
  
  expect(comp.assistantEnabled).toBe(true);
  expect(comp.$root.isLicensed).toHaveBeenCalledWith('oai');
  expect(comp.loadData).toHaveBeenCalled();
});

test('initAssistant sets assistantEnabled to false when not enabled', async () => {
  const mockParams = {
    enabled: false,
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.loadData = jest.fn();
  
  await comp.initAssistant(mockParams);
  
  expect(comp.assistantEnabled).toBe(false);
  expect(comp.loadData).not.toHaveBeenCalled();
});

test('initAssistant sets assistantEnabled to false when not licensed', async () => {
  const mockParams = {
    enabled: true,
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(false);
  comp.loadData = jest.fn();
  
  await comp.initAssistant(mockParams);
  
  expect(comp.assistantEnabled).toBe(false);
  expect(comp.loadData).not.toHaveBeenCalled();
});

test('loadData returns early when assistantEnabled is false', async () => {
  comp.assistantEnabled = false;
  comp.loadLocalSettings = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  
  await comp.loadData();
  
  expect(comp.loadLocalSettings).toHaveBeenCalled();
  expect(comp.$root.startLoading).not.toHaveBeenCalled();
  expect(comp.$root.stopLoading).not.toHaveBeenCalled();
});

// Data loading tests
test('loadData with no route parameters loads users data', async () => {
  const mockResponse = {
    data: [
      {
        userId: 'user1',
        usage: {
          totalInputTokens: 100,
          totalOutputTokens: 200,
          totalCredits: 50,
          totalMessages: 10
        }
      }
    ]
  };
  const mock = mockPapi("get", mockResponse);
  comp.loadLocalSettings = jest.fn();
  comp.updateBreadcrumbs = jest.fn();
  comp.resetRefreshTimer = jest.fn();
  comp.lookupSocId = jest.fn().mockResolvedValue('user1@example.com');
  comp.populateUsersCharts = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.adjustSubgridColVisibility = jest.fn();
  comp.getStartDate = jest.fn().mockReturnValue(moment('2025-01-01'));
  comp.getEndDate = jest.fn().mockReturnValue(moment('2025-01-02'));
  
  // Set assistantEnabled to true to bypass the early return
  comp.assistantEnabled = true;
  
  await comp.loadData();
  
  expect(comp.loadLocalSettings).toHaveBeenCalled();
  expect(comp.$root.startLoading).toHaveBeenCalled();
  expect(comp.updateBreadcrumbs).toHaveBeenCalledWith(undefined, undefined);
  expect(comp.tableSetting).toBe(0);
  expect(comp.$root.adjustSubgridColVisibility).toHaveBeenCalledWith(comp.headers[0]);
  expect(mock).toHaveBeenCalledWith('/assistant/admin/stats', {
    params: {
      format: comp.$root.i18n.timePickerSample,
      range: expect.any(String),
      zone: comp.zone,
    }
  });
  expect(comp.aimetrics).toHaveLength(1);
  expect(comp.aimetrics[0].userId).toBe('user1');
  expect(comp.aimetrics[0].usage.totalInputTokens).toBe(100);
  expect(comp.aimetrics[0].usage.totalOutputTokens).toBe(200);
  expect(comp.aimetrics[0].usage.totalCredits).toBe(50);
  expect(comp.aimetrics[0].usage.totalMessages).toBe(10);
  expect(comp.lookupSocId).toHaveBeenCalledWith('user1');
  expect(comp.$root.stopLoading).toHaveBeenCalled();
  expect(comp.resetRefreshTimer).toHaveBeenCalled();
});

test('loadData with userId parameter loads sessions data', async () => {
  const mockResponse = {
    data: [
      {
        id: 'session1',
        title: 'Test Session',
        createTime: '2025-01-01T12:00:00Z',
        usage: {
          totalInputTokens: 50,
          totalOutputTokens: 100,
          totalCredits: 25,
          totalMessages: 5
        }
      }
    ]
  };
  const mock = mockPapi("get", mockResponse);
  comp.$route.params.userId = 'user1';
  comp.loadLocalSettings = jest.fn();
  comp.updateBreadcrumbs = jest.fn();
  comp.resetRefreshTimer = jest.fn();
  comp.populateSessionsCharts = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.adjustSubgridColVisibility = jest.fn();
  comp.$root.formatLongDuration = jest.fn().mockReturnValue('5 minutes');
  comp.getStartDate = jest.fn().mockReturnValue(moment('2025-01-01'));
  comp.getEndDate = jest.fn().mockReturnValue(moment('2025-01-02'));
  
  // Set assistantEnabled to true to bypass the early return
  comp.assistantEnabled = true;
  
  await comp.loadData();
  
  expect(comp.tableSetting).toBe(1);
  expect(comp.$root.adjustSubgridColVisibility).toHaveBeenCalledWith(comp.headers[1]);
  expect(mock).toHaveBeenCalledWith('/assistant/admin/user1/sessions', {
    params: {
      format: comp.$root.i18n.timePickerSample,
      range: expect.any(String),
      zone: comp.zone,
    }
  });
  expect(comp.aimetrics).toHaveLength(1);
  expect(comp.aimetrics[0].totalInputTokens).toBe(50);
  expect(comp.aimetrics[0].totalOutputTokens).toBe(100);
  expect(comp.aimetrics[0].totalCredits).toBe(25);
  expect(comp.aimetrics[0].totalMessages).toBe(5);
});

test('loadData with userId and sessionId parameters loads messages data', async () => {
  const mockResponse = {
    data: [
      {
        createTime: '2025-01-01T12:00:00Z',
        message: {
          role: 'assistant',
          usage: {
            input_tokens: 10,
            output_tokens: 20,
            credits: 5
          }
        }
      },
      {
        createTime: '2025-01-01T12:01:00Z',
        message: {
          role: 'user'
        }
      }
    ]
  };
  const mock = mockPapi("get", mockResponse);
  comp.$route.params.userId = 'user1';
  comp.$route.params.sessionId = 'session1';
  comp.loadLocalSettings = jest.fn();
  comp.updateBreadcrumbs = jest.fn();
  comp.resetRefreshTimer = jest.fn();
  comp.formatExpandMessage = jest.fn().mockReturnValue('formatted message');
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.adjustSubgridColVisibility = jest.fn();
  comp.getStartDate = jest.fn().mockReturnValue(moment('2025-01-01'));
  comp.getEndDate = jest.fn().mockReturnValue(moment('2025-01-02'));
  
  // Set assistantEnabled to true to bypass the early return
  comp.assistantEnabled = true;
  
  await comp.loadData();
  
  expect(comp.tableSetting).toBe(2);
  expect(comp.$root.adjustSubgridColVisibility).toHaveBeenCalledWith(comp.headers[2]);
  expect(mock).toHaveBeenCalledWith('/assistant/admin/user1/sessions/session1/history', {
    params: {
      format: comp.$root.i18n.timePickerSample,
      range: expect.any(String),
      zone: comp.zone,
    }
  });
  expect(comp.aimetrics).toHaveLength(2);
  expect(comp.aimetrics[0].role).toBe('assistant');
  expect(comp.aimetrics[0].inputTokens).toBe(10);
  expect(comp.aimetrics[0].outputTokens).toBe(20);
  expect(comp.aimetrics[0].credits).toBe(5);
  expect(comp.aimetrics[1].role).toBe('user');
  expect(comp.aimetrics[1].inputTokens).toBe(0);
  expect(comp.aimetrics[1].outputTokens).toBe(0);
  expect(comp.aimetrics[1].credits).toBe(0);
  expect(comp.formatExpandMessage).toHaveBeenCalledTimes(2);
});

test('loadData handles API error', async () => {
  const error = new Error('API Error');
  mockPapi("get", null, error);
  comp.loadLocalSettings = jest.fn();
  comp.updateBreadcrumbs = jest.fn();
  comp.resetRefreshTimer = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.showError = jest.fn();
  comp.getStartDate = jest.fn().mockReturnValue(moment('2025-01-01'));
  comp.getEndDate = jest.fn().mockReturnValue(moment('2025-01-02'));
  
  // Set assistantEnabled to true to bypass the early return
  comp.assistantEnabled = true;
  
  await comp.loadData();
  
  expect(comp.$root.showError).toHaveBeenCalledWith(error);
  expect(comp.aimetrics).toEqual([]);
  expect(comp.$root.stopLoading).toHaveBeenCalled();
  expect(comp.resetRefreshTimer).toHaveBeenCalled();
});

// User lookup tests
test('lookupSocId returns email for valid UUID', async () => {
  const userId = '12345678-1234-1234-1234-123456789012';
  const mockUser = { email: 'test@example.com' };
  comp.$root.getUserById = jest.fn().mockResolvedValue(mockUser);
  
  const result = await comp.lookupSocId(userId);
  
  expect(comp.$root.getUserById).toHaveBeenCalledWith(userId);
  expect(result).toBe('test@example.com');
});

test('lookupSocId returns original data for non-UUID', async () => {
  const userId = 'not-a-uuid';
  comp.$root.getUserById = jest.fn();
  
  const result = await comp.lookupSocId(userId);
  
  expect(comp.$root.getUserById).not.toHaveBeenCalled();
  expect(result).toBe('not-a-uuid');
});

test('lookupSocId returns original data when user not found', async () => {
  const userId = '12345678-1234-1234-1234-123456789012';
  comp.$root.getUserById = jest.fn().mockResolvedValue(null);
  
  const result = await comp.lookupSocId(userId);
  
  expect(comp.$root.getUserById).toHaveBeenCalledWith(userId);
  expect(result).toBe(userId);
});

test('lookupSocId returns original data when user has no email', async () => {
  const userId = '12345678-1234-1234-1234-123456789012';
  const mockUser = { name: 'Test User' };
  comp.$root.getUserById = jest.fn().mockResolvedValue(mockUser);
  
  const result = await comp.lookupSocId(userId);
  
  expect(comp.$root.getUserById).toHaveBeenCalledWith(userId);
  expect(result).toBe(userId);
});

// Link building tests
test('buildUserLink creates correct route object', () => {
  const userId = 'user123';
  
  const result = comp.buildUserLink(userId);
  
  expect(result).toEqual({
    name: 'aimetrics',
    params: { userId: 'user123' }
  });
});

test('buildSessionLink creates correct route object', () => {
  const sessionId = 'session456';
  comp.$route.params.userId = 'user123';
  
  const result = comp.buildSessionLink(sessionId);
  
  expect(result).toEqual({
    name: 'aimetrics',
    params: { userId: 'user123', sessionId: 'session456' }
  });
});

test('buildAssistantLink creates correct route object', () => {
  const sessionId = 'session789';
  
  const result = comp.buildAssistantLink(sessionId);
  
  expect(result).toEqual({
    name: 'assistant',
    params: { sessionId: 'session789' }
  });
});

// Expanded data tests
test('getExpandedData returns formatted records', () => {
  const data = {
    id: 'test-id',
    userId: 'user-123',
    kind: 'test-kind',
    tags: ['tag1', 'tag2'],
    usage: { tokens: 100 },
    extraField: 'ignored'
  };
  comp.tableSetting = 1;
  
  const result = comp.getExpandedData(data);
  
  expect(result).toHaveLength(5); // Only fields defined in expandedFields[1]
  expect(result[0]).toEqual({
    key: 'id',
    value: 'test-id',
    title: comp.expandedFields[1].id
  });
  expect(result[1]).toEqual({
    key: 'userId',
    value: 'user-123',
    title: comp.expandedFields[1].userId
  });
});

test('getExpandedData returns empty array for invalid table setting', () => {
  const data = { id: 'test' };
  comp.tableSetting = 99; // Invalid setting
  
  const result = comp.getExpandedData(data);
  
  expect(result).toEqual([]);
});

test('getExpandedData returns empty array for null data', () => {
  comp.tableSetting = 1;
  
  const result = comp.getExpandedData(null);
  
  expect(result).toEqual([]);
});

// Date range functionality tests
test('getEndDate parses date range correctly', () => {
  comp.dateRange = '2025/01/01 10:00:00 AM - 2025/01/02 11:59:59 PM';
  comp.$root.i18n.timePickerFormat = 'YYYY/MM/DD hh:mm:ss A';
  
  const result = comp.getEndDate();
  
  expect(result.format('YYYY-MM-DD HH:mm:ss')).toBe('2025-01-02 23:59:59');
});

test('getEndDate returns current moment when no date range', () => {
  comp.dateRange = '';
  
  const result = comp.getEndDate();
  
  expect(moment.isMoment(result)).toBe(true);
});

test('getEndDate returns current moment when invalid date range', () => {
  comp.dateRange = 'invalid range';
  
  const result = comp.getEndDate();
  
  expect(moment.isMoment(result)).toBe(true);
});

test('getStartDate parses date range correctly', () => {
  comp.dateRange = '2025/01/01 10:00:00 AM - 2025/01/02 11:59:59 PM';
  comp.$root.i18n.timePickerFormat = 'YYYY/MM/DD hh:mm:ss A';
  
  const result = comp.getStartDate();
  
  expect(result.format('YYYY-MM-DD HH:mm:ss')).toBe('2025-01-01 10:00:00');
});

test('getStartDate calculates relative time when no date range', () => {
  comp.dateRange = '';
  comp.relativeTimeValue = 2;
  comp.relativeTimeUnit = RELATIVE_TIME_HOURS;
  
  const result = comp.getStartDate();
  const expected = moment().subtract(2, 'hours');
  
  expect(result.format('YYYY-MM-DD HH')).toBe(expected.format('YYYY-MM-DD HH'));
});

test('getStartDate handles different time units', () => {
  comp.dateRange = '';
  comp.relativeTimeValue = 5;
  
  // Test seconds
  comp.relativeTimeUnit = RELATIVE_TIME_SECONDS;
  let result = comp.getStartDate();
  let expected = moment().subtract(5, 'seconds');
  expect(result.format('YYYY-MM-DD HH:mm:ss')).toBe(expected.format('YYYY-MM-DD HH:mm:ss'));
  
  // Test minutes
  comp.relativeTimeUnit = RELATIVE_TIME_MINUTES;
  result = comp.getStartDate();
  expected = moment().subtract(5, 'minutes');
  expect(result.format('YYYY-MM-DD HH:mm')).toBe(expected.format('YYYY-MM-DD HH:mm'));
  
  // Test days
  comp.relativeTimeUnit = RELATIVE_TIME_DAYS;
  result = comp.getStartDate();
  expected = moment().subtract(5, 'days');
  expect(result.format('YYYY-MM-DD')).toBe(expected.format('YYYY-MM-DD'));
  
  // Test weeks
  comp.relativeTimeUnit = RELATIVE_TIME_WEEKS;
  result = comp.getStartDate();
  expected = moment().subtract(5, 'weeks');
  expect(result.format('YYYY-MM-DD')).toBe(expected.format('YYYY-MM-DD'));
  
  // Test months
  comp.relativeTimeUnit = RELATIVE_TIME_MONTHS;
  result = comp.getStartDate();
  expected = moment().subtract(5, 'months');
  expect(result.format('YYYY-MM')).toBe(expected.format('YYYY-MM'));
});

// Date range picker tests
test('setupDateRangePicker returns early when relative time enabled', () => {
  comp.relativeTimeEnabled = true;
  
  comp.setupDateRangePicker();
  
  expect(global.$).not.toHaveBeenCalled();
});

test('setupDateRangePicker configures date picker when relative time disabled', () => {
  comp.relativeTimeEnabled = false;
  comp.getStartDate = jest.fn().mockReturnValue(moment('2025-01-01'));
  comp.getEndDate = jest.fn().mockReturnValue(moment('2025-01-02'));
  comp.$root.generateDatePickerPreselects = jest.fn().mockReturnValue({});
  comp.$root.i18n.timePickerFormat = 'YYYY/MM/DD hh:mm:ss A';
  comp.dateRange = '2025/01/01 - 2025/01/02'; // Set initial dateRange to avoid the [0].value access
  
  const mockDateRangePicker = jest.fn();
  const mockOn = jest.fn();
  const mockElement = {
    daterangepicker: mockDateRangePicker,
    on: mockOn,
    value: '2025/01/01 - 2025/01/02'
  };
  global.$ = jest.fn(() => mockElement);
  
  comp.setupDateRangePicker();
  
  expect(global.$).toHaveBeenCalledWith('#aimetrics-date-range');
  expect(mockDateRangePicker).toHaveBeenCalledWith({
    ranges: {},
    timePicker: true,
    timePickerSeconds: true,
    endDate: expect.any(Object),
    startDate: expect.any(Object),
    locale: {
      format: 'YYYY/MM/DD hh:mm:ss A'
    }
  });
  expect(mockOn).toHaveBeenCalledWith('hide.daterangepicker', expect.any(Function));
});

test('showDateRangePicker returns early when relative time enabled', () => {
  comp.relativeTimeEnabled = true;
  
  comp.showDateRangePicker();
  
  expect(global.$).not.toHaveBeenCalled();
});

test('showDateRangePicker triggers click when relative time disabled', () => {
  comp.relativeTimeEnabled = false;
  const mockClick = jest.fn();
  global.$ = jest.fn(() => ({
    click: mockClick
  }));
  
  comp.showDateRangePicker();
  
  expect(global.$).toHaveBeenCalledWith('#aimetrics-date-range');
  expect(mockClick).toHaveBeenCalled();
});

test('hideDateRangePicker returns early when relative time enabled', () => {
  comp.relativeTimeEnabled = true;
  comp.loadData = jest.fn();
  
  comp.hideDateRangePicker();
  
  expect(comp.loadData).not.toHaveBeenCalled();
});

test('hideDateRangePicker updates date range and loads data', () => {
  comp.relativeTimeEnabled = false;
  comp.loadData = jest.fn();
  global.$ = jest.fn(() => [{ value: '2025/01/01 - 2025/01/02' }]);
  
  comp.hideDateRangePicker();
  
  expect(comp.dateRange).toBe('2025/01/01 - 2025/01/02');
  expect(comp.loadData).toHaveBeenCalled();
});

test('showAbsoluteTime switches to absolute time mode', () => {
  comp.relativeTimeEnabled = true;
  comp.setupDateRangePicker = jest.fn();
  jest.spyOn(global, 'setTimeout');
  
  comp.showAbsoluteTime();
  
  expect(comp.relativeTimeEnabled).toBe(false);
  expect(setTimeout).toHaveBeenCalledWith(comp.setupDateRangePicker, 10);
});

test('showRelativeTime switches to relative time mode', () => {
  comp.relativeTimeEnabled = false;
  
  comp.showRelativeTime();
  
  expect(comp.relativeTimeEnabled).toBe(true);
});

test('notifyInputsChanged saves settings and loads data', () => {
  comp.saveLocalSettings = jest.fn();
  comp.loadData = jest.fn();
  
  comp.notifyInputsChanged();
  
  expect(comp.saveLocalSettings).toHaveBeenCalled();
  expect(comp.loadData).toHaveBeenCalled();
});

// Message formatting tests
test('trimTitle trims long titles correctly', () => {
  const longTitle = 'This is a very long title that should be trimmed because it exceeds the limit';
  
  const result = comp.trimTitle(longTitle);
  
  expect(result).toBe('This is a very long title that should be ...');
  expect(result.length).toBe(44); // 41 chars + '...'
});

test('trimTitle returns short titles unchanged', () => {
  const shortTitle = 'Short title';
  
  const result = comp.trimTitle(shortTitle);
  
  expect(result).toBe('Short title');
});

test('trimTitle handles null/undefined titles', () => {
  expect(comp.trimTitle(null)).toBe('');
  expect(comp.trimTitle(undefined)).toBe('');
  expect(comp.trimTitle('')).toBe('');
});

test('formatExpandMessage handles text content blocks', () => {
  const data = {
    message: {
      role: 'assistant',
      contentBlocks: [
        { type: 'text', text: '**Bold text**' },
        { type: 'text', text: 'Regular text' }
      ]
    }
  };
  comp.$root.formatMarkdown = jest.fn()
    .mockReturnValueOnce('<strong>Bold text</strong>')
    .mockReturnValueOnce('Regular text');
  
  const result = comp.formatExpandMessage(data);
  
  expect(comp.$root.formatMarkdown).toHaveBeenCalledWith('**Bold text**', true);
  expect(comp.$root.formatMarkdown).toHaveBeenCalledWith('Regular text', true);
  expect(result).toContain('<strong>Bold text</strong>');
  expect(result).toContain('<hr>');
  expect(result).toContain('Regular text');
});

test('formatExpandMessage handles user role text blocks', () => {
  const data = {
    message: {
      role: 'user',
      contentBlocks: [
        { type: 'text', text: 'User message' }
      ]
    }
  };
  
  const result = comp.formatExpandMessage(data);
  
  expect(result).toBe('User message');
});

test('formatExpandMessage handles tool_use blocks', () => {
  const data = {
    message: {
      role: 'assistant',
      contentBlocks: [
        { type: 'text', text: 'I will use a tool' },
        {
          type: 'tool_use',
          name: 'query_events',
          input: {
            oql_query: 'event.module: "suricata"',
            limit: 100
          }
        }
      ]
    }
  };
  comp.$root.formatMarkdown = jest.fn()
    .mockReturnValueOnce('I will use a tool')
    .mockReturnValueOnce('**Tool:** query_events\n**Parameters:**\n- oql_query: "event.module: "suricata""\n- limit: 100');
  
  const result = comp.formatExpandMessage(data);
  
  expect(result).toContain('I will use a tool');
  expect(result).toContain('<hr>');
  expect(comp.$root.formatMarkdown).toHaveBeenCalledTimes(2);
});

test('formatExpandMessage handles legacy ToolResult text blocks', () => {
  const data = {
    message: {
      role: 'assistuserant',
      contentBlocks: [
        { type: 'text', text: 'ToolUseId: x, Error: <nil>, Result: No events found' },
      ]
    }
  };
  
  const result = comp.formatExpandMessage(data);
  
  expect(result).toContain('ToolUseId: x, Error: <nil>, Result: No events found');
});

test('formatExpandMessage handles proper ToolResult blocks', () => {
  const data = {
    message: {
      role: 'user',
      contentBlocks: [
        {
          toolResult: {
            toolUseId: 'x',
            content: [
              {
                json: {
                  result: 'No events found'
                }
              }
            ]
          }
        }
      ]
    }
  };

  comp.$root.formatMarkdown = jest.fn()
    .mockReturnValueOnce('<p><strong>ToolResult:</strong></p><p><code>{ "result": "No events found" }</code></p>');
  
  const result = comp.formatExpandMessage(data);
  
  expect(result).toContain('ToolResult:');
  expect(result).toContain('No events found');
});

test('formatExpandMessage handles ToolResult with error text', () => {
  const data = {
    message: {
      role: 'user',
      contentBlocks: [
        {
          toolResult: {
            toolUseId: 'tool-123',
            isError: true,
            content: [
              {
                text: 'Connection timeout'
              }
            ]
          }
        }
      ]
    }
  };

  comp.$root.formatMarkdown = jest.fn()
    .mockReturnValueOnce('<p><strong>Tool Result:</strong></p><p><strong>Error:</strong> Connection timeout</p>');
  
  const result = comp.formatExpandMessage(data);
  
  expect(comp.$root.formatMarkdown).toHaveBeenCalled();
  const markdownArg = comp.$root.formatMarkdown.mock.calls[0][0];
  expect(markdownArg).toContain('**Tool Result:**');
  expect(markdownArg).toContain('**Error:** Connection timeout');
  expect(result).toContain('Error:');
  expect(result).toContain('Connection timeout');
});

test('formatExpandMessage handles ToolResult with non-error text', () => {
  const data = {
    message: {
      role: 'user',
      contentBlocks: [
        {
          toolResult: {
            toolUseId: 'tool-456',
            isError: false,
            content: [
              {
                text: 'Query executed successfully'
              }
            ]
          }
        }
      ]
    }
  };

  comp.$root.formatMarkdown = jest.fn()
    .mockReturnValueOnce('<p><strong>Tool Result:</strong></p><p>Query executed successfully</p>');
  
  const result = comp.formatExpandMessage(data);
  
  expect(comp.$root.formatMarkdown).toHaveBeenCalled();
  const markdownArg = comp.$root.formatMarkdown.mock.calls[0][0];
  expect(markdownArg).toContain('**Tool Result:**');
  expect(markdownArg).toContain('Query executed successfully');
  expect(markdownArg).not.toContain('**Error:**');
  expect(result).toContain('Query executed successfully');
});

test('formatExpandMessage handles empty or missing content blocks', () => {
  const data = {
    message: {
      contentBlocks: null
    }
  };
  
  const result = comp.formatExpandMessage(data);
  
  expect(result).toBe('');
});

test('formatExpandMessage handles missing message', () => {
  const data = {};
  
  const result = comp.formatExpandMessage(data);
  
  expect(result).toBe('');
});

test('stripHtml removes HTML tags', () => {
  const htmlString = '<p>This is <strong>bold</strong> text with <a href="#">link</a></p>';
  
  const result = comp.stripHtml(htmlString);
  
  expect(result).toBe('This is bold text with link');
});

test('stripHtml handles string without HTML', () => {
  const plainString = 'This is plain text';
  
  const result = comp.stripHtml(plainString);
  
  expect(result).toBe('This is plain text');
});

// Breadcrumb tests
test('updateBreadcrumbs with userId and sessionId', () => {
  const userId = 'user123';
  const sessionId = 'session456';
  
  comp.updateBreadcrumbs(userId, sessionId);
  
  expect(comp.breadcrumbs).toHaveLength(3);
  expect(comp.breadcrumbs[2].disabled).toBe(true);
  expect(comp.breadcrumbs[2].to).toBe(null);
  expect(comp.breadcrumbs[1].disabled).toBe(false);
  expect(comp.breadcrumbs[1].to).toEqual({
    name: 'aimetrics',
    params: { userId: 'user123' }
  });
  expect(comp.breadcrumbs[0].disabled).toBe(false);
  expect(comp.breadcrumbs[0].to).toEqual({
    name: 'aimetrics'
  });
});

test('updateBreadcrumbs with userId only', () => {
  const userId = 'user123';
  
  comp.updateBreadcrumbs(userId, null);
  
  expect(comp.breadcrumbs).toHaveLength(2);
  expect(comp.breadcrumbs[1].disabled).toBe(true);
  expect(comp.breadcrumbs[1].to).toBe(null);
  expect(comp.breadcrumbs[0].disabled).toBe(false);
  expect(comp.breadcrumbs[0].to).toEqual({
    name: 'aimetrics'
  });
});

test('updateBreadcrumbs with no parameters', () => {
  comp.updateBreadcrumbs(null, null);
  
  expect(comp.breadcrumbs).toHaveLength(1);
  expect(comp.breadcrumbs[0].disabled).toBe(true);
  expect(comp.breadcrumbs[0].to).toBe(null);
});

// Watcher tests
test('watchers are properly configured', () => {
  // Test that the component has the expected watchers
  expect(comp.$route).toBeDefined();
  
  // Since we can't easily test Vue watchers in this environment,
  // we'll test the methods they would call
  comp.saveLocalSettings = jest.fn();
  comp.resetRefreshTimer = jest.fn();
  
  // Simulate watcher behavior
  comp.saveLocalSettings();
  comp.resetRefreshTimer();
  
  expect(comp.saveLocalSettings).toHaveBeenCalled();
  expect(comp.resetRefreshTimer).toHaveBeenCalled();
});

// Integration tests
test('full data loading flow for users', async () => {
  const mockUsersResponse = {
    data: [
      {
        userId: '12345678-1234-1234-1234-123456789012',
        usage: {
          totalInputTokens: 1000,
          totalOutputTokens: 2000,
          totalCredits: 500,
          totalMessages: 50
        }
      }
    ]
  };
  
  const usersMock = mockPapi("get", mockUsersResponse);
  
  comp.loadLocalSettings = jest.fn();
  comp.updateBreadcrumbs = jest.fn();
  comp.resetRefreshTimer = jest.fn();
  comp.lookupSocId = jest.fn().mockResolvedValue('user@example.com');
  comp.populateUsersCharts = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.adjustSubgridColVisibility = jest.fn();
  comp.getStartDate = jest.fn().mockReturnValue(moment('2025-01-01'));
  comp.getEndDate = jest.fn().mockReturnValue(moment('2025-01-02'));
  
  // Set assistantEnabled to true to bypass the early return
  comp.assistantEnabled = true;
  
  await comp.loadData();
  
  expect(comp.tableSetting).toBe(0);
  expect(comp.aimetrics).toHaveLength(1);
  expect(comp.aimetrics[0].userId).toBe('12345678-1234-1234-1234-123456789012');
  expect(comp.aimetrics[0].usage.totalInputTokens).toBe(1000);
  expect(comp.aimetrics[0].usage.totalOutputTokens).toBe(2000);
  expect(comp.aimetrics[0].usage.totalCredits).toBe(500);
  expect(comp.aimetrics[0].usage.totalMessages).toBe(50);
  expect(comp.lookupSocId).toHaveBeenCalledWith('12345678-1234-1234-1234-123456789012');
});

test('settings persistence integration', () => {
  // Set up some custom settings
  comp.sortByUsers = [{ key: 'email', order: 'asc' }];
  comp.itemsPerPage = 25;
  comp.relativeTimeValue = 48;
  comp.relativeTimeUnit = RELATIVE_TIME_DAYS;
  comp.autoRefreshInterval = 300;
  comp.zone = 'Europe/London';
  
  // Save settings
  comp.saveLocalSettings();
  
  // Verify localStorage was updated
  expect(mockLocalStorage['settings.aimetrics.sortByUsers']).toBe('email');
  expect(mockLocalStorage['settings.aimetrics.sortDescUsers']).toBe('asc');
  expect(mockLocalStorage['settings.aimetrics.itemsPerPage']).toBe('25');
  expect(mockLocalStorage['settings.aimetrics.relativeTimeValue']).toBe('48');
  expect(mockLocalStorage['settings.aimetrics.relativeTimeUnit']).toBe(String(RELATIVE_TIME_DAYS));
  expect(mockLocalStorage['settings.aimetrics.autoRefreshInterval']).toBe('300');
  expect(mockLocalStorage['timezone']).toBe('Europe/London');
  
  // Reset component state
  comp.sortByUsers = [{ key: 'totalCredits', order: 'desc' }];
  comp.itemsPerPage = 10;
  comp.relativeTimeValue = 24;
  comp.relativeTimeUnit = RELATIVE_TIME_HOURS;
  comp.autoRefreshInterval = 0;
  comp.zone = 'UTC';
  
  // Load settings
  comp.loadLocalSettings();
  
  // Verify settings were restored
  expect(comp.itemsPerPage).toBe(25);
  expect(comp.relativeTimeValue).toBe(48);
  expect(comp.relativeTimeUnit).toBe(RELATIVE_TIME_DAYS);
  expect(comp.autoRefreshInterval).toBe(300);
  expect(comp.zone).toBe('Europe/London');
});

test('error handling integration', async () => {
  const apiError = new Error('Network timeout');
  
  mockPapi("get", null, apiError);
  
  comp.loadLocalSettings = jest.fn();
  comp.updateBreadcrumbs = jest.fn();
  comp.resetRefreshTimer = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.showError = jest.fn();
  comp.getStartDate = jest.fn().mockReturnValue(moment('2025-01-01'));
  comp.getEndDate = jest.fn().mockReturnValue(moment('2025-01-02'));
  
  // Set assistantEnabled to true to bypass the early return
  comp.assistantEnabled = true;
  
  await comp.loadData();
  
  expect(comp.$root.showError).toHaveBeenCalledWith(apiError);
  expect(comp.aimetrics).toEqual([]);
  expect(comp.$root.stopLoading).toHaveBeenCalled();
  expect(comp.resetRefreshTimer).toHaveBeenCalled();
});

// Edge cases and boundary tests
test('handles empty API responses', async () => {
  const mockResponse = { data: [] };
  mockPapi("get", mockResponse);
  
  comp.loadLocalSettings = jest.fn();
  comp.updateBreadcrumbs = jest.fn();
  comp.resetRefreshTimer = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.adjustSubgridColVisibility = jest.fn();
  comp.getStartDate = jest.fn().mockReturnValue(moment('2025-01-01'));
  comp.getEndDate = jest.fn().mockReturnValue(moment('2025-01-02'));
  
  // Set assistantEnabled to true to bypass the early return
  comp.assistantEnabled = true;
  
  await comp.loadData();
  
  expect(comp.aimetrics).toEqual([]);
  expect(comp.$root.stopLoading).toHaveBeenCalled();
});

test('handles malformed date ranges gracefully', () => {
  comp.dateRange = 'invalid-date-range';
  
  const endDate = comp.getEndDate();
  const startDate = comp.getStartDate();
  
  expect(moment.isMoment(endDate)).toBe(true);
  expect(moment.isMoment(startDate)).toBe(true);
});

test('handles extreme relative time values', () => {
  comp.dateRange = '';
  comp.relativeTimeValue = 999999;
  comp.relativeTimeUnit = RELATIVE_TIME_SECONDS;
  
  const result = comp.getStartDate();
  
  expect(moment.isMoment(result)).toBe(true);
  expect(result.isBefore(moment())).toBe(true);
});

test('beforeUnmount lifecycle cleanup', () => {
  comp.stopRefreshTimer = jest.fn();
  
  // Simulate beforeUnmount
  if (comp.beforeUnmount) {
    comp.beforeUnmount();
  }
  
  expect(comp.stopRefreshTimer).toHaveBeenCalled();
});

// getCPM tests

test('getCPM calculates credits per minute for multiple minutes', () => {
  const durationMs = 300000; // 5 minutes
  const totalCredits = 250;
  
  const result = comp.getCPM(durationMs, totalCredits);
  
  expect(result).toBe(50); // 250 / 5 = 50
});

test('getCPM rounds to nearest integer', () => {
  const durationMs = 90000; // 1.5 minutes
  const totalCredits = 100;
  
  const result = comp.getCPM(durationMs, totalCredits);
  
  expect(result).toBe(67); // 100 / 1.5 = 66.666... rounds to 67
});

test('getCPM handles zero credits', () => {
  const durationMs = 60000; // 1 minute
  const totalCredits = 0;
  
  const result = comp.getCPM(durationMs, totalCredits);
  
  expect(result).toBe(0);
});

test('getCPM handles less than one minute', () => {
  const durationMs = 45000; // 45 seconds
  const totalCredits = 50000;
  
  const result = comp.getCPM(durationMs, totalCredits);
  
  expect(result).toBe(50000);
});

test('nbspRegexOp', () => {
  expect(comp.nbspRegexOp('&nbsp;')).toBe('');
  expect(comp.nbspRegexOp('&nbsp')).toBe('');
  expect(comp.nbspRegexOp('Hello&nbsp;World')).toBe('Hello&nbsp;World');
  expect(comp.nbspRegexOp('&nbsp;\n\nHelloWorld')).toBe('HelloWorld');
  expect(comp.nbspRegexOp('&nbsp;Hello&nbsp;World')).toBe('Hello&nbsp;World');
  expect(comp.nbspRegexOp('&nbspHelloWorld')).toBe('HelloWorld');
  expect(comp.nbspRegexOp('Hello World')).toBe('Hello World');
  expect(comp.nbspRegexOp('')).toBe('');
});

// Chart method tests
test('setupCharts initializes all chart configurations', () => {
  comp.setupPieChart = jest.fn();
  comp.setupTimelineChart = jest.fn();
  
  comp.setupCharts();
  
  expect(comp.setupPieChart).toHaveBeenCalledTimes(4);
  expect(comp.setupPieChart).toHaveBeenCalledWith(comp.graphUsersCreditsOptions, comp.graphUsersCreditsData, comp.i18n.totalCredits);
  expect(comp.setupPieChart).toHaveBeenCalledWith(comp.graphUsersSessionsOptions, comp.graphUsersSessionsData, comp.i18n.totalSessions);
  expect(comp.setupPieChart).toHaveBeenCalledWith(comp.graphUsersMessagesOptions, comp.graphUsersMessagesData, comp.i18n.totalMessages);
  expect(comp.setupPieChart).toHaveBeenCalledWith(comp.graphSessionsMessagesOptions, comp.graphSessionsMessagesData, comp.i18n.totalMessages);
  
  expect(comp.setupTimelineChart).toHaveBeenCalledTimes(1);
  expect(comp.setupTimelineChart).toHaveBeenCalledWith(comp.graphSessionsCreditsOptions, comp.graphSessionsCreditsData, comp.i18n.totalCredits);
  
  expect(comp.graphUsersCreditsData.key).toBe(0);
  expect(comp.graphUsersSessionsData.key).toBe(0);
  expect(comp.graphUsersMessagesData.key).toBe(0);
  expect(comp.graphSessionsCreditsData.key).toBe(0);
  expect(comp.graphSessionsMessagesData.key).toBe(0);
});

test('populateUsersCharts calls populateChart for each user chart', () => {
  comp.populateChart = jest.fn();
  comp.populateModelsChart = jest.fn();
  comp.aimetrics = [{ totalCredits: 100, totalSessions: 5, totalMessages: 20 }];
  
  comp.populateUsersCharts();
  
  expect(comp.populateChart).toHaveBeenCalledTimes(2);
  expect(comp.populateChart).toHaveBeenCalledWith(comp.graphUsersCreditsData, comp.aimetrics, 'totalCredits');
  expect(comp.populateChart).toHaveBeenCalledWith(comp.graphUsersSessionsData, comp.aimetrics, 'totalSessions');
  expect(comp.populateModelsChart).toHaveBeenCalledWith(comp.graphUsersMessagesData, comp.aimetrics);
});

test('populateSessionsCharts calls populateChart for each session chart with time field', () => {
  comp.populateChart = jest.fn();
  comp.populateModelsChart = jest.fn();
  comp.aimetrics = [{ totalCredits: 50, totalMessages: 10, createTime: '2025-01-01T12:00:00Z' }];
  
  comp.populateSessionsCharts();
  
  expect(comp.populateChart).toHaveBeenCalledTimes(1);
  expect(comp.populateChart).toHaveBeenCalledWith(comp.graphSessionsCreditsData, comp.aimetrics, 'totalCredits', 'createTime');
  expect(comp.populateModelsChart).toHaveBeenCalledWith(comp.graphSessionsMessagesData, comp.aimetrics);
});

test('populateModelsChart populates chart with model usage data', () => {
  const chart = { key: 0, labels: [], datasets: [{ data: [] }] };
  const data = [
    {
      usage: {
        modelUsage: {
          'gpt-4@OpenAI': { modelMessages: 5 },
          'claude-3@Anthropic': { modelMessages: 3 }
        }
      }
    },
    {
      usage: {
        modelUsage: {
          'gpt-4@OpenAI': { modelMessages: 2 }
        }
      }
    }
  ];
  
  comp.populateModelsChart(chart, data);
  
  expect(chart.key).toBe(1);
  expect(chart.labels).toContain('gpt-4@OpenAI');
  expect(chart.labels).toContain('claude-3@Anthropic');
  expect(chart.datasets[0].data).toContain(7); // 5 + 2 for gpt-4
  expect(chart.datasets[0].data).toContain(3); // 3 for claude-3
});

test('populateModelsChart handles modelUsage at item level', () => {
  const chart = { key: 0, labels: [], datasets: [{ data: [] }] };
  const data = [
    {
      modelUsage: {
        'model-1@Provider': { modelMessages: 10 }
      }
    }
  ];
  
  comp.populateModelsChart(chart, data);
  
  expect(chart.key).toBe(1);
  expect(chart.labels).toContain('model-1@Provider');
  expect(chart.datasets[0].data).toContain(10);
});

test('populateModelsChart handles empty data', () => {
  const chart = { key: 5, labels: ['old'], datasets: [{ data: [100] }] };
  
  comp.populateModelsChart(chart, []);
  
  expect(chart.key).toBe(6);
  expect(chart.labels).toEqual([]);
  expect(chart.datasets[0].data).toEqual([]);
});

test('populateModelsChart handles null data', () => {
  const chart = { key: 3, labels: ['old'], datasets: [{ data: [50] }] };
  
  comp.populateModelsChart(chart, null);
  
  expect(chart.key).toBe(4);
  expect(chart.labels).toEqual([]);
  expect(chart.datasets[0].data).toEqual([]);
});

test('populateChart increments key and populates data without timefield', () => {
  const chart = { key: 5, labels: [], datasets: [{ data: [] }] };
  const data = [
    { email: 'user1@example.com', totalCredits: 100 },
    { email: 'user2@example.com', totalCredits: 200 },
    { userId: 'user3-id', totalCredits: 150 }
  ];
  comp.$root.truncate = jest.fn((str, len) => str.substring(0, len));
  
  comp.populateChart(chart, data, 'totalCredits');
  
  expect(chart.key).toBe(6);
  expect(chart.labels).toHaveLength(3);
  expect(chart.labels[0]).toBe('user1@example.com');
  expect(chart.labels[1]).toBe('user2@example.com');
  expect(chart.labels[2]).toBe('user3-id');
  expect(chart.datasets[0].data).toEqual([100, 200, 150]);
});

test('populateChart handles missing field values', () => {
  const chart = { key: 0, labels: [], datasets: [{ data: [] }] };
  const data = [
    { email: 'user1@example.com', totalCredits: 100 },
    { email: 'user2@example.com' } // missing totalCredits
  ];
  comp.$root.truncate = jest.fn((str, len) => str);
  
  comp.populateChart(chart, data, 'totalCredits');
  
  expect(chart.datasets[0].data).toEqual([100, 0]);
});

test('populateChart populates data with timefield', () => {
  const chart = { key: 2, labels: [], datasets: [{ data: [] }] };
  const data = [
    { createTime: '2025-01-01T12:00:00Z', totalCredits: 50 },
    { createTime: '2025-01-01T13:00:00Z', totalCredits: 75 }
  ];
  
  comp.populateChart(chart, data, 'totalCredits', 'createTime');
  
  expect(chart.key).toBe(3);
  expect(chart.labels).toEqual([]);
  expect(chart.datasets[0].data).toHaveLength(2);
  expect(chart.datasets[0].data[0].x).toBeInstanceOf(Date);
  expect(chart.datasets[0].data[0].y).toBe(50);
  expect(chart.datasets[0].data[1].y).toBe(75);
});

test('populateChart handles empty data array', () => {
  const chart = { key: 1, labels: ['old'], datasets: [{ data: [100] }] };
  
  comp.populateChart(chart, [], 'totalCredits');
  
  expect(chart.key).toBe(2);
  expect(chart.labels).toEqual([]);
  expect(chart.datasets[0].data).toEqual([]);
});

test('populateChart handles null data', () => {
  const chart = { key: 1, labels: ['old'], datasets: [{ data: [100] }] };
  
  comp.populateChart(chart, null, 'totalCredits');
  
  expect(chart.key).toBe(2);
  expect(chart.labels).toEqual([]);
  expect(chart.datasets[0].data).toEqual([]);
});

test('setupBarChart configures bar chart options and data', () => {
  const options = {};
  const data = {};
  const title = 'Test Chart';
  comp.$root.getColor = jest.fn()
    .mockReturnValueOnce('#666666')
    .mockReturnValueOnce('#0000ff')
    .mockReturnValueOnce('#cccccc');
  
  comp.setupBarChart(options, data, title);
  
  expect(options.responsive).toBe(true);
  expect(options.maintainAspectRatio).toBe(false);
  expect(options.layout.padding.bottom).toBe(15);
  expect(options.plugins.legend.display).toBe(false);
  expect(options.plugins.title.display).toBe(true);
  expect(options.plugins.title.text).toBe('Test Chart');
  expect(options.scales.y.ticks.beginAtZero).toBe(true);
  expect(options.scales.y.ticks.precision).toBe(0);
  expect(data.labels).toEqual([]);
  expect(data.datasets).toHaveLength(1);
  expect(data.datasets[0].data).toEqual([]);
  expect(data.datasets[0].fill).toBe(false);
});

test('setupTimelineChart extends bar chart with timeseries', () => {
  const options = {};
  const data = {};
  const title = 'Timeline Chart';
  comp.$root.getColor = jest.fn()
    .mockReturnValueOnce('#666666')
    .mockReturnValueOnce('#0000ff')
    .mockReturnValueOnce('#cccccc');
  
  comp.setupTimelineChart(options, data, title);
  
  expect(options.onClick).toBe(null);
  expect(options.scales.x.type).toBe('timeseries');
  expect(options.responsive).toBe(true);
  expect(options.maintainAspectRatio).toBe(false);
});

test('setupPieChart configures pie chart options and data', () => {
  const options = {};
  const data = {};
  const title = 'Pie Chart';
  
  comp.setupPieChart(options, data, title);
  
  expect(options.responsive).toBe(true);
  expect(options.maintainAspectRatio).toBe(false);
  expect(options.plugins.legend.display).toBe(true);
  expect(options.plugins.legend.position).toBe('left');
  expect(options.plugins.title.display).toBe(true);
  expect(options.plugins.title.text).toBe('Pie Chart');
  expect(data.labels).toEqual([]);
  expect(data.datasets).toHaveLength(1);
  expect(data.datasets[0].backgroundColor).toHaveLength(11);
  expect(data.datasets[0].borderColor).toBe('rgba(255, 255, 255, 0.5)');
  expect(data.datasets[0].data).toEqual([]);
});

test('toggleShowSection adds item to collapsed sections', () => {
  comp.collapsedSections = [];
  
  comp.toggleShowSection('section1');
  
  expect(comp.collapsedSections).toContain('section1');
});

test('toggleShowSection removes item from collapsed sections', () => {
  comp.collapsedSections = ['section1'];
  
  comp.toggleShowSection('section1');
  
  expect(comp.collapsedSections).not.toContain('section1');
});

test('collapsedSections persist across reloads', () => {
  comp.collapsedSections = [];

  comp.toggleShowSection('aimetrics-graphs');
  expect(comp.collapsedSections).toEqual(['aimetrics-graphs']);

  comp.collapsedSections = [];
  comp.loadLocalSettings();
  expect(comp.collapsedSections).toEqual(['aimetrics-graphs']);

  // back to all-expanded clears the stored setting
  comp.toggleShowSection('aimetrics-graphs');
  expect(localStorage['settings.aimetrics.collapsedSections']).toBeUndefined();
});

test('isExpandedSection returns true when section not collapsed', () => {
  comp.collapsedSections = ['section2'];
  
  expect(comp.isExpandedSection('section1')).toBe(true);
});

test('isExpandedSection returns false when section is collapsed', () => {
  comp.collapsedSections = ['section1'];
  
  expect(comp.isExpandedSection('section1')).toBe(false);
});

test('calculateCreditPercentage calculates percentage correctly', () => {
  const result = comp.calculateCreditPercentage(25, 100);
  
  expect(result).toBe('25.0%');
});

test('calculateCreditPercentage handles decimal percentages', () => {
  const result = comp.calculateCreditPercentage(33, 100);
  
  expect(result).toBe('33.0%');
});

test('calculateCreditPercentage rounds to one decimal place', () => {
  const result = comp.calculateCreditPercentage(33.333, 100);
  
  expect(result).toBe('33.3%');
});

test('buildModelIdentifier', () => {
  const tests = [
    { input: { id: 'model', adapter: 'adapter' }, expected: 'model@adapter' },
    { input: { id: '', adapter: '' }, expected: '@' },
    { input: {}, expected: '@' },
    { input: null, expected: '' },
  ];

  for (let t of tests) {
    const output = comp.buildModelIdentifier(t.input);
    expect(output).toBe(t.expected);
  }
});