// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./destinations-manager.js');

let comp;

beforeEach(() => {
  comp = getComponent('destinations-manager');
  resetPapi();
});

test('getDestinations success', async () => {
  const mockData = [
    {
      id: 'soc-bell',
      name: 'SOC Bell',
      type: 'soc',
      enabled: true,
      scheduleIds: ['work-hours'],
      severities: ['high', 'critical'],
      params: {},
    },
  ];
  const mock = mockPapi('get', mockData);
  await comp.getDestinations();
  expect(mock).toHaveBeenCalledWith('notifications/destinations');
  expect(comp.destinations).toEqual(mockData);
});

test('getDestinations error handling', async () => {
  mockPapi('get', null, 'Failed to fetch destinations');
  await comp.getDestinations();
  expect(comp.$root.error).toBe(true);
  expect(comp.$root.errorMessage).toBe('Failed to fetch destinations');
});

test('getSchedules success', async () => {
  const mockSchedules = [
    { id: 'sch-1', name: 'Work Hours', enabled: true },
    { id: 'sch-2', name: 'Off Hours', enabled: false },
  ];
  const mock = mockPapi('get', mockSchedules);
  await comp.getSchedules();
  expect(mock).toHaveBeenCalledWith('schedules/');
  expect(comp.schedules).toEqual(mockSchedules);
  const opts = typeof comp.scheduleOptions === 'function' ? comp.scheduleOptions() : comp.scheduleOptions;
  expect(opts.length).toBe(2);
  expect(opts[0].title).toBe('Work Hours (Enabled)');
  expect(opts[1].title).toBe('Off Hours (Disabled)');
});

test('showAddDestination initializes default form', () => {
  comp.showAddDestination();
  expect(comp.destinationDialog).toBe(true);
  expect(comp.form.isEdit).toBe(false);
  expect(comp.form.id).toBe('');
  expect(comp.form.name).toBe('');
  expect(comp.form.type).toBe('soc');
  expect(comp.form.enabled).toBe(true);
  expect(comp.form.scheduleIds).toEqual([]);
  expect(comp.form.severities).toEqual([]);
  expect(comp.form.params).toEqual({});
  expect(comp.testResult).toBeNull();
});

test('showEditDestination populates form', () => {
  const dest = {
    id: 'soc-bell',
    name: 'SOC Alert Bell',
    type: 'soc',
    enabled: false,
    scheduleIds: ['sch-1'],
    severities: ['critical'],
    params: {},
  };
  comp.showEditDestination(dest);
  expect(comp.destinationDialog).toBe(true);
  expect(comp.form.isEdit).toBe(true);
  expect(comp.form.id).toBe('soc-bell');
  expect(comp.form.name).toBe('SOC Alert Bell');
  expect(comp.form.type).toBe('soc');
  expect(comp.form.enabled).toBe(false);
  expect(comp.form.scheduleIds).toEqual(['sch-1']);
  expect(comp.form.severities).toEqual(['critical']);
  expect(comp.form.params).toEqual({});
  expect(comp.testResult).toBeNull();
});

test('saveDestination creates new destination', async () => {
  comp.showAddDestination();
  comp.form.name = 'New Slack';
  comp.form.type = 'soc';
  comp.form.scheduleIds = ['sch-1'];
  comp.form.severities = ['high', 'critical'];

  const postMock = mockPapi('post', { success: true });
  mockPapi('get', []); // loadData destinations
  await comp.saveDestination();

  expect(postMock).toHaveBeenCalledWith('notifications/destinations', {
    id: undefined,
    name: 'New Slack',
    type: 'soc',
    enabled: true,
    scheduleIds: ['sch-1'],
    severities: ['high', 'critical'],
    params: {},
  });
  expect(comp.destinationDialog).toBe(false);
});

test('saveDestination updates existing destination', async () => {
  comp.showEditDestination({
    id: 'soc-bell',
    name: 'SOC Bell',
    type: 'soc',
    enabled: true,
    scheduleIds: ['sch-1'],
    severities: ['critical'],
    params: {},
  });
  comp.form.name = 'Renamed SOC Bell';
  comp.form.enabled = false;
  comp.form.scheduleIds = ['sch-1', 'sch-2'];

  const putMock = mockPapi('put', { success: true });
  mockPapi('get', []); // loadData destinations
  await comp.saveDestination();

  expect(putMock).toHaveBeenCalledWith('notifications/destinations/soc-bell', {
    id: 'soc-bell',
    name: 'Renamed SOC Bell',
    type: 'soc',
    enabled: false,
    scheduleIds: ['sch-1', 'sch-2'],
    severities: ['critical'],
    params: {},
  });
  expect(comp.destinationDialog).toBe(false);
});

test('saveDestination ignores empty name', async () => {
  comp.showAddDestination();
  comp.form.name = '';
  const postMock = mockPapi('post', { success: true });
  await comp.saveDestination();
  expect(postMock).not.toHaveBeenCalled();
});

test('isDefaultDestination checks default id', () => {
  expect(comp.isDefaultDestination({ id: 'soc-bell' })).toBe(true);
  expect(comp.isDefaultDestination({ id: 'custom-dest' })).toBe(false);
  expect(comp.isDefaultDestination(null)).toBe(false);
});

test('deleteDestination flow for custom destination', async () => {
  const defaultDest = { id: 'soc-bell', name: 'SOC Bell' };
  comp.showDeleteDestination(defaultDest);
  expect(comp.deleteDestinationDialog).toBe(false);
  expect(comp.destinationToDelete).toBeNull();

  const customDest = { id: 'custom-dest', name: 'Custom Channel' };
  comp.showDeleteDestination(customDest);
  expect(comp.deleteDestinationDialog).toBe(true);
  expect(comp.destinationToDelete).toEqual(customDest);

  const deleteMock = mockPapi('delete', { success: true });
  mockPapi('get', []); // loadData destinations
  await comp.deleteDestination();

  expect(deleteMock).toHaveBeenCalledWith('notifications/destinations/custom-dest');
  expect(comp.deleteDestinationDialog).toBe(false);
  expect(comp.destinationToDelete).toBeNull();
});

test('hideDeleteDestination resets state', () => {
  comp.showDeleteDestination({ id: 'custom-dest', name: 'Custom Channel' });
  comp.hideDeleteDestination();
  expect(comp.deleteDestinationDialog).toBe(false);
  expect(comp.destinationToDelete).toBeNull();
});

test('testDestination success and error handling', async () => {
  const postMock = mockPapi('post', { success: true });
  await comp.testDestination({ id: 'soc-bell' });
  expect(postMock).toHaveBeenCalledWith('notifications/destinations/soc-bell/test');
  expect(comp.$root.notification).toBe(true);

  // Error case
  mockPapi('post', null, 'Connection failed');
  await comp.testDestination({ id: 'soc-bell' });
  expect(comp.$root.error).toBe(true);
});

test('testCurrentForm in editor dialog', async () => {
  comp.form.id = 'soc-bell';
  const postMock = mockPapi('post', { success: true });
  await comp.testCurrentForm();
  expect(postMock).toHaveBeenCalledWith('notifications/destinations/soc-bell/test');
  expect(comp.testResult).toEqual({
    success: true,
    message: 'Test notification sent successfully!',
  });

  // Error case
  mockPapi('post', null, 'Driver timeout');
  await comp.testCurrentForm();
  expect(comp.testResult).toEqual({
    success: false,
    message: 'Driver timeout',
  });
});

test('helpers for channel and severity formatting', () => {
  expect(comp.getChannelIcon('soc')).toBe('fa-envelope');
  expect(comp.getChannelIcon('smtp')).toBe('fa-at');
  expect(comp.getChannelIcon('slack')).toBe('fab fa-slack');
  expect(comp.getChannelIcon('matrix')).toBe('fa-comments');
  expect(comp.getChannelIcon('other')).toBe('fa-envelope');

  expect(comp.getSeverityColor('critical')).toBe('red');
  expect(comp.getSeverityColor('high')).toBe('orange');
  expect(comp.getSeverityColor('medium')).toBe('amber');
  expect(comp.getSeverityColor('low')).toBe('blue');
  expect(comp.getSeverityColor('info')).toBe('grey');

  expect(comp.getSeverityLabel('critical')).toBe('Critical');
  expect(comp.getSeverityLabel('high')).toBe('High');

  // getDestinationName tests
  expect(comp.getDestinationName({ name: 'Custom Name', type: 'soc' })).toBe('Custom Name');
  expect(comp.getDestinationName({ name: '', type: 'soc', id: 'soc-bell' })).toBe('Built-in SOC Notifications');
  expect(comp.getDestinationName({ name: '   ', type: 'soc', id: 'soc-bell' })).toBe('Built-in SOC Notifications');
  expect(comp.getDestinationName({ name: '', type: 'smtp', id: 'smtp-1' })).toBe('smtp-1');
  expect(comp.getDestinationName(null)).toBe('');
});

test('isDestinationScheduleActive and getDestinationScheduleNames evaluations', () => {
  // No schedule -> always active
  expect(comp.isDestinationScheduleActive({ scheduleIds: [] })).toBe(true);
  expect(comp.isDestinationScheduleActive(null)).toBe(true);

  // Missing schedule -> fails open to true
  comp.schedules = [{ id: 'sch-1', name: 'Work', enabled: true, definitions: [{ type: 'daily', allDay: true }] }];
  expect(comp.isDestinationScheduleActive({ scheduleIds: ['missing'] })).toBe(true);

  // Active schedule
  expect(comp.isDestinationScheduleActive({ scheduleIds: ['sch-1'] })).toBe(true);

  // Disabled schedule -> false
  comp.schedules = [{ id: 'sch-2', name: 'Disabled', enabled: false, definitions: [{ type: 'daily', allDay: true }] }];
  expect(comp.isDestinationScheduleActive({ scheduleIds: ['sch-2'] })).toBe(false);

  // Multiple schedules: active if any is active
  comp.schedules = [
    { id: 'sch-1', name: 'Work', enabled: true, definitions: [{ type: 'daily', allDay: true }] },
    { id: 'sch-2', name: 'Disabled', enabled: false, definitions: [{ type: 'daily', allDay: true }] },
  ];
  expect(comp.isDestinationScheduleActive({ scheduleIds: ['sch-1', 'sch-2'] })).toBe(true);

  // Names helper
  expect(comp.getDestinationScheduleNames({ scheduleIds: ['sch-1'] })).toEqual(['Work']);
  expect(comp.getDestinationScheduleNames({ scheduleIds: ['sch-1', 'sch-2'] })).toEqual(['Work', 'Disabled']);
  expect(comp.getDestinationScheduleNames(null)).toEqual([]);
});
