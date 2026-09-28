// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./alarms-manager.js');

let comp;

beforeEach(() => {
  comp = getComponent('alarms-manager');
  resetPapi();
});

test('loadData populates alarms, metrics, states, nodes, destinations and users', async () => {
  const mockAlarms = [
    {
      id: 'alarm-1',
      name: 'CPU Alarm',
      metric: 'cpu',
      operator: 'gt',
      threshold: '80',
      durationSeconds: 120,
      severity: 'high',
      clearedSeverity: 'none',
      enabled: true,
    },
  ];
  const mockMetrics = [
    { metric: 'cpu', titleKey: 'metricsCpuUsage', keys: ['cpu_used'], labelKeys: ['cpuUsageAbbr'], type: 'numeric', units: 'percent' },
    { metric: 'memory', titleKey: 'metricsMemUsage', keys: ['memory_used'], labelKeys: ['memUsageAbbr'], type: 'numeric', units: 'percent' },
  ];
  const mockStates = [
    { alarmId: 'alarm-1', nodeId: 'sensor-1', status: 'alarm', currentValue: '85.4' },
  ];
  const mockNodes = [{ id: 'sensor-1' }, { id: 'manager-1' }];
  const mockDests = [{ id: 'soc-bell', name: 'SOC Bell' }];
  const mockUsers = [{ id: 'user-1', email: 'admin@soc.local' }];

  mockPapi('get', mockAlarms); // alarms
  mockPapi('get', mockMetrics); // alarms/metrics
  mockPapi('get', mockStates); // alarms/states
  mockPapi('get', mockNodes); // grid/
  mockPapi('get', mockDests); // notifications/destinations
  mockPapi('get', mockUsers); // users

  let emittedData = null;
  comp.$emit = jest.fn((evt, data) => {
    if (evt === 'alarms-loaded') emittedData = data;
  });

  await comp.loadData();

  expect(comp.alarms).toEqual(mockAlarms);
  expect(comp.metrics).toEqual(mockMetrics);
  expect(comp.states).toEqual(mockStates);
  expect(comp.nodes).toEqual(mockNodes);
  expect(comp.destinations).toEqual(mockDests);
  expect(comp.users).toEqual(mockUsers);
  expect(emittedData).toEqual(mockAlarms);
});

test('showAddAlarm initializes form defaults', () => {
  comp.metrics = [
    { metric: 'cpu', titleKey: 'metricsCpuUsage', keys: ['cpu_used'], type: 'numeric' },
  ];
  comp.showAddAlarm();
  expect(comp.alarmDialog).toBe(true);
  expect(comp.form.isEdit).toBe(false);
  expect(comp.form.name).toBe('');
  expect(comp.form.metric).toBe('cpu');
  expect(comp.form.metricKey).toBe('cpu_used');
  expect(comp.form.operator).toBe('gt');
  expect(comp.form.threshold).toBe('80');
  expect(comp.form.durationSeconds).toBe(120);
  expect(comp.form.severity).toBe('high');
  expect(comp.form.clearedSeverity).toBe('none');
  expect(comp.form.enabled).toBe(true);
});

test('operatorOptions filters based on metric type', () => {
  comp.metrics = [
    { metric: 'cpu', type: 'numeric' },
    { metric: 'process_status', type: 'string' },
    { metric: 'os_needs_restart', type: 'bool' },
  ];

  comp.form.metric = 'cpu';
  let ops = comp.getOperatorOptions().map(o => o.value);
  expect(ops).toContain('gt');
  expect(ops).toContain('lt');
  expect(ops).not.toContain('contains');

  comp.form.metric = 'process_status';
  ops = comp.getOperatorOptions().map(o => o.value);
  expect(ops).toContain('eq');
  expect(ops).toContain('ne');
  expect(ops).toContain('contains');
  expect(ops).not.toContain('gt');

  comp.form.metric = 'os_needs_restart';
  ops = comp.getOperatorOptions().map(o => o.value);
  expect(ops).toContain('eq');
  expect(ops).toContain('ne');
  expect(ops).not.toContain('contains');
  expect(ops).not.toContain('gt');
});

test('showEditAlarm populates form with existing alarm', () => {
  const alarm = {
    id: 'alarm-1',
    name: 'Memory Alarm',
    metric: 'memory',
    metricKey: 'memory_used',
    operator: 'gte',
    threshold: '90',
    durationSeconds: 300,
    severity: 'critical',
    clearedSeverity: 'info',
    destinations: ['soc-bell'],
    recipients: ['user-1'],
    note: 'Memory is exhausted',
    enabled: true,
  };

  comp.showEditAlarm(alarm);
  expect(comp.alarmDialog).toBe(true);
  expect(comp.form.isEdit).toBe(true);
  expect(comp.form.id).toBe('alarm-1');
  expect(comp.form.name).toBe('Memory Alarm');
  expect(comp.form.metric).toBe('memory');
  expect(comp.form.metricKey).toBe('memory_used');
  expect(comp.form.operator).toBe('gte');
  expect(comp.form.threshold).toBe('90');
  expect(comp.form.durationSeconds).toBe(300);
  expect(comp.form.severity).toBe('critical');
  expect(comp.form.clearedSeverity).toBe('info');
  expect(comp.form.destinations).toEqual(['soc-bell']);
  expect(comp.form.recipients).toEqual(['user-1']);
  expect(comp.form.note).toBe('Memory is exhausted');
});

test('onMetricChange updates metricKey when metric changes', () => {
  comp.metrics = [
    { metric: 'cpu', keys: ['cpu_used'] },
    { metric: 'disk', keys: ['disk_used_root', 'disk_used_nsm'] },
  ];
  comp.form.metric = 'disk';
  comp.onMetricChange('disk');
  expect(comp.form.metricKey).toBe('disk_used_root');
});

test('saveAlarm creates new alarm via POST', async () => {
  comp.form = {
    isEdit: false,
    name: 'New Alarm',
    enabled: true,
    metric: 'cpu',
    metricKey: 'cpu_used',
    operator: 'gt',
    threshold: '75',
    durationSeconds: 60,
    severity: 'high',
    clearedSeverity: 'none',
    destinations: [],
    recipients: [],
    note: 'Note test',
  };

  const postMock = mockPapi('post', { id: 'new-id' });
  mockPapi('get', []); // loadData reload
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);

  comp.$emit = jest.fn();

  await comp.saveAlarm();

  expect(postMock).toHaveBeenCalledWith('alarms', expect.objectContaining({
    name: 'New Alarm',
    metric: 'cpu',
    threshold: '75',
    durationSeconds: 60,
  }));
  expect(comp.alarmDialog).toBe(false);
  expect(comp.$emit).toHaveBeenCalledWith('alarm-saved', expect.anything());
});

test('saveAlarm updates existing alarm via PUT', async () => {
  comp.form = {
    isEdit: true,
    id: 'alarm-1',
    name: 'Updated Alarm',
    enabled: false,
    metric: 'cpu',
    operator: 'gt',
    threshold: '85',
    durationSeconds: 120,
    severity: 'critical',
    clearedSeverity: 'info',
    destinations: ['soc-bell'],
    recipients: [],
    note: '',
  };

  const putMock = mockPapi('put', { id: 'alarm-1' });
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);

  await comp.saveAlarm();

  expect(putMock).toHaveBeenCalledWith('alarms/alarm-1', expect.objectContaining({
    name: 'Updated Alarm',
    enabled: false,
    durationSeconds: 120,
  }));
});

test('deleteAlarm deletes alarm via DELETE', async () => {
  comp.alarmToDelete = { id: 'alarm-1', name: 'To Delete' };
  comp.deleteAlarmDialog = true;

  const deleteMock = mockPapi('delete', null);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);
  mockPapi('get', []);

  comp.$emit = jest.fn();

  await comp.deleteAlarm();

  expect(deleteMock).toHaveBeenCalledWith('alarms/alarm-1');
  expect(comp.deleteAlarmDialog).toBe(false);
  expect(comp.alarmToDelete).toBeNull();
  expect(comp.$emit).toHaveBeenCalledWith('alarm-deleted', { id: 'alarm-1', name: 'To Delete' });
});

test('alarm state helpers and formatting', () => {
  comp.states = [
    { alarmId: 'alarm-1', nodeId: 'node-1', status: 'alarm', currentValue: '92.0' },
    { alarmId: 'alarm-2', nodeId: 'node-1', status: 'ok', currentValue: '40.0' },
  ];
  comp.metrics = [
    { metric: 'cpu', titleKey: 'metricsCpuUsage' },
  ];
  comp.destinations = [
    { id: 'soc-bell', name: 'SOC Bell' },
    { id: 'unnamed-bell', name: '' },
  ];

  const activeAlarm = { id: 'alarm-1', metric: 'cpu', operator: 'gt', threshold: '80', durationSeconds: 120, severity: 'high', enabled: true };
  const okAlarm = { id: 'alarm-2', metric: 'cpu', operator: 'gt', threshold: '80', durationSeconds: 0, severity: 'high', enabled: true };
  const disabledAlarm = { id: 'alarm-3', metric: 'cpu', operator: 'gt', threshold: '80', enabled: false };

  expect(comp.isAlarmActive(activeAlarm)).toBe(true);
  expect(comp.isAlarmActive(okAlarm)).toBe(false);

  expect(comp.getAlarmStateColor(activeAlarm)).toBe('error');
  expect(comp.getAlarmStateColor(okAlarm)).toBe('success');
  expect(comp.getAlarmStateColor(disabledAlarm)).toBe('grey');

  expect(comp.getAlarmStateLabel(activeAlarm)).toBe(comp.i18n.alarmActive || 'Alarming');
  expect(comp.getAlarmStateLabel(okAlarm)).toBe(comp.i18n.alarmCleared || 'OK');
  expect(comp.getAlarmStateLabel(disabledAlarm)).toBe(comp.i18n.disabled || 'Disabled');

  expect(comp.formatCondition(activeAlarm)).toBe('> 80 for >= 2 minutes');
  expect(comp.formatCondition(okAlarm)).toBe('> 80');

  expect(comp.getCurrentValue(activeAlarm)).toBe('92.0');
  expect(comp.getDestinationName('soc-bell')).toBe('SOC Bell');
  expect(comp.getDestinationName('unknown-dest')).toBe('unknown-dest');
});

test('onAlarmStateUpdate inserts or updates alarm states in real time', () => {
  comp.states = [
    { alarmId: 'alarm-1', nodeId: 'node-1', status: 'ok', currentValue: '50.0' },
  ];

  // Update existing state
  comp.onAlarmStateUpdate({
    alarmId: 'alarm-1',
    nodeId: 'node-1',
    status: 'alarm',
    currentValue: '95.0',
  });

  expect(comp.states).toHaveLength(1);
  expect(comp.states[0].status).toBe('alarm');
  expect(comp.states[0].currentValue).toBe('95.0');

  // Insert new state
  comp.onAlarmStateUpdate({
    alarmId: 'alarm-2',
    nodeId: 'node-2',
    status: 'alarm',
    currentValue: '88.0',
  });

  expect(comp.states).toHaveLength(2);
  expect(comp.states[1].alarmId).toBe('alarm-2');
});
