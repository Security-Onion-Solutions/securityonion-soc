// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./schedules-manager.js');

let comp;

beforeEach(() => {
  comp = getComponent('schedules-manager');
  resetPapi();
});

test('getSchedules success', async () => {
  const mockData = [
    {
      id: 'sch-1',
      name: 'Work Hours',
      description: 'Standard work hours',
      enabled: true,
      timezone: 'UTC',
      definitions: [
        {
          type: 'weekly',
          daysOfWeek: [1, 2, 3, 4, 5],
          startTime: '08:00',
          endTime: '17:00',
        },
      ],
    },
  ];
  const mock = mockPapi('get', mockData);
  await comp.getSchedules();
  expect(mock).toHaveBeenCalledWith('schedules/');
  expect(comp.schedules).toEqual(mockData);
});

test('getSchedules error handling', async () => {
  mockPapi('get', null, 'Failed to fetch schedules');
  await comp.getSchedules();
  expect(comp.$root.error).toBe(true);
  expect(comp.$root.errorMessage).toBe('Failed to fetch schedules');
});

test('showAddSchedule initializes form', () => {
  comp.showAddSchedule();
  expect(comp.scheduleDialog).toBe(true);
  expect(comp.form.isEdit).toBe(false);
  expect(comp.form.id).toBe('');
  expect(comp.form.enabled).toBe(true);
  expect(comp.form.excludeScheduleIds).toEqual([]);
  expect(comp.form.definitions.length).toBe(1);
});

test('showEditSchedule sets up edit mode', () => {
  const sched = {
    id: 'sch-1',
    name: 'My Sched',
    description: 'Desc',
    enabled: false,
    timezone: 'America/New_York',
    excludeScheduleIds: ['sch-holiday'],
    definitions: [{ type: 'daily', allDay: true }],
  };
  comp.showEditSchedule(sched);
  expect(comp.scheduleDialog).toBe(true);
  expect(comp.form.isEdit).toBe(true);
  expect(comp.form.id).toBe('sch-1');
  expect(comp.form.name).toBe('My Sched');
  expect(comp.form.enabled).toBe(false);
  expect(comp.form.timezone).toBe('America/New_York');
  expect(comp.form.excludeScheduleIds).toEqual(['sch-holiday']);
  expect(comp.form.definitions.length).toBe(1);
});

test('duplicateSchedule creates copy with suffixed name', () => {
  const sched = {
    id: 'sch-1',
    name: 'My Sched',
    enabled: true,
    timezone: 'UTC',
    excludeScheduleIds: ['sch-holiday'],
    definitions: [{ type: 'daily', allDay: true }],
  };
  comp.duplicateSchedule(sched);
  expect(comp.scheduleDialog).toBe(true);
  expect(comp.form.isEdit).toBe(false);
  expect(comp.form.id).toBe('');
  expect(comp.form.name).toBe('My Sched (Copy)');
  expect(comp.form.excludeScheduleIds).toEqual(['sch-holiday']);
});

test('addDefinition and removeDefinition', () => {
  comp.form.definitions = [];
  comp.addDefinition();
  expect(comp.form.definitions.length).toBe(1);
  comp.addDefinition();
  expect(comp.form.definitions.length).toBe(2);
  comp.removeDefinition(0);
  expect(comp.form.definitions.length).toBe(1);
});

test('saveSchedule create (POST)', async () => {
  const postMock = mockPapi('post', { status: 200 });
  const getMock = mockPapi('get', []);
  comp.form = {
    isEdit: false,
    id: 'new-sch',
    name: 'New Schedule',
    description: 'Description',
    enabled: true,
    timezone: 'UTC',
    excludeScheduleIds: ['holiday-sched'],
    definitions: [
      {
        type: 'weekly',
        allDay: false,
        startTime: '09:00',
        endTime: '17:00',
        daysOfWeek: [1, 2, 3],
      },
    ],
  };
  await comp.saveSchedule();
  expect(postMock).toHaveBeenCalledWith('schedules/', expect.objectContaining({
    id: 'new-sch',
    name: 'New Schedule',
    excludeScheduleIds: ['holiday-sched'],
  }));
  expect(getMock).toHaveBeenCalled();
  expect(comp.scheduleDialog).toBe(false);
});

test('saveSchedule update (PUT)', async () => {
  const putMock = mockPapi('put', { status: 200 });
  const getMock = mockPapi('get', []);
  comp.form = {
    isEdit: true,
    id: 'sch-1',
    name: 'Updated Name',
    description: 'Updated Desc',
    enabled: false,
    timezone: 'UTC',
    excludeScheduleIds: [],
    definitions: [{ type: 'daily', allDay: true }],
  };
  await comp.saveSchedule();
  expect(putMock).toHaveBeenCalledWith('schedules/sch-1', expect.objectContaining({
    id: 'sch-1',
    name: 'Updated Name',
  }));
  expect(getMock).toHaveBeenCalled();
  expect(comp.scheduleDialog).toBe(false);
});

test('deleteSchedule flow', async () => {
  const deleteMock = mockPapi('delete', { status: 200 });
  const getMock = mockPapi('get', []);
  const sched = { id: 'sch-to-delete', name: 'Delete Me' };
  comp.showDeleteSchedule(sched);
  expect(comp.deleteScheduleDialog).toBe(true);
  expect(comp.scheduleToDelete).toBe(sched);

  await comp.deleteSchedule();
  expect(deleteMock).toHaveBeenCalledWith('schedules/sch-to-delete');
  expect(getMock).toHaveBeenCalled();
  expect(comp.deleteScheduleDialog).toBe(false);
  expect(comp.scheduleToDelete).toBe(null);
});

test('formatScheduleSummary and formatDefinitionSummary', () => {
  expect(comp.formatScheduleSummary(null)).toBe('Always Active');
  expect(comp.formatScheduleSummary({ definitions: [] })).toBe('Always Active');

  const defDaily = { type: 'daily', allDay: true };
  expect(comp.formatDefinitionSummary(defDaily)).toContain('Daily (All Day)');

  const defWeekly = {
    type: 'weekly',
    allDay: false,
    startTime: '08:00',
    endTime: '17:00',
    daysOfWeek: [1, 2, 3, 4, 5],
  };
  expect(comp.formatDefinitionSummary(defWeekly)).toContain('Weekly: Mon, Tue, Wed, Thu, Fri (08:00 - 17:00)');

  const defMonthly = {
    type: 'monthly',
    allDay: true,
    daysOfMonth: [1, 15, -1],
  };
  expect(comp.formatDefinitionSummary(defMonthly)).toContain('Monthly: Day 1, Day 15, Last Day of Month (All Day)');

  const defAnnual = {
    type: 'annually',
    allDay: true,
    months: [12],
    daysOfMonth: [25],
  };
  expect(comp.formatDefinitionSummary(defAnnual)).toContain('Annually: Dec, Day 25 (All Day)');
});

test('formatScheduleSummary includes exception schedules', () => {
  comp.schedules = [
    { id: 'holidays', name: 'US Holidays' },
    { id: 'convention', name: 'Annual Convention' },
  ];

  const sched = {
    definitions: [
      {
        type: 'weekly',
        daysOfWeek: [1, 2, 3, 4, 5],
        allDay: false,
        startTime: '08:00',
        endTime: '17:00',
      },
    ],
    excludeScheduleIds: ['holidays', 'convention'],
  };

  const summary = comp.formatScheduleSummary(sched);
  expect(summary).toContain('Weekly: Mon, Tue, Wed, Thu, Fri (08:00 - 17:00)');
  expect(summary).toContain('(Exceptions: US Holidays, Annual Convention)');
});

test('eligibleExceptionSchedules filters out self and transitive cycles at any depth', () => {
  const allSchedules = [
    { id: 'sch-1', name: 'Schedule 1', excludeScheduleIds: [] },
    { id: 'sch-2', name: 'Schedule 2', excludeScheduleIds: ['sch-1'] },
    { id: 'sch-3', name: 'Schedule 3', excludeScheduleIds: ['sch-2'] },
    { id: 'sch-4', name: 'Schedule 4', excludeScheduleIds: [] },
  ];
  comp.schedules = allSchedules;

  comp.form.id = 'sch-1';
  const eligibleFor1 = comp.eligibleExceptionSchedules();
  expect(eligibleFor1.map(s => s.id)).toEqual(['sch-4']);

  comp.form.id = 'sch-2';
  const eligibleFor2 = comp.eligibleExceptionSchedules();
  expect(eligibleFor2.map(s => s.id)).toEqual(['sch-1', 'sch-4']);

  comp.form.id = '';
  const eligibleNew = comp.eligibleExceptionSchedules();
  expect(eligibleNew.map(s => s.id)).toEqual(['sch-1', 'sch-2', 'sch-3', 'sch-4']);
});

test('isScheduleActive helper with exclusions and cycle handling', () => {
  expect(comp.isScheduleActive({ enabled: true, definitions: [] })).toBe(true);
  expect(comp.isScheduleActive({ enabled: false, definitions: [{ type: 'daily', allDay: true }] })).toBe(false);
  expect(comp.isScheduleActive({ enabled: true, timezone: 'UTC', definitions: [{ type: 'daily', allDay: true }] })).toBe(true);

  const holidays = {
    id: 'holidays',
    enabled: true,
    timezone: 'UTC',
    definitions: [
      {
        type: 'annually',
        months: [12],
        daysOfMonth: [25],
        allDay: true,
      },
    ],
  };

  const workWeek = {
    id: 'work-week',
    enabled: true,
    timezone: 'UTC',
    definitions: [
      {
        type: 'weekly',
        daysOfWeek: [1, 2, 3, 4, 5],
        allDay: false,
        startTime: '08:00',
        endTime: '17:00',
      },
    ],
    excludeScheduleIds: ['holidays'],
  };

  const schedules = [holidays, workWeek];

  const nowMonday = new Date(Date.UTC(2026, 8, 14, 10, 0, 0));
  expect(comp.isScheduleActive(workWeek, nowMonday, schedules)).toBe(true);

  const nowChristmas = new Date(Date.UTC(2026, 11, 25, 10, 0, 0));
  expect(comp.isScheduleActive(workWeek, nowChristmas, schedules)).toBe(false);

  holidays.enabled = false;
  expect(comp.isScheduleActive(workWeek, nowChristmas, schedules)).toBe(true);

  const schedA = { id: 'A', enabled: true, definitions: [{ type: 'daily', allDay: true }], excludeScheduleIds: ['B'] };
  const schedB = { id: 'B', enabled: true, definitions: [{ type: 'daily', allDay: true }], excludeScheduleIds: ['A'] };
  expect(() => comp.isScheduleActive(schedA, nowMonday, [schedA, schedB])).not.toThrow();
});

test('detectBrowserTimezone falls back gracefully', () => {
  comp.form.timezone = '';
  comp.detectBrowserTimezone();
  expect(comp.form.timezone).toBeTruthy();
});
