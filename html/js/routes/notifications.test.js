// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('../components/destinations-manager.js');
require('../components/schedules-manager.js');
require('./notifications.js');

let comp;

beforeEach(() => {
  comp = getComponent('notifications');
  resetPapi();
});

test('initializes with default tab and delegates refresh', () => {
  expect(comp.tab).toBe('destinations');

  const loadDestDataMock = jest.fn();
  const loadSchedDataMock = jest.fn();
  comp.$refs = {
    destinationsManager: {
      loadData: loadDestDataMock,
    },
    schedulesManager: {
      loadData: loadSchedDataMock,
    },
  };

  comp.refresh();
  expect(loadDestDataMock).toHaveBeenCalled();
  expect(loadSchedDataMock).toHaveBeenCalled();
});

test('delegates add actions based on active tab', () => {
  const showAddDestMock = jest.fn();
  const showAddSchedMock = jest.fn();

  comp.$refs = {
    destinationsManager: {
      showAddDestination: showAddDestMock,
    },
    schedulesManager: {
      showAddSchedule: showAddSchedMock,
    },
  };

  comp.tab = 'destinations';
  comp.addDestination();
  expect(showAddDestMock).toHaveBeenCalled();
  expect(showAddSchedMock).not.toHaveBeenCalled();

  comp.tab = 'schedules';
  comp.addSchedule();
  expect(showAddSchedMock).toHaveBeenCalled();
});
