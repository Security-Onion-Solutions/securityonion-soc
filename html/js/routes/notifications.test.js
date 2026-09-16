// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('../components/schedules-manager.js');
require('./notifications.js');

let comp;

beforeEach(() => {
  comp = getComponent('notifications');
  resetPapi();
});

test('initializes with default tab and delegates refresh', () => {
  expect(comp.tab).toBe('schedules');

  const loadDataMock = jest.fn();
  comp.$refs = {
    schedulesManager: {
      loadData: loadDataMock,
    },
  };

  comp.refresh();
  expect(loadDataMock).toHaveBeenCalled();
});
