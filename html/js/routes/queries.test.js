// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./queries.js');

let comp;

beforeEach(() => {
  comp = getComponent("queries");
  resetPapi();
});

test('loadData', async () => {
  resetPapi();
  var mock = mockPapi("get", { data: [{ taskId: '1', gridId: 'g1', details: 'd1', elapsedMs: 100 }] });
  comp.filterEnabled = true;
  await comp.loadData();
  expect(mock).toHaveBeenCalledWith('query/active', { params: { filter: 'true' } });
  expect(comp.queries).toEqual([{ taskId: '1', gridId: 'g1', details: 'd1', elapsedMs: 100 }]);

  comp.filterEnabled = false;
  mock = mockPapi("get", { data: [{ taskId: '1', gridId: 'g1', details: 'd1', elapsedMs: 100 }] });
  await comp.loadData();
  expect(mock).toHaveBeenCalledWith('query/active', { params: { filter: 'false' } });
});

test('cancelQuery', async () => {
  resetPapi();
  const mock = mockPapi("post");
  const queryTask = { taskId: '1', gridId: 'g1' };
  comp.showCancelQueryConfirm(queryTask);
  await comp.cancelQuery(queryTask);
  expect(mock).toHaveBeenCalledWith('query/cancel/1', { gridId: 'g1' });
});

test('saveLocalSettings', () => {
  comp.sortBy = [{ key: 'taskId', order: 'desc' }];
  comp.itemsPerPage = 50;
  comp.saveLocalSettings();
  expect(localStorage['settings.queries.sortBy']).toBe('taskId');
  expect(localStorage['settings.queries.sortDesc']).toBe('desc');
  expect(localStorage['settings.queries.itemsPerPage']).toBe('50');
});

test('loadLocalSettings', () => {
  localStorage['settings.queries.sortBy'] = 'gridId';
  localStorage['settings.queries.sortDesc'] = 'asc';
  localStorage['settings.queries.itemsPerPage'] = '250';
  comp.loadLocalSettings();
  expect(comp.sortBy).toEqual([{ key: 'gridId', order: 'asc' }]);
  expect(comp.itemsPerPage).toBe(250);
});

test('loadLocalSettings_defaults', () => {
  delete localStorage['settings.queries.sortBy'];
  delete localStorage['settings.queries.itemsPerPage'];
  comp.sortBy = [{ key: 'elapsedMs', order: 'asc' }];
  comp.itemsPerPage = 10;
  comp.loadLocalSettings();
  expect(comp.sortBy).toEqual([{ key: 'elapsedMs', order: 'asc' }]);
  expect(comp.itemsPerPage).toBe(10);
});
