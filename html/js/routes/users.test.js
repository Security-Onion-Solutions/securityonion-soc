// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./users.js');

let comp;

beforeEach(() => {
  comp = getComponent("users");
  resetPapi();
});

test('toggleStatus', async () => {
  const mock = mockPapi("put", {status: 200});
  const getUsersMock = mockPapi("get", [{id: 'my-id', status: 'unlocked'}]);
  await comp.toggleStatus({ id: 'my-id', status: 'locked'});
  expect(mock).toHaveBeenCalledWith('users/my-id/enable');
  expect(getUsersMock).toHaveBeenCalledTimes(1);
});

test('removeUser', async () => {
  const mock = mockPapi("delete", {status: 200});
  await comp.removeUser('my-id');
  expect(mock).toHaveBeenCalledWith('users/my-id');
});

test('updatePassword', async () => {
  const mock = mockPapi("put", {status: 200});
  comp.form.password = "test";
  await comp.updatePassword({id: 'my-id'});
  expect(mock).toHaveBeenCalledWith('users/my-id/password', {password:"test"});
});

test('removeRole', async () => {
  const mock = mockPapi("delete", {status: 200});
  const getUsersMock = mockPapi("get", [{id: 'my-id', status: 'unlocked'}]);
  await comp.removeRole({id: 'my-id'}, 'myrole');
  expect(mock).toHaveBeenCalledWith('users/my-id/role/myrole');
  expect(getUsersMock).toHaveBeenCalledTimes(1);
});

test('addRole', async () => {
  const mock = mockPapi("post", {status: 200});
  const getUsersMock = mockPapi("get", [{id: 'my-id', status: 'unlocked'}]);
  await comp.addRole({id: 'my-id'}, 'myrole');
  expect(mock).toHaveBeenCalledWith('users/my-id/role/myrole');
  expect(getUsersMock).toHaveBeenCalledTimes(1);
});

test('toggleRole_add', async () => {
  const mock = mockPapi("post", {status: 200});
  const getUsersMock = mockPapi("get", [{id: 'my-id', status: 'unlocked'}]);
  await comp.toggleRole({id: 'my-id', roles: []}, 'myrole');
  expect(mock).toHaveBeenCalledWith('users/my-id/role/myrole');
  expect(getUsersMock).toHaveBeenCalledTimes(1);
});

test('toggleRole_remove', async () => {
  const mock = mockPapi("delete", {status: 200});
  const getUsersMock = mockPapi("get", [{id: 'my-id', status: 'unlocked'}]);
  await comp.toggleRole({id: 'my-id', roles: ['myrole']}, 'myrole');
  expect(mock).toHaveBeenCalledWith('users/my-id/role/myrole');
  expect(getUsersMock).toHaveBeenCalledTimes(1);
});

test('updateProfile', async () => {
  const mock = mockPapi("put", {status: 200});
  const getUsersMock = mockPapi("get", [{id: 'my-id', status: 'unlocked'}]);
  comp.form.note = "my note";
  comp.form.firstName = "my first";
  comp.form.lastName = "my last";
  await comp.updateProfile({id: 'my-id'});
  expect(mock).toHaveBeenCalledWith('users/my-id', {firstName: 'my first', lastName: 'my last', note: 'my note'});
  expect(getUsersMock).toHaveBeenCalledTimes(1);
});

test('add', async () => {
  const mock = mockPapi("post", {status: 200});
  const getUsersMock = mockPapi("get", [{id: 'my-id', status: 'unlocked'}]);
  comp.form.email = "my email";
  comp.form.role = "my role";
  comp.form.password = "my pass";
  comp.form.note = "my note";
  comp.form.firstName = "my first";
  comp.form.lastName = "my last";
  await comp.add();
  expect(mock).toHaveBeenCalledWith('users/', {email: 'my email', roles: ['my role'], password: 'my pass', firstName: 'my first', lastName: 'my last', note: 'my note'});
  expect(getUsersMock).toHaveBeenCalledTimes(1);
});

test('hasRole', () => {
  expect(comp.hasRole(null, 'test')).toBe(false);
  expect(comp.hasRole({}, 'test')).toBe(false);
  expect(comp.hasRole({roles: null}, 'test')).toBe(false);
  expect(comp.hasRole({roles: []}, 'test')).toBe(false);
  expect(comp.hasRole({roles: ['foo']}, 'test')).toBe(false);
  expect(comp.hasRole({roles: ['foo','test']}, 'test')).toBe(true);
});