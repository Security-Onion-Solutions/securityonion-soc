// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./clients.js');

let comp;

beforeEach(() => {
  comp = getComponent("clients");
  resetPapi();
});

test('getClients400Error', async () => {
  const mock = mockPapi("get", null, {response: {status: 400}});
  await comp.getClients();
  expect(mock).toHaveBeenCalledTimes(1);
  expect(comp.$root.error).toBe(true);
  expect(comp.$root.errorMessage).toBe(comp.i18n.clientCheckHydraEnabled);
});

test('getClients500Error', async () => {
  const mock = mockPapi("get", null, "failed");
  await comp.getClients();
  expect(mock).toHaveBeenCalledTimes(1);
  expect(comp.$root.error).toBe(true);
  expect(comp.$root.errorMessage).toBe("failed");
});

test('removeClient', async () => {
  const mock = mockPapi("delete", {status: 200});
  await comp.removeClient('my-id');
  expect(mock).toHaveBeenCalledWith('clients/my-id');
});

test('generateSecret', async () => {
  const mock = mockPapi("put", {status: 200});
  comp.form.password = "test";
  await comp.generateSecret({id: 'my-id'});
  expect(mock).toHaveBeenCalledWith('clients/my-id/secret');
});

test('removePermission', async () => {
  const mock = mockPapi("delete", {status: 200});
  const getClientsMock = mockPapi("get", [{id: 'my-id'}]);
  await comp.removePermission({id: 'my-id'}, 'my', 'perm');
  expect(mock).toHaveBeenCalledWith('clients/my-id/permission/my/perm');
  expect(getClientsMock).toHaveBeenCalledTimes(1);
});

test('addPermission', async () => {
  const mock = mockPapi("post", {status: 200});
  const getClientsMock = mockPapi("get", [{id: 'my-id'}]);
  await comp.addPermission({id: 'my-id'}, 'my', 'perm');
  expect(mock).toHaveBeenCalledWith('clients/my-id/permission/my/perm');
  expect(getClientsMock).toHaveBeenCalledTimes(1);
});

test('togglePermission_add', async () => {
  const mock = mockPapi("post", {status: 200});
  const getClientsMock = mockPapi("get", [{id: 'my-id'}]);
  await comp.togglePermission({id: 'my-id', roles: []}, 'my', 'perm');
  expect(mock).toHaveBeenCalledWith('clients/my-id/permission/my/perm');
  expect(getClientsMock).toHaveBeenCalledTimes(1);
});

test('togglePermission_remove', async () => {
  const mock = mockPapi("delete", {status: 200});
  const getClientsMock = mockPapi("get", [{id: 'my-id'}]);
  await comp.togglePermission({id: 'my-id', permissions: ['my/perm']}, 'my', 'perm');
  expect(mock).toHaveBeenCalledWith('clients/my-id/permission/my/perm');
  expect(getClientsMock).toHaveBeenCalledTimes(1);
});

test('update', async () => {
  const mock = mockPapi("put", {status: 200});
  const getClientsMock = mockPapi("get", [{id: 'my-id'}]);
  comp.form.note = "my note";
  comp.form.name = "my name";
  comp.form.searchUsername = 'my un';
  await comp.update({id: 'my-id'});
  expect(mock).toHaveBeenCalledWith('clients/my-id', {name: 'my name', note: 'my note', searchUsername: 'my un'});
  expect(getClientsMock).toHaveBeenCalledTimes(1);
});

test('add', async () => {
  const mock = mockPapi("post", {status: 200});
  const getClientsMock = mockPapi("get", [{id: 'my-id'}]);
  comp.form.name = "name";
  comp.form.note = "my note";
  await comp.add();
  expect(mock).toHaveBeenCalledWith('clients/', {name: 'name', note: 'my note'});
  expect(getClientsMock).toHaveBeenCalledTimes(1);
});

test('hasPermission', () => {
  expect(comp.hasPermission(null, 'test')).toBe(false);
  expect(comp.hasPermission({}, 'test')).toBe(false);
  expect(comp.hasPermission({permissions: null}, 'test')).toBe(false);
  expect(comp.hasPermission({permissions: []}, 'test')).toBe(false);
  expect(comp.hasPermission({permissions: ['foo']}, 'test')).toBe(false);
  expect(comp.hasPermission({permissions: ['foo/bar','test/this']}, 'test', 'this')).toBe(true);
});