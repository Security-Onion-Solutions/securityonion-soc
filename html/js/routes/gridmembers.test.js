// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./gridmembers.js');

let comp;

beforeEach(() => {
  comp = getComponent("gridmembers");
  resetPapi();
});

test('show', () => {
  const node = {id: '123'}
  comp.show(node);
  expect(comp.dialog).toBe(true);
  comp.hide();
  expect(comp.dialog).toBe(false);
  expect(comp.selected).toBe(node);
});

test('isUnaccepted', () => {
  const node = {id: '123', status: "accepted"};
  expect(comp.isUnaccepted(node)).toBe(false);

  node.status = "unaccepted";
  expect(comp.isUnaccepted(node)).toBe(true);
});

test('colorNodeStatus', () => {
  expect(comp.colorNodeStatus("unaccepted")).toBe("gray");
  expect(comp.colorNodeStatus("unsupported")).toBe("gray");
  expect(comp.colorNodeStatus("accepted")).toBe("success");
  expect(comp.colorNodeStatus("rejected")).toBe("error");
  expect(comp.colorNodeStatus("denied")).toBe("warning");
});

test('loadData', async () => {
  data = [];
  data.push({id:'a', status:'accepted'});
  data.push({id:'u', status:'unaccepted'});
  data.push({id:'r', status:'rejected'});
  data.push({id:'d', status:'denied'});
  const loadmock = mockPapi("get", { data: data });
  await comp.loadData();
  expect(loadmock).toHaveBeenCalledWith('gridmembers/');
  expect(comp.accepted[0]).toBe(data[0]);
  expect(comp.unaccepted[0]).toBe(data[1]);
  expect(comp.rejected[0]).toBe(data[2]);
  expect(comp.denied[0]).toBe(data[3]);
});

test('accept', async () => {
  const node = {id: '123', status: "unaccepted"};
  const mock = mockPapi("post");
  const loadmock = mockPapi("get");
  await comp.accept(node);
  expect(mock).toHaveBeenCalledWith('gridmembers/123/add');
  expect(loadmock).toHaveBeenCalledWith('gridmembers/');
});

test('reject', async () => {
  const node = {id: '123', status: "unaccepted"};
  const mock = mockPapi("post");
  const loadmock = mockPapi("get");
  await comp.reject(node);
  expect(mock).toHaveBeenCalledWith('gridmembers/123/reject');
  expect(loadmock).toHaveBeenCalledWith('gridmembers/');
});

test('remove', async () => {
  const node = {id: '123', status: "unaccepted"};
  const mock = mockPapi("post");
  const loadmock = mockPapi("get");
  await comp.remove(node);
  expect(mock).toHaveBeenCalledWith('gridmembers/123/delete');
  expect(loadmock).toHaveBeenCalledWith('gridmembers/');
});