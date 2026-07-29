// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./case-details-col.js');

let comp;

beforeEach(() => {
  comp = getComponent("CaseDetailsCol");
});

test('isEdit', () => {
  comp.editForm = { roId: 'case-status' };
  expect(comp.isEdit('case-status')).toBe(true);
  expect(comp.isEdit('case-tlp')).toBe(false);

  comp.editForm = {};
  expect(comp.isEdit('case-status')).toBe(false);
});

test('startEdit populates editForm and registers keyup listener', async () => {
  const addSpy = jest.spyOn(window, 'addEventListener');
  document.body.innerHTML = '<input id="case-status-input" />';

  await comp.startEdit('case-status-input', 'New', 'case-status', 'status', false);

  expect(comp.editForm.focusId).toBe('case-status-input');
  expect(comp.editForm.orig).toBe('New');
  expect(comp.editForm.val).toBe('New');
  expect(comp.editForm.roId).toBe('case-status');
  expect(comp.editForm.field).toBe('status');
  expect(comp.editForm.isMultiline).toBe(false);
  expect(comp.editForm.valid).toBe(true);
  expect(addSpy).toHaveBeenCalledWith('keyup', comp.onEditKeyUp);

  addSpy.mockRestore();
  document.body.innerHTML = '';
});

test('startEdit is a no-op when focusId already matches', async () => {
  comp.editForm = { focusId: 'case-status-input', val: 'Existing' };

  await comp.startEdit('case-status-input', 'Other', 'case-status', 'status', false);

  expect(comp.editForm.val).toBe('Existing');
});

test('startEdit aborts when current edit is invalid', async () => {
  comp.editForm = { valid: false, field: 'priority', orig: 1, val: 'bad', focusId: 'old' };

  await comp.startEdit('case-status-input', 'New', 'case-status', 'status', false);

  expect(comp.editForm.field).toBe('priority');
  expect(comp.editForm.focusId).toBe('old');
});

test('stopEdit without commit clears editForm and removes listener', async () => {
  const removeSpy = jest.spyOn(window, 'removeEventListener');
  comp.editForm = { valid: true, field: 'status', orig: 'a', val: 'b' };

  const result = await comp.stopEdit();

  expect(result).toBe(true);
  expect(comp.editForm).toEqual({ valid: true });
  expect(comp.emit).not.toHaveBeenCalled();
  expect(removeSpy).toHaveBeenCalledWith('keyup', comp.onEditKeyUp);

  removeSpy.mockRestore();
});

test('stopEdit with commit emits save when value changed', async () => {
  comp.editForm = { valid: true, field: 'status', orig: 'a', val: 'b' };

  const result = await comp.stopEdit(true);

  expect(result).toBe(true);
  expect(comp.emit).toHaveBeenCalledWith('save', { field: 'status', value: 'b' });
  expect(comp.editForm).toEqual({ valid: true });
});

test('stopEdit with commit does not emit when value unchanged', async () => {
  comp.editForm = { valid: true, field: 'status', orig: 'a', val: 'a' };

  const result = await comp.stopEdit(true);

  expect(result).toBe(true);
  expect(comp.emit).not.toHaveBeenCalled();
});

test('stopEdit with commit on invalid form returns false and preserves form', async () => {
  comp.editForm = { valid: false, field: 'priority', orig: 1, val: 'bad' };

  const result = await comp.stopEdit(true);

  expect(result).toBe(false);
  expect(comp.editForm.field).toBe('priority');
  expect(comp.emit).not.toHaveBeenCalled();
});

test('onEditKeyUp Escape stops edit without committing', () => {
  comp.stopEdit = jest.fn();
  comp.onEditKeyUp({ key: 'Escape' });
  expect(comp.stopEdit).toHaveBeenCalledWith();
});

test('onEditKeyUp Enter commits when not multiline', () => {
  comp.stopEdit = jest.fn();
  comp.editForm = { isMultiline: false };
  comp.onEditKeyUp({ key: 'Enter' });
  expect(comp.stopEdit).toHaveBeenCalledWith(true);
});

test('onEditKeyUp Enter is ignored when multiline', () => {
  comp.stopEdit = jest.fn();
  comp.editForm = { isMultiline: true };
  comp.onEditKeyUp({ key: 'Enter' });
  expect(comp.stopEdit).not.toHaveBeenCalled();
});

test.each([
  ['hello', 'fallback', 'hello'],
  [42, 'fallback', 42],
  [['x'], 'fallback', ['x']],
  [null, 'fallback', 'fallback'],
  [undefined, 'fallback', 'fallback'],
  ['', 'fallback', 'fallback'],
])('withDefault(%p, %p) -> %p', (value, deflt, expected) => {
  expect(comp.withDefault(value, deflt)).toEqual(expected);
});

test('getPresets returns labels when preset exists', () => {
  comp.presets = { status: { labels: ['Open', 'Closed'] } };
  expect(comp.getPresets('status')).toEqual(['Open', 'Closed']);
});

test('getPresets returns empty array when preset is missing', () => {
  comp.presets = {};
  expect(comp.getPresets('status')).toEqual([]);

  comp.presets = null;
  expect(comp.getPresets('status')).toEqual([]);
});

test('isPresetCustomEnabled', () => {
  comp.presets = {
    status: { customEnabled: true },
    tlp:    { customEnabled: false },
    pap:    {},
  };
  expect(comp.isPresetCustomEnabled('status')).toBe(true);
  expect(comp.isPresetCustomEnabled('tlp')).toBe(false);
  expect(comp.isPresetCustomEnabled('pap')).toBe(false);
  expect(comp.isPresetCustomEnabled('missing')).toBe(false);

  comp.presets = null;
  expect(comp.isPresetCustomEnabled('status')).toBe(false);
});

test('selectList returns presets only when customEnabled is false', () => {
  comp.presets = { status: { labels: ['Open', 'Closed'], customEnabled: false } };
  expect(comp.selectList('status', 'New')).toEqual(['Open', 'Closed']);
});

test('selectList appends scalar value when customEnabled and not already present', () => {
  comp.presets = { status: { labels: ['Open', 'Closed'], customEnabled: true } };
  expect(comp.selectList('status', 'New')).toEqual(['Open', 'Closed', 'New']);
  expect(comp.selectList('status', 'Open')).toEqual(['Open', 'Closed']);
  expect(comp.selectList('status', '')).toEqual(['Open', 'Closed']);
});

test('selectList merges array values when customEnabled', () => {
  comp.presets = { tags: { labels: ['a', 'b'], customEnabled: true } };
  expect(comp.selectList('tags', ['b', 'c', 'd'])).toEqual(['a', 'b', 'c', 'd']);
});


test('mounted populates userList from $root.getActiveUsers', async () => {
  const users = [{ id: 'u1', email: 'a@b.c' }];
  comp.$root.getActiveUsers = jest.fn().mockResolvedValue(users);

  await comp.mounted();

  expect(comp.userList).toBe(users);
  expect(comp.$root.getActiveUsers).toHaveBeenCalled();
});

test('beforeUnmount removes the keyup listener', () => {
  const removeSpy = jest.spyOn(window, 'removeEventListener');

  comp.beforeUnmount();

  expect(removeSpy).toHaveBeenCalledWith('keyup', comp.onEditKeyUp);
  removeSpy.mockRestore();
});
