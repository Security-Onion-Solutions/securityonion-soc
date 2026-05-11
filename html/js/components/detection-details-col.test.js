// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./detection-details-col.js');

let comp;

beforeEach(() => {
  resetPapi();
  comp = getComponent("DetectionDetailsCol");
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.showTip = jest.fn();
  comp.$root.showError = jest.fn();
});

test('initial data', () => {
  expect(comp.panel).toEqual([0, 1, 2]);
  expect(comp.confirmDeleteDialog).toBe(false);
  expect(comp.i18n).toBe(comp.$root.i18n);
});

test('isNew is true only when route id is "create"', () => {
  comp.$route.params.id = 'create';
  expect(comp.isNew()).toBe(true);

  comp.$route.params.id = 'abc-123';
  expect(comp.isNew()).toBe(false);

  comp.$route.params.id = '';
  expect(comp.isNew()).toBe(false);
});

test('deleteDetection opens the confirmation dialog', () => {
  expect(comp.confirmDeleteDialog).toBe(false);
  comp.deleteDetection();
  expect(comp.confirmDeleteDialog).toBe(true);
});

test('cancelDeleteDetection closes the confirmation dialog', () => {
  comp.confirmDeleteDialog = true;
  comp.cancelDeleteDetection();
  expect(comp.confirmDeleteDialog).toBe(false);
});

test('confirmDeleteDetection deletes, navigates, and shows tip on success', async () => {
  const deleteMock = jest.fn().mockReturnValue(Promise.resolve({ data: [] }));
  comp.$root.papi.delete = deleteMock;
  comp.$route.params.id = 'testid';
  comp.confirmDeleteDialog = true;

  await comp.confirmDeleteDetection();

  expect(comp.confirmDeleteDialog).toBe(false);
  expect(deleteMock).toHaveBeenCalledWith('/detection/testid');
  expect(comp.$router.length).toBe(1);
  expect(comp.$router[0]).toEqual({ name: 'detections' });
  expect(comp.$root.showTip).toHaveBeenCalledWith(comp.i18n.detectionDeleteSuccessful);
  expect(comp.$root.showError).not.toHaveBeenCalled();
  expect(comp.$root.startLoading).toHaveBeenCalled();
  expect(comp.$root.stopLoading).toHaveBeenCalled();
});

test('confirmDeleteDetection url-encodes the route id', async () => {
  const deleteMock = jest.fn().mockReturnValue(Promise.resolve({ data: [] }));
  comp.$root.papi.delete = deleteMock;
  comp.$route.params.id = 'has spaces/and+symbols';

  await comp.confirmDeleteDetection();

  expect(deleteMock).toHaveBeenCalledWith('/detection/has%20spaces%2Fand%2Bsymbols');
});

test('confirmDeleteDetection shows error and skips navigation on failure', async () => {
  const err = new Error('boom');
  comp.$root.papi.delete = jest.fn().mockImplementation(() => { throw err; });
  comp.$route.params.id = 'testid';
  comp.confirmDeleteDialog = true;

  await comp.confirmDeleteDetection();

  expect(comp.confirmDeleteDialog).toBe(false);
  expect(comp.$root.showError).toHaveBeenCalledWith(err);
  expect(comp.$router.length).toBe(0);
  expect(comp.$root.showTip).not.toHaveBeenCalled();
  expect(comp.$root.stopLoading).toHaveBeenCalled();
});
