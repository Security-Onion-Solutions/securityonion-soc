// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { actionMethods } from './actions.js';

let mockThis;

beforeEach(() => {
  mockThis = {
    $root: {
      papi: {
        post: jest.fn(),
        get: jest.fn(),
      },
      startLoading: jest.fn(),
      stopLoading: jest.fn(),
      showError: jest.fn(),
      showTip: jest.fn(),
      showWarning: jest.fn(),
      showInfo: jest.fn(),
    },
    i18n: {
      eventCaseTitle: 'Event Escalation from SOC',
      caseEscalatedDescription: 'This event has been escalated to a case.',
      bulkActionStarted: 'Updating {total} detections. This may take awhile.',
      bulkActionDeleteStarted: 'Deleting {total} detections. This may take awhile.',
      bulkError: '{error} error(s) arose during a bulk operation. Please check the SOC logs for more information.',
      bulkSuccessFiltered: 'Bulk update successfully updated {modified} of {total} events. However, the statuses of {filtered} of the updated detections are controlled by the current regex filter settings and were reverted. <a href="/#/config?s=soc.config.server.modules.suricataengine" data-aid="warning_bulk_update_configure_filters">Click here to configure those filters.</a> ({time})',
      bulkSuccessUpdate: 'Bulk update successfully updated {modified} of {total} events. ({time})',
      bulkSuccessDelete: 'Bulk delete successfully deleted {modified} of {total} events. ({time})',
      ERROR_BULK_COMMUNITY: 'ERROR_BULK_COMMUNITY'
    },
    hunt: jest.fn(),
    formatSafeString: (str) => str,
    // Component data
    selectedAction: '',
    showBulkDeleteConfirmDialog: false,
    selectAllState: false,
    selectAllIndeterminate: false,
    eventData: [],
    query: '',
    selectedCount: 0,
  };
});

function validateCase(
    name, template, mod, dataset, severity, message,
    expectedTitle, expectedDescription, expectedSeverity, expectedTemplate) {
  const item = {
    "rule.name": name,
    "rule.case_template": template,
    "event.module": mod,
    "event.dataset": dataset,
    "event.severity": severity,
    "message": message,
  };
  const caseObj = actionMethods.buildCase.call(mockThis, item)
  expect(caseObj.title).toBe(expectedTitle);
  expect(caseObj.description).toBe(expectedDescription);
  expect(caseObj.severity).toBe(expectedSeverity);
  expect(caseObj.template).toBe(expectedTemplate);
}

test('buildCase', () => {
  mockThis.escalateRelatedEventsEnabled = true;

  // has rule name and message, etc (happy path)
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'myTitle', mockThis.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name, module, and dataset
  validateCase('', 'myTemplate', '', '', 'mySeverity', 'myMessage',
      'Event Escalation from SOC', mockThis.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has module
  validateCase('', 'myTemplate', 'myModule', '', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule', mockThis.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has dataset
  validateCase('', 'myTemplate', '', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myDataset', mockThis.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has module and dataset
  validateCase('', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule - myDataset', mockThis.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');
  validateCase(null, 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule - myDataset', mockThis.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing message
  mockThis.escalateRelatedEventsEnabled = false;
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', '',
      'myTitle', '{\"rule.name\":\"myTitle\",\"rule.case_template\":\"myTemplate\",\"event.module\":\"myModule\",\"event.dataset\":\"myDataset\",\"event.severity\":\"mySeverity\",\"message\":\"\"}', 'mySeverity', 'myTemplate');

  mockThis.escalateRelatedEventsEnabled = true;
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', '',
      'myTitle', mockThis.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing severity
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', '', 'myMessage',
      'myTitle', mockThis.i18n.caseEscalatedDescription, '', 'myTemplate');

  // missing template
  validateCase('myTitle', '', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'myTitle', mockThis.i18n.caseEscalatedDescription, 'mySeverity', '');

});

test('bulkAction - delete - pre-confirm', async () => {
  mockThis.selectedAction = 'delete';
  mockThis.selectedCount = 2;

  await actionMethods.bulkAction.call(mockThis);

  expect(mockThis.showBulkDeleteConfirmDialog).toBe(true);
  expect(mockThis.selectedCount).toBe(2);
});

test('bulkAction - enable', async () => {
  mockThis.selectedAction = 'enable';
  mockThis.selectedCount = 2;
  mockThis.selectAllIndeterminate = true;
  mockThis.eventData = [{ _isSelected: true, soc_id: "1" }, { _isSelected: false, soc_id: "2" }, { _isSelected: true, soc_id: "3" }];
  mockThis.$root.papi.post.mockResolvedValue({ data: { count: 2 } });

  await actionMethods.bulkAction.call(mockThis, true);

  expect(mockThis.showBulkDeleteConfirmDialog).toBe(false);
  expect(mockThis.selectAllState).toBe(false);
  expect(mockThis.selectedCount).toBe(0);
  expect(mockThis.$root.papi.post).toHaveBeenCalledTimes(1);
  expect(mockThis.$root.papi.post).toHaveBeenCalledWith('detection/bulk/enable', { ids: ["1", "3"] });
  expect(mockThis.hunt).toHaveBeenCalledTimes(1);
  expect(mockThis.hunt).toHaveBeenCalledWith(false);
  expect(mockThis.$root.showTip).toHaveBeenCalledWith('Updating 2 detections. This may take awhile.');
});

test('bulkAction - disable', async () => {
  mockThis.selectedAction = 'disable';
  mockThis.selectedCount = 2;
  mockThis.selectAllIndeterminate = true;
  mockThis.eventData = [{ _isSelected: true, soc_id: "1" }, { _isSelected: false, soc_id: "2" }, { _isSelected: true, soc_id: "3" }];
  mockThis.$root.papi.post.mockResolvedValue({ data: { count: 2 } });

  await actionMethods.bulkAction.call(mockThis, true);

  expect(mockThis.showBulkDeleteConfirmDialog).toBe(false);
  expect(mockThis.selectAllState).toBe(false);
  expect(mockThis.selectedCount).toBe(0);
  expect(mockThis.$root.papi.post).toHaveBeenCalledTimes(1);
  expect(mockThis.$root.papi.post).toHaveBeenCalledWith('detection/bulk/disable', { ids: ["1", "3"] });
  expect(mockThis.hunt).toHaveBeenCalledTimes(1);
  expect(mockThis.hunt).toHaveBeenCalledWith(false);
  expect(mockThis.$root.showTip).toHaveBeenCalledWith('Updating 2 detections. This may take awhile.');
});

test('bulkAction - delete - confirm - success', async () => {
  mockThis.selectedAction = 'delete';
  mockThis.showBulkDeleteConfirmDialog = true;
  mockThis.selectedCount = 2;
  mockThis.selectAllIndeterminate = true;
  mockThis.eventData = [{ _isSelected: true, soc_id: "1" }, { _isSelected: false, soc_id: "2" }, { _isSelected: true, soc_id: "3" }];
  mockThis.$root.papi.post.mockResolvedValue({ data: { count: 2 } });

  await actionMethods.bulkAction.call(mockThis, true);

  expect(mockThis.showBulkDeleteConfirmDialog).toBe(false);
  expect(mockThis.selectAllState).toBe(false);
  expect(mockThis.selectedCount).toBe(0);
  expect(mockThis.$root.papi.post).toHaveBeenCalledTimes(1);
  expect(mockThis.$root.papi.post).toHaveBeenCalledWith('detection/bulk/delete', { ids: ["1", "3"] });
  expect(mockThis.hunt).toHaveBeenCalledTimes(1);
  expect(mockThis.hunt).toHaveBeenCalledWith(false);
  expect(mockThis.$root.showTip).toHaveBeenCalledWith('Deleting 2 detections. This may take awhile.');
});

test('bulkAction - delete - confirm - failure', async () => {
  mockThis.selectedAction = 'delete';
  mockThis.showBulkDeleteConfirmDialog = true;
  mockThis.selectedCount = 2;
  mockThis.selectAllIndeterminate = true;
  mockThis.eventData = [{ _isSelected: true, soc_id: "1" }, { _isSelected: false, soc_id: "2" }, { _isSelected: true, soc_id: "3" }];
  const err = { response: { data: "ERROR_BULK_COMMUNITY" } };
  mockThis.$root.papi.post.mockRejectedValue(err);

  await actionMethods.bulkAction.call(mockThis, true);

  expect(mockThis.showBulkDeleteConfirmDialog).toBe(false);
  expect(mockThis.selectAllState).toBe(false);
  expect(mockThis.selectAllIndeterminate).toBe(true);
  expect(mockThis.selectedCount).toBe(2);
  expect(mockThis.$root.papi.post).toHaveBeenCalledTimes(1);
  expect(mockThis.$root.papi.post).toHaveBeenCalledWith('detection/bulk/delete', { ids: ["1", "3"] });
  expect(mockThis.$root.showError).toHaveBeenCalledWith(err);
});

test('bulkUpdateReport - error', () => {
  let stats = {
    error: 1,
  };

  actionMethods.bulkUpdateReport.call(mockThis, stats)

  expect(mockThis.$root.showError).toHaveBeenCalledWith('1 error(s) arose during a bulk operation. Please check the SOC logs for more information.');
});

test('bulkUpdateReport - update success', () => {
  let stats = {
    time: 10,
    filtered: 0,
    verb: 'update',
    modified: 2,
    total: 2,
  };

  actionMethods.bulkUpdateReport.call(mockThis, stats)

  expect(mockThis.$root.showInfo).toHaveBeenCalledWith('Bulk update successfully updated 2 of 2 events. (10s)', true);
});

test('bulkUpdateReport - delete success', () => {
  let stats = {
    time: 1000,
    filtered: 0,
    verb: 'delete',
    modified: 200,
    total: 200,
  };

  actionMethods.bulkUpdateReport.call(mockThis, stats)

  expect(mockThis.$root.showInfo).toHaveBeenCalledWith('Bulk delete successfully deleted 200 of 200 events. (16m 40s)', true);
});

test('bulkUpdateReport - filtered success', () => {
  let stats = {
    time: 200,
    filtered: 1,
    verb: 'update',
    modified: 20,
    total: 20,
  };

  actionMethods.bulkUpdateReport.call(mockThis, stats)

  expect(mockThis.$root.showWarning).toHaveBeenCalledWith('Bulk update successfully updated 20 of 20 events. However, the statuses of 1 of the updated detections are controlled by the current regex filter settings and were reverted. <a href="/#/config?s=soc.config.server.modules.suricataengine" data-aid="warning_bulk_update_configure_filters">Click here to configure those filters.</a> (3m 20s)', true);
});