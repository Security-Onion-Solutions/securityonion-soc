// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./automation-stop-dialog.js');

const fs = require('fs');
const path = require('path');

const tmpl = fs.readFileSync(path.resolve(__dirname, '../../pages/automation-stop-dialog.html'), 'utf8');

let comp;

beforeEach(() => {
  comp = getComponent('automation-stop-dialog');
  comp.i18n = comp.$root.i18n;
  comp.$emit = jest.fn();
});

function tag(dataAid) {
  const match = tmpl.match(new RegExp('<v-btn[^>]*data-aid="' + dataAid + '"[^>]*>', 'g'));
  expect(match).not.toBeNull();
  return match;
}

test('names the automation in the title', () => {
  comp.automationName = 'Alert Triage';
  expect(comp.title()).toBe('Stop the current run of Alert Triage?');
});

test.each([
  ['on', true, true],
  ['off', false, false],
  // Deleted: nothing to turn off.
  ['deleted', null, false],
])('turning off is offered when the automation is %s: %s -> %s', (_, enabled, expected) => {
  comp.automationEnabled = enabled;
  expect(comp.canTurnOff()).toBe(expected);
});

test('the turn-off button and the next-run lines depend on the automation being on', () => {
  expect(tag('automation_stop_dialog_stop_disable')[0]).toContain('v-if="canTurnOff()"');

  const turnOffLines = tmpl.match(/<template v-if="canTurnOff\(\)">([\s\S]*?)<\/template>/);
  expect(turnOffLines).not.toBeNull();
  expect(turnOffLines[1]).toContain('i18n.automationStopDialogNextRun');
  expect(turnOffLines[1]).toContain('i18n.automationStopDialogTurnOffHint');
  expect(turnOffLines[1]).not.toContain('automationStopDialogIntro');
  expect(turnOffLines[1]).not.toContain('automationStopDialogRequeue');

  expect(tag('automation_stop_dialog_stop')).toHaveLength(1);
  expect(tag('automation_stop_dialog_stop')[0]).toContain('v-bind="stopButtonProps()"');
  expect(tag('automation_stop_dialog_stop')[0]).not.toContain('v-if');
  expect(tag('automation_stop_dialog_cancel')[0]).not.toContain('v-if');
});

test.each([
  [true, { variant: 'text', color: 'primary' }],
  [false, { variant: 'flat', color: 'error' }],
  [null, { variant: 'flat', color: 'error' }],
])('with the automation enabled %s, Stop run is styled %o', (enabled, expected) => {
  comp.automationEnabled = enabled;
  expect(comp.stopButtonProps()).toEqual(expected);
});

test.each([false, true])('stop(%s) emits the turn-off choice and closes', (disable) => {
  comp.stop(disable);
  expect(comp.$emit).toHaveBeenNthCalledWith(1, 'stop', { disable });
  expect(comp.$emit).toHaveBeenNthCalledWith(2, 'update:modelValue', false);
});

test('cancel only closes', () => {
  comp.cancel();
  expect(comp.$emit).toHaveBeenCalledTimes(1);
  expect(comp.$emit).toHaveBeenCalledWith('update:modelValue', false);
});

test('focus starts on Cancel', () => {
  expect(tag('automation_stop_dialog_cancel')[0]).toContain('autofocus');
  expect(tmpl.match(/autofocus/g)).toHaveLength(1);
});

// Vuetify passes these from v-dialog to the overlay element that carries role="dialog".
test('the dialog is labelled by its title and described by its consequences', () => {
  const dialog = tmpl.match(/<v-dialog[^>]*>/)[0];
  expect(dialog).toContain('aria-labelledby="automation-stop-dialog-title"');
  expect(dialog).toContain('aria-describedby="automation-stop-dialog-text"');
  expect(dialog).toContain('data-aid="automation_stop_dialog"');

  expect(tmpl).toContain('id="automation-stop-dialog-title"');
  expect(tmpl).toContain('id="automation-stop-dialog-text"');
});
