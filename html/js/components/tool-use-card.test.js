// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./tool-use-card.js');

// The component has no data(), so getComponent() can't build it; call the computed directly.
const computed = global.components.find(c => c.name === 'tool-use-card').component.computed;
const app = getApp();

const errorText = (toolUse) => computed.errorText.call({ toolUse, ctx: { i18n: app.i18n }, $root: app });

test('errorText shows the reject key for a rejected tool', () => {
  expect(errorText({ status: 'rejected', error: 'Tool execution was rejected by the user.' })).toBe(app.i18n.assistantToolUseReject);
});

test('errorText shows the key text for a known code', () => {
  expect(errorText({ status: 'error', error: 'ERROR_ASSISTANT_NOTIFICATIONS_UNLICENSED' })).toBe(app.i18n.ERROR_ASSISTANT_NOTIFICATIONS_UNLICENSED);
});

test('errorText leaves unknown text unchanged', () => {
  expect(errorText({ status: 'error', error: 'The query timed out' })).toBe('The query timed out');
});

test('errorText strips tags from key text that contains a link', () => {
  const text = errorText({ status: 'error', error: 'ERROR_UPSTREAM_SERVICE_ERROR' });

  expect(app.i18n.ERROR_UPSTREAM_SERVICE_ERROR).toContain('<a ');
  expect(text).not.toContain('<');
  expect(text).toContain('Security Onion status page');
});
