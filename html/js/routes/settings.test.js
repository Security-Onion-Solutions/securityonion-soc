// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./settings.js');

let comp;

beforeEach(() => {
  comp = getComponent("settings");
  resetPapi();
});

test('extractTotpData', () => {
  comp.extractTotpData({ data: { ui: { nodes: [ {} ] }}});
  expect(comp.totpForm.qr).toBe(null);
  expect(comp.totpForm.secret).toBe(null);
  expect(comp.unlink_totp_available).toBe(false);

  var response = { data: { ui: { nodes: [ { attributes: { id: 'totp_qr', src: 'abc' }}, 
                                          { attributes: { id: 'totp_secret_key', text: { text: 'xyz' }}}, 
                                          { attributes: { name: 'totp_unlink' }}],
                 }}};
  comp.extractTotpData(response);
  expect(comp.totpForm.qr).toBe('abc');
  expect(comp.totpForm.secret).toBe('xyz');
  expect(comp.unlink_totp_available).toBe(true);
});