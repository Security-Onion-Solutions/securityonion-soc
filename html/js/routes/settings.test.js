// Copyright 2020-2023 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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