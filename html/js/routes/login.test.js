// Copyright 2020-2023 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

require('../test_common.js');
require('./login.js');

let comp;

beforeEach(() => {
  comp = getComponent("login");
  resetPapi();
});

test('shouldSubmitTotp', () => {
  var submitted = false;
  const getElementByIdMock = global.document.getElementById = jest.fn().mockReturnValueOnce({value:""}).mockReturnValueOnce({submit:function(){ submitted = true}});
  comp.submitTotp('123');
  expect(comp.form.totpCode).toBe('123');
  expect(getElementByIdMock).toHaveBeenCalledWith('totp_code');
  expect(getElementByIdMock).toHaveBeenCalledWith('loginForm');
});