// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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