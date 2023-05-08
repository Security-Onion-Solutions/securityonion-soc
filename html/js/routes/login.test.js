// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./login.js');

let comp;

beforeEach(() => {
  comp = getComponent("login");
  resetPapi();
  resetAuthApi();
});

test('shouldSubmitTotp', () => {
  var submitted = false;
  const getElementByIdMock = global.document.getElementById = jest.fn().mockReturnValueOnce({value:""}).mockReturnValueOnce({submit:function(){ submitted = true}});
  comp.submitTotp('123');
  expect(comp.form.totpCode).toBe('123');
  expect(getElementByIdMock).toHaveBeenCalledWith('totp_code');
  expect(getElementByIdMock).toHaveBeenCalledWith('loginForm');
});

test('shouldDetectThrottling_BadParam', () => {
  const _setTimeout = global.setTimeout;
  const setTimeoutMock = jest.fn();
  global.setTimeout = setTimeoutMock;

  const _getSearchParam = comp.$root.getSearchParam;
  const mock = jest.fn().mockReturnValue("abc");
  comp.$root.getSearchParam = mock;

  expect(comp.throttled).toBe(false);
  comp.created();
  
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith("thr");
  expect(comp.throttled).toBe(true);
  expect(comp.countdown).toBe(30);
  expect(setTimeoutMock).toHaveBeenCalledTimes(1);
  expect(setTimeoutMock).toHaveBeenCalledWith(comp.countdownRelogin, 1000);
  comp.$root.getSearchParam = _getSearchParam;
  global.setTimeout = _setTimeout;
});

test('shouldDetectThrottling', () => {
  const _setTimeout = global.setTimeout;
  const setTimeoutMock = jest.fn();
  global.setTimeout = setTimeoutMock;

  const _getSearchParam = comp.$root.getSearchParam;
  const mock = jest.fn().mockReturnValue("123");
  comp.$root.getSearchParam = mock;

  expect(comp.throttled).toBe(false);
  comp.created();
  
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith("thr");
  expect(comp.throttled).toBe(true);
  expect(comp.countdown).toBe(123);
  expect(setTimeoutMock).toHaveBeenCalledTimes(1);
  expect(setTimeoutMock).toHaveBeenCalledWith(comp.countdownRelogin, 1000);
  comp.$root.getSearchParam = _getSearchParam;
  global.setTimeout = _setTimeout;
});

test('shouldCountdownThrottling', () => {
  const _setTimeout = global.setTimeout;
  const setTimeoutMock = jest.fn();
  global.setTimeout = setTimeoutMock;

  const _showLogin = comp.$root.showLogin;
  const showLoginMock = jest.fn().mockReturnValue();
  comp.$root.showLogin = showLoginMock;

  comp.countdown = 2;

  // After first countdown counter will be at 1
  comp.countdownRelogin();
  
  expect(showLoginMock).toHaveBeenCalledTimes(0);
  expect(setTimeoutMock).toHaveBeenCalledTimes(1);
  expect(setTimeoutMock).toHaveBeenCalledWith(comp.countdownRelogin, 1000);
  
  // Now counter will be at 0
  comp.countdownRelogin();
  expect(showLoginMock).toHaveBeenCalledTimes(1);
  expect(setTimeoutMock).toHaveBeenCalledTimes(1);

  comp.$root.showLogin = _showLogin;
  global.setTimeout = _setTimeout;
});

test('shouldHandleUnexpectedLoginResponse', async () => {
  const _showLogin = comp.$root.showLogin;
  const showLoginMock = jest.fn();
  comp.$root.showLogin = showLoginMock;


  const data = 'banner text';

  const _createApi = comp.$root.createApi;
  const createApiMock = jest.fn().mockReturnValue({
    get: () => { return { data: data } },
  });
  
  const authApiMock = mockAuthApi("get", {"data":{}});
  comp.$root.createApi = createApiMock;

  await comp.loadData();

  expect(showLoginMock).toHaveBeenCalledTimes(1);
  expect(authApiMock).toHaveBeenCalledTimes(1);
  expect(authApiMock).toHaveBeenCalledWith('login/flows?id=null');
  expect(createApiMock).toHaveBeenCalledTimes(1);
  expect(comp.banner).toBe("<p>banner text</p>\n");

  comp.$root.createApi = _createApi;
  comp.$root.showLogin = _showLogin;
});