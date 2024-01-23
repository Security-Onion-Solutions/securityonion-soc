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

test('shouldNotExtractWebauthnData', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const passwordMethod = {attributes: {name: 'method', value: 'password'}};
  const nodes = [identifier, passwordMethod];
  const response = {data: {ui: {nodes: nodes}}};

  expect(comp.webauthnForm.enabled).toBe(false);

  comp.extractWebauthnData(response);

  expect(comp.webauthnForm.enabled).toBe(false);
});

test('shouldExtractWebauthnDataWithoutTrigger', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const passwordMethod = {attributes: {name: 'method', value: 'password'}};
  const webauthnMethod = {attributes: {name: 'method', value: 'webauthn'}};
  const nodes = [identifier, passwordMethod, webauthnMethod];
  const response = {data: {ui: {nodes: nodes}}};

  expect(comp.webauthnForm.enabled).toBe(false);

  comp.extractWebauthnData(response);

  expect(comp.webauthnForm.enabled).toBe(true);
  expect(comp.webauthnForm.continue).toBe(false);
});

test('shouldExtractWebauthnData', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const passwordMethod = {attributes: {name: 'method', value: 'password'}};
  const webauthnMethod = {attributes: {name: 'method', value: 'webauthn'}};
  const webauthnTrigger = {attributes: {name: 'webauthn_login_trigger', onclick: 'some_event'}};
  const webauthnLogin = {attributes: {name: 'webauthn_login', value: 'some_key'}};
  const scriptObj = {id: 'webauthn_script', type: 'some_type', crossorigin: 'some_origin', referrerpolicy: 'some_policy', integrity: 'some_integrity', nonce: 'some_nonce', src: 'some_src'};
  const webauthnScript = {attributes: scriptObj};
  const nodes = [identifier, passwordMethod, webauthnMethod, webauthnTrigger, webauthnLogin, webauthnScript];
  const response = {data: {ui: {nodes: nodes}}};

  expect(comp.webauthnForm.enabled).toBe(false);
  expect(comp.webauthnForm.continue).toBe(false);

  var savedChild = null;
  const appendChildMock = jest.fn().mockImplementationOnce(child => savedChild = child);
  document.body.appendChild = appendChildMock;

  comp.extractWebauthnData(response);

  expect(comp.webauthnForm.enabled).toBe(true);
  expect(comp.webauthnForm.continue).toBe(true);
  expect(comp.webauthnForm.onclick).toBe('some_event');
  expect(comp.webauthnForm.key).toBe('some_key');
  expect(comp.webauthnForm.email).toBe('some_identifier');
  expect(comp.webauthnForm.script).toEqual(scriptObj);
  expect(appendChildMock).toHaveBeenCalledTimes(1);
  expect(savedChild).not.toBeNull();
  expect(savedChild.getAttribute('type')).toBe('some_type');
  expect(savedChild.getAttribute('id')).toBe('webauthn_script');
  expect(savedChild.getAttribute('crossorigin')).toBe('some_origin');
  expect(savedChild.getAttribute('referrerpolicy')).toBe('some_policy');
  expect(savedChild.getAttribute('integrity')).toBe('some_integrity');
  expect(savedChild.getAttribute('nonce')).toBe('some_nonce');
  expect(savedChild.getAttribute('src')).toBe('some_src');
});

test('shouldRunWebauthn', () => {
  comp.webauthnForm.onclick = 'this.foo = 123';
  comp.runWebauthn();
  expect(comp.foo).toBe(123);
});

test('shouldExtractPasswordData', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const passwordMethod = {group: 'password', attributes: {name: 'method', value: 'password'}};
  const nodes = [identifier, passwordMethod];
  const response = {data: {ui: {nodes: nodes}}};

  expect(comp.passwordEnabled).toBe(false);

  comp.extractPasswordData(response);

  expect(comp.passwordEnabled).toBe(true);
});

test('shouldExtractTotpData', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const totpMethod = {group: 'totp', attributes: {name: 'method', value: 'totp'}};
  const nodes = [identifier, totpMethod];
  const response = {data: {ui: {nodes: nodes}}};

  expect(comp.totpEnabled).toBe(false);

  comp.extractTotpData(response);

  expect(comp.totpEnabled).toBe(true);
});

test('shouldExtractOidcData', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const oidcMethod = {group: 'oidc', type: 'input', attributes: {value: 'SSO'}};
  const nodes = [identifier, oidcMethod];
  const response = {data: {ui: {nodes: nodes}}};

  expect(comp.oidc.length).toBe(0);

  comp.extractOidcData(response);

  expect(comp.oidc.length).toBe(1);
  expect(comp.oidc[0]).toBe('SSO');
});
