// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

test('shouldNotExtractWebauthnData', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const passwordMethod = {attributes: {name: 'method', value: 'password'}};
  const nodes = [identifier, passwordMethod];
  const response = {data: {ui: {nodes: nodes}}};

  expect(comp.webauthnForm.onclick).toBeNull;

  comp.extractWebauthnData(response);

  expect(comp.webauthnForm.onclick).toBeNull;
});

test('shouldExtractWebauthnData', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const passwordMethod = {attributes: {name: 'method', value: 'password'}};
  const webauthnTrigger = {attributes: {name: 'webauthn_register_trigger', onclick: 'some_event'}};
  const webauthnDisplayName = {attributes: {name: 'webauthn_register_displayname', value: 'some_name'}};
  const webauthnRegister = {attributes: {name: 'webauthn_register', value: 'some_key'}};
  const scriptObj = {id: 'webauthn_script', type: 'some_type', crossorigin: 'some_origin', referrerpolicy: 'some_policy', integrity: 'some_integrity', nonce: 'some_nonce', src: 'some_src'};
  const webauthnScript = {attributes: scriptObj};
  const webauthnRemove = {attributes: {name: 'webauthn_remove', value: 'some_key'}, meta: {label: {id: 'some_id', context: {display_name: 'some_name', added_at: 'some_date'}}}};
  const nodes = [identifier, passwordMethod, webauthnTrigger, webauthnRegister, webauthnScript, webauthnDisplayName, webauthnRemove];
  const response = {data: {ui: {nodes: nodes}}};

  var savedChild = null;
  const appendChildMock = jest.fn().mockImplementationOnce(child => savedChild = child);
  document.body.appendChild = appendChildMock;

  comp.extractWebauthnData(response);

  expect(comp.webauthnForm.onclick).toBe('some_event');
  expect(comp.webauthnForm.key).toBe('some_key');
  expect(comp.webauthnForm.name).toBe('some_name');
  expect(comp.webauthnForm.script).toEqual(scriptObj);
  expect(comp.webauthnForm.existingKeys).toEqual([{value: 'some_key', id: 'some_id', name: 'some_name', date: 'some_date'}]);
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

test('shouldExtractOidcData', () => {
  const identifier = {attributes: {name: 'identifier', value: 'some_identifier'}};
  const oidcMethod = {group: 'oidc', type: 'input', attributes: {name: 'link', value: 'SSO'}};
  const nodes = [identifier, oidcMethod];
  const response = {data: {ui: {nodes: nodes}}};

  expect(comp.oidcProviders.length).toBe(0);
  expect(comp.oidcEnabled).toBe(false);

  comp.extractOidcData(response);

  expect(comp.oidcEnabled).toBe(true);
  expect(comp.oidcProviders.length).toBe(1);
  expect(comp.oidcProviders[0].id).toBe('SSO');
  expect(comp.oidcProviders[0].op).toBe('link');
});
