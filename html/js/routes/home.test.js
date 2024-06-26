// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./home.js');

let comp;

beforeEach(() => {
  comp = getComponent("home");
  resetPapi();
});

test('loadChanges', async () => {
  const showErrorMock = mockShowError();
  const data = 'MOTD';

  const _createApi = comp.$root.createApi;
  const mock = jest.fn().mockReturnValue({
    get: () => { return { data: data } },
  });

  comp.$root.createApi = mock;

  // test
  await comp.loadChanges();

  // verify
  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(mock).toHaveBeenCalledTimes(1);
  expect(comp.motd).toBe(data);

  comp.$root.createApi = _createApi;
});

test('loadChanges error', async () => {
  const showErrorMock = mockShowError();
  const _createApi = comp.$root.createApi;
  const mock = jest.fn().mockReturnValue({
    get: () => { throw new Error() },
  });

  comp.$root.createApi = mock;

  // test
  await comp.loadChanges();

  // verify
  expect(mock).toHaveBeenCalledTimes(1);
  expect(showErrorMock).toHaveBeenCalledTimes(1);
  expect(comp.motd).toBe('');

  comp.$root.createApi = _createApi;
});