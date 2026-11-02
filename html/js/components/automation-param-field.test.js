// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./automation-param-field.js');

const methods = global.components.find(c => c.name === 'automation-param-field').component.methods;

test('marks required settings and shows the default as a placeholder', () => {
  const required = { field: { key: 'groupBy', label: 'Group By', type: 'array', required: true } };
  expect(methods.label.call(required)).toBe('Group By *');
  expect(methods.placeholder.call(required)).toBe('');

  const optional = { field: { key: 'maxFailures', label: 'Max Failures', type: 'integer', default: 3, required: false } };
  expect(methods.label.call(optional)).toBe('Max Failures');
  expect(methods.placeholder.call(optional)).toBe('3');
});
