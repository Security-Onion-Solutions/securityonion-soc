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

test('an object param edits each key\'s values, in key order', () => {
  const comp = { field: { key: 'groupByModule' }, params: { groupByModule: { sigma: ['rule.uuid'], strelka: ['hash.sha256'] } }, newKey: '' };
  Object.assign(comp, methods);
  expect(comp.objectKeys()).toEqual(['sigma', 'strelka']);

  const before = comp.params.groupByModule;
  comp.setObjectValues('sigma', ['rule.uuid', 'event_data.host.name']);
  expect(comp.params.groupByModule).toEqual({ sigma: ['rule.uuid', 'event_data.host.name'], strelka: ['hash.sha256'] });
  expect(comp.params.groupByModule).not.toBe(before);

  comp.newKey = ' suricata ';
  comp.addObjectKey();
  expect(comp.params.groupByModule.suricata).toEqual([]);
  expect(comp.newKey).toBe('');

  comp.newKey = 'sigma';
  comp.addObjectKey();
  expect(comp.params.groupByModule.sigma).toEqual(['rule.uuid', 'event_data.host.name'], 'an existing key keeps its values');
  expect(comp.newKey).toBe('sigma');

  comp.newKey = '  ';
  comp.addObjectKey();
  expect(comp.objectKeys()).toEqual(['sigma', 'strelka', 'suricata']);

  comp.removeObjectKey('strelka');
  expect(comp.objectKeys()).toEqual(['sigma', 'suricata']);
});

test('an object param starts empty when the params lack it', () => {
  const comp = { field: { key: 'groupByModule' }, params: {}, newKey: 'sigma' };
  Object.assign(comp, methods);
  expect(comp.objectKeys()).toEqual([]);

  comp.addObjectKey();
  expect(comp.params.groupByModule).toEqual({ sigma: [] });
});
