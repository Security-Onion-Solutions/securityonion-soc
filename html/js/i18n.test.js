// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('./i18n.js');

const table = global.i18n.getLocalizedTranslations('en-US');

// endTime and months were silently overridden by later duplicates in 3.4.0.
test('restored keys keep their original text', () => {
  expect(table.endTime).toBe('Filter End');
  expect(table.months).toBe('months');
  expect(table.scheduleEndTime).toBe('End Time');
  expect(table.scheduleMonths).toBe('Months');
});

test('keys the UI reads are defined', () => {
  expect(table.currentValue).toBe('Current Value');
  expect(table.ERROR_REQUEST_FAILED).toBe('Something went wrong while processing the request. Check SOC logs for details.');
  expect(table.ERROR_PERMISSION_DENIED).toBeTruthy();
});
