// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./lucide-set.js');

test('toPascalCase', () => {
  const cases = [
    { input: 'home', expected: 'Home' },
    { input: 'arrow-right', expected: 'ArrowRight' },
    { input: 'book-open-text', expected: 'BookOpenText' },
    { input: 'ArrowRight', expected: 'ArrowRight' },
    { input: 'a-b-c', expected: 'ABC' },
    { input: 'circle-2', expected: 'Circle2' },
    { input: 'type-2-diabetes', expected: 'Type2Diabetes' },
    { input: 'arrow_right', expected: 'ArrowRight' },
    { input: 'book_open_text', expected: 'BookOpenText' },
    { input: 'arrow_right-down', expected: 'ArrowRightDown' },
    { input: '', expected: '' },
    { input: 'a', expected: 'A' },
    { input: 'A', expected: 'A' },
    { input: '-arrow', expected: 'Arrow' },
    { input: 'ARROW-RIGHT', expected: 'ARROWRIGHT' },
    { input: 'arRow-rIght', expected: 'ArRowRIght' },
    { input: '123', expected: '123' },
    { input: '1-2-3', expected: '123' },
  ];

  for (const { input, expected } of cases) {
    expect(toPascalCase(input)).toBe(expected);
  }
});