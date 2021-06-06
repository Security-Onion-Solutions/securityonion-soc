// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

require('./test_common.js');

const app = global.getApp();

test('escape', () => {
  expect(app.escape('')).toBe('');
  expect(app.escape('hello')).toBe('hello');
  expect(app.escape('hello "bob" the builder\\bricklayer')).toBe('hello \\\"bob\\\" the builder\\\\bricklayer');
  expect(app.escape(1234)).toBe(1234);
});

test('base64encode', () => {
  expect(app.base64encode('')).toBe('');
  expect(app.base64encode('hello')).toBe('aGVsbG8=');
});

test('replaceActionVar', () => {
  expect(app.replaceActionVar('test here', 'foo', 'bar', true)).toBe('test here');
  expect(app.replaceActionVar('test {bar} here', 'foo', 'bar', true)).toBe('test {bar} here');
  expect(app.replaceActionVar('test {foo} here', 'foo', 'bar', true)).toBe('test bar here');
  expect(app.replaceActionVar('test {foo} here', 'foo', 'sand bar', true)).toBe('test sand%20bar here');
  expect(app.replaceActionVar('test {foo|base64} here', 'foo', 'sand bar', true)).toBe('test c2FuZCBiYXI%3D here');
  expect(app.replaceActionVar('test {foo|escape} here', 'foo', 'sand "bar\\bad"', false)).toBe('test sand \\\"bar\\\\bad\\\" here');
  expect(app.replaceActionVar('test {foo|escape} here', 'foo', 'sand "bar\\bad"', true)).toBe('test sand%20%5C%22bar%5C%5Cbad%5C%22 here');
  expect(app.replaceActionVar('test {foo|escape|base64} here', 'foo', 'sand "bar\\bad"', false)).toBe('test c2FuZCBcImJhclxcYmFkXCI= here');
  expect(app.replaceActionVar('test {foo|escape|base64} here', 'foo', 'sand "bar\\bad"', true)).toBe('test c2FuZCBcImJhclxcYmFkXCI%3D here');
  expect(app.replaceActionVar('test {foo} here', 'foo', null, true)).toBe('test {foo} here');
  expect(app.replaceActionVar('test {foo} here', 'foo', undefined, true)).toBe('test {foo} here');
});
