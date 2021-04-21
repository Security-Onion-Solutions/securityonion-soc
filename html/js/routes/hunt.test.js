// Copyright 2020,2021 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

require('../test_common.js');
require('./hunt.js');

const comp = getComponent("hunt");

test('escape', () => {
  expect(comp.escape('')).toBe('');
  expect(comp.escape('hello')).toBe('hello');
  expect(comp.escape('hello "bob" the builder\\bricklayer')).toBe('hello \\\"bob\\\" the builder\\\\bricklayer');
  expect(comp.escape(1234)).toBe(1234);
});

test('base64encode', () => {
  expect(comp.base64encode('')).toBe('');
  expect(comp.base64encode('hello')).toBe('aGVsbG8=');
});

test('replaceActionVar', () => {
  expect(comp.replaceActionVar('test here', 'foo', 'bar', true)).toBe('test here');
  expect(comp.replaceActionVar('test {bar} here', 'foo', 'bar', true)).toBe('test {bar} here');
  expect(comp.replaceActionVar('test {foo} here', 'foo', 'bar', true)).toBe('test bar here');
  expect(comp.replaceActionVar('test {foo} here', 'foo', 'sand bar', true)).toBe('test sand%20bar here');
  expect(comp.replaceActionVar('test {foo|base64} here', 'foo', 'sand bar', true)).toBe('test c2FuZCBiYXI%3D here');
  expect(comp.replaceActionVar('test {foo|escape} here', 'foo', 'sand "bar\\bad"', false)).toBe('test sand \\\"bar\\\\bad\\\" here');
  expect(comp.replaceActionVar('test {foo|escape} here', 'foo', 'sand "bar\\bad"', true)).toBe('test sand%20%5C%22bar%5C%5Cbad%5C%22 here');
  expect(comp.replaceActionVar('test {foo|escape|base64} here', 'foo', 'sand "bar\\bad"', false)).toBe('test c2FuZCBcImJhclxcYmFkXCI= here');
  expect(comp.replaceActionVar('test {foo|escape|base64} here', 'foo', 'sand "bar\\bad"', true)).toBe('test c2FuZCBcImJhclxcYmFkXCI%3D here');
  expect(comp.replaceActionVar('test {foo} here', 'foo', null, true)).toBe('test {foo} here');
  expect(comp.replaceActionVar('test {foo} here', 'foo', undefined, true)).toBe('test {foo} here');
});

test('localizeValue', () => {
  expect(comp.localizeValue('foo')).toBe('foo');
  expect(comp.localizeValue('__missing__')).toBe('*Missing');
});

test('removeDataFromView', () => {
  const a = {};
  const b = {};
  const c = { count: 10 };
  data = [a, b, c];
  comp.totalEvents = 11;

  comp.removeDataItemFromView(data, a);
  expect(comp.totalEvents).toBe(10);
  expect(data.length).toBe(2);

  comp.removeDataItemFromView(data, c);
  expect(comp.totalEvents).toBe(0);
  expect(data.length).toBe(1);

  // Removing non-existent item should be no-op
  comp.removeDataItemFromView(data, a);
  expect(comp.totalEvents).toBe(0);
  expect(data.length).toBe(1);

  // Ensure totalEvents never drops below 0 (shouldn't, but double check)
  comp.removeDataItemFromView(data, b);
  expect(comp.totalEvents).toBe(0);
  expect(data.length).toBe(0);
});

test('sortEventsAscending', () => {
  const index = [ 'x' ];
  const desc = [ false ];
  const item1 = { 'x': 1 };
  const item2 = { 'x': 2 };
  const item3 = { 'x': 3 };
  const unsorted = [item1, item2, item3];
  const sorted = comp.sortEvents(unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[0]).toBe(item1);
  expect(sorted[1]).toBe(item2);
  expect(sorted[2]).toBe(item3);
});

test('sortEventsDescending', () => {
  const index = [ 'x' ];
  const desc = [ true ];
  const item1 = { 'x': 1 };
  const item2 = { 'x': 2 };
  const item3 = { 'x': 3 };
  const unsorted = [item1, item2, item3];
  const sorted = comp.sortEvents(unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[2]).toBe(item1);
  expect(sorted[1]).toBe(item2);
  expect(sorted[0]).toBe(item3);
});

test('sortAlertsAscending', () => {
  const index = [ 'x' ];
  const desc = [ false ];
  const item1 = { 'x': 1 };
  const item2 = { 'x': 2 };
  const item3 = { 'x': 3 };
  const unsorted = [item1, item2, item3];
  const sorted = comp.sortEvents(unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[0]).toBe(item1);
  expect(sorted[1]).toBe(item2);
  expect(sorted[2]).toBe(item3);
});

test('sortAlertsDescending', () => {
  const index = [ 'event.severity_label' ];
  const desc = [ false ];
  const item1 = { 'event.severity_label': 'low' };
  const item2 = { 'event.severity_label': 'medium' };
  const item3 = { 'event.severity_label': 'high' };
  const item4 = { 'event.severity_label': 'critical' };
  const unsorted = [item2, item3, item4, item1];
  const sorted = comp.sortEvents(unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[0]).toBe(item1);
  expect(sorted[1]).toBe(item2);
  expect(sorted[2]).toBe(item3);
  expect(sorted[3]).toBe(item4);
});

test('sortAlertsAscending', () => {
  const index = [ 'event.severity_label' ];
  const desc = [ true ];
  const item1 = { 'event.severity_label': 'low' };
  const item2 = { 'event.severity_label': 'medium' };
  const item3 = { 'event.severity_label': 'high' };
  const item4 = { 'event.severity_label': 'critical' };
  const unsorted = [item2, item3, item4, item1];
  const sorted = comp.sortEvents(unsorted, index, desc);
  expect(sorted.length).toBe(unsorted.length);
  expect(sorted[3]).toBe(item1);
  expect(sorted[2]).toBe(item2);
  expect(sorted[1]).toBe(item3);
  expect(sorted[0]).toBe(item4);
});