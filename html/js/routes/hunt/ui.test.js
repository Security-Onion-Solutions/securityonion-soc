// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import uiMethods from './ui.js';

describe('Hunt UI Methods', () => {
  let comp;

  beforeEach(() => {
    comp = {
      i18n: {
        seconds: 'seconds',
        minutes: 'minutes',
        hours: 'hours',
        days: 'days',
        weeks: 'weeks',
        months: 'months',
        __missing__: '*Missing',
      },
      relativeTimeUnits: [
        { title: 'seconds', value: 10 },
        { title: 'minutes', value: 20 },
        { title: 'hours', value: 30 },
        { title: 'days', value: 40 },
        { title: 'weeks', value: 50 },
        { title: 'months', value: 60 },
      ],
      ...uiMethods
    };
  });

  test('formatSafeString', () => {
    const longstr = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    const expected = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567...";
    comp.safeStringMaxLength = 100;
    const actual = comp.formatSafeString(longstr);
    expect(actual).toBe(expected);
  });

  test('getGroupByFieldStartIndex', () => {
    comp.aggregationActionsEnabled = false;
    expect(comp.getGroupByFieldStartIndex()).toBe(1);

    comp.aggregationActionsEnabled = true;
    expect(comp.getGroupByFieldStartIndex()).toBe(2);
  });

  test('getRelativeTimeUnits', () => {
    comp.relativeTimeUnit = 10;
    expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.seconds);

    comp.relativeTimeUnit = 20;
    expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.minutes);

    comp.relativeTimeUnit = 30;
    expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.hours);

    comp.relativeTimeUnit = 40;
    expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.days);

    comp.relativeTimeUnit = 50;
    expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.weeks);

    comp.relativeTimeUnit = 60;
    expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.months);

    comp.relativeTimeUnit = -1;
    expect(comp.getRelativeTimeUnits()).toBe(comp.i18n.hours);
  });

  test('setRelativeTimeUnits', () => {
    for (let i = 0; i < comp.relativeTimeUnits.length; i++) {
      comp.setRelativeTimeUnits(comp.relativeTimeUnits[i].title);
      expect(comp.relativeTimeUnit).toBe(comp.relativeTimeUnits[i].value);
    }

    comp.setRelativeTimeUnits("foo");
    expect(comp.relativeTimeUnit).toBe(30);
  });

  test('isNumeric', () => {
    let table = [
      { value: '', expected: false },
      { value: 'foo', expected: false },
      { value: '1', expected: true },
      { value: '1.9', expected: true },
      { value: '3.1.4', expected: false },
      { value: '6,8', expected: false },
      { value: '-32', expected: true },
      { value: '-0.7', expected: true },
      { value: '-1.2.3', expected: false },
      { value: '1-1', expected: false },
      { value: '6.4-5', expected: false },
      { value: '--0', expected: false },
      { value: NaN, expected: false },
    ];

    for (let i = 0; i < table.length; i++) {
      expect(comp.isNumeric(table[i].value)).toBe(table[i].expected);
    }
  });

  test('updateBulkSelector', () => {
    const selected = { _isSelected: true };
    const unselected = { _isSelected: false };

    comp.totalEvents = 2;
    comp.selectedCount = 0;
    comp.selectAllState = false;
    comp.selectAllIndeterminate = false;

    expect(comp.selectedCount).toBe(0);
    expect(comp.selectAllState).toBe(false);
    expect(comp.selectAllIndeterminate).toBe(false);

    comp.updateBulkSelector(selected);

    expect(comp.selectedCount).toBe(1);
    expect(comp.selectAllState).toBe(false);
    expect(comp.selectAllIndeterminate).toBe(true);

    comp.updateBulkSelector(selected);

    expect(comp.selectedCount).toBe(2);
    expect(comp.selectAllState).toBe(true);
    expect(comp.selectAllIndeterminate).toBe(false);

    comp.updateBulkSelector(unselected);

    expect(comp.selectedCount).toBe(1);
    expect(comp.selectAllState).toBe(false);
    expect(comp.selectAllIndeterminate).toBe(true);

    comp.updateBulkSelector(unselected);

    expect(comp.selectedCount).toBe(0);
    expect(comp.selectAllState).toBe(false);
    expect(comp.selectAllIndeterminate).toBe(false);
  });

  test('toggleSelectAll', () => {
    comp.totalEvents = 11;
    comp.eventData = [];
    comp.eventCurrentItems = [];
    comp.selectedCount = 0;

    for (let i = 0; i < comp.totalEvents; i++) {
      let obj = { _isSelected: i === 0 };
      comp.eventData.push(obj);
      if (comp.eventCurrentItems.length < 10) {
        comp.eventCurrentItems.push(obj);
      }
    }

    comp.selectAllState = 'indeterminate';
    comp.countSelected();

    expect(comp.selectedCount).toBe(1);
    expect(comp.isPageSelected()).toBe(false);

    // the comp has 11 eventData, the first 10 are in eventCurrentItems
    // eventData[0] is the only one selected

    // some selected => none selected
    comp.toggleSelectAll();

    expect(comp.selectAllState).toBe(false);
    expect(comp.selectAllIndeterminate).toBe(false);
    expect(comp.selectedCount).toBe(0);
    expect(comp.eventData[0]._isSelected).toBe(false);
    comp.countSelected();
    expect(comp.selectedCount).toBe(0);
    expect(comp.isPageSelected()).toBe(false);

    // none selected => page selected
    comp.toggleSelectAll();

    expect(comp.selectAllState).toBe(false);
    expect(comp.selectAllIndeterminate).toBe(true);
    expect(comp.selectedCount).toBe(10);
    expect(comp.eventData[10]._isSelected).toBe(false);
    comp.countSelected();
    expect(comp.selectedCount).toBe(10);
    expect(comp.isPageSelected()).toBe(true);

    // page selected => all selected
    comp.selectAllEvents(true, true);

    expect(comp.selectAllState).toBe(true);
    expect(comp.selectAllIndeterminate).toBe(false);
    expect(comp.selectedCount).toBe(11);
    expect(comp.eventData[10]._isSelected).toBe(true);
    comp.countSelected();
    expect(comp.selectedCount).toBe(11);
    expect(comp.isPageSelected()).toBe(true);

    // all selected => none selected
    comp.toggleSelectAll();

    expect(comp.selectAllState).toBe(false);
    expect(comp.selectAllIndeterminate).toBe(false);
    expect(comp.selectedCount).toBe(0);
    comp.countSelected();
    expect(comp.selectedCount).toBe(0);
    expect(comp.isPageSelected()).toBe(false);
  });

  test('getDisplayedQueryVar', () => {
    comp.isAdvanced = () => false;
    expect(comp.getDisplayedQueryVar()).toBe('queryName');

    comp.isAdvanced = () => true;
    comp.showFullQuery = true;
    expect(comp.getDisplayedQueryVar()).toBe('query');

    comp.isAdvanced = () => true;
    comp.showFullQuery = false;
    expect(comp.getDisplayedQueryVar()).toBe('querySearch');
  });
});