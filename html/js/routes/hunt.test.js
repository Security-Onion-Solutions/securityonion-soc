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

test('localizeValue', () => {
  expect(comp.localizeValue('foo')).toBe('foo');
  expect(comp.localizeValue('__missing__')).toBe('*Missing');
  expect(comp.localizeValue(123)).toBe(123);
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

test('saveTimezone', () => {
  comp.zone = "Foo/Bar";
  comp.saveTimezone();
  comp.zone = "Test";
  comp.loadLocalSettings();
  expect(comp.zone).toBe("Foo/Bar");
});

test('removeFilter', () => {
  comp.query = "abc def | groupby foo bar*"; 
  comp.removeFilter('def')
  expect(comp.query).toBe("abc  | groupby foo bar*");

  comp.removeFilter('abc')
  expect(comp.query).toBe("* | groupby foo bar*");

  // no-op
  comp.removeFilter('*')
  expect(comp.query).toBe("* | groupby foo bar*");
});

test('removeGroupBy', () => {
  comp.query = "abc | groupby foo bar*"; 
  comp.removeGroupBy('foo')
  expect(comp.query).toBe("abc | groupby bar*");

  comp.removeGroupBy('bar*')
  expect(comp.query).toBe("abc");

  // no-op
  comp.removeGroupBy('bar*')
  expect(comp.query).toBe("abc");
});

test('removeSortBy', () => {
  comp.query = "abc | sortby foo bar^"; 
  comp.removeSortBy('foo')
  expect(comp.query).toBe("abc | sortby bar^");

  comp.removeSortBy('bar^')
  expect(comp.query).toBe("abc");

  // no-op
  comp.removeSortBy('bar^')
  expect(comp.query).toBe("abc");

  comp.query = "abc | sortby foo bar^ | groupby xyz"; 
  comp.removeSortBy('foo')
  expect(comp.query).toBe("abc | sortby bar^ | groupby xyz");

  comp.removeSortBy('bar^')
  expect(comp.query).toBe("abc | groupby xyz");

  // no-op
  comp.removeSortBy('bar^')
  expect(comp.query).toBe("abc | groupby xyz");
});

test('formatCaseSummary', () => {
  const caseObj = {id:"12", title:"This is a case title"};
  const summary = comp.formatCaseSummary(caseObj);
  expect(summary).toBe('This is a case title');
});

test('toggleEscalationMenu', () => {
  comp.escalateRelatedEventsEnabled = true;
  const domEvent = {clientX: 12, clientY: 34};
  const event = {id:"33",foo:"bar"};
  comp.$nextTick = function(fn) { fn(); };
  comp.toggleEscalationMenu(domEvent, event);
  expect(comp.escalationMenuX).toBe(12);
  expect(comp.escalationMenuY).toBe(34);
  expect(comp.escalationItem).toBe(event);
  expect(comp.escalationMenuVisible).toBe(true);
});

test('toggleEscalationMenuAlreadyOpen', () => {
  comp.escalateRelatedEventsEnabled = true;
  comp.quickActionVisible = true;
  comp.escalationMenuVisible = true;
  comp.toggleEscalationMenu();
  expect(comp.quickActionVisible).toBe(false);
  expect(comp.escalationMenuVisible).toBe(false);
});

function validateCase(
    name, template, mod, dataset, severity, message,
    expectedTitle, expectedDescription, expectedSeverity, expectedTemplate) {
  const item = {
    "rule.name": name,
    "rule.case_template": template,
    "event.module": mod,
    "event.dataset": dataset,
    "event.severity": severity,
    "message": message,
  };
  const caseObj = comp.buildCase(item)
  expect(caseObj.title).toBe(expectedTitle);
  expect(caseObj.description).toBe(expectedDescription);
  expect(caseObj.severity).toBe(expectedSeverity);
  expect(caseObj.template).toBe(expectedTemplate);
}

test('buildCase', () => {
  // has rule name and message, etc (happy path)
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'myTitle', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name, module, and dataset
  validateCase('', 'myTemplate', '', '', 'mySeverity', 'myMessage',
      'Event Escalation from SOC', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has module
  validateCase('', 'myTemplate', 'myModule', '', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has dataset
  validateCase('', 'myTemplate', '', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myDataset', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing rule name but has module and dataset
  validateCase('', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule - myDataset', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');
  validateCase(null, 'myTemplate', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'Event Escalation from SOC: myModule - myDataset', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing message
  comp.escalateRelatedEventsEnabled = false;
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', '',
      'myTitle', '{\"rule.name\":\"myTitle\",\"rule.case_template\":\"myTemplate\",\"event.module\":\"myModule\",\"event.dataset\":\"myDataset\",\"event.severity\":\"mySeverity\",\"message\":\"\"}', 'mySeverity', 'myTemplate');

  comp.escalateRelatedEventsEnabled = true;
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', 'mySeverity', '',
      'myTitle', comp.i18n.caseEscalatedDescription, 'mySeverity', 'myTemplate');

  // missing severity
  validateCase('myTitle', 'myTemplate', 'myModule', 'myDataset', '', 'myMessage',
      'myTitle', comp.i18n.caseEscalatedDescription, '', 'myTemplate');

  // missing template
  validateCase('myTitle', '', 'myModule', 'myDataset', 'mySeverity', 'myMessage',
      'myTitle', comp.i18n.caseEscalatedDescription, 'mySeverity', '');

});

test('applyQuerySubstitutions', () => {
  comp.$root.user = {id:'123'};
  const queries = [{ query: 'foo'}, { query: 'bar:{myId}' }];
  const newQueries = comp.applyQuerySubstitutions(queries);
  expect(newQueries).toBe(queries);
  expect(newQueries[0].query).toBe('foo');
  expect(newQueries[1].query).toBe('bar:123');
});