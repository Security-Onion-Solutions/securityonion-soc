// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./config.js');

global.GridMemberAccepted = "accepted";

const a = {
  category: 'general',
  id: 'fake.setting.foo',
  description: 'Nearby',
  title: 'Farout',
  nodeValues: new Map(),
  regex: "True|False",
  regexFailureMessage: "Wrong!",

};

const b = { category: 'general', id: 'car', title: 'CCA', description: 'NADA', nodeValues: new Map() };
const c = { category: 'ui', id: 'fake.setting.bar', title: 'Barley', description: 'Cocoa', nodeValues: new Map()};

let comp;

beforeEach(() => {
  comp = getComponent("config");
  resetPapi();
  global.localStorage = {};
});

test('loadData', async () => {
  loaddata = [{id:'mia-test-001'}];
  const loadmock = mockPapi("get", { data: loaddata });

  a.nodeId = 'mia-test-001';
  a.value = 'hi';
  data = [a, b, c];
  const mock = mockPapi("get", { data: data });
  comp.settings = [];
  await comp.loadData();
  expect(loadmock).toHaveBeenCalledWith('gridmembers/');
  expect(mock).toHaveBeenCalledWith('config/', {params: { advanced: false }});

  expect(comp.nodes).toBe(loaddata);

  const m1 = new Map();
  m1.set('mia-test-001', 'hi');
  const expectedSettings = [{
      "advanced": undefined,
      "default": null,
      "defaultAvailable": false,
      "description": "Nearby",
      "duplicates": undefined,
      "file": undefined,
      "forcedType": undefined,
      "global": false,
      "helpLink": undefined,
      "id": "fake.setting.foo",
      "multiline": undefined,
      "name": "foo",
      "node": undefined,
      "nodeValues": m1,
      "optionSeparator": undefined,
      "options": undefined,
      "readonly": undefined,
      "readonlyUi": undefined,
      "regex": "True|False",
      "regexFailureMessage": "Wrong!",
      "required": undefined,
      "sensitive": undefined,
      "syntax": undefined,
      "title": "Farout",
      "uiElements": undefined,
      "uiElementsDeleteMessage": undefined,
      "value": null,
    },
    {
      "advanced": undefined,
      "default": undefined,
      "defaultAvailable": undefined,
      "description": "NADA",
      "duplicates": undefined,
      "file": undefined,
      "forcedType": undefined,
      "global": undefined,
      "helpLink": undefined,
      "id": "car",
      "multiline": undefined,
      "name": "car",
      "node": false,
      "nodeValues": new Map(),
      "optionSeparator": undefined,
      "options": undefined,
      "readonly": undefined,
      "readonlyUi": undefined,
      "regex": undefined,
      "regexFailureMessage": undefined,
      "required": undefined,
      "sensitive": undefined,
      "syntax": undefined,
      "title": "CCA",
      "uiElements": undefined,
      "uiElementsDeleteMessage": undefined,
      "value": undefined,
    },
    {
      "advanced": undefined,
      "default": undefined,
      "defaultAvailable": undefined,
      "description": "Cocoa",
      "duplicates": undefined,
      "file": undefined,
      "forcedType": undefined,
      "global": undefined,
      "helpLink": undefined,
      "id": "fake.setting.bar",
      "multiline": undefined,
      "name": "bar",
      "node": false,
      "nodeValues": new Map(),
      "optionSeparator": undefined,
      "options": undefined,
      "readonly": undefined,
      "readonlyUi": undefined,
      "regex": undefined,
      "regexFailureMessage": undefined,
      "required": undefined,
      "sensitive": undefined,
      "syntax": undefined,
      "title": "Barley",
      "uiElements": undefined,
      "uiElementsDeleteMessage": undefined,
      "value": undefined,
    }
  ];

  const expectedHierarchy = [
    {
      "children": [
        {
          "children": [
            {
              "advanced": undefined,
              "default": null,
              "defaultAvailable": false,
              "description": "Nearby",
              "duplicates": undefined,
              "file": undefined,
              "forcedType": undefined,
              "global": false,
              "helpLink": undefined,
              "id": "fake.setting.foo",
              "multiline": undefined,
              "name": "foo",
              "node": undefined,
              "nodeValues": m1,
              "optionSeparator": undefined,
              "options": undefined,
              "readonly": undefined,
              "readonlyUi": undefined,
              "regex": "True|False",
              "regexFailureMessage": "Wrong!",
              "required": undefined,
              "sensitive": undefined,
              "syntax": undefined,
              "title": "Farout",
              "uiElements": undefined,
              "uiElementsDeleteMessage": undefined,
              "value": null,
            },
            {
              "advanced": undefined,
              "default": undefined,
              "defaultAvailable": undefined,
              "description": "Cocoa",
              "duplicates": undefined,
              "file": undefined,
              "forcedType": undefined,
              "global": undefined,
              "helpLink": undefined,
              "id": "fake.setting.bar",
              "multiline": undefined,
              "name": "bar",
              "node": false,
              "nodeValues": new Map(),
              "optionSeparator": undefined,
              "options": undefined,
              "readonly": undefined,
              "readonlyUi": undefined,
              "regex": undefined,
              "regexFailureMessage": undefined,
              "required": undefined,
              "sensitive": undefined,
              "syntax": undefined,
              "title": "Barley",
              "uiElements": undefined,
              "uiElementsDeleteMessage": undefined,
              "value": undefined,
            }
          ],
          "id": "fake.setting",
          "name": "setting"
        }
      ],
      "id": "fake",
      "name": "fake"
    },
    {
      "advanced": undefined,
      "default": undefined,
      "defaultAvailable": undefined,
      "description": "NADA",
      "duplicates": undefined,
      "file": undefined,
      "forcedType": undefined,
      "global": undefined,
      "helpLink": undefined,
      "id": "car",
      "multiline": undefined,
      "name": "car",
      "node": false,
      "nodeValues": new Map(),
      "optionSeparator": undefined,
      "options": undefined,
      "readonly": undefined,
      "readonlyUi": undefined,
      "regex": undefined,
      "regexFailureMessage": undefined,
      "required": undefined,
      "sensitive": undefined,
      "syntax": undefined,
      "title": "CCA",
      "uiElements": undefined,
      "uiElementsDeleteMessage": undefined,
      "value": undefined,
    }
  ];
  expect(comp.settings).toStrictEqual(expectedSettings);
  expect(comp.hierarchy).toStrictEqual(expectedHierarchy);
});

test('getSettingName', () => {
  expect(comp.getSettingName({id:"fake.setting.foo", title: 'fake'})).toBe("Fake Setting Translated");
  expect(comp.getSettingName({id:"fake.setting.untranslated", title: "Untranslated Name"})).toBe("Untranslated Name");
  expect(comp.getSettingName({id:"fake.setting.untranslated"})).toBe(undefined);
});

test('getSettingDescription', () => {
  expect(comp.getSettingDescription({id:"fake.setting.foo"})).toBe("This is a transalated fake setting description.");
  expect(comp.getSettingDescription({id:"fake.setting.untranslated", description: "some description"})).toBe("some description");
  expect(comp.getSettingDescription({id:"fake.setting.untranslated"})).toBe("fake.setting.untranslated");
  expect(comp.getSettingDescription({id:"foo.advanced", name:"advanced", multiline: true})).toBe("Provide optional, custom configuration in YAML format. Note that improper customizations often are the cause of grid malfunctions.");
});

test('findActiveSetting', () => {
  expect(comp.findActiveSetting()).toBe(null);

  comp.active = [a.id];
  comp.settings = [a, b, c]
  expect(comp.findActiveSetting()).toBe(a);
});

test('clearFilter', () => {
  comp.search = "foo";
  comp.searchFilter = "foo";
  comp.clearFilter();
  expect(comp.search).toBe("");
  expect(comp.searchFilter).toBe("");
});

test('filter', () => {
  a.nodeValues['mia-test-001'] = 'hi';
  a.value = 'a1';
  let ii = { raw: a };
  expect(comp.filter(a.id, 'foO', ii)).toBe(true);
  expect(comp.filter(a.id, 'bY', ii)).toBe(true);
  expect(comp.filter(a.id, 'OUt', ii)).toBe(true);
  expect(comp.filter(a.id, 'A1', ii)).toBe(true);
  expect(comp.filter(a.id, 'FaROut', ii)).toBe(true);
  expect(comp.filter(a.id, 'bar', ii)).toBe(false);
  expect(comp.filter(a.id, null, ii)).toBe(true);
});

test('isMultiline', () => {
  const setting = {};
  expect(comp.isMultiline(setting)).toBe(false);

  setting.multiline = true;
  expect(comp.isMultiline(setting)).toBe(true);

  setting.multiline = false;
  expect(comp.isMultiline(setting)).toBe(false);

  setting.multiline = false;
  setting.advanced = true;
  setting.description = "";
  expect(comp.isMultiline(setting)).toBe(true);
});

test('isPendingSave', () => {
  comp.form.key = null;
  comp.form.value = null;
  const values = new Map();
  values.set('bar', '123');
  const setting = { id: 'foo', value: "something", nodeValues: values};

  // Form key is null, nothing pending
  var nodeId = null;
  expect(comp.isPendingSave(setting, nodeId)).toBe(false);

  // Form key matches setting id, global value doesn't match form value (null) so save is pending
  comp.form.key = "foo";
  expect(comp.isPendingSave(setting, nodeId)).toBe(true);

  // Form key match doesn't match setting's node ID, so nothing pending
  comp.form.key = "bar";
  expect(comp.isPendingSave(setting, nodeId)).toBe(false);

  // Form key matches setting's node ID, and form value has been touched, so save is pending
  nodeId = "bar"
  comp.form.key = "bar";
  comp.form.value = "changed";
  expect(comp.isPendingSave(setting, nodeId)).toBe(true);

  // Form key matches node Id but form value matches that node's value, so nothing pending
  comp.form.value = '123';
  expect(comp.isPendingSave(setting, nodeId)).toBe(false);
});

test('reset', () => {
  const setting = { id: 'foo', default: '123' };
  comp.form.key = "bar";
  comp.form.value = "abc";

  comp.reset(setting);
  expect(comp.form.value).toBe(setting.default);
  expect(comp.form.key).toBe(setting.id);
});

setupSettings = () => {
  comp.cancelDialog = true;
  comp.nodes = [{id: "n1", status: GridMemberAccepted }, {id: "n1a", status: GridMemberAccepted },
                {id: "n2", name: "node2", role: "standalone", status: "accepted" }, {id:"n3", status: "pending" }];

  const nodeValues = new Map();
  nodeValues.set("n1", "123");
  nodeValues.set("n1a", "abc");

  const nodeValues2 = new Map();
  nodeValues2.set("n1", "123-2");
  nodeValues2.set("n1a", "abc-2");

  comp.active = ["s-id"];
  comp.activeBackup = ["s-id"];
  comp.settings = [{id: "s-id", value: 'orig-value', default: 'def-value', nodeValues: nodeValues},
                   {id: "s-id2", value: 'orig-value2', nodeValues: nodeValues2}];
};

test('showHistory', async () => {
  mockPapi("get", { data: { history: [], total: 0 } });
  expect(comp.showHistoryDialog).toBe(false);
  await comp.showHistory({id: 'test'});
  expect(comp.showHistoryDialog).toBe(true);
  expect(comp.historySetting).toEqual({id: 'test'});
  expect(comp.historyNodeId).toBe('');
  expect(comp.isGlobalHistory).toBe(false);
  expect(comp.historyPage).toBe(1);
  expect(comp.expandedHistoryRows).toStrictEqual(new Set());
});

test('showHistory_withNodeId', async () => {
  mockPapi("get", { data: { history: [], total: 0 } });
  await comp.showHistory({id: 'test.id'}, 'node1');
  expect(comp.historySetting).toEqual({id: 'test.id'});
  expect(comp.historyNodeId).toBe('node1');
  expect(comp.isGlobalHistory).toBe(false);
});

test('showGlobalHistory', async () => {
  mockPapi("get", { data: { history: [], total: 0 } });
  await comp.showGlobalHistory();
  expect(comp.isGlobalHistory).toBe(true);
  expect(comp.historySetting).toBeNull();
});

test('fetchHistory', async () => {
  const mock = mockPapi("get", { data: { history: [{id: 1, userId: 'u1'}, {id: 2, userId: 'u2'}], total: 2 } });
  comp.$root.populateUserDetails = jest.fn();
  comp.isGlobalHistory = true;
  comp.historySetting = null;
  comp.historyPage = 2;
  comp.pageSize = 25;
  comp.historySort = 'ts';
  comp.historyOrder = 'desc';

  await comp.fetchHistory();

  expect(mock).toHaveBeenCalledWith('config/history', {
    params: { limit: 25, offset: 25, sort: 'ts', order: 'desc' }
  });
  expect(comp.auditHistory.length).toBe(2);
  expect(comp.historyTotal).toBe(2);
  expect(comp.showHistoryDialog).toBe(true);
  expect(comp.$root.populateUserDetails).toHaveBeenCalledTimes(2);
});

test('fetchHistory_settingSpecific', async () => {
  const mock = mockPapi("get", { data: { history: [], total: 0 } });
  comp.isGlobalHistory = false;
  comp.historySetting = {id: 'my.setting'};
  comp.historyNodeId = 'node1';
  comp.historyPage = 1;
  comp.pageSize = 25;
  comp.historySort = 'ts';
  comp.historyOrder = 'desc';

  await comp.fetchHistory();

  expect(mock).toHaveBeenCalledWith('config/history/my.setting/node1', {
    params: { limit: 25, offset: 0, sort: 'ts', order: 'desc' }
  });
});

test('fetchHistory_settingSpecific_noNode', async () => {
  const mock = mockPapi("get", { data: { history: [], total: 0 } });
  comp.isGlobalHistory = false;
  comp.historySetting = {id: 'my.setting'};
  comp.historyNodeId = '';
  comp.historyPage = 1;
  comp.pageSize = 25;
  comp.historySort = 'ts';
  comp.historyOrder = 'desc';

  await comp.fetchHistory();

  expect(mock).toHaveBeenCalledWith('config/history/my.setting', {
    params: { limit: 25, offset: 0, sort: 'ts', order: 'desc' }
  });
});

test('fetchHistory_error', async () => {
  mockPapi("get", null, new Error('fail'));
  const showErrorMock = mockShowError();
  comp.isGlobalHistory = true;
  comp.historySetting = null;
  comp.historyPage = 1;
  comp.pageSize = 25;
  comp.historySort = 'ts';
  comp.historyOrder = 'desc';

  await comp.fetchHistory();

  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.settingHistoryError);
});

test('fetchHistory_populateUserDetails_fallback', async () => {
  mockPapi("get", { data: { history: [{id: 1, userId: 'user1'}], total: 1 } });
  delete comp.$root.populateUserDetails;
  comp.isGlobalHistory = true;
  comp.historySetting = null;
  comp.historyPage = 1;
  comp.pageSize = 25;
  comp.historySort = 'ts';
  comp.historyOrder = 'desc';

  await comp.fetchHistory();

  expect(comp.auditHistory[0].userName).toBe('user1');
});

test('toggleHistoryRow', () => {
  comp.expandedHistoryRows = new Set([1, 3]);
  comp.toggleHistoryRow(1);
  expect(comp.expandedHistoryRows.has(1)).toBe(false);
  expect(comp.expandedHistoryRows.has(3)).toBe(true);

  comp.toggleHistoryRow(2);
  expect(comp.expandedHistoryRows.has(2)).toBe(true);
  expect(comp.expandedHistoryRows.has(3)).toBe(true);
});

test('getFirstLine', () => {
  expect(comp.getFirstLine(null)).toBe('-');
  expect(comp.getFirstLine(undefined)).toBe('-');
  expect(comp.getFirstLine('')).toBe('-');
  expect(comp.getFirstLine('single line')).toBe('single line');
  expect(comp.getFirstLine('line1\nline2\nline3')).toBe('line1');
});

test('getSortLabel', () => {
  expect(comp.getSortLabel('ts')).toBe('Time');
  expect(comp.getSortLabel('settingId')).toBe('Setting ID');
  expect(comp.getSortLabel('user')).toBe('User');
  expect(comp.getSortLabel('nodeId')).toBe('Node');
  expect(comp.getSortLabel('unknown')).toBe('unknown');
  expect(comp.getSortLabel('anything')).toBe('anything');
});

test('filteredAuditHistory_noFilter', () => {
  comp.appliedHistorySearch = '';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
    { settingId: 'baz.qux', newValue: 'val2', oldValue: null, nodeId: 'node2', userId: 'user2', userName: 'User Two' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(2);
});

test('filteredAuditHistory_filterBySettingId', () => {
  comp.appliedHistorySearch = 'foo';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
    { settingId: 'baz.qux', newValue: 'val2', oldValue: null, nodeId: 'node2', userId: 'user2', userName: 'User Two' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(1);
  expect(comp.filteredAuditHistory()[0].settingId).toBe('foo.bar');
});

test('filteredAuditHistory_filterByNewValue', () => {
  comp.appliedHistorySearch = 'val2';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
    { settingId: 'baz.qux', newValue: 'val2', oldValue: null, nodeId: 'node2', userId: 'user2', userName: 'User Two' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(1);
  expect(comp.filteredAuditHistory()[0].settingId).toBe('baz.qux');
});

test('filteredAuditHistory_filterByOldValue', () => {
  comp.appliedHistorySearch = 'val0';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
    { settingId: 'baz.qux', newValue: 'val2', oldValue: null, nodeId: 'node2', userId: 'user2', userName: 'User Two' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(1);
  expect(comp.filteredAuditHistory()[0].settingId).toBe('foo.bar');
});

test('filteredAuditHistory_filterByNodeId', () => {
  comp.appliedHistorySearch = 'node2';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
    { settingId: 'baz.qux', newValue: 'val2', oldValue: null, nodeId: 'node2', userId: 'user2', userName: 'User Two' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(1);
  expect(comp.filteredAuditHistory()[0].nodeId).toBe('node2');
});

test('filteredAuditHistory_filterByUserName', () => {
  comp.appliedHistorySearch = 'User Two';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
    { settingId: 'baz.qux', newValue: 'val2', oldValue: null, nodeId: 'node2', userId: 'user2', userName: 'User Two' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(1);
  expect(comp.filteredAuditHistory()[0].userName).toBe('User Two');
});

test('filteredAuditHistory_filterByUserId', () => {
  comp.appliedHistorySearch = 'user2';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
    { settingId: 'baz.qux', newValue: 'val2', oldValue: null, nodeId: 'node2', userId: 'user2', userName: 'User Two' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(1);
  expect(comp.filteredAuditHistory()[0].userId).toBe('user2');
});

test('filteredAuditHistory_filterNoMatch', () => {
  comp.appliedHistorySearch = 'nonexistent';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(0);
});

test('filteredAuditHistory_caseInsensitive', () => {
  comp.appliedHistorySearch = 'FOO';
  comp.auditHistory = [
    { settingId: 'foo.bar', newValue: 'val1', oldValue: 'val0', nodeId: 'node1', userId: 'user1', userName: 'User One' },
  ];
  expect(comp.filteredAuditHistory().length).toBe(1);
});

test('historyTotalPages_usesFilteredCount', () => {
  comp.appliedHistorySearch = '';
  comp.auditHistory = Array.from({length: 26}, (_, i) => ({ settingId: 's' + i }));
  comp.pageSize = 25;
  comp.historyFilteredTotal = 26;
  expect(comp.historyTotalPages()).toBe(2);

  comp.appliedHistorySearch = 's1';
  comp.historyFilteredTotal = 11;
  expect(comp.filteredAuditHistory().length).toBe(11);
  expect(comp.historyTotalPages()).toBe(1);
});

test('applyHistoryFilter', () => {
  comp.historySearch = 's1';
  comp.appliedHistorySearch = '';
  comp.historyPage = 5;
  comp.auditHistory = Array.from({length: 26}, (_, i) => ({ settingId: 's' + i }));
  comp.pageSize = 25;
  comp.historyFilteredTotal = 26;

  comp.applyHistoryFilter();

  expect(comp.appliedHistorySearch).toBe('s1');
  expect(comp.historyFilteredTotal).toBe(11);
});

test('applyHistoryFilter_emptyResets', () => {
  comp.historySearch = '';
  comp.appliedHistorySearch = 'old';
  comp.auditHistory = [];
  comp.pageSize = 25;

  comp.applyHistoryFilter();

  expect(comp.appliedHistorySearch).toBe('');
});

test('applyHistoryFilter_adjustsPageIfBeyondLast', () => {
  comp.historySearch = 's1';
  comp.appliedHistorySearch = '';
  comp.auditHistory = Array.from({length: 26}, (_, i) => ({ settingId: 's' + i }));
  comp.pageSize = 5;
  comp.historyPage = 5;
  comp.historyFilteredTotal = 26;

  comp.applyHistoryFilter();

  expect(comp.filteredAuditHistory().length).toBe(11);
  expect(comp.historyFilteredTotal).toBe(11);
  expect(comp.historyTotalPages()).toBe(3);
  expect(comp.historyPage).toBe(3);
});

test('goToFirstPage', async () => {
  mockPapi("get", { data: { history: [], total: 0 } });
  comp.historyPage = 5;
  comp.isGlobalHistory = true;
  comp.historySetting = null;
  comp.pageSize = 25;
  comp.historySort = 'ts';
  comp.historyOrder = 'desc';

  await comp.goToFirstPage();

  expect(comp.historyPage).toBe(1);
});

test('goToLastPage', async () => {
  mockPapi("get", { data: { history: [], total: 60 } });
  comp.historyPage = 1;
  comp.isGlobalHistory = true;
  comp.historySetting = null;
  comp.pageSize = 25;
  comp.historySort = 'ts';
  comp.historyOrder = 'desc';
  comp.historyTotal = 60;

  await comp.goToLastPage();

  expect(comp.historyPage).toBe(3);
});

test('showHistory_resetsSearch', async () => {
  comp.historySearch = 'old search';
  comp.appliedHistorySearch = 'old search';
  mockPapi("get", { data: { history: [], total: 0 } });
  await comp.showHistory({id: 'test'});
  expect(comp.historySearch).toBe('');
  expect(comp.appliedHistorySearch).toBe('');
});

test('goToSetting', () => {
  comp.showHistoryDialog = true;
  comp.active = [];
  comp.goToSetting('some.setting.id');
  expect(comp.active).toEqual(['some.setting.id']);
  expect(comp.showHistoryDialog).toBe(false);
});

test('updateHistorySort_sameColumn', async () => {
  mockPapi("get", { data: { history: [], total: 0 } });
  comp.historySort = 'ts';
  comp.historyOrder = 'desc';
  comp.isGlobalHistory = true;
  comp.historySetting = null;
  comp.historyPage = 3;
  comp.pageSize = 25;

  comp.updateHistorySort('ts');

  expect(comp.historyOrder).toBe('asc');
  expect(comp.historySort).toBe('ts');
  expect(comp.historyPage).toBe(1);
});

test('updateHistorySort_differentColumn', async () => {
  mockPapi("get", { data: { history: [], total: 0 } });
  comp.historySort = 'ts';
  comp.historyOrder = 'asc';
  comp.isGlobalHistory = true;
  comp.historySetting = null;
  comp.historyPage = 3;
  comp.pageSize = 25;

  comp.updateHistorySort('user');

  expect(comp.historySort).toBe('user');
  expect(comp.historyOrder).toBe('desc');
  expect(comp.historyPage).toBe(1);
});

test('revertSetting_nonGlobal', async () => {
  mockPapi("get", { data: { count: 3 } });
  comp.isGlobalHistory = false;
  const entry = { timestamp: '2025-01-01T00:00:00Z', settingId: 'test.setting' };

  await comp.revertSetting(entry);

  expect(comp.confirmRevertEntry).toBe(entry);
  expect(comp.revertAllSettings).toBe(false);
  expect(comp.confirmRevertAllInput).toBe('');
  expect(comp.confirmRevertAllCount).toBe(3);
  expect(comp.confirmRevertDialog).toBe(true);
  expect(comp.restoreNote).toContain('Reverting setting to state prior to');
  expect(comp.restoreNoteDefault).toBe(comp.restoreNote);
});

test('revertSetting_global_withCount', async () => {
  mockPapi("get", { data: { count: 5 } });
  comp.isGlobalHistory = true;
  const entry = { timestamp: '2025-01-01T00:00:00Z' };

  await comp.revertSetting(entry);

  expect(comp.confirmRevertAllCount).toBe(5);
  expect(comp.confirmRevertDialog).toBe(true);
});

test('revertSetting_global_error', async () => {
  mockPapi("get", null, new Error('fail'));
  comp.isGlobalHistory = true;
  const entry = { timestamp: '2025-01-01T00:00:00Z' };

  await comp.revertSetting(entry);

  expect(comp.confirmRevertAllCount).toBe(0);
  expect(comp.confirmRevertDialog).toBe(true);
});

test('confirmRevert_globalRevertAll', async () => {
  const postMock = mockPapi("post", {});
  mockPapi("get", { data: [] });
  comp.isGlobalHistory = true;
  comp.revertAllSettings = true;
  comp.confirmRevertAllCount = 1;
  comp.confirmRevertAllInput = '';
  comp.confirmRevertEntry = { timestamp: '2025-01-01T00:00:00Z' };
  comp.restoreNote = 'reverting';
  comp.settings = [];

  await comp.confirmRevert();

  expect(postMock).toHaveBeenCalledWith('config/history/revert/all', {
    timestamp: '2025-01-01T00:00:00Z',
    note: 'reverting'
  });
  expect(comp.confirmRevertDialog).toBe(false);
  expect(comp.showHistoryDialog).toBe(false);
});

test('confirmRevert_globalRevertAll_blockedByCount', async () => {
  const postMock = mockPapi("post", {});
  comp.isGlobalHistory = true;
  comp.revertAllSettings = true;
  comp.confirmRevertAllCount = 5;
  comp.confirmRevertAllInput = '3';
  comp.confirmRevertEntry = { timestamp: '2025-01-01T00:00:00Z' };
  comp.restoreNote = 'reverting';

  await comp.confirmRevert();

  expect(postMock).toHaveBeenCalledTimes(0);
});

test('confirmRevert_singleSetting_globalValue', async () => {
  const postMock = mockPapi("post", {});
  comp.isGlobalHistory = false;
  comp.revertAllSettings = false;
  comp.confirmRevertEntry = { settingId: 'test.id', nodeId: null, oldValue: 'oldVal', timestamp: '2025-01-01T00:00:00Z' };
  comp.restoreNote = 'reverting';
  comp.settings = [{ id: 'test.id', value: 'currentVal', nodeValues: new Map() }];

  await comp.confirmRevert();

  expect(postMock).toHaveBeenCalledWith('config/history/revert/test.id', {
    timestamp: '2025-01-01T00:00:00Z',
    note: 'reverting'
  });
  expect(comp.settings[0].value).toBe('oldVal');
  expect(comp.confirmRevertDialog).toBe(false);
  expect(comp.showHistoryDialog).toBe(false);
});

test('confirmRevert_singleSetting_nodeValue', async () => {
  const postMock = mockPapi("post", {});
  comp.isGlobalHistory = false;
  comp.revertAllSettings = false;
  comp.confirmRevertEntry = { settingId: 'test.id', nodeId: 'node1', oldValue: 'oldNodeVal', timestamp: '2025-01-01T00:00:00Z' };
  comp.restoreNote = 'reverting';
  const nv = new Map();
  nv.set('node1', 'currentNodeVal');
  comp.settings = [{ id: 'test.id', value: 'globalVal', nodeValues: nv }];

  await comp.confirmRevert();

  expect(postMock).toHaveBeenCalledWith('config/history/revert/test.id/node1', {
    timestamp: '2025-01-01T00:00:00Z',
    note: 'reverting'
  });
  expect(comp.settings[0].nodeValues.get('node1')).toBe('oldNodeVal');
});

test('confirmRevert_singleSetting_nodeValue_null', async () => {
  const postMock = mockPapi("post", {});
  comp.isGlobalHistory = false;
  comp.revertAllSettings = false;
  comp.confirmRevertEntry = { settingId: 'test.id', nodeId: 'node1', oldValue: null, timestamp: '2025-01-01T00:00:00Z' };
  comp.restoreNote = 'reverting';
  const nv = new Map();
  nv.set('node1', 'currentNodeVal');
  comp.settings = [{ id: 'test.id', value: 'globalVal', nodeValues: nv }];

  await comp.confirmRevert();

  expect(comp.settings[0].nodeValues.has('node1')).toBe(false);
});

test('confirmRevert_error', async () => {
  mockPapi("post", null, new Error('fail'));
  const showErrorMock = mockShowError();
  comp.isGlobalHistory = false;
  comp.revertAllSettings = false;
  comp.confirmRevertEntry = { settingId: 'test.id', nodeId: null, oldValue: 'old', timestamp: '2025-01-01T00:00:00Z' };
  comp.restoreNote = 'reverting';
  comp.settings = [];

  await comp.confirmRevert();

  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.settingRevertError);
});

test('confirmRevert_settingNotFound', async () => {
  const postMock = mockPapi("post", {});
  comp.isGlobalHistory = false;
  comp.revertAllSettings = false;
  comp.confirmRevertEntry = { settingId: 'missing.id', nodeId: null, oldValue: 'old', timestamp: '2025-01-01T00:00:00Z' };
  comp.restoreNote = 'reverting';
  comp.settings = [{ id: 'other.id', value: 'val', nodeValues: new Map() }];

  await comp.confirmRevert();

  expect(postMock).toHaveBeenCalled();
  expect(comp.confirmRevertDialog).toBe(false);
});

test('confirmRevert_nonGlobalRevertAll', async () => {
  const postMock = mockPapi("post", {});
  mockPapi("get", { data: [] });
  comp.isGlobalHistory = false;
  comp.revertAllSettings = true;
  comp.confirmRevertAllCount = 1;
  comp.confirmRevertAllInput = '';
  comp.confirmRevertEntry = { timestamp: '2025-01-01T00:00:00Z', settingId: 'test.id' };
  comp.restoreNote = 'reverting all';
  comp.settings = [];

  await comp.confirmRevert();

  expect(postMock).toHaveBeenCalledWith('config/history/revert/all', {
    timestamp: '2025-01-01T00:00:00Z',
    note: 'reverting all'
  });
  expect(comp.confirmRevertDialog).toBe(false);
  expect(comp.showHistoryDialog).toBe(false);
});

test('revertAllSettings_watcher_updatesNote_whenNotCustomized', async () => {
  const entry = { timestamp: '2025-01-01T00:00:00Z' };
  comp.confirmRevertEntry = entry;
  comp.restoreNote = 'Reverting setting to state prior to 2025-01-01T00:00:00Z';
  comp.restoreNoteDefault = comp.restoreNote;

  comp.watch.revertAllSettings.call(comp, true);

  expect(comp.restoreNote).toContain('Reverting all settings to state prior to');
  expect(comp.restoreNoteDefault).toBe(comp.restoreNote);

  comp.watch.revertAllSettings.call(comp, false);

  expect(comp.restoreNote).toContain('Reverting setting to state prior to');
  expect(comp.restoreNoteDefault).toBe(comp.restoreNote);
});

test('revertAllSettings_watcher_preservesNote_whenCustomized', async () => {
  const entry = { timestamp: '2025-01-01T00:00:00Z' };
  comp.confirmRevertEntry = entry;
  comp.restoreNote = 'my custom note';
  comp.restoreNoteDefault = 'Reverting setting to state prior to 2025-01-01T00:00:00Z';

  comp.watch.revertAllSettings.call(comp, true);

  expect(comp.restoreNote).toBe('my custom note');
});

test('onRestoreNoteInput_removed', () => {
  expect(comp.onRestoreNoteInput).toBeUndefined();
});

test('selectSetting', () => {
  comp.form.entriesExpanded = 12;
  setupSettings();

  comp.selectSetting();

  expect(comp.activeBackup).toStrictEqual(["s-id"]);
  expect(comp.availableNodes).toStrictEqual([{title: "node2 (standalone)", value: "n2"}]);
  expect(comp.cancelDialog).toBe(false);
  expect(comp.confirmResetDialog).toBe(false);
  expect(comp.form.entriesExpanded).toBeNull();
});

test('cancel', () => {
  comp.form.entriesExpanded = 12;
  comp.active = ["cancel-id"];
  comp.settings = [{id: "cancel-id", value: "abc"}];
  comp.form.value = "123";

  // Force the cancel (no dialog popup)
  comp.form.key = "cancel-id";
  comp.cancelDialog = true;
  comp.cancel(true);
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);

  // Normal cancel - expect popup
  comp.form.key = "cancel-id";
  comp.activeBackup = ["cancel-id"];
  comp.cancelDialog = true;
  comp.cancel(false);
  expect(comp.cancelDialog).toBe(true);
  expect(comp.form.key).toBe("cancel-id");
  expect(comp.form.entriesExpanded).toBe(12);
});

test('userCancel', () => {
  comp.form.entriesExpanded = 12;
  comp.userCancel();
  expect(comp.form.entriesExpanded).toBeNull();
});

test('remove', () => {
  expect(comp.confirmResetDialog).toBe(false);
  expect(comp.resetSetting).toBe(null);
  expect(comp.resetNodeId).toBe(null);
  comp.resetNodeId = "foo"
  comp.resetSetting = "bar"
  comp.confirmResetDialog = true
  comp.remove("bar", "foo");
  expect(comp.confirmResetDialog).toBe(true);
  expect(comp.resetSetting).toBe("bar");
  expect(comp.resetNodeId).toBe("foo");
});

test('cancelReset', () => {
  expect(comp.confirmResetDialog).toBe(false);
  expect(comp.resetSetting).toBe(null);
  expect(comp.resetNodeId).toBe(null);
  comp.resetNodeId = "foo"
  comp.resetSetting = "bar"
  comp.confirmResetDialog = true
  comp.cancelRemove("bar", "foo");
  expect(comp.confirmResetDialog).toBe(false);
  expect(comp.resetSetting).toBe(null);
  expect(comp.resetNodeId).toBe(null);
});

test('confirmRemove', async () => {
  setupSettings();

  // No-op path
  comp.remove(comp.settings[0], "nonexisting");
  var mock = mockPapi("delete");
  await comp.confirmRemove();
  var expectedNodeValues = new Map();
  expectedNodeValues.set("n1", "123");
  expectedNodeValues.set("n1a", "abc");
  expect(comp.settings[0].nodeValues).toStrictEqual(expectedNodeValues);
  expect(comp.resetSetting).toBe(null);
  expect(comp.resetNodeId).toBe(null);
  expect(comp.confirmResetDialog).toBe(false);
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', { params: {"id": "s-id", "minion": "nonexisting" }});

  // Good path
  comp.remove(comp.settings[0], "n1");
  mock = mockPapi("delete");
  await comp.confirmRemove();
  expectedNodeValues = new Map();
  expectedNodeValues.set("n1a", "abc");
  expect(comp.settings[0].nodeValues).toStrictEqual(expectedNodeValues);
  expect(comp.resetSetting).toBe(null);
  expect(comp.resetNodeId).toBe(null);
  expect(comp.confirmResetDialog).toBe(false);
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', { params: {"id": "s-id", "minion": "n1" }});
});

test('save', async () => {
  setupSettings();

  // Global save
  comp.form.value = "test-value";
  comp.form.key = "s-id";
  var mock = mockPapi("put");
  await comp.save(comp.settings[0], null);
  expect(comp.showNoteDialog).toBe(true);
  await comp.save();
  expect(comp.settings[0].value).toBe("test-value")
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', {"id": "s-id", "nodeId": null, "value": "test-value", "note": "", "file": undefined, "syntax": undefined});

  // Node save
  setupSettings();
  comp.form.value = "test-value"
  comp.form.key = "n2";
  mock = mockPapi("put");
  await comp.save(comp.settings[0], "n2");
  expect(comp.showNoteDialog).toBe(true);
  await comp.save();
  expect(comp.settings[0].value).toBe("orig-value")
  expectedNodeValues = new Map();
  expectedNodeValues.set("n1a", "abc");
  expectedNodeValues.set("n1", "123");
  expectedNodeValues.set("n2", "test-value");
  expect(comp.settings[0].nodeValues).toStrictEqual(expectedNodeValues);
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', {"id": "s-id", "nodeId": "n2", "value": "test-value", "note": "", "file": undefined, "syntax": undefined});
});

test('save_with_note', async () => {
  setupSettings();
  comp.form.value = "test-value";
  comp.form.key = "s-id";
  var mock = mockPapi("put");
  await comp.save(comp.settings[0], null);
  expect(comp.showNoteDialog).toBe(true);
  comp.note = "test note";
  await comp.save();
  expect(comp.settings[0].value).toBe("test-value")
  expect(mock).toHaveBeenCalledWith('config/', {"id": "s-id", "nodeId": null, "value": "test-value", "note": "test note", "file": undefined, "syntax": undefined});
});

test('saveBool', async () => {
  setupSettings();
  comp.form.value = true;
  comp.form.key = "s-id";
  var mock = mockPapi("put");
  await comp.save(comp.settings[0], null);
  expect(comp.showNoteDialog).toBe(true);
  await comp.save();
  expect(comp.settings[0].value).toBe("true")
  expect(mock).toHaveBeenCalledWith('config/', {"id": "s-id", "nodeId": null, "value": "true", "note": "", "file": undefined, "syntax": undefined});
});

test('saveRegexFailure', async () => {
  comp.settings = [{
    id: 'test.id',
    value: '123',
    regex: '^([0-9]){3}$',
    regexFailureMessage: 'do better',
  }];

  comp.form.value = "test-value";
  comp.form.key = "test.id";
  const showErrorMock = mockShowError();
  const mock = mockPapi("post");
  await comp.save(comp.settings[0], null);

  expect(showErrorMock).toHaveBeenCalledWith('do better');
  expect(comp.settings[0].value).toBe("123")
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe('test.id');
  expect(mock).toHaveBeenCalledTimes(0);
});

test('saveRegexFailureMultiline', async () => {
  comp.settings = [{
    id: 'test.id',
    value: '123',
    multiline: true,
    regex: '^([0-9]){3}$',
    regexFailureMessage: 'do better',
  }];

  comp.form.value = "test-value\nanother-value\n";
  comp.form.key = "test.id";
  const showErrorMock = mockShowError();
  const mock = mockPapi("post");
  await comp.save(comp.settings[0], null);

  expect(showErrorMock).toHaveBeenCalledWith('do better');
  expect(comp.settings[0].value).toBe("123")
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe('test.id');
  expect(mock).toHaveBeenCalledTimes(0);
});

test('saveRegexValidMultiline', async () => {
  comp.settings = [{
    id: 'test.id',
    value: '123',
    multiline: true,
    regex: '^([0-9]){3}$',
    regexFailureMessage: 'do better',
  }];

  comp.form.value = "123\n456\n";
  comp.form.key = "test.id";
  const showErrorMock = mockShowError(true);
  const mock = mockPapi("put");
  await comp.save(comp.settings[0], null);
  expect(comp.showNoteDialog).toBe(true);
  await comp.save();

  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.settings[0].value).toBe("123\n456")
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', {"id": "test.id", "nodeId": null, "value": "123\n456", "note": "", "file": undefined, "syntax": undefined});
});

test('saveRequiredEmptyValue', async () => {
  comp.settings = [{
    id: 'test.id',
    value: 'original',
    required: true,
  }];
  comp.form.value = "";
  comp.form.key = "test.id";
  const showErrorMock = mockShowError();
  const mock = mockPapi("put");

  await comp.save(comp.settings[0], null);

  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.settingValidationFailed);
  expect(comp.settings[0].value).toBe('original');
  expect(comp.form.key).toBe('test.id');
  expect(mock).toHaveBeenCalledTimes(0);
});

test('saveRequiredNonEmptyValue', async () => {
  comp.settings = [{
    id: 'test.id',
    value: 'original',
    required: true,
  }];
  comp.form.value = "new-value";
  comp.form.key = "test.id";
  const showErrorMock = mockShowError(true);
  const mock = mockPapi("put");

  await comp.save(comp.settings[0], null);
  expect(comp.showNoteDialog).toBe(true);
  await comp.save();

  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.settings[0].value).toBe('new-value');
  expect(comp.form.key).toBe(null);
});

test('savePackError', async () => {
  comp.settings = [{
    id: 'test.id',
    value: 'original',
    syntax: 'json',
    uiElements: [{field: 'foo'}],
  }];
  comp.form.value = "test";
  comp.form.key = "test.id";
  comp.form.entries = [{foo: 'bar'}, {_title: 'empty'}];
  comp.pack = jest.fn().mockImplementation(() => { throw new Error('pack error'); });
  const showErrorMock = mockShowError();
  const mock = mockPapi("put");

  await comp.save(comp.settings[0], null);

  expect(showErrorMock).toHaveBeenCalledWith(comp.i18n.settingValidationFailed);
  expect(mock).toHaveBeenCalledTimes(0);
});

test('saveIncompleteUiElements', async () => {
  comp.settings = [{
    id: 'test.id',
    value: 'original',
    syntax: 'json',
    uiElements: [{field: 'foo'}],
  }];
  comp.form.value = "test";
  comp.form.key = "test.id";
  comp.form.entries = [{foo: 'bar'}, {_title: '+'}];
  comp.uiElementsValid = false;
  comp.isEntryEmpty = jest.fn().mockReturnValue(false);
  const showWarningMock = jest.fn();
  comp.$root.showWarning = showWarningMock;
  const mock = mockPapi("put");

  await comp.save(comp.settings[0], null);

  expect(showWarningMock).toHaveBeenCalledWith(comp.i18n.settingIncomplete);
  expect(mock).toHaveBeenCalledTimes(0);
});

test('saveArrayWithSeparator', async () => {
  comp.settings = [{
    id: 'test.id',
    value: 'original',
    optionSeparator: ',',
  }];
  comp.form.value = ["a", "b", "c"];
  comp.form.key = "test.id";
  const mock = mockPapi("put");

  await comp.save(comp.settings[0], null);
  expect(comp.showNoteDialog).toBe(true);
  expect(comp.form.value).toBe("a,b,c");
  await comp.save();

  expect(comp.settings[0].value).toBe("a,b,c");
  expect(mock).toHaveBeenCalledWith('config/', {"id": "test.id", "nodeId": null, "value": "a,b,c", "note": "", "file": undefined, "syntax": undefined});
});

test('saveArrayWithDefaultSeparator', async () => {
  comp.settings = [{
    id: 'test.id',
    value: 'original',
  }];
  comp.form.value = ["x", "y"];
  comp.form.key = "test.id";
  const mock = mockPapi("put");

  await comp.save(comp.settings[0], null);
  expect(comp.showNoteDialog).toBe(true);
  expect(comp.form.value).toBe("x\ny");
  await comp.save();

  expect(comp.settings[0].value).toBe("x\ny");
  expect(mock).toHaveBeenCalledWith('config/', {"id": "test.id", "nodeId": null, "value": "x\ny", "note": "", "file": undefined, "syntax": undefined});
});

test('saveNullSetting', async () => {
  comp.form.value = "test";
  comp.form.key = "some-id";
  comp.note = "";

  await comp.save(null, null);

  expect(comp.showNoteDialog).toBe(true);
  expect(comp.pendingSave).toEqual({ setting: null, nodeId: null });
});

test('edit', async () => {
  // Global edit, nothing pending
  setupSettings();
  comp.cancelDialog = false;
  comp.form.value = null;
  comp.form.key = null;
  comp.edit(comp.settings[0], null);
  await new Promise(resolve => setTimeout(resolve, 2));
  expect(comp.form.key).toBe("s-id");
  expect(comp.form.value).toBe("orig-value");
  expect(comp.cancelDialog).toBe(false);

  // Global edit, something else pending save
  setupSettings();
  comp.cancelDialog = false;
  comp.form.value = "touched-value";
  comp.form.key = "s-id2";
  comp.activeBackup = ["s-id2"];
  comp.edit(comp.settings[0], null);
  await new Promise(resolve => setTimeout(resolve, 2));
  expect(comp.form.key).toBe("s-id2");
  expect(comp.form.value).toBe("touched-value");
  expect(comp.cancelDialog).toBe(true);

  // Node edit, nothing pending
  setupSettings();
  comp.form.value = null;
  comp.form.key = null;
  comp.edit(comp.settings[0], "n1");
  await new Promise(resolve => setTimeout(resolve, 2));
  expect(comp.form.key).toBe("n1");
  expect(comp.form.value).toBe("123");
  expect(comp.cancelDialog).toBe(false);

  // Node edit, something else pending save
  setupSettings();
  comp.form.value = "touched-value";
  comp.form.key = "n2";
  comp.edit(comp.settings[0], "n1");
  await new Promise(resolve => setTimeout(resolve, 2));
  expect(comp.form.key).toBe("n2");
  expect(comp.form.value).toBe("touched-value");
  expect(comp.cancelDialog).toBe(true);
});

test('addNode', () => {
  // Node add, nothing pending
  setupSettings();
  expect(comp.cancelDialog).toBe(true);
  comp.addNode(comp.settings[0], "n2");
  expect(comp.settings[0].nodeValues.get('n2')).toBe("def-value");
  expect(comp.cancelDialog).toBe(false);

  // Node add, something else pending save
  setupSettings();
  comp.cancelDialog = false;
  comp.form.value = "touched-value";
  comp.form.key = "n1";
  comp.addNode(comp.settings[0], "n2");
  expect(comp.settings[0].nodeValues.get('n2')).toBe(undefined);
  expect(comp.form.key).toBe("n1");
  expect(comp.form.value).toBe("touched-value");
  expect(comp.cancelDialog).toBe(true);
});

test('addToNode_Malformed', () => {
  const closure = () => {
    comp.addToNode({name: 'test'}, {}, ['parent'], {name: 'test'});
  };
  expect(closure).toThrow("Setting name 'test' conflicts with another similarly named setting");
});

test('toggleDuplicate', () => {
  const setting = {
    id: "a.b.c",
    name: "c",
    duplicates: true,
  }
  expect(comp.showDuplicate).toBe(false)
  comp.toggleDuplicate(setting)
  expect(comp.duplicateId).toBe("c_dup");
  expect(comp.showDuplicate).toBe(true)
});

test('duplicate', () => {
  const setting = {
    id: "a.b.c",
    name: "c",
    duplicates: true,
  }
  const setting2 = {
    id: "a.b.c",
    name: "c",
    duplicates: true,
  }

  Vue = {
    toRaw: jest.fn().mockReturnValueOnce(setting),
  };
  global.structuredClone = jest.fn().mockReturnValueOnce(setting2);

  comp.settings = [setting];
  comp.duplicateId = "foo"
  expect(comp.settings.length).toBe(1);

  comp.duplicate(setting);
  expect(comp.settings.length).toBe(2);
  expect(comp.settings[1].id).toBe("a.b.foo");
  expect(comp.settings[1].name).toBe("foo");
});

test('applySearchFilter', () => {
  comp.search = "foo";
  comp.searchFilter = "";
  comp.applySearchFilter();
  expect(comp.searchFilter).toBe(comp.search);
  comp.clearFilter();
  expect(comp.search).toBe("");
  expect(comp.searchFilter).toBe("");
});

test('isReadOnly', () => {
  const setting = {
    id: "a1",
    readonly: false,
    readonlyUi: false,
  };
  expect(comp.isReadOnly(setting)).toBe(false);
  setting.readonly = true;
  expect(comp.isReadOnly(setting)).toBe(true);
  setting.readonly = false;
  setting.readonlyUi = true;
  expect(comp.isReadOnly(setting)).toBe(true);
  setting.readonly = true;
  expect(comp.isReadOnly(setting)).toBe(true);
});

test('processRouteParameters', () => {
  comp.$route.query = {
    f: 'search',
  };
  comp.$nextTick = jest.fn();

  // Local grid
  comp.oldGridId = null;
  expect(comp.processRouteParameters()).toBe(false);

  expect(comp.search).toBe('search');
  expect(comp.autoSelect).toBe('');
  expect(comp.autoExpand).toBe(false);
  expect(comp.searchFilter).toBe('search');
  expect(comp.advanced).toBe(false);
  expect(comp.$nextTick).toHaveBeenCalledTimes(0);

  // Remote grid
  comp.search = '';
  comp.searchFilter = '';
  comp.$route.query = {
    e: '1',
    gridId: 'my_grid',
  };

  expect(comp.processRouteParameters()).toBe(true);

  expect(comp.search).toBe('');
  expect(comp.autoSelect).toBe('');
  expect(comp.autoExpand).toBe(true);
  expect(comp.searchFilter).toBe('');
  expect(comp.advanced).toBe(false);
  expect(comp.$nextTick).toHaveBeenCalledTimes(0);

  comp.autoExpand = false;
  comp.$route.query = {
    a: '1',
  };

  comp.processRouteParameters();

  expect(comp.search).toBe('');
  expect(comp.autoSelect).toBe('');
  expect(comp.autoExpand).toBe(false);
  expect(comp.searchFilter).toBe('');
  expect(comp.advanced).toBe(true);
  expect(comp.$nextTick).toHaveBeenCalledTimes(0);

  comp.advanced = false
  comp.$route.query = {
    a: '1',
    e: '1',
    f: 'search',
  };

  comp.processRouteParameters();

  expect(comp.search).toBe('search');
  expect(comp.autoSelect).toBe('');
  expect(comp.autoExpand).toBe(true);
  expect(comp.searchFilter).toBe('search');
  expect(comp.advanced).toBe(true);
  expect(comp.$nextTick).toHaveBeenCalledTimes(1);
});

test('getSettingBreadcrumbs', () => {
  setting = { id: "foo.bar.car", advanced: false };
  expect(comp.getSettingBreadcrumbs(setting)).toStrictEqual(['foo', 'bar', 'car']);

  setting = { id: "foo.bar.car", advanced: false, title: "Carbine" };
  expect(comp.getSettingBreadcrumbs(setting)).toStrictEqual(['foo', 'bar', 'Carbine']);

  setting = { id: "foo.bar.car", advanced: true };
  expect(comp.getSettingBreadcrumbs(setting)).toStrictEqual(['foo', 'bar', 'car [adv]']);

  setting = { id: "foo.bar.car", advanced: true, title: "Carbine" };
  expect(comp.getSettingBreadcrumbs(setting)).toStrictEqual(['foo', 'bar', 'Carbine [adv]']);
});

test('hasUiElements', () => {
  setting = {};
  expect(comp.hasUiElements(setting)).toBe(false);

  setting = { uiElements: [] };
  expect(comp.hasUiElements(setting)).toBe(false);

  setting = { uiElements: [{}] };
  expect(comp.hasUiElements(setting)).toBe(false);

  setting = { syntax: 'json' };
  expect(comp.hasUiElements(setting)).toBe(false);

  setting = { uiElements: [{}], syntax: 'json' };
  expect(comp.hasUiElements(setting)).toBe(true);
});

test('pack_unpack', () => {
  comp.form.value = "{}"
  comp.form.entries = [{foo: 'bar\ncar', _title:'ignore'},{_title:'empty'}];
  setting = {id: 'myid', uiElements:[{field: 'foo', label:'some fooness', multiline: true, forcedType: "[]string"}], syntax: 'json'}
  comp.pack(setting);
  expect(comp.form.value).toBe('[{"foo":["bar","car"]}]')

  comp.form.entries = null;
  setting.value = '[{"foo":["bar", "car"]}]';
  comp.settings = [setting];
  comp.active = ['myid'];
  comp.unpack(setting);
  expect(comp.form.entries.length).toBe(2);
  expect(comp.form.entries[0].foo).toBe('bar\ncar');
  expect(comp.form.entries[0]._title).toBe('1. bar,car');
  expect(comp.form.entries[1]._title).toBe('+');
});

test('pack_unpack_multiple', () => {
  comp.form.value = "{}"
  comp.form.entries = [{foo: 'bar', _title:'ignore'},{_title:'empty'},{foo: 'bar2', _title:'ignore2'},{_title:'empty2'}];
  setting = {id: 'myid', uiElements:[{field: 'foo', label:'some fooness'}], syntax: 'json'}
  comp.pack(setting);
  expect(comp.form.value).toBe('[{"foo":"bar"},{"foo":"bar2"}]')

  comp.form.entries = null;
  setting.value = '[{"foo":"bar"},{"foo":"bar2"}]';
  comp.settings = [setting];
  comp.active = ['myid'];
  comp.unpack(setting);
  expect(comp.form.entries.length).toBe(3);
  expect(comp.form.entries[0].foo).toBe('bar');
  expect(comp.form.entries[0]._title).toBe('1. bar');
  expect(comp.form.entries[1].foo).toBe('bar2');
  expect(comp.form.entries[1]._title).toBe('2. bar2');
  expect(comp.form.entries[2]._title).toBe('+');
});

test('pack_unpack_array_of_json', () => {
  comp.form.value = "{}"
  comp.form.entries = [{foo: 'bar', _title:'ignore'},{_title:'empty'}];
  setting = {id: 'myid', forcedType: "[]{}", uiElements:[{field: 'foo', label:'some fooness'}], syntax: 'json'}
  comp.pack(setting);
  expect(comp.form.value).toBe('{"foo":"bar"}')

  comp.form.entries = null;
  setting.value = '{"foo":"bar"}';
  comp.settings = [setting];
  comp.active = ['myid'];
  comp.unpack(setting);
  expect(comp.form.entries.length).toBe(2);
  expect(comp.form.entries[0].foo).toBe('bar');
  expect(comp.form.entries[0]._title).toBe('1. bar');
  expect(comp.form.entries[1]._title).toBe('+');
});

test('pack_unpack_multiple_array_of_json', () => {
  comp.form.value = "{}"
  comp.form.entries = [{foo: 'bar', _title:'ignore'},{_title:'empty'},{foo: 'bar2', _title:'ignore2'},{_title:'empty2'}];
  setting = {id: 'myid', forcedType: "[]{}", uiElements:[{field: 'foo', label:'some fooness'}], syntax: 'json'}
  comp.pack(setting);
  expect(comp.form.value).toBe('{"foo":"bar"}\n{"foo":"bar2"}')

  comp.form.entries = null;
  setting.value = '{"foo":"bar"}\n{"foo":"bar2"}';
  comp.settings = [setting];
  comp.active = ['myid'];
  comp.unpack(setting);
  expect(comp.form.entries.length).toBe(3);
  expect(comp.form.entries[0].foo).toBe('bar');
  expect(comp.form.entries[0]._title).toBe('1. bar');
  expect(comp.form.entries[1].foo).toBe('bar2');
  expect(comp.form.entries[1]._title).toBe('2. bar2');
  expect(comp.form.entries[2]._title).toBe('+');
});

test('generateEntryTitle', () => {
  entry = {id: 'something', foo:'hi'};
  comp.settings = [entry];
  comp.active = [entry.id];
  comp.generateEntryTitle(entry, 1);
  expect(entry._title).toBe('2. ');
  entry.uiElements = [{field: 'foo'}];
  comp.generateEntryTitle(entry, 1);
  expect(entry._title).toBe('2. hi');
});

test('markDirtyEntries', () => {
  comp.form.value = 123;
  comp.markDirtyEntries();
  expect(comp.form.value.length).toBe(13);
});

test('showClearEntryDialog', () => {
  expect(comp.confirmRemoveEntryDialog).toBe(false);
  const setting = {uiElementsDeleteMessage: 'hi'};
  comp.showClearEntryDialog(setting, 2);
  expect(comp.confirmRemoveEntryDialog).toBe(true);
  expect(comp.confirmRemoveEntryMessage).toBe('hi');
  expect(comp.confirmRemoveEntryIdx).toBe(2);
});

test('cancelClearEntry', () => {
  comp.confirmRemoveEntryDialog = true;
  comp.confirmRemoveEntryMessage = 'hi';
  comp.confirmRemoveEntryIdx = 2;
  comp.cancelClearEntry();
  expect(comp.confirmRemoveEntryDialog).toBe(false);
  expect(comp.confirmRemoveEntryMessage).toBe('');
  expect(comp.confirmRemoveEntryIdx).toBe(0);
});

test('confirmClearEntry', () => {
  entry = {foo: 'bar', some: 'value', _title: 'title'};
  comp.form.value = 123;
  comp.form.entries = [entry]
  comp.confirmRemoveEntryIdx = 0;
  comp.confirmClearEntry();
  expect(comp.form.value.length).toBe(13);
  expect(entry.foo).toBe('');
  expect(entry.some).toBe('');
  expect(entry._title).toBe('1. (pending deletion)');

  entry = {foo: 'bar', some: 'value', _title: '+'};
  comp.confirmClearEntry(entry, 1);
  expect(entry._title).toBe('+');
});

test('createEmptyUiElementEntry', () => {
  const setting = {
    uiElements: [
      { field: 'field1', default: 'default1' },
      { field: 'field2' },
      { field: 'field3', default: 'default3' },
    ],
  };

  const emptyEntry = comp.createEmptyUiElementEntry(setting);

  expect(emptyEntry._title).toBe('+');
  expect(emptyEntry.field1).toBe('default1');
  expect(emptyEntry.field3).toBe('default3');
  expect(emptyEntry.field2).toBeUndefined();
});

test('getElementLabel', () => {
  let element = { label: 'Test Label', required: false };
  expect(comp.getElementLabel(element)).toBe('Test Label');

  element = { label: 'Test Label', required: true };
  expect(comp.getElementLabel(element)).toBe('Test Label *');
});

test('validateRegexMatch', () => {
  let setting = { regex: '^test$', regexFailureMessage: 'Regex failed' };
  expect(comp.validateRegexMatch(setting, 'test')).toBe(true);
  expect(comp.validateRegexMatch(setting, 'fail')).toBe('Regex failed');

  setting = { regex: '^test$' };
  expect(comp.validateRegexMatch(setting, 'test')).toBe(true);
  expect(comp.validateRegexMatch(setting, 'fail')).toBe(comp.i18n.settingValidationFailed);
});

test('buildInputRules', () => {
  let setting = { required: false, regex: null };
  expect(comp.buildInputRules(setting)).toEqual([]);

  setting = { required: true, regex: null };
  let rules = comp.buildInputRules(setting);
  expect(rules.length).toBe(1);
  expect(rules[0]('')).toBe('Required.');

  setting = { required: false, regex: '^test$', regexFailureMessage: 'Regex failed' };
  rules = comp.buildInputRules(setting);
  expect(rules.length).toBe(1);
  expect(rules[0]('test')).toBe(true);
  expect(rules[0]('fail')).toBe('Regex failed');

  setting = { required: true, regex: '^test$', regexFailureMessage: 'Regex failed' };
  rules = comp.buildInputRules(setting);
  expect(rules.length).toBe(2);
  expect(rules[0]('')).toBe('Required.');
  expect(rules[1]('test')).toBe(true);
  expect(rules[1]('fail')).toBe('Regex failed');
});

test('isUiElementReadonly', () => {
  let entry = { _title: '1' };
  let setting = { readonly: false };
  expect(comp.isUiElementReadonly(entry, setting)).toBe(false);

  setting = { readonly: true };
  expect(comp.isUiElementReadonly(entry, setting)).toBe(true);

  entry = { _title: '+' };
  setting = { readonly: true };
  expect(comp.isUiElementReadonly(entry, setting)).toBe(false);
});

test('uiElementsHaveValidInputs', () => {
  comp.form.entries = null;
  let setting = { uiElements: [{}] };
  expect(comp.uiElementsHaveValidInputs(setting)).toBe(true);

  comp.form.entries = [{ valid: true }];
  setting = { uiElements: [{field: "valid", default: true}] };
  expect(comp.uiElementsHaveValidInputs(setting)).toBe(true);

  comp.form.entries = [{ valid: true }];
  setting = { uiElements: [{field: "valid", default: true}] };
  comp.uiElementsValid = false;
  expect(comp.uiElementsHaveValidInputs(setting)).toBe(true);

  comp.form.entries = [{ valid: false }, { _title: '+' }];
  setting = { uiElements: [{}] };
  comp.uiElementsValid = false;
  expect(comp.uiElementsHaveValidInputs(setting)).toBe(true);

  comp.form.entries = [{ valid: false }, { _title: '+' }];
  setting = { uiElements: [{}] };
  comp.uiElementsValid = false;
  comp.isEntryEmpty = jest.fn().mockReturnValue(false);
  expect(comp.uiElementsHaveValidInputs(setting)).toBe(false);
});

test('isEntryEmpty', () => {
  let setting = { uiElements: [{ field: 'foo', default: 'default' }] };
  let entry = { foo: 'default', _title: 'title' };
  expect(comp.isEntryEmpty(setting, entry)).toBe(true);

  setting = { uiElements: [{ field: 'foo', default: 'default' }] };
  entry = { foo: 'notDefault', _title: 'title' };
  expect(comp.isEntryEmpty(setting, entry)).toBe(false);
});

test('convertMultilineElement', () => {
  let element = { field: 'foo', multiline: true, forcedType: '[]string' };
  let modifiedEntry = { foo: 'bar\ncar\n' };

  comp.convertMultilineElement(element, modifiedEntry, false);
  expect(modifiedEntry.foo).toEqual(['bar', 'car']);

  comp.convertMultilineElement(element, modifiedEntry, true);
  expect(modifiedEntry.foo).toBe('bar\ncar');

  element = { field: 'foo', multiline: true, forcedType: '[]string' };
  modifiedEntry = { foo: null };

  comp.convertMultilineElement(element, modifiedEntry, false);
  expect(modifiedEntry.foo).toEqual([]);

  comp.convertMultilineElement(element, modifiedEntry, true);
  expect(modifiedEntry.foo).toBe('');
});

test('convertMultilineElementWithJSONObject', () => {
  let element = { field: 'foo', multiline: true, forcedType: '{}' };
  let modifiedEntry = { foo: {"foo": "bar"} };

  comp.convertMultilineElement(element, modifiedEntry, true);
  expect(modifiedEntry.foo).toBe('{\"foo\":\"bar\"}');

  comp.convertMultilineElement(element, modifiedEntry, false);
  expect(modifiedEntry.foo).toStrictEqual({"foo": "bar"});

});

test('canMoveEntry', () => {
  comp.form.entries = [{_title: '1'}, {_title: '2'}, {_title: '+'}];
  expect(comp.canMoveEntry(0, true)).toBe(true);
  expect(comp.canMoveEntry(0, false)).toBe(true);
  expect(comp.canMoveEntry(1, true)).toBe(true);
  expect(comp.canMoveEntry(1, false)).toBe(true);
  expect(comp.canMoveEntry(2, true)).toBe(false);
  expect(comp.canMoveEntry(2, false)).toBe(false);

  comp.form.entries = [{_title: '1'}, {_title: '2'}];
  expect(comp.canMoveEntry(0, true)).toBe(true);
  expect(comp.canMoveEntry(0, false)).toBe(true);
  expect(comp.canMoveEntry(1, true)).toBe(true);
  expect(comp.canMoveEntry(1, false)).toBe(true);
});

test('moveEntry', () => {
  comp.form.entries = [{_title: '1'}, {_title: '2'}, {_title: '+'}];
  comp.isPendingSave = jest.fn().mockReturnValue(false);
  comp.editNow = jest.fn();
  comp.generateEntryTitle = jest.fn();
  comp.markDirtyEntries = jest.fn();

  comp.moveEntry({}, 0, false);
  expect(comp.isPendingSave).toHaveBeenCalledWith({});
  expect(comp.editNow).toHaveBeenCalled();
  expect(comp.generateEntryTitle).toHaveBeenCalledTimes(2);
  expect(comp.markDirtyEntries).toHaveBeenCalled();
  expect(comp.form.entries[0]._title).toBe('2');
  expect(comp.form.entries[1]._title).toBe('1');

  comp.moveEntry({}, 1, true);
  expect(comp.form.entries[0]._title).toBe('1');
  expect(comp.form.entries[1]._title).toBe('2');
});

test('moveEntryWrap', () => {
  comp.form.entries = [{_title: '1'}, {_title: '2'}, {_title: '3'}, {_title: '+'}];
  comp.isPendingSave = jest.fn().mockReturnValue(false);
  comp.editNow = jest.fn();
  comp.generateEntryTitle = jest.fn();
  comp.markDirtyEntries = jest.fn();

  comp.moveEntry({}, 0, true);
  expect(comp.isPendingSave).toHaveBeenCalledWith({});
  expect(comp.editNow).toHaveBeenCalled();
  expect(comp.generateEntryTitle).toHaveBeenCalledTimes(4);
  expect(comp.markDirtyEntries).toHaveBeenCalled();

  expect(comp.form.entries[0]._title).toBe('2');
  expect(comp.form.entries[1]._title).toBe('3');
  expect(comp.form.entries[2]._title).toBe('1');
  expect(comp.form.entries[3]._title).toBe('+');

  comp.moveEntry({}, 2, false);
  expect(comp.form.entries[0]._title).toBe('1');
  expect(comp.form.entries[1]._title).toBe('2');
  expect(comp.form.entries[2]._title).toBe('3');
  expect(comp.form.entries[3]._title).toBe('+');
});

test('moveEntryWrapWithoutPlus', () => {
  comp.form.entries = [{_title: '1'}, {_title: '2'}, {_title: '3'}];
  comp.isPendingSave = jest.fn().mockReturnValue(false);
  comp.editNow = jest.fn();
  comp.generateEntryTitle = jest.fn();
  comp.markDirtyEntries = jest.fn();

  comp.moveEntry({}, 0, true);
  expect(comp.isPendingSave).toHaveBeenCalledWith({});
  expect(comp.editNow).toHaveBeenCalled();
  expect(comp.generateEntryTitle).toHaveBeenCalledTimes(3);
  expect(comp.markDirtyEntries).toHaveBeenCalled();

  expect(comp.form.entries[0]._title).toBe('2');
  expect(comp.form.entries[1]._title).toBe('3');
  expect(comp.form.entries[2]._title).toBe('1');

  comp.moveEntry({}, 2, false);
  expect(comp.form.entries[0]._title).toBe('1');
  expect(comp.form.entries[1]._title).toBe('2');
  expect(comp.form.entries[2]._title).toBe('3');
});

test('getSettingLink', () => {
  const setting = { id: 'test.setting', advanced: true };

  comp.$route = { path: '/config' };
  const link = comp.getSettingLink(setting);
  expect(link).toBe('https://example.com/#/config?s=test.setting&a=1');

  setting.advanced = false;
  const link2 = comp.getSettingLink(setting);
  expect(link2).toBe('https://example.com/#/config?s=test.setting&a=0');
});

test('notifyChangedSetting', () => {
  // Test adding new module
  comp.nodes = [{id: 'onlyone'}];
  comp.changedModules = [];
  const setting = { id: 'module1.setting1' };
  comp.notifyChangedSetting(setting);
  expect(comp.changedModules).toEqual(['module1']);

  // Test adding another new module
  const setting2 = { id: 'module2.setting2' };
  comp.notifyChangedSetting(setting2);
  expect(comp.changedModules).toEqual(['module1', 'module2']);

  // Test adding duplicate module (should not add again)
  comp.notifyChangedSetting(setting);
  expect(comp.changedModules).toEqual(['module1', 'module2']);

  // Test sorting after adding a module that comes first alphabetically
  const setting3 = { id: 'a_module.setting' };
  comp.notifyChangedSetting(setting3);
  expect(comp.changedModules).toEqual(['a_module', 'module1', 'module2']);
});

test('notifyChangedSetting with moduleStateMap', () => {
  // Test override with advanced prefix
  comp.nodes = [{id: 'onlyone'}];
  comp.changedModules = [];
  const settingAdvanced = { id: 'advanced.some.setting' };
  comp.notifyChangedSetting(settingAdvanced);
  expect(comp.changedModules).toEqual(['fake1-to-trigger-highstate', 'fake2-to-trigger-highstate']);

  // Test override with bpf.zeek prefix
  comp.changedModules = [];
  const settingBpfZeek = { id: 'bpf.zeek.config' };
  comp.notifyChangedSetting(settingBpfZeek);
  expect(comp.changedModules).toEqual(['zeek']);

  // Test override with bpf.pcap prefix
  comp.changedModules = [];
  const settingBpfPcap = { id: 'bpf.pcap.interface' };
  comp.notifyChangedSetting(settingBpfPcap);
  expect(comp.changedModules).toEqual(['pcap']);

  // Test override with bpf.suricata prefix
  comp.changedModules = [];
  const settingBpfSuricata = { id: 'bpf.suricata.rules' };
  comp.notifyChangedSetting(settingBpfSuricata);
  expect(comp.changedModules).toEqual(['suricata']);

  // Test override with elastic_fleet_package_registry prefix
  comp.changedModules = [];
  const settingElasticFleet = { id: 'elastic_fleet_package_registry.version' };
  comp.notifyChangedSetting(settingElasticFleet);
  expect(comp.changedModules).toEqual(['elastic-fleet-package-registry']);

  // Test override with global prefix
  comp.changedModules = [];
  const settingGlobal = { id: 'global.timeout' };
  comp.notifyChangedSetting(settingGlobal);
  expect(comp.changedModules).toEqual(['fake1-to-trigger-highstate', 'fake2-to-trigger-highstate']);

  // Test override with host prefix
  comp.changedModules = [];
  const settingHost = { id: 'host.network' };
  comp.notifyChangedSetting(settingHost);
  expect(comp.changedModules).toEqual(['fake1-to-trigger-highstate', 'fake2-to-trigger-highstate']);

  // Test override with patch prefix
  comp.changedModules = [];
  const settingPatch = { id: 'patch.schedule' };
  comp.notifyChangedSetting(settingPatch);
  expect(comp.changedModules).toEqual(['patch.os']);

  // Test override with vm prefix
  comp.changedModules = [];
  const settingVm = { id: 'vm.config' };
  comp.notifyChangedSetting(settingVm);
  expect(comp.changedModules).toEqual(['vm.user']);

  // Test no override, falls back to default logic
  comp.changedModules = [];
  const settingDefault = { id: 'unknown.module' };
  comp.notifyChangedSetting(settingDefault);
  expect(comp.changedModules).toEqual(['unknown']);

  // Test multiple calls with overrides and ensure uniqueness and sorting
  comp.changedModules = [];
  comp.notifyChangedSetting(settingAdvanced); // adds fake1, fake2
  comp.notifyChangedSetting(settingBpfZeek); // adds zeek
  comp.notifyChangedSetting(settingAdvanced); // duplicate, should not add again
  expect(comp.changedModules).toEqual(['fake1-to-trigger-highstate', 'fake2-to-trigger-highstate', 'zeek']);
});

test('notifyChangedSetting_MultiNode', () => {
  // Setup multi-node environment
  comp.nodes = [
    { id: 'master', role: 'manager' },
    { id: 'worker', role: 'sensor' }
  ];
  
  // Verify isSingleNodeGrid returns false
  expect(comp.isSingleNodeGrid()).toBe(false);

  const managerOnlyStates = [
    "backup",
    "ca",
    "elastalert",
    "hydra",
    "influxdb",
    "kibana",
    "kratos",
    "manager",
    "registry",
    "soc",
    "telegraf"
  ];

  // Scenario 1: Verify all manager-only states
  managerOnlyStates.forEach(module => {
    comp.changedModules = [];
    const setting = { id: module + '.enabled' };
    comp.notifyChangedSetting(setting);
    expect(comp.changedModules).toEqual([module]);
  });

  const REQUIRE_GRID_HIGHSTATE = ["fake1-to-trigger-highstate", "fake2-to-trigger-highstate"];

  // Scenario 2: Verify removed states trigger highstate
  ["nginx", "ssl"].forEach(module => {
    comp.changedModules = [];
    const setting = { id: module + '.enabled' };
    comp.notifyChangedSetting(setting);
    expect(comp.changedModules).toEqual(REQUIRE_GRID_HIGHSTATE);
  });

  // Scenario 3: Changing a module that is NOT in managerOnlyStates (e.g., unknown)
  comp.changedModules = [];
  const settingUnknown = { id: 'unknown.module' };
  comp.notifyChangedSetting(settingUnknown);
  // Should escalate to full grid highstate
  expect(comp.changedModules).toEqual(REQUIRE_GRID_HIGHSTATE);
});

test('saveLocalSettings', () => {
  comp.advanced = true;
  comp.saveLocalSettings();
  expect(localStorage['settings.config.advanced']).toBe('true');

  comp.advanced = false;
  comp.saveLocalSettings();
  expect(localStorage['settings.config.advanced']).toBe('false');
});

test('loadLocalSettings', () => {
  localStorage['settings.config.advanced'] = 'true';
  comp.loadLocalSettings();
  expect(comp.advanced).toBe(true);

  localStorage['settings.config.advanced'] = 'false';
  comp.loadLocalSettings();
  expect(comp.advanced).toBe(false);

  delete localStorage['settings.config.advanced'];
  comp.loadLocalSettings();
  expect(comp.advanced).toBe(false); // default value
});
