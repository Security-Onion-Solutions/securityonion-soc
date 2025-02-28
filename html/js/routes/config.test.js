// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
              "value": null
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
              "value": undefined
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
      "value": undefined
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
  expect(comp.settings[0].value).toBe("test-value")
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', {"id": "s-id", "nodeId": null, "value": "test-value"});

  // Node save
  setupSettings();
  comp.form.value = "test-value"
  comp.form.key = "n2";
  mock = mockPapi("put");
  await comp.save(comp.settings[0], "n2");
  expect(comp.settings[0].value).toBe("orig-value")
  expectedNodeValues = new Map();
  expectedNodeValues.set("n1a", "abc");
  expectedNodeValues.set("n1", "123");
  expectedNodeValues.set("n2", "test-value");
  expect(comp.settings[0].nodeValues).toStrictEqual(expectedNodeValues);
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', {"id": "s-id", "nodeId": "n2", "value": "test-value"});
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

  expect(showErrorMock).toHaveBeenCalledTimes(0);
  expect(comp.settings[0].value).toBe("123\n456")
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', {"id": "test.id", "nodeId": null, "value": "123\n456"});
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

  comp.processRouteParameters();

  expect(comp.search).toBe('search');
  expect(comp.autoSelect).toBe('');
  expect(comp.autoExpand).toBe(false);
  expect(comp.searchFilter).toBe('search');
  expect(comp.advanced).toBe(false);
  expect(comp.$nextTick).toHaveBeenCalledTimes(0);

  comp.search = '';
  comp.searchFilter = '';
  comp.$route.query = {
    e: '1',
  };

  comp.processRouteParameters();

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
  expect(comp.getSettingBreadcrumbs(setting)).toBe("foo > bar > car");

  setting = { id: "foo.bar.car", advanced: false, title: "Carbine" };
  expect(comp.getSettingBreadcrumbs(setting)).toBe("foo > bar > Carbine");

  setting = { id: "foo.bar.car", advanced: true };
  expect(comp.getSettingBreadcrumbs(setting)).toBe("foo > bar > car [adv]");

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
