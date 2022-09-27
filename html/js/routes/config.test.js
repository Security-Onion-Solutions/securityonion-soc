// Copyright Jason Ertel (github.com/jertel).
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
  expect(mock).toHaveBeenCalledWith('config/');

  expect(comp.nodes).toBe(loaddata);

  const m1 = new Map();
  m1.set('mia-test-001', 'hi');
  const expectedSettings = [{
      "advanced": undefined,
      "default": null,
      "defaultAvailable": false, 
      "description": "Nearby",
      "file": undefined,
      "global": false,
      "helpLink": undefined,
      "id": "fake.setting.foo",
      "multiline": undefined,
      "name": "foo",
      "node": undefined,
      "nodeValues": m1,
      "readonly": undefined,
      "regex": "True|False",
      "regexFailureMessage": "Wrong!",
      "sensitive": undefined,
      "syntax": undefined,
      "title": "Farout",
      "value": null,
    },
    {
      "advanced": undefined,
      "default": undefined,
      "defaultAvailable": undefined, 
      "description": "NADA",
      "file": undefined,
      "global": undefined,
      "helpLink": undefined,
      "id": "car",
      "multiline": undefined,
      "name": "car",
      "node": false,
      "nodeValues": new Map(),
      "readonly": undefined,
      "regex": undefined,
      "regexFailureMessage": undefined,
      "sensitive": undefined,
      "syntax": undefined,
      "title": "CCA",
      "value": undefined,
    },
    {
      "advanced": undefined,
      "default": undefined,
      "defaultAvailable": undefined, 
      "description": "Cocoa",
      "file": undefined,
      "global": undefined,
      "helpLink": undefined,
      "id": "fake.setting.bar",
      "multiline": undefined,
      "name": "bar",
      "node": false,
      "nodeValues": new Map(),
      "readonly": undefined,
      "regex": undefined,
      "regexFailureMessage": undefined,
      "sensitive": undefined,
      "syntax": undefined,
      "title": "Barley",
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
              "file": undefined,
              "global": false, 
              "helpLink": undefined,
              "id": "fake.setting.foo", 
              "multiline": undefined, 
              "name": "foo", 
              "node": undefined, 
              "nodeValues": m1, 
              "readonly": undefined, 
              "regex": "True|False",
              "regexFailureMessage": "Wrong!",
              "sensitive": undefined, 
              "syntax": undefined,
              "title": "Farout", 
              "value": null
            }, 
            {
              "advanced": undefined,
              "default": undefined,
              "defaultAvailable": undefined, 
              "description": "Cocoa", 
              "file": undefined,
              "global": undefined, 
              "helpLink": undefined,
              "id": "fake.setting.bar", 
              "multiline": undefined, 
              "name": "bar", 
              "node": false, 
              "nodeValues": new Map(), 
              "readonly": undefined, 
              "regex": undefined,
              "regexFailureMessage": undefined,
              "sensitive": undefined, 
              "syntax": undefined,
              "title": "Barley", 
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
      "file": undefined,
      "global": undefined, 
      "helpLink": undefined,
      "id": "car", 
      "multiline": undefined, 
      "name": "car", 
      "node": false, 
      "nodeValues": new Map(), 
      "readonly": undefined, 
      "regex": undefined,
      "regexFailureMessage": undefined,
      "sensitive": undefined, 
      "syntax": undefined,
      "title": "CCA", 
      "value": undefined
    }
  ];
  expect(comp.settings).toStrictEqual(expectedSettings);
  expect(comp.hierarchy).toStrictEqual(expectedHierarchy);
});

test('getSettingName', () => {
  expect(comp.getSettingName({id:"fake.setting.foo", name: 'fake'})).toBe("Fake Setting Translated");
  expect(comp.getSettingName({id:"fake.setting.untranslated", name: "Untranslated Name"})).toBe("Untranslated Name");
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
  comp.clearFilter();
  expect(comp.search).toBe("");
});

test('filter', () => {
  a.nodeValues['mia-test-001'] = 'hi';
  a.value = 'a1';
  expect(comp.filter(a, 'foO')).toBe(true);
  expect(comp.filter(a, 'bY')).toBe(true);
  expect(comp.filter(a, 'OUt')).toBe(true);
  expect(comp.filter(a, 'A1')).toBe(true);
  expect(comp.filter(a, 'FaROut')).toBe(true);
  expect(comp.filter(a, 'bar')).toBe(false);
  expect(comp.filter(a)).toBe(true);
});

test('isMultiline', () => {
  const setting = {};
  expect(comp.isMultiline(setting)).toBe(false);

  setting.multiline = true;
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
  comp.nodes = [{id: "n1", status: GridMemberAccepted }, {id: "n1a", status: GridMemberAccepted }, {id: "n2", name: "node2", role: "standalone", status: "accepted" }, {id:"n3", status: "pending" }];

  const nodeValues = new Map();
  nodeValues.set("n1", "123");
  nodeValues.set("n1a", "abc");

  const nodeValues2 = new Map();
  nodeValues2.set("n1", "123-2");
  nodeValues2.set("n1a", "abc-2");

  comp.active = ["s-id"];
  comp.settings = [{id: "s-id", value: 'orig-value', default: 'def-value', nodeValues: nodeValues},{id: "s-id2", value: 'orig-value2', nodeValues: nodeValues2}];
};

test('selectSetting', () => {
  setupSettings();

  comp.selectSetting();

  expect(comp.activeBackup).toStrictEqual(["s-id"]);
  expect(comp.availableNodes).toStrictEqual([{text: "node2 (standalone)", value: "n2"}]);
  expect(comp.cancelDialog).toBe(false);
});

test('cancel', () => {
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
  comp.cancelDialog = true;
  comp.cancel(false);
  expect(comp.cancelDialog).toBe(true);
  expect(comp.form.key).toBe("cancel-id");
});

test('remove', async () => {
  setupSettings();

  // No-op path
  var mock = mockPapi("delete");
  await comp.remove(comp.settings[0], "nonexisting");
  var expectedNodeValues = new Map();
  expectedNodeValues.set("n1", "123");
  expectedNodeValues.set("n1a", "abc");
  expect(comp.settings[0].nodeValues).toStrictEqual(expectedNodeValues);
  expect(comp.cancelDialog).toBe(false);
  expect(comp.form.key).toBe(null);
  expect(mock).toHaveBeenCalledWith('config/', { params: {"id": "s-id", "minion": "nonexisting" }});

  // Good path
  mock = mockPapi("delete");
  await comp.remove(comp.settings[0], "n1");
  expectedNodeValues = new Map();
  expectedNodeValues.set("n1a", "abc");
  expect(comp.settings[0].nodeValues).toStrictEqual(expectedNodeValues);
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

test('edit', () => {
  // Global edit, nothing pending
  setupSettings();
  comp.cancelDialog = false;
  comp.form.value = null;
  comp.form.key = null;
  comp.edit(comp.settings[0], null);
  expect(comp.form.key).toBe("s-id");
  expect(comp.form.value).toBe("orig-value");
  expect(comp.cancelDialog).toBe(false);

  // Global edit, something else pending save
  setupSettings();
  comp.cancelDialog = false;
  comp.form.value = "touched-value";
  comp.form.key = "s-id2";
  comp.edit(comp.settings[0], null);
  expect(comp.form.key).toBe("s-id2");
  expect(comp.form.value).toBe("touched-value");
  expect(comp.cancelDialog).toBe(true);

  // Node edit, nothing pending
  setupSettings();
  comp.form.value = null;
  comp.form.key = null;
  comp.edit(comp.settings[0], "n1");
  expect(comp.form.key).toBe("n1");
  expect(comp.form.value).toBe("123");
  expect(comp.cancelDialog).toBe(false);

  // Node edit, something else pending save
  setupSettings();
  comp.form.value = "touched-value";
  comp.form.key = "n2";
  comp.edit(comp.settings[0], "n1");
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