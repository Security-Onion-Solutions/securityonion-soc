// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./assistant.utils.js');
require('./agentstudio.js');

let comp;
let originalConsole;
let mockLocalStorage;

// Assistant client parameters for an enabled, licensed, agentic deployment.
const agenticParams = () => ({
  enabled: true,
  agentic: true,
  availableModels: [
    { id: 'model-a', displayName: 'Model A', adapter: 'soai', enabled: true, contextLimitLarge: 200000, contextLimitSmall: 8000 },
    { id: 'model-b', displayName: 'Model B', adapter: 'anthropic', enabled: true, contextLimitSmall: 8000 },
  ],
  availableSkills: [
    // additionalPrompt is intentionally never sent by the backend; include it here
    // to prove the mapping drops it.
    { name: 'hunt', tools: ['query', 'grid'], additionalPrompt: 'should not surface', isSystem: true, enabled: true, personaAddendum: 'narrow queries' },
    { name: 'cases', tools: ['createCase'], isSystem: false, enabled: true },
  ],
  availableAgents: [
    { name: 'Coordinator', isOrchestrator: true, allowedSkills: ['hunt'], canDelegateTo: ['Hunter'], agentDescription: 'Routes work', isSystem: true, enabled: true, personaAddendum: 'be brief' },
    { name: 'Hunter', isOrchestrator: false, allowedSkills: ['hunt', 'cases'], canDelegateTo: [], agentDescription: 'Hunts', isSystem: false, enabled: true },
  ],
  availableTools: ['query', 'grid', 'createCase'],
  agentMapping: { Coordinator: 'model-a@soai', Hunter: 'model-b' },
});

// Captures what a save wrote: the endpoint it hit and the single row it sent.
const savedRow = (putMock, call = 0) => ({
  url: putMock.mock.calls[call][0],
  row: putMock.mock.calls[call][1],
});

// mockPapi reuses the same jest.fn, so later calls accumulate on one mock.
const lastSavedRow = (putMock) => savedRow(putMock, putMock.mock.calls.length - 1);



beforeEach(() => {
  originalConsole = { log: console.log, error: console.error, warn: console.warn };
  console.log = jest.fn();
  console.error = jest.fn();
  console.warn = jest.fn();

  comp = getComponent("agentstudio");
  resetPapi();

  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showError = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.loadParameters = jest.fn();

  // Mock localStorage backed by a plain object, honoring both property access
  // and removeItem, so save/load settings tests can assert against it.
  const storageData = {};
  const localStorageMock = {
    removeItem: jest.fn((key) => { delete storageData[key]; }),
  };
  global.localStorage = new Proxy(localStorageMock, {
    get(target, prop) {
      if (typeof prop === 'string' && prop.startsWith('settings.')) {
        return storageData[prop];
      }
      return target[prop];
    },
    set(target, prop, value) {
      if (typeof prop === 'string' && prop.startsWith('settings.')) {
        storageData[prop] = String(value);
        return true;
      }
      target[prop] = value;
      return true;
    },
    deleteProperty(target, prop) {
      delete storageData[prop];
      return true;
    }
  });
  mockLocalStorage = global.localStorage;
});

afterEach(() => {
  console.log = originalConsole.log;
  console.error = originalConsole.error;
  console.warn = originalConsole.warn;
});

test('reload starts the loading spinner and requests the assistant parameters', () => {
  comp.reload();

  expect(comp.$root.startLoading).toHaveBeenCalled();
  expect(comp.$root.loadParameters).toHaveBeenCalledWith('assistant', comp.initAssistant);
});

test('initAssistant enables the page and loads data when enabled, licensed, and agentic', () => {
  comp.initAssistant(agenticParams());

  expect(comp.paramsLoaded).toBe(true);
  expect(comp.assistantEnabled).toBe(true);
  expect(comp.agentic).toBe(true);
  expect(comp.$root.isLicensed).toHaveBeenCalledWith('oai');
  expect(comp.$root.stopLoading).toHaveBeenCalled();

  expect(comp.models.map(m => m.displayName)).toEqual(['Model A', 'Model B']);
  expect(comp.models.map(m => m.selector)).toEqual(['model-a@soai', 'model-b@anthropic']);
  // contextWindow prefers the large limit, falling back to the small one.
  expect(comp.models[0].contextWindow).toBe(200000);
  expect(comp.models[1].contextWindow).toBe(8000);

  expect(comp.skills.map(s => s.name)).toEqual(['hunt', 'cases']);
  expect(comp.agents.map(a => a.name)).toEqual(['Coordinator', 'Hunter']);
});

test('initAssistant is disabled when the assistant is not enabled', () => {
  const params = agenticParams();
  params.enabled = false;

  comp.initAssistant(params);

  expect(comp.paramsLoaded).toBe(true);
  expect(comp.assistantEnabled).toBe(false);
  // No data is loaded when the page is not shown.
  expect(comp.agents).toEqual([]);
  expect(comp.skills).toEqual([]);
  expect(comp.models).toEqual([]);
});

test('initAssistant is disabled when the oai feature is not licensed', () => {
  comp.$root.isLicensed = jest.fn().mockReturnValue(false);

  comp.initAssistant(agenticParams());

  expect(comp.assistantEnabled).toBe(false);
  expect(comp.agents).toEqual([]);
});

test('initAssistant loads no data when the assistant is not in agentic mode', () => {
  const params = agenticParams();
  params.agentic = false;

  comp.initAssistant(params);

  expect(comp.paramsLoaded).toBe(true);
  expect(comp.assistantEnabled).toBe(true);
  expect(comp.agentic).toBe(false);
  expect(comp.agents).toEqual([]);
  expect(comp.skills).toEqual([]);
  expect(comp.models).toEqual([]);
});

test('initAssistant tolerates null/empty parameters', () => {
  comp.initAssistant(null);

  expect(comp.paramsLoaded).toBe(true);
  expect(comp.assistantEnabled).toBeFalsy();
  expect(comp.agentic).toBe(false);
  expect(comp.$root.stopLoading).toHaveBeenCalled();
});

test('skill mapping keeps name and tools but drops the hidden prompt guidance', () => {
  comp.initAssistant(agenticParams());

  const hunt = comp.skills.find(s => s.name === 'hunt');
  expect(hunt.id).toBe('hunt');
  expect(hunt.tools).toEqual(['query', 'grid']);
  // AdditionalPrompt is not exposed to the browser, so it must not be mapped in.
  expect(hunt.additionalPrompt).toBeUndefined();
  // Each skill row defaults to the tools sub-tab.
  expect(comp.skillTabs['hunt']).toBe('tools');
});

test('agentsFromParams maps agent fields and resolves the mapped selector to a display name', () => {
  comp.initAssistant(agenticParams());
  const rows = comp.agents;

  expect(rows).toHaveLength(2);
  const coordinator = rows[0];
  expect(coordinator.id).toBe('Coordinator');
  expect(coordinator.name).toBe('Coordinator');
  expect(coordinator.isOrchestrator).toBe(true);
  // id@adapter selector resolves to the model's display name; the raw selector
  // is kept alongside it.
  expect(coordinator.model).toBe('Model A');
  expect(coordinator.provider).toBe('soai');
  expect(coordinator.modelSelector).toBe('model-a@soai');
  expect(coordinator.description).toBe('Routes work');
  expect(coordinator.allowedSkills).toEqual(['hunt']);
  expect(coordinator.canDelegateTo).toEqual(['Hunter']);

  // A bare-id selector resolves too.
  expect(rows[1].model).toBe('Model B');
  expect(rows[1].modelSelector).toBe('model-b');
  expect(rows[1].provider).toBe('anthropic');
});

test('agentsFromParams shows the raw selector when it does not resolve or the model has no display name', () => {
  const params = agenticParams();
  params.availableModels = [
    { id: 'model-a', adapter: 'soai', enabled: true },
  ];
  comp.initAssistant(params);

  // model-a has no displayName: display falls back to its id@adapter selector.
  expect(comp.agents[0].model).toBe('model-a@soai');
  // model-b is not configured at all: the raw mapping value is shown as-is.
  expect(comp.agents[1].model).toBe('model-b');
});

test('agentsFromParams defaults missing fields and handles no agents', () => {
  expect(comp.agentsFromParams({})).toEqual([]);

  const rows = comp.agentsFromParams({
    availableAgents: [{ name: 'Solo' }],
  });
  expect(rows[0].model).toBe('');
  expect(rows[0].provider).toBe('');
  expect(rows[0].description).toBe('');
  expect(rows[0].allowedSkills).toEqual([]);
  expect(rows[0].canDelegateTo).toEqual([]);
  expect(rows[0].isOrchestrator).toBe(false);
});

test('setAgents keys rows by name and defaults each to the identity sub-tab', () => {
  comp.setAgents([{ id: 'stale', name: 'A1' }, { name: 'A2' }]);

  expect(comp.agents).toHaveLength(2);
  // A row's id is always its name, whatever the caller passed in.
  expect(comp.agents.map(a => a.id)).toEqual(['A1', 'A2']);
  expect(comp.agentTabs['A1']).toBe('identity');
  expect(comp.agentTabs['A2']).toBe('identity');
});

test('roleLabel returns the orchestrator or specialist label', () => {
  expect(comp.roleLabel({ isOrchestrator: true })).toBe(comp.i18n.agentStudioOrchestrator);
  expect(comp.roleLabel({ isOrchestrator: false })).toBe(comp.i18n.agentStudioSpecialist);
});

test('skillUsedBy lists the agents granted a skill', () => {
  comp.initAssistant(agenticParams());

  expect(comp.skillUsedBy('hunt')).toEqual(['Coordinator', 'Hunter']);
  expect(comp.skillUsedBy('cases')).toEqual(['Hunter']);
  expect(comp.skillUsedBy('missing')).toEqual([]);
});

test('agentNames returns the names of the loaded agents', () => {
  comp.initAssistant(agenticParams());

  // The test harness flattens computed properties into plain functions.
  expect(comp.agentNames()).toEqual(['Coordinator', 'Hunter']);
});

test('saveSetting stores value in localStorage with correct key', () => {
  comp.saveSetting('testSetting', 'testValue');

  expect(mockLocalStorage['settings.agentstudio.testSetting']).toBe('testValue');
});

test('saveSetting removes item when value equals default', () => {
  mockLocalStorage['settings.agentstudio.testSetting'] = 'someValue';

  comp.saveSetting('testSetting', 'defaultValue', 'defaultValue');

  expect(mockLocalStorage['settings.agentstudio.testSetting']).toBeUndefined();
});

test('saveSetting stores value when different from default', () => {
  comp.saveSetting('testSetting', 'customValue', 'defaultValue');

  expect(mockLocalStorage['settings.agentstudio.testSetting']).toBe('customValue');
});

test('saveLocalSettings saves all settings', () => {
  comp.saveSetting = jest.fn();
  comp.sortByAgents = [{ key: 'role', order: 'desc' }];
  comp.sortBySkills = [{ key: 'name', order: 'asc' }];
  comp.itemsPerPage = 50;

  comp.saveLocalSettings();

  expect(comp.saveSetting).toHaveBeenCalledWith('sortByAgents', 'role', 'name');
  expect(comp.saveSetting).toHaveBeenCalledWith('sortDescAgents', 'desc', 'asc');
  expect(comp.saveSetting).toHaveBeenCalledWith('sortBySkills', 'name', 'name');
  expect(comp.saveSetting).toHaveBeenCalledWith('sortDescSkills', 'asc', 'asc');
  expect(comp.saveSetting).toHaveBeenCalledWith('itemsPerPage', 50, 10);
});

test('loadLocalSettings loads all settings from localStorage', () => {
  mockLocalStorage['settings.agentstudio.sortByAgents'] = 'role';
  mockLocalStorage['settings.agentstudio.sortDescAgents'] = 'desc';
  mockLocalStorage['settings.agentstudio.sortBySkills'] = 'usedBy';
  mockLocalStorage['settings.agentstudio.sortDescSkills'] = 'desc';
  mockLocalStorage['settings.agentstudio.itemsPerPage'] = '250';

  comp.loadLocalSettings();

  expect(comp.sortByAgents).toEqual([{ key: 'role', order: 'desc' }]);
  expect(comp.sortBySkills).toEqual([{ key: 'usedBy', order: 'desc' }]);
  expect(comp.itemsPerPage).toBe(250);
});

test('loadLocalSettings leaves values unchanged when localStorage is empty', () => {
  comp.sortByAgents = [{ key: 'model', order: 'desc' }];
  comp.sortBySkills = [{ key: 'name', order: 'asc' }];
  comp.itemsPerPage = 1000;

  delete mockLocalStorage['settings.agentstudio.sortByAgents'];
  delete mockLocalStorage['settings.agentstudio.sortDescAgents'];
  delete mockLocalStorage['settings.agentstudio.sortBySkills'];
  delete mockLocalStorage['settings.agentstudio.sortDescSkills'];
  delete mockLocalStorage['settings.agentstudio.itemsPerPage'];

  comp.loadLocalSettings();

  expect(comp.sortByAgents).toEqual([{ key: 'model', order: 'desc' }]);
  expect(comp.sortBySkills).toEqual([{ key: 'name', order: 'asc' }]);
  expect(comp.itemsPerPage).toBe(1000);
});

test('initAssistant loads local settings when enabled, licensed, and agentic', () => {
  mockLocalStorage['settings.agentstudio.itemsPerPage'] = '50';

  comp.initAssistant(agenticParams());

  expect(comp.itemsPerPage).toBe(50);
});

test('system and custom rows are distinguished, with enabled state and persona', () => {
  comp.initAssistant(agenticParams());

  const [coordinator, hunter] = comp.agents;
  expect(coordinator.isSystem).toBe(true);
  expect(coordinator.enabled).toBe(true);
  expect(coordinator.persona).toBe('be brief');
  expect(hunter.isSystem).toBe(false);

  expect(comp.skills[0].isSystem).toBe(true);
  expect(comp.skills[0].persona).toBe('narrow queries');
  expect(comp.tools).toEqual(['query', 'grid', 'createCase']);
});

test('a system agent persists only the fields an admin may change', () => {
  comp.initAssistant(agenticParams());

  const payload = comp.agentPayload(comp.agents[0]);

  // Name, role, description and skills come from the built-in definition, so
  // writing them back could overwrite a later release's improvements.
  expect(payload).toEqual({
    name: 'Coordinator',
    enabled: true,
    model: 'model-a@soai',
    canDelegateTo: ['Hunter'],
    persona: 'be brief',
  });
});

test('a custom agent persists every field', () => {
  comp.initAssistant(agenticParams());

  expect(comp.agentPayload(comp.agents[1])).toEqual({
    name: 'Hunter',
    enabled: true,
    isOrchestrator: false,
    model: 'model-b',
    allowedSkills: ['hunt', 'cases'],
    canDelegateTo: [],
    description: 'Hunts',
    persona: '',
  });
});

test('a system skill persists only enabled and persona; a custom skill also its tools', () => {
  comp.initAssistant(agenticParams());

  expect(comp.skillPayload(comp.skills[0])).toEqual({ name: 'hunt', enabled: true, persona: 'narrow queries' });
  expect(comp.skillPayload(comp.skills[1])).toEqual({ name: 'cases', enabled: true, tools: ['createCase'], persona: '' });
});

test('saving an agent sends only that agent, without re-fetching info', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.expandedAgents = ['Hunter'];
  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { description: 'Hunts harder' });
  await comp.saveAgent(comp.agents[1]);

  const saved = savedRow(put);
  // One row per request: the server merges it, so a stale list cannot be replayed.
  expect(saved.url).toBe('assistant/agents/Hunter');
  expect(saved.row.name).toBe('Hunter');
  expect(saved.row.description).toBe('Hunts harder');
  // Rows are refreshed by the server's websocket push, not by re-fetching /info.
  expect(comp.$root.papi.get).toBeUndefined();
  expect(comp.expandedAgents).toEqual([]);
  expect(comp.agentDrafts['Hunter']).toBeUndefined();
});

test('an agentic push rebuilds the rows from the updated parameters', () => {
  comp.initAssistant(agenticParams());
  expect(comp.agents.map(a => a.name)).toEqual(['Coordinator', 'Hunter']);

  // What app.js does when the push lands: merge into the cached parameters.
  const pushed = agenticParams();
  pushed.availableAgents.push({ name: 'Triage', isSystem: false, enabled: true, allowedSkills: [], canDelegateTo: [] });
  comp.$root.parameters = { assistant: pushed };

  comp.onAgenticUpdate();

  expect(comp.agents.map(a => a.name)).toEqual(['Coordinator', 'Hunter', 'Triage']);
});

test('an agentic push tolerates missing parameters', () => {
  comp.initAssistant(agenticParams());
  comp.$root.parameters = {};

  comp.onAgenticUpdate();

  expect(comp.agents).toEqual([]);
});

test('a failed save leaves the row expanded and its draft intact', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', null, new Error('nope'));

  comp.expandedAgents = ['Hunter'];
  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { description: 'Hunts harder' });
  await comp.saveAgent(comp.agents[1]);

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.expandedAgents).toEqual(['Hunter']);
  expect(comp.agentDrafts['Hunter'].description).toBe('Hunts harder');
  // The table still shows the committed value.
  expect(comp.agents[1].description).toBe('Hunts');
});

test('toggling enabled sends just that row', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  await comp.toggleAgentEnabled(comp.agents[1]);

  expect(put).toHaveBeenCalledTimes(1);
  const saved = savedRow(put);
  expect(saved.url).toBe('assistant/agents/Hunter');
  expect(saved.row.enabled).toBe(false);
});

test('the last enabled orchestrator cannot be disabled', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  await comp.toggleAgentEnabled(comp.agents[0]);

  expect(comp.$root.showError).toHaveBeenCalledWith(comp.i18n.agentStudioLastOrchestrator);
  expect(put).not.toHaveBeenCalled();
});

test('an orchestrator can be disabled while another stays enabled', async () => {
  const params = agenticParams();
  params.availableAgents[1].isOrchestrator = true;
  comp.initAssistant(params);
  const put = mockPapi('put', {});

  expect(comp.canDisableAgent(comp.agents[0])).toBe(true);
  await comp.toggleAgentEnabled(comp.agents[0]);

  expect(savedRow(put).row.enabled).toBe(false);
});

test('duplicating a custom agent appends an editable copy with a free name', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  await comp.duplicateAgent(comp.agents[1]);

  const saved = savedRow(put);
  expect(saved.url).toBe('assistant/agents/Hunter%20(copy)');
  expect(saved.row.name).toBe('Hunter (copy)');
  // A copy is always custom, so every field is written and editable.
  expect(saved.row.allowedSkills).toEqual(['hunt', 'cases']);
  expect(saved.row.description).toBe('Hunts');
});

test('copyName avoids names already in use', () => {
  expect(comp.copyName('A', ['A'])).toBe('A (copy)');
  expect(comp.copyName('A', ['A', 'A (copy)'])).toBe('A (copy) 2');
  expect(comp.copyName('A', ['A', 'A (copy)', 'A (copy) 2'])).toBe('A (copy) 3');
});

test('deleting is refused for system rows and calls the delete endpoint for custom ones', async () => {
  comp.initAssistant(agenticParams());
  const del = mockPapi('delete', {});

  await comp.removeAgent(comp.agents[0]);
  expect(del).not.toHaveBeenCalled();

  await comp.removeAgent(comp.agents[1]);
  expect(del).toHaveBeenCalledWith('assistant/agents/Hunter');
  expect(comp.agents.map(a => a.name)).toEqual(['Coordinator']);
});

test('creating an agent rejects a blank or duplicate name', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.newAgent = { name: '   ' };
  await comp.saveNewAgent();
  expect(put).not.toHaveBeenCalled();

  comp.newAgent = { name: 'hunter' };
  await comp.saveNewAgent();
  expect(comp.$root.showError).toHaveBeenCalledWith(comp.i18n.agentStudioDuplicateName);
  expect(put).not.toHaveBeenCalled();
});

test('creating an agent appends it and closes the dialog', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.showAddAgent();
  expect(comp.newAgent.modelSelector).toBe('model-a@soai');
  comp.newAgent.name = 'Triage';
  await comp.saveNewAgent();

  expect(savedRow(put).url).toBe('assistant/agents/Triage');
  expect(comp.agents.map(a => a.name)).toEqual(['Coordinator', 'Hunter', 'Triage']);
  expect(comp.createAgentDialog).toBe(false);
});

test('creating a skill writes to the skills setting', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.showAddSkill();
  comp.newSkill.name = 'Triage';
  comp.newSkill.tools = ['query'];
  await comp.saveNewSkill();

  const saved = savedRow(put);
  expect(saved.url).toBe('assistant/skills/Triage');
  expect(saved.row).toEqual({ name: 'Triage', enabled: true, tools: ['query'], persona: '' });
});

test('expanding snapshots a draft and collapsing discards it', () => {
  comp.initAssistant(agenticParams());
  const toggleExpand = jest.fn();

  comp.onToggleAgent(comp.agents[1], toggleExpand, {});
  expect(comp.agentDrafts['Hunter']).not.toBe(comp.agents[1]);
  expect(comp.agentDrafts['Hunter'].name).toBe('Hunter');

  comp.agentDrafts['Hunter'].description = 'edited';
  expect(comp.agentDirty(comp.agents[1])).toBe(true);
  // The table is untouched until a save succeeds.
  expect(comp.agents[1].description).toBe('Hunts');

  comp.expandedAgents = ['Hunter'];
  comp.onToggleAgent(comp.agents[1], toggleExpand, {});
  expect(comp.agentDrafts['Hunter']).toBeUndefined();
});

test('agentDirty and skillDirty are false without an edit', () => {
  comp.initAssistant(agenticParams());

  expect(comp.agentDirty(comp.agents[0])).toBe(false);
  comp.agentDrafts['Coordinator'] = JSON.parse(JSON.stringify(comp.agents[0]));
  expect(comp.agentDirty(comp.agents[0])).toBe(false);

  comp.skillDrafts['hunt'] = JSON.parse(JSON.stringify(comp.skills[0]));
  expect(comp.skillDirty(comp.skills[0])).toBe(false);
  comp.skillDrafts['hunt'].persona = 'changed';
  expect(comp.skillDirty(comp.skills[0])).toBe(true);
});

test('delegateChoices excludes the agent itself', () => {
  comp.initAssistant(agenticParams());

  expect(comp.delegateChoices(comp.agents[0])).toEqual(['Hunter']);
});

test('providerFor resolves the adapter of a selector', () => {
  comp.initAssistant(agenticParams());

  expect(comp.providerFor('model-a@soai')).toBe('soai');
  expect(comp.providerFor('nope')).toBe('');
});

test('toggling enabled updates the row immediately, without waiting for the push', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', {});

  await comp.toggleAgentEnabled(comp.agents[1]);

  // The switch is bound to the row, so the row must change on save, not on the push.
  expect(comp.agents.find(a => a.name === 'Hunter').enabled).toBe(false);
  expect(comp.agents.find(a => a.name === 'Coordinator').enabled).toBe(true);
});

test('a failed toggle leaves the row untouched', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', null, new Error('nope'));

  await comp.toggleAgentEnabled(comp.agents[1]);

  expect(comp.agents.find(a => a.name === 'Hunter').enabled).toBe(true);
});

test('saving, duplicating and deleting all show up in the table right away', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', {});

  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { description: 'Hunts harder' });
  await comp.saveAgent(comp.agents[1]);
  expect(comp.agents.find(a => a.name === 'Hunter').description).toBe('Hunts harder');

  mockPapi('put', {});
  await comp.duplicateAgent(comp.agents[1]);
  expect(comp.agents.map(a => a.name)).toContain('Hunter (copy)');

  mockPapi('delete', {});
  await comp.removeAgent(comp.agents.find(a => a.name === 'Hunter (copy)'));
  expect(comp.agents.map(a => a.name)).not.toContain('Hunter (copy)');
});

test('toggling a skill updates its row immediately', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', {});

  await comp.toggleSkillEnabled(comp.skills[0]);

  expect(comp.skills[0].enabled).toBe(false);
});

test('saves go to the assistant endpoints, never straight to config', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  await comp.toggleSkillEnabled(comp.skills[0]);

  // Writing config/ directly would send the whole list and clobber other rows.
  expect(put.mock.calls[0][0]).toBe('assistant/skills/hunt');
  expect(put.mock.calls.some(c => c[0] === 'config/')).toBe(false);
});

test('renaming a custom agent addresses the row by its stored name', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { name: 'Tracker' });
  await comp.saveAgent(comp.agents[1]);

  // URL identifies the stored row; the body carries the new name, so the server
  // replaces it in place instead of leaving an orphan behind.
  const saved = savedRow(put);
  expect(saved.url).toBe('assistant/agents/Hunter');
  expect(saved.row.name).toBe('Tracker');
});

test('writes show the standard page loading overlay', async () => {
  comp.initAssistant(agenticParams());
  comp.$root.startLoading.mockClear();
  comp.$root.stopLoading.mockClear();
  mockPapi('put', {});

  await comp.toggleAgentEnabled(comp.agents[1]);

  expect(comp.$root.startLoading).toHaveBeenCalledTimes(1);
  expect(comp.$root.stopLoading).toHaveBeenCalledTimes(1);
});

test('the loading overlay is cleared when a write fails', async () => {
  comp.initAssistant(agenticParams());
  comp.$root.stopLoading.mockClear();
  mockPapi('put', null, new Error('nope'));

  await comp.toggleAgentEnabled(comp.agents[1]);

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.$root.stopLoading).toHaveBeenCalledTimes(1);
});

test('changing a model updates the table immediately, not just the dropdown', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', {});
  expect(comp.agents[1].model).toBe('Model B');

  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { modelSelector: 'model-a@soai' });
  await comp.saveAgent(comp.agents[1]);

  // The Model column shows the resolved display name, so it has to be re-derived
  // from the selector rather than carried over from the old row.
  expect(comp.agents[1].modelSelector).toBe('model-a@soai');
  expect(comp.agents[1].model).toBe('Model A');
  expect(comp.agents[1].provider).toBe('soai');
});

test('renaming onto another row is refused before any request', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { name: 'Coordinator' });
  await comp.saveAgent(comp.agents[1]);

  // The server refuses it too; catching it here avoids a pointless 409.
  expect(comp.$root.showError).toHaveBeenCalledWith(comp.i18n.agentStudioDuplicateName);
  expect(put).not.toHaveBeenCalled();
  expect(comp.agents[1].name).toBe('Hunter');
});

test('renaming to an unused name is allowed', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { name: 'Tracker' });
  await comp.saveAgent(comp.agents[1]);

  expect(put).toHaveBeenCalled();
  expect(savedRow(put).row.name).toBe('Tracker');
});

test('a save that does not rename is unaffected by the name check', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { persona: 'edited' });
  await comp.saveAgent(comp.agents[1]);

  expect(put).toHaveBeenCalled();
  expect(comp.$root.showError).not.toHaveBeenCalled();
});

test('renaming a skill onto another skill is refused', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.skillDrafts['cases'] = Object.assign({}, comp.skills[1], { name: 'hunt' });
  await comp.saveSkill(comp.skills[1]);

  expect(comp.$root.showError).toHaveBeenCalledWith(comp.i18n.agentStudioDuplicateName);
  expect(put).not.toHaveBeenCalled();
});

test('a renamed row is addressed by its new name on the next write', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', {});

  comp.agentDrafts['Hunter'] = Object.assign({}, comp.agents[1], { name: 'Tracker' });
  await comp.saveAgent(comp.agents[1]);

  // The row's id is its stored name; keeping the old one made the next write look
  // like a second rename and the server answered 409.
  const renamed = comp.agents.find(a => a.name === 'Tracker');
  expect(renamed.id).toBe('Tracker');

  const put = mockPapi('put', {});
  await comp.toggleAgentEnabled(renamed);

  expect(lastSavedRow(put).url).toBe('assistant/agents/Tracker');
});

test('a renamed skill is addressed by its new name on the next write', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', {});

  comp.skillDrafts['cases'] = Object.assign({}, comp.skills[1], { name: 'triage' });
  await comp.saveSkill(comp.skills[1]);

  const renamed = comp.skills.find(s => s.name === 'triage');
  expect(renamed.id).toBe('triage');

  const put = mockPapi('put', {});
  await comp.toggleSkillEnabled(renamed);

  expect(lastSavedRow(put).url).toBe('assistant/skills/triage');
});

test('the options dialog loads the limits from the client parameters', () => {
  const params = agenticParams();
  params.maxDelegationDepth = 3;
  params.maxSubSessionTokens = 5000;
  comp.initAssistant(params);

  comp.showOptions();

  // Reading them from params avoids a full config fetch just to show two numbers.
  expect(comp.maxDelegationDepth).toBe(3);
  expect(comp.maxSubSessionTokens).toBe(5000);
  expect(comp.optionsDirty()).toBe(false);
});

test('options save writes only the limits that changed', async () => {
  const params = agenticParams();
  params.maxDelegationDepth = 3;
  params.maxSubSessionTokens = 5000;
  comp.initAssistant(params);
  const put = mockPapi('put', {});

  comp.showOptions();
  comp.maxDelegationDepth = 5;
  expect(comp.optionsDirty()).toBe(true);

  await comp.persistOptions();

  expect(put).toHaveBeenCalledTimes(1);
  expect(put.mock.calls[0][0]).toBe('config/');
  expect(put.mock.calls[0][1].id).toBe('soc.config.server.modules.assistant.maxDelegationDepth');
  expect(put.mock.calls[0][1].value).toBe('5');
  expect(comp.showOptionsDialog).toBe(false);
  expect(comp.optionsDirty()).toBe(false);
});

test('a failed options save keeps the dialog open', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('put', null, new Error('nope'));

  comp.showOptions();
  comp.maxDelegationDepth = 9;
  await comp.persistOptions();

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.showOptionsDialog).toBe(true);
});

test('a push does not overwrite limits being edited in the open dialog', () => {
  const params = agenticParams();
  params.maxDelegationDepth = 3;
  comp.initAssistant(params);

  comp.showOptions();
  comp.maxDelegationDepth = 7;

  const pushed = agenticParams();
  pushed.maxDelegationDepth = 4;
  comp.$root.parameters = { assistant: pushed };
  comp.onAgenticUpdate();

  // The admin's in-progress edit survives; the baseline still tracks the server.
  expect(comp.maxDelegationDepth).toBe(7);
  expect(comp.savedMaxDelegationDepth).toBe(4);
});

test('options save writes both limits when both changed', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.showOptions();
  comp.maxDelegationDepth = 2;
  comp.maxSubSessionTokens = 1000;
  await comp.persistOptions();

  expect(put).toHaveBeenCalledTimes(2);
  expect(put.mock.calls.map(c => c[1].id)).toEqual([
    'soc.config.server.modules.assistant.maxDelegationDepth',
    'soc.config.server.modules.assistant.maxSubSessionTokens',
  ]);
  expect(put.mock.calls.map(c => c[1].value)).toEqual(['2', '1000']);
});

test('creating an agent with delegators updates those agents, not the new one', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.showAddAgent();
  comp.newAgent.name = 'Triage';
  comp.newAgent.delegators = ['Coordinator'];
  await comp.saveNewAgent();

  expect(put).toHaveBeenCalledTimes(2);

  // The new agent is written first, without a delegators field of its own.
  const created = savedRow(put, 0);
  expect(created.url).toBe('assistant/agents/Triage');
  expect(created.row.delegators).toBeUndefined();

  // Delegation lives on the delegating agent, so Coordinator is what changes.
  const delegator = savedRow(put, 1);
  expect(delegator.url).toBe('assistant/agents/Coordinator');
  expect(delegator.row.canDelegateTo).toEqual(['Hunter', 'Triage']);
  expect(comp.createAgentDialog).toBe(false);
});

test('creating an agent without delegators writes only the new agent', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  comp.showAddAgent();
  comp.newAgent.name = 'Triage';
  await comp.saveNewAgent();

  expect(put).toHaveBeenCalledTimes(1);
});

test('a delegator already pointing at the name is left alone', async () => {
  const params = agenticParams();
  params.availableAgents[0].canDelegateTo = ['Hunter', 'Triage'];
  comp.initAssistant(params);
  const put = mockPapi('put', {});

  comp.showAddAgent();
  comp.newAgent.name = 'Triage';
  comp.newAgent.delegators = ['Coordinator'];
  await comp.saveNewAgent();

  // No duplicate entry, and no pointless write.
  expect(put).toHaveBeenCalledTimes(1);
});

test('a failed delegator update still closes the dialog and names what failed', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});
  put.mockReset();
  put.mockImplementationOnce(async () => ({}));
  put.mockImplementationOnce(async () => { throw new Error('nope'); });

  comp.showAddAgent();
  comp.newAgent.name = 'Triage';
  comp.newAgent.delegators = ['Coordinator'];
  await comp.saveNewAgent();

  // The agent was created, so leaving the dialog open would imply it wasn't.
  expect(comp.createAgentDialog).toBe(false);
  const message = comp.$root.showError.mock.calls.at(-1)[0];
  expect(message).toContain('Coordinator');
});

test('one failing delegator does not stop the others', async () => {
  const params = agenticParams();
  params.availableAgents[1].isOrchestrator = true;
  comp.initAssistant(params);
  const put = mockPapi('put', {});
  put.mockReset();
  put.mockImplementationOnce(async () => ({}));
  put.mockImplementationOnce(async () => { throw new Error('nope'); });
  put.mockImplementation(async () => ({}));

  comp.showAddAgent();
  comp.newAgent.name = 'Triage';
  comp.newAgent.delegators = ['Coordinator', 'Hunter'];
  await comp.saveNewAgent();

  // Create + both delegators attempted, and only the failure is reported.
  expect(put).toHaveBeenCalledTimes(3);
  const message = comp.$root.showError.mock.calls.at(-1)[0];
  expect(message).toContain('Coordinator');
  expect(message).not.toContain('Hunter');
});

// Memories are fetched rather than delivered in the client parameters, so these
// tests drive the papi calls the Memory tab makes.
const memoryParams = () => Object.assign(agenticParams(), { memoryEnabled: true });

const memoryPage = (memories = [], total = memories.length) => ({
  data: { memories: memories, total: total, offset: 0, limit: 25 },
});

const storedMemory = (over = {}) => Object.assign({
  id: 'mem-1',
  memoryText: 'prefers dark mode',
  scope: 'user',
  targetUserId: 'user-1',
  userDefined: false,
  usageCount: 3,
  sessionId: 'sess-1',
  updateTime: '2026-08-18T12:00:00Z',
}, over);

test('the memory tab is hidden unless the server has memory enabled', () => {
  comp.initAssistant(agenticParams());
  expect(comp.memoryEnabled).toBe(false);

  comp.initAssistant(memoryParams());
  expect(comp.memoryEnabled).toBe(true);
});

test('memories are not fetched while memory is disabled', async () => {
  const get = mockPapi('get', memoryPage([storedMemory()]));
  comp.initAssistant(agenticParams());

  await comp.loadMemories();

  expect(get).not.toHaveBeenCalled();
});

test('loading memories sends the scope, search and paging as query params', async () => {
  const get = mockPapi('get', memoryPage([storedMemory()], 42));
  comp.initAssistant(memoryParams());
  comp.memoryScope = 'global';
  comp.memorySearch = 'dark mode';
  comp.memoryPage = 3;
  comp.memoryItemsPerPage = 10;

  await comp.loadMemories();

  expect(get).toHaveBeenCalledWith('assistant/memories', {
    params: { scope: 'global', q: 'dark mode', limit: 10, offset: 20 },
  });
  expect(comp.memories.length).toBe(1);
  expect(comp.memoryTotal).toBe(42);
});

test('changing a filter returns to the first page', async () => {
  mockPapi('get', memoryPage());
  comp.initAssistant(memoryParams());
  comp.memoryPage = 4;

  comp.onMemoryFilterChanged();

  expect(comp.memoryPage).toBe(1);
});

test('table paging options drive the next fetch', async () => {
  const get = mockPapi('get', memoryPage());
  comp.initAssistant(memoryParams());

  comp.onMemoryOptions({ page: 2, itemsPerPage: 50 });

  expect(comp.memoryPage).toBe(2);
  expect(comp.memoryItemsPerPage).toBe(50);
  expect(get.mock.calls[0][1].params.offset).toBe(50);
});

test('expanding a memory snapshots it into a draft that is dropped on collapse', () => {
  comp.initAssistant(memoryParams());
  comp.memories = [storedMemory()];

  const toggle = jest.fn();
  comp.onToggleMemory(comp.memories[0], toggle, {});
  expect(toggle).toHaveBeenCalled();

  const draft = comp.draftForMemory(comp.memories[0]);
  draft.memoryText = 'prefers light mode';
  expect(comp.memories[0].memoryText).toBe('prefers dark mode');
  expect(comp.memoryDirty(comp.memories[0])).toBe(true);

  comp.expandedMemories = ['mem-1'];
  comp.onToggleMemory(comp.memories[0], toggle, {});
  expect(comp.memoryDrafts['mem-1']).toBeUndefined();
});

test('a memory with no edits is not dirty', () => {
  comp.initAssistant(memoryParams());
  comp.memories = [storedMemory()];

  comp.onToggleMemory(comp.memories[0], jest.fn(), {});

  expect(comp.memoryDirty(comp.memories[0])).toBe(false);
});

test('saving a memory writes the draft and reloads the page', async () => {
  const put = mockPapi('put', {});
  const get = mockPapi('get', memoryPage([storedMemory({ userDefined: true })]));
  comp.initAssistant(memoryParams());
  comp.memories = [storedMemory()];

  comp.onToggleMemory(comp.memories[0], jest.fn(), {});
  comp.draftForMemory(comp.memories[0]).memoryText = 'prefers light mode';

  await comp.saveMemory(comp.memories[0]);

  expect(put).toHaveBeenCalledWith('assistant/memories/mem-1', {
    memoryText: 'prefers light mode',
    scope: 'user',
    targetUserId: 'user-1',
  });
  expect(get).toHaveBeenCalled();
});

test('moving a memory to global scope drops its owner', async () => {
  const put = mockPapi('put', {});
  mockPapi('get', memoryPage());
  comp.initAssistant(memoryParams());
  comp.memories = [storedMemory()];

  comp.onToggleMemory(comp.memories[0], jest.fn(), {});
  comp.draftForMemory(comp.memories[0]).scope = 'global';

  await comp.saveMemory(comp.memories[0]);

  expect(lastSavedRow(put).row).toEqual({
    memoryText: 'prefers dark mode',
    scope: 'global',
    targetUserId: '',
  });
});

test('an empty memory is refused before any request', async () => {
  const put = mockPapi('put', {});
  comp.initAssistant(memoryParams());
  comp.memories = [storedMemory()];

  comp.onToggleMemory(comp.memories[0], jest.fn(), {});
  comp.draftForMemory(comp.memories[0]).memoryText = '   ';

  await comp.saveMemory(comp.memories[0]);

  expect(put).not.toHaveBeenCalled();
  expect(comp.$root.showError).toHaveBeenCalledWith(comp.i18n.agentStudioMemoryTextRequired);
});

test('a failed save surfaces the error and clears the overlay', async () => {
  mockPapi('put', null, new Error('nope'));
  comp.initAssistant(memoryParams());
  comp.memories = [storedMemory()];

  comp.onToggleMemory(comp.memories[0], jest.fn(), {});
  comp.draftForMemory(comp.memories[0]).memoryText = 'prefers light mode';

  await comp.saveMemory(comp.memories[0]);

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.$root.stopLoading).toHaveBeenCalled();
});

test('deleting a memory calls the endpoint and reloads', async () => {
  const del = mockPapi('delete', {});
  const get = mockPapi('get', memoryPage());
  comp.initAssistant(memoryParams());
  comp.memories = [storedMemory()];

  await comp.removeMemory(comp.memories[0]);

  expect(del).toHaveBeenCalledWith('assistant/memories/mem-1');
  expect(get).toHaveBeenCalled();
});

test('creating a memory posts it, closes the dialog and shows the tab', async () => {
  const post = mockPapi('post', {});
  const get = mockPapi('get', memoryPage());
  comp.initAssistant(memoryParams());

  comp.showAddMemory();
  expect(comp.createMemoryDialog).toBe(true);
  comp.newMemory.memoryText = 'the DMZ is 10.4.0.0/16';
  comp.newMemory.scope = 'global';

  await comp.saveNewMemory();

  expect(post).toHaveBeenCalledWith('assistant/memories', {
    memoryText: 'the DMZ is 10.4.0.0/16',
    scope: 'global',
    targetUserId: '',
  });
  expect(comp.createMemoryDialog).toBe(false);
  expect(comp.tab).toBe('memories');
  expect(get).toHaveBeenCalled();
});

test('a new memory with no text is refused before any request', async () => {
  const post = mockPapi('post', {});
  comp.initAssistant(memoryParams());

  comp.showAddMemory();
  await comp.saveNewMemory();

  expect(post).not.toHaveBeenCalled();
  expect(comp.$root.showError).toHaveBeenCalledWith(comp.i18n.agentStudioMemoryTextRequired);
  expect(comp.createMemoryDialog).toBe(true);
});

test('a global memory shows every user as its owner', () => {
  comp.initAssistant(memoryParams());

  expect(comp.memoryOwner(storedMemory({ scope: 'global', targetUserId: '' }))).toBe(comp.i18n.all);
  expect(comp.memoryOwner(storedMemory())).toBe('user-1');
});

test('a memory that has never been recalled says so', () => {
  comp.initAssistant(memoryParams());
  comp.$root.formatDateTime = jest.fn().mockReturnValue('2026-08-18 12:00');

  expect(comp.memoryLastRecalled(storedMemory())).toBe(comp.i18n.agentStudioMemoryNeverRecalled);
  expect(comp.memoryLastRecalled(storedMemory({ lastUsedAt: '2026-08-18T12:00:00Z' }))).toBe('2026-08-18 12:00');
});

test('a non-agentic deployment with memory enabled still opens the page, on the memory tab', () => {
  const params = memoryParams();
  params.agentic = false;

  comp.initAssistant(params);

  expect(comp.assistantEnabled).toBe(true);
  expect(comp.agentic).toBe(false);
  expect(comp.memoryEnabled).toBe(true);
  expect(comp.tab).toBe('memories');
});

test('an agentic deployment still opens on the agents tab', () => {
  comp.initAssistant(memoryParams());

  expect(comp.tab).toBe('agents');
});

test('a deployment with neither agentic nor memory loads nothing', () => {
  const params = agenticParams();
  params.agentic = false;

  comp.initAssistant(params);

  expect(comp.agents).toEqual([]);
  expect(comp.skills).toEqual([]);
  expect(comp.memoryEnabled).toBe(false);
});

test('the options dialog loads the memory tunables from the client parameters', () => {
  const params = memoryParams();
  params.memoryParams = {
    useMemory: true,
    useMemoryScanner: false,
    scanIntervalSeconds: 60,
    memoryProximityThreshold: 0.8,
    messageProximityThreshold: 0.5,
    maxUserMemoriesToInclude: 5,
    maxGlobalMemoriesToInclude: 5,
    maxUserMemoriesToReconcile: 20,
    maxGlobalMemoriesToReconcile: 20,
  };

  comp.initAssistant(params);
  comp.showOptions();

  expect(comp.memoryOptions.useMemory).toBe(true);
  expect(comp.memoryOptions.scanIntervalSeconds).toBe(60);
  expect(comp.optionsDirty()).toBe(false);
});

test('only the changed memory tunables are written', async () => {
  const put = mockPapi('put', {});
  const params = memoryParams();
  params.memoryParams = { useMemory: false, scanIntervalSeconds: 300, maxUserMemoriesToInclude: 5 };

  comp.initAssistant(params);
  comp.showOptions();
  comp.memoryOptions.useMemory = true;
  comp.memoryOptions.scanIntervalSeconds = 60;

  expect(comp.optionsDirty()).toBe(true);

  await comp.persistOptions();

  const written = put.mock.calls.map(c => [c[1].id, c[1].value]);
  expect(written).toEqual([
    ['soc.config.server.modules.assistant.useMemory', 'true'],
    ['soc.config.server.modules.assistant.memoryScanIntervalSeconds', '60'],
  ]);
  expect(comp.showOptionsDialog).toBe(false);
  expect(comp.optionsDirty()).toBe(false);
});

test('a push does not overwrite memory tunables being edited in the open dialog', () => {
  const params = memoryParams();
  params.memoryParams = { scanIntervalSeconds: 300 };

  comp.initAssistant(params);
  comp.showOptions();
  comp.memoryOptions.scanIntervalSeconds = 60;

  const pushed = memoryParams();
  pushed.memoryParams = { scanIntervalSeconds: 900 };
  comp.$root.parameters = { assistant: pushed };
  comp.onAgenticUpdate();

  expect(comp.memoryOptions.scanIntervalSeconds).toBe(60, 'the draft survives the push');
  expect(comp.savedMemoryOptions.scanIntervalSeconds).toBe(900);
});

test('a failed memory options save keeps the dialog open', async () => {
  mockPapi('put', null, new Error('nope'));
  const params = memoryParams();
  params.memoryParams = { useMemory: false };

  comp.initAssistant(params);
  comp.showOptions();
  comp.memoryOptions.useMemory = true;

  await comp.persistOptions();

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.showOptionsDialog).toBe(true);
});

// Turning memory off must not hide the switches that turn it back on.
test('memory tunables are still editable after memory has been disabled', async () => {
  const put = mockPapi('put', {});
  const params = memoryParams();
  params.memoryEnabled = false;
  params.memoryParams = { useMemory: false, useMemoryScanner: false };

  comp.initAssistant(params);
  expect(comp.memoryEnabled).toBe(false);

  comp.showOptions();
  expect(comp.memoryOptions.useMemory).toBe(false);

  comp.memoryOptions.useMemory = true;
  await comp.persistOptions();

  expect(put.mock.calls[0][1]).toMatchObject({
    id: 'soc.config.server.modules.assistant.useMemory',
    value: 'true',
  });
});

test('turning the scanner on asks about historical conversations', () => {
  comp.onChangeUseMemoryScanner(true);
  expect(comp.scanHistoricalDialog).toBe(true);
});

test('turning the scanner off asks nothing', () => {
  comp.onChangeUseMemoryScanner(false);
  expect(comp.scanHistoricalDialog).toBe(false);
});

test('cancelling the scan history dialog reverts the scanner switch', () => {
  comp.memoryOptions.useMemoryScanner = true;
  comp.scanHistoricalDialog = true;

  comp.cancelScanHistorical();

  expect(comp.scanHistoricalDialog).toBe(false);
  expect(comp.memoryOptions.useMemoryScanner).toBe(false);
});

test('answering yes to scan history clears the cutoff', () => {
  comp.memoryOptions.dontScanBefore = '2026-01-01T00:00:00.000Z';
  comp.scanHistoricalDialog = true;

  comp.saveScanHistorical(true);

  expect(comp.scanHistoricalDialog).toBe(false);
  expect(comp.memoryOptions.dontScanBefore).toBe('');
});

test('answering no to scan history stamps the current timestamp', () => {
  jest.useFakeTimers().setSystemTime(new Date('2026-01-05T12:00:00.000Z'));
  comp.scanHistoricalDialog = true;

  comp.saveScanHistorical(false);
  jest.useRealTimers();

  expect(comp.scanHistoricalDialog).toBe(false);
  expect(comp.memoryOptions.dontScanBefore).toBe('2026-01-05T12:00:00.000Z');
});

test('the scan history cutoff is written with the scanner setting', async () => {
  const put = mockPapi('put', {});
  const params = memoryParams();
  params.memoryParams = { useMemoryScanner: false, dontScanBefore: '' };

  comp.initAssistant(params);
  comp.showOptions();
  comp.memoryOptions.useMemoryScanner = true;
  comp.onChangeUseMemoryScanner(true);
  jest.useFakeTimers().setSystemTime(new Date('2026-01-05T12:00:00.000Z'));
  comp.saveScanHistorical(false);
  jest.useRealTimers();

  await comp.persistOptions();

  const written = put.mock.calls.map(c => [c[1].id, c[1].value]);
  expect(written).toEqual(expect.arrayContaining([
    ['soc.config.server.modules.assistant.useMemoryScanner', 'true'],
    ['soc.config.server.modules.assistant.dontScanBefore', '2026-01-05T12:00:00.000Z'],
  ]));
});

const memoryModelParams = () => {
  const params = memoryParams();
  params.availableAdapters = [
    { name: 'soai', protocol: 'securityonion_ai_cloud', supportsEmbeddings: true },
    { name: 'anthropic', protocol: 'openai_chat', supportsEmbeddings: false },
  ];
  params.memoryParams = {
    memoryModel: 'model-a@soai',
    embedModel: 'model-a@soai',
    reconcileModel: 'model-a@soai',
  };
  return params;
};

test('the embedding model list is limited to adapters that support embeddings', () => {
  comp.initAssistant(memoryModelParams());

  expect(comp.modelItems().map(i => i.value)).toEqual(['model-a@soai', 'model-b@anthropic']);
  expect(comp.embedModelItems().map(i => i.value)).toEqual(['model-a@soai']);
});

test('a memory role whose model is missing is flagged instead of failing silently', () => {
  const params = memoryModelParams();
  params.memoryParams.embedModel = 'gone@soai';

  comp.initAssistant(params);
  comp.showOptions();

  expect(comp.memoryRoleResolves('memoryModel')).toBe(true);
  expect(comp.memoryRoleResolves('embedModel')).toBe(false);
  expect(comp.memoryRoleHint('embedModel', 'help')).toBe(comp.i18n.agentStudioMemoryRoleDisabled);
  expect(comp.memoryRoleHint('memoryModel', 'help')).toBe('help');
});

test('an unset memory model reads as disabled', () => {
  const params = memoryModelParams();
  params.memoryParams.reconcileModel = '';

  comp.initAssistant(params);
  comp.showOptions();

  expect(comp.memoryRoleResolves('reconcileModel')).toBe(false);
});

test('changing a memory model writes its setting', async () => {
  const put = mockPapi('put', {});

  comp.initAssistant(memoryModelParams());
  comp.showOptions();
  comp.memoryOptions.embedModel = 'model-b@anthropic';

  await comp.persistOptions();

  expect(lastSavedRow(put).row).toMatchObject({
    id: 'soc.config.server.modules.assistant.embedModel',
    value: 'model-b@anthropic',
  });
});

test('the persona popup edits the same draft the options dialog saves', async () => {
  const put = mockPapi('put', {});
  const params = memoryModelParams();
  params.memoryParams.memoryPersona = '';

  comp.initAssistant(params);
  comp.showOptions();

  expect(comp.showPersonaDialog).toBe(false);
  expect(comp.memoryPersonaDirty()).toBe(false);

  comp.showPersonaDialog = true;
  comp.memoryOptions.memoryPersona = 'never record IP addresses';
  comp.showPersonaDialog = false;

  expect(comp.memoryPersonaDirty()).toBe(true);
  expect(comp.optionsDirty()).toBe(true, 'a persona edit makes the options dialog dirty');

  await comp.persistOptions();

  expect(lastSavedRow(put).row).toMatchObject({
    id: 'soc.config.server.modules.assistant.memoryPersona',
    value: 'never record IP addresses',
  });
});

test('cancelling the options dialog discards a persona edit', () => {
  const params = memoryModelParams();
  params.memoryParams.reconcilePersona = 'original';

  comp.initAssistant(params);
  comp.showOptions();
  comp.memoryOptions.reconcilePersona = 'edited';

  // Cancel does not persist; reopening reloads from the last known server value.
  comp.showOptions();

  expect(comp.memoryOptions.reconcilePersona).toBe('original');
  expect(comp.optionsDirty()).toBe(false);
});

// The marker tracks unsaved edits, not whether a persona has content, so a saved
// persona must not leave the button marked.
test('an existing persona is not marked until it is edited', () => {
  const params = memoryModelParams();
  params.memoryParams.memoryPersona = '';
  params.memoryParams.reconcilePersona = 'prefer the older wording';

  comp.initAssistant(params);
  comp.showOptions();

  expect(comp.memoryPersonaDirty()).toBe(false);

  comp.memoryOptions.reconcilePersona = 'prefer the newer wording';
  expect(comp.memoryPersonaDirty()).toBe(true);

  comp.memoryOptions.reconcilePersona = 'prefer the older wording';
  expect(comp.memoryPersonaDirty()).toBe(false, 'reverting the edit clears the marker');
});

test('clearing a persona counts as a pending change', () => {
  const params = memoryModelParams();
  params.memoryParams.memoryPersona = 'be terse';

  comp.initAssistant(params);
  comp.showOptions();
  comp.memoryOptions.memoryPersona = '';

  expect(comp.memoryPersonaDirty()).toBe(true);
});

test('the marker clears once the personas are saved', async () => {
  mockPapi('put', {});
  const params = memoryModelParams();
  params.memoryParams.memoryPersona = '';

  comp.initAssistant(params);
  comp.showOptions();
  comp.memoryOptions.memoryPersona = 'be terse';

  await comp.persistOptions();

  expect(comp.memoryPersonaDirty()).toBe(false);
});

test('the memory model dropdowns group models under their adapter', () => {
  comp.initAssistant(memoryModelParams());

  const grouped = comp.groupModelItems(comp.modelItems());

  expect(grouped.map(i => i.header || i.value)).toEqual([
    'anthropic', 'model-b@anthropic',
    'soai', 'model-a@soai',
  ]);
});

test('the embed dropdown groups only the embedding-capable models', () => {
  comp.initAssistant(memoryModelParams());

  const grouped = comp.groupModelItems(comp.embedModelItems());

  expect(grouped.map(i => i.header || i.value)).toEqual(['soai', 'model-a@soai']);
});

test('memories awaiting re-embedding are surfaced and update on a push', () => {
  const params = memoryModelParams();
  params.memoryParams.staleMemoryCount = 340;

  comp.initAssistant(params);
  expect(comp.staleMemoryCount).toBe(340);

  // The server pushes progress as the pass runs.
  const pushed = memoryModelParams();
  pushed.memoryParams.staleMemoryCount = 120;
  comp.$root.parameters = { assistant: pushed };
  comp.onAgenticUpdate();

  expect(comp.staleMemoryCount).toBe(120);
});

test('no stale count means nothing to warn about', () => {
  comp.initAssistant(memoryModelParams());

  expect(comp.staleMemoryCount).toBe(0);
});

test('the memory page size persists separately from the agent and skill tables', () => {
  comp.initAssistant(memoryParams());
  comp.saveSetting = jest.fn();

  comp.itemsPerPage = 50;
  comp.memoryItemsPerPage = 250;
  comp.saveLocalSettings();

  expect(comp.saveSetting).toHaveBeenCalledWith('itemsPerPage', 50, 10);
  expect(comp.saveSetting).toHaveBeenCalledWith('memoryItemsPerPage', 250, 10);
});

test('the memory page size is restored from local storage', () => {
  mockLocalStorage['settings.agentstudio.itemsPerPage'] = '50';
  mockLocalStorage['settings.agentstudio.memoryItemsPerPage'] = '250';

  comp.initAssistant(memoryParams());

  expect(comp.itemsPerPage).toBe(50);
  expect(comp.memoryItemsPerPage).toBe(250);
});

test('changing the agent page size leaves the memory table alone', async () => {
  const get = mockPapi('get', memoryPage());
  comp.initAssistant(memoryParams());
  comp.memoryItemsPerPage = 10;

  comp.itemsPerPage = 250;

  expect(comp.memoryItemsPerPage).toBe(10, 'the two page sizes are independent');
  expect(get).not.toHaveBeenCalled();
});
