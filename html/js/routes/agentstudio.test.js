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
    { name: 'Coordinator', isOrchestrator: true, allowedSkills: ['hunt'], canDelegateTo: ['Hunter'], agentDescription: 'Routes work', isSystem: true, enabled: true, personaAddendum: 'be brief', maxConcurrentInstances: 1 },
    { name: 'Hunter', isOrchestrator: false, allowedSkills: ['hunt', 'cases'], canDelegateTo: [], agentDescription: 'Hunts', isSystem: false, enabled: true, maxConcurrentInstances: 2 },
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
    maxConcurrentInstances: 1,
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
    maxConcurrentInstances: 2,
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

test('toggling enabled preserves maxConcurrentInstances', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  // The tab has no input for it yet, so a save that dropped it would silently
  // reset a limit set by hand or through the API.
  await comp.toggleAgentEnabled(comp.agents[1]);

  expect(savedRow(put).row.maxConcurrentInstances).toBe(2);
});

test('a duplicated agent carries its concurrency limit', async () => {
  comp.initAssistant(agenticParams());
  const put = mockPapi('put', {});

  await comp.duplicateAgent(comp.agents[1]);

  expect(savedRow(put).row.maxConcurrentInstances).toBe(2);
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

test('deleting an agent drops it from other rows and open editors', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('delete', {});
  const coordinator = comp.agents[0];
  comp.agentDrafts[coordinator.id] = JSON.parse(JSON.stringify(coordinator));

  await comp.removeAgent(comp.agents[1]);

  expect(comp.agents[0].canDelegateTo).toEqual([]);
  expect(comp.agentDrafts[coordinator.id].canDelegateTo).toEqual([]);
});

test('deleting a skill drops it from agents and open editors', async () => {
  comp.initAssistant(agenticParams());
  mockPapi('delete', {});
  const hunter = comp.agents[1];
  comp.agentDrafts[hunter.id] = JSON.parse(JSON.stringify(hunter));

  await comp.removeSkill(comp.skills.find(s => s.name === 'cases'));

  expect(comp.skills.map(s => s.name)).toEqual(['hunt']);
  expect(comp.agents[1].allowedSkills).toEqual(['hunt']);
  expect(comp.agentDrafts[hunter.id].allowedSkills).toEqual(['hunt']);
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

test('options save writes the automation settings that changed', async () => {
  const params = agenticParams();
  params.automationTickIntervalSeconds = 60;
  params.alertTriageEpoch = '2026-09-24T00:00:00Z';
  comp.initAssistant(params);
  const put = mockPapi('put', {});

  comp.showOptions();
  expect(comp.automationTickSeconds).toBe(60);
  expect(comp.alertTriageEpoch).toBe('2026-09-24T00:00:00Z');
  expect(comp.optionsDirty()).toBe(false);

  comp.automationTickSeconds = 30;
  comp.alertTriageEpoch = '2026-01-01T00:00:00Z';
  await comp.persistOptions();

  expect(put.mock.calls.map(call => [call[1].id, call[1].value])).toEqual([
    ['soc.config.server.modules.assistant.automationSettings.tickIntervalSeconds', '30'],
    ['soc.config.server.modules.assistant.automationSettings.alertTriageEpoch', '2026-01-01T00:00:00Z'],
  ]);
  expect(comp.optionsDirty()).toBe(false);
});

const passes = (rules, value) => rules.every(rule => rule(value) === true);

test('the option rules accept only their ranges', () => {
  const { nonNegative, positive, fraction } = comp.optionRules;

  for (const value of [0, 5, '3']) expect(passes(nonNegative, value)).toBe(true);
  for (const value of [-1, 1.5, '']) expect(passes(nonNegative, value)).toBe(false);

  for (const value of [1, 60]) expect(passes(positive, value)).toBe(true);
  for (const value of [0, -5, 1.5, '']) expect(passes(positive, value)).toBe(false);

  for (const value of [0, 0.5, 1]) expect(passes(fraction, value)).toBe(true);
  for (const value of [-0.1, 1.5, '']) expect(passes(fraction, value)).toBe(false);
});

test('the alert triage start must be a UTC timestamp', () => {
  for (const epoch of ['2026-09-24T00:00:00Z', '2026-09-24T00:00:00.5Z']) {
    expect(comp.alertTriageEpochRule(epoch)).toBe(true);
  }
  for (const epoch of ['', 'yesterday', '2026-09-24', '2026-09-24T00:00:00-06:00']) {
    expect(comp.alertTriageEpochRule(epoch)).toBe(comp.i18n.agentStudioAlertTriageEpochInvalid);
  }
});

test('the interval hint names the scheduler\'s check interval', () => {
  const params = agenticParams();
  params.automationTickIntervalSeconds = 30;
  comp.initAssistant(params);

  expect(comp.automationIntervalHelp()).toContain('30-second check interval');
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
    memoryExtractBatchSize: 5,
    maxMemoryRetries: 2,
  };

  comp.initAssistant(params);
  comp.showOptions();

  expect(comp.memoryOptions.useMemory).toBe(true);
  expect(comp.memoryOptions.scanIntervalSeconds).toBe(60);
  expect(comp.memoryOptions.memoryExtractBatchSize).toBe(5);
  expect(comp.memoryOptions.maxMemoryRetries).toBe(2);
  expect(comp.optionsDirty()).toBe(false);
});

test('only the changed memory tunables are written', async () => {
  const put = mockPapi('put', {});
  const params = memoryParams();
  params.memoryParams = { useMemory: false, scanIntervalSeconds: 300, maxUserMemoriesToInclude: 5, maxMemoryRetries: 2 };

  comp.initAssistant(params);
  comp.showOptions();
  comp.memoryOptions.useMemory = true;
  comp.memoryOptions.scanIntervalSeconds = 60;
  comp.memoryOptions.maxMemoryRetries = 4;

  expect(comp.optionsDirty()).toBe(true);

  await comp.persistOptions();

  const written = put.mock.calls.map(c => [c[1].id, c[1].value]);
  expect(written).toEqual([
    ['soc.config.server.modules.assistant.useMemory', 'true'],
    ['soc.config.server.modules.assistant.memoryScanIntervalSeconds', '60'],
    ['soc.config.server.modules.assistant.maxMemoryRetries', '4'],
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

test('the run history page size persists on its own', () => {
  comp.initAssistant(memoryParams());
  comp.saveSetting = jest.fn();

  comp.itemsPerPage = 50;
  comp.runItemsPerPage = 250;
  comp.saveLocalSettings();

  expect(comp.saveSetting).toHaveBeenCalledWith('itemsPerPage', 50, 10);
  expect(comp.saveSetting).toHaveBeenCalledWith('runItemsPerPage', 250, 10);

  mockLocalStorage['settings.agentstudio.runItemsPerPage'] = '50';
  comp.loadLocalSettings();
  expect(comp.runItemsPerPage).toBe(50);
  delete mockLocalStorage['settings.agentstudio.runItemsPerPage'];
});

const TRIAGE_ID = 'a1d3f5b7-9c2e-4e68-8b4a-6f0c2d9e7b13';
const CLOUDFLARE_ID = '7a3d8e41-2b5c-4f90-8d1e-6c2a9b4f3e08';
const CRITICAL_ID = 'd29f4c61-8a37-4b0e-9c52-3e1f7a6b8d04';

const alertTriageKind = () => ({
  name: 'alert_triage',
  displayName: 'Alert Triage',
  paramSchema: { json: {
    type: 'object',
    properties: {
      filter: { type: 'string', description: 'OQL search' },
      groupBy: { type: 'array', description: 'Group fields' },
      maxGroupsPerScan: { type: 'integer', description: 'Groups per scan', default: 25 },
      maxFailures: { type: 'integer', description: 'Failed runs', default: 3 },
      floor: { type: 'string', description: 'RFC3339 time' },
    },
    required: ['groupBy'],
  } },
});

const automationParams = () => Object.assign(agenticParams(), { availableAutomationKinds: [alertTriageKind()] });

const storedAutomations = () => [
  {
    id: TRIAGE_ID, displayName: 'Alert Triage', automationKind: 'alert_triage', isSystem: true, enabled: false,
    agent: 'Investigator', intervalSeconds: 300, userId: '',
    params: { groupBy: ['source.ip', 'rule.uuid', 'destination.ip'] },
  },
  {
    // Unknown kind.
    id: CLOUDFLARE_ID, displayName: 'Cloudflare Audit Logs', automationKind: 'cloudflare_audit', isSystem: false, enabled: true,
    agent: 'Orchestrator', intervalSeconds: 3600, userId: 'jsmith', params: {},
  },
  {
    id: CRITICAL_ID, displayName: 'Critical Alert Investigation', automationKind: 'alert_triage', isSystem: false, enabled: true,
    agent: 'Orchestrator', intervalSeconds: 900, userId: 'akhan',
    params: { filter: 'event.severity_label:critical', groupBy: ['rule.name'], maxGroupsPerScan: 10, maxFailures: 3 },
  },
];

const runHistory = (runs, extra = {}) => ({ data: Object.assign({ backlog: { pending: 0, running: 0, applying: 0 }, runs, hasMore: false }, extra) });

const seedAutomations = () => {
  comp.initAssistant(automationParams());
  comp.setAutomations(storedAutomations());
};

const mockReload = (automations) => {
  mockPapi('get', { data: automations });
  automations.forEach(() => mockPapi('get', runHistory([])));
};

test('automations load from the server, then each row\'s run history', async () => {
  comp.initAssistant(automationParams());
  const get = mockPapi('get', { data: storedAutomations() });
  mockPapi('get', runHistory([]));
  mockPapi('get', runHistory([]));
  mockPapi('get', runHistory([{ id: 'r1', state: 'running', startTime: '2026-09-30T10:00:00Z' }]));

  await comp.loadAutomations();
  await Promise.resolve();

  expect(get).toHaveBeenCalledWith('assistant/automations');
  expect(get).toHaveBeenCalledWith('assistant/automations/' + CRITICAL_ID + '/runs', { params: { limit: 20, offset: 0 } });
  expect(comp.automations.map(a => a.id)).toEqual([TRIAGE_ID, CLOUDFLARE_ID, CRITICAL_ID]);
  expect(comp.automationTabs[TRIAGE_ID]).toBe('general');
  expect(comp.automationStatus(comp.automations[0])).toBe('idle');
  expect(comp.automationStatus(comp.automations[2])).toBe('running');
});

test('a failed automation list is reported', async () => {
  comp.initAssistant(automationParams());
  mockPapi('get', null, new Error('boom'));

  await comp.loadAutomations();

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.automations).toEqual([]);
});

test('a failed history load is reported, and keeps what was already loaded', async () => {
  seedAutomations();
  const row = comp.automations[2];
  mockPapi('get', null, new Error('down'));

  await comp.loadAutomationRuns(row);
  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.automationRuns[row.id]).toBeUndefined();
  expect(comp.automationStatus(row)).toBe('', 'no status rather than a guess');

  const loaded = { runs: [{ id: 'r1', state: 'running' }], backlog: {}, hasMore: true };
  comp.automationRuns[row.id] = loaded;
  await comp.loadAutomationRuns(row, true);
  expect(comp.automationRuns[row.id]).toBe(loaded);
  expect(comp.automationStatus(row)).toBe('running');
});

test('a row\'s status is its latest run while in flight or failed, else idle', () => {
  seedAutomations();
  const row = comp.automations[2];
  expect(comp.automationStatus(row)).toBe('', 'blank until the history loads');

  const status = (state) => {
    comp.automationRuns[row.id] = { runs: [{ id: 'r', state, startTime: '2026-09-30T10:00:00Z' }] };
    return comp.automationStatus(row);
  };
  expect(status('queued')).toBe('queued');
  expect(status('running')).toBe('running');
  expect(status('failed')).toBe('failed');
  expect(status('succeeded')).toBe('idle');

  comp.automationRuns[row.id] = { runs: [] };
  expect(comp.automationStatus(row)).toBe('idle', 'never run');
  expect(comp.automationStatusLabel('succeeded')).toBe(comp.i18n.completed);
  expect(comp.automationStatusColor('failed')).toBe('error');
});

test('more runs append the next page, and the backlog lists only open states', async () => {
  seedAutomations();
  const row = comp.automations[2];
  const get = mockPapi('get', runHistory([{ id: 'r2' }, { id: 'r1' }], { hasMore: true, backlog: { pending: 3, running: 1, applying: 0 } }));
  mockPapi('get', runHistory([{ id: 'r0' }]));

  await comp.loadAutomationRuns(row);
  expect(comp.automationHistory(row).hasMore).toBe(true);
  expect(comp.automationBacklog(row)).toEqual([{ state: 'pending', count: 3 }, { state: 'running', count: 1 }]);

  await comp.loadAutomationRuns(row, true);
  expect(get).toHaveBeenLastCalledWith('assistant/automations/' + CRITICAL_ID + '/runs', { params: { limit: 20, offset: 2 } });
  expect(comp.automationHistory(row).runs.map(r => r.id)).toEqual(['r2', 'r1', 'r0']);
  expect(comp.automationHistory(row).hasMore).toBe(false);
});

test('run rows count their done and failed items', () => {
  const run = { itemCounts: { done: 4, failed: 1 } };

  expect(comp.runItemCount(run, 'done')).toBe(4);
  expect(comp.runItemCount(run, 'failed')).toBe(1);
  expect(comp.runItemCount({}, 'failed')).toBe(0);
});

test('a finished run opens in Agent Monitor\'s run history; one still going opens In Flight', () => {
  expect(comp.runMonitorLink({ id: 'run-1', state: 'failed' })).toEqual({ name: 'agentmonitor', query: { run: 'run-1' } });
  expect(comp.runMonitorLink({ id: 'run-2', state: 'succeeded' })).toEqual({ name: 'agentmonitor', query: { run: 'run-2' } });
  expect(comp.runMonitorLink({ id: 'run-3', state: 'running' })).toEqual({ name: 'agentmonitor' });
  expect(comp.runMonitorLink({ id: 'run-4', state: 'queued' })).toEqual({ name: 'agentmonitor' });
});

test('an agent can be opened in Onion AI on a new session', () => {
  comp.initAssistant(agenticParams());

  expect(comp.agentHeaders.map(h => h.value)).not.toContain('actions');
  expect(comp.chatWithAgentLink(comp.agents[1])).toEqual({ name: 'assistant', query: { agent: 'Hunter' } });
});

test('a link can open a specific automation, as Agent Monitor does, once the list loads', async () => {
  comp.$route.query = { tab: 'automations', automation: TRIAGE_ID };
  comp.initAssistant(automationParams());
  expect(comp.tab).toBe('automations');

  mockPapi('get', { data: storedAutomations() });
  await comp.loadAutomations();

  expect(comp.expandedAutomations).toEqual([TRIAGE_ID]);
  expect(comp.automationDrafts[TRIAGE_ID]).toEqual(comp.automations[0]);
  expect(comp.automationDrafts[TRIAGE_ID]).not.toBe(comp.automations[0]);

  comp.openRouteAutomation();
  expect(comp.expandedAutomations).toEqual([TRIAGE_ID]);
});

test('an unknown automation in the link is ignored, but the tab still applies', () => {
  comp.$route.query = { tab: 'automations', automation: 'no-such-automation' };
  seedAutomations();
  comp.openRouteAutomation();

  expect(comp.tab).toBe('automations');
  expect(comp.expandedAutomations).toEqual([]);

  comp.$route.query = {};
  comp.tab = 'agents';
  comp.applyRouteQuery();
  expect(comp.tab).toBe('agents', 'no query leaves the page where it was');
});

test('custom automations are hidden behind the read-only flag', () => {
  expect(comp.automationsReadOnly).toBe(true);
});

test('the payload is the body the automation routes take, with server-stamped fields left out', () => {
  seedAutomations();

  expect(comp.automationPayload(comp.automations[0])).toEqual({
    displayName: 'Alert Triage',
    automationKind: 'alert_triage',
    agent: 'Investigator',
    enabled: false,
    intervalSeconds: 300,
    params: { groupBy: ['source.ip', 'rule.uuid', 'destination.ip'] },
    isSystem: true,
  });
  expect(comp.automationPayload(comp.automations[2]).isSystem).toBe(false);
});

test('an agent is always named, but only needs to be usable while enabled', () => {
  comp.initAssistant(automationParams());
  const base = { displayName: 'x', automationKind: 'alert_triage', intervalSeconds: 60, params: { groupBy: ['rule.name'] } };

  expect(comp.automationValid({ ...base, agent: '' })).toBe(false, 'a custom automation must name one');
  expect(comp.automationValid({ ...base, agent: '', isSystem: true })).toBe(true, 'a built-in\'s blank agent is its shipped one');
  // Investigator isn't among the fixture agents.
  expect(comp.automationValid({ ...base, agent: 'Investigator', enabled: false })).toBe(true);
  expect(comp.automationValid({ ...base, agent: 'Investigator', enabled: true })).toBe(false);
  expect(comp.automationValid({ ...base, agent: 'Hunter', enabled: true })).toBe(true);
});

test('a stale agent stays listed for its automation', () => {
  seedAutomations();

  expect(comp.automationAgentChoices(comp.automations[0])).toEqual(['Coordinator', 'Hunter', 'Investigator']);
  expect(comp.automationAgentChoices({ agent: 'Hunter' })).toEqual(['Coordinator', 'Hunter']);
});

test('enabling with an agent that cannot run is refused before any save', async () => {
  seedAutomations();
  const put = mockPapi('put', {});

  await comp.toggleAutomationEnabled(comp.automations[0]);

  expect(comp.$root.showError).toHaveBeenCalledWith(comp.i18n.agentStudioAutomationAgentUnavailable);
  expect(put).not.toHaveBeenCalled();
  expect(comp.automations[0].enabled).toBe(false);
});

test('toggling saves the automation, then reloads the list', async () => {
  seedAutomations();
  const row = Object.assign({}, comp.automations[0], { agent: 'Hunter' });
  comp.setAutomations([row].concat(comp.automations.slice(1)));
  const put = mockPapi('put', {});
  const stored = storedAutomations();
  Object.assign(stored[0], { agent: 'Hunter', enabled: true, userId: 'me' });
  mockReload(stored);

  await comp.toggleAutomationEnabled(comp.automations[0]);

  expect(put).toHaveBeenCalledWith('assistant/automations/' + TRIAGE_ID, expect.objectContaining({ enabled: true, agent: 'Hunter', isSystem: true }));
  expect(comp.$root.papi.get).toHaveBeenCalledWith('assistant/automations');
  expect(comp.automations[0]).toMatchObject({ enabled: true, userId: 'me' });
});

test('a refused toggle leaves the row as it was', async () => {
  seedAutomations();
  mockPapi('put', null, new Error('ERROR_AUTOMATION_PARAMS_INVALID'));

  await comp.toggleAutomationEnabled(comp.automations[2]);

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.automations[2].enabled).toBe(true);
});

test('creators are shown by name once resolved', async () => {
  seedAutomations();
  comp.$root.getUserById = jest.fn(async () => ({ id: 'akhan', email: 'akhan@example.com' }));

  expect(comp.automationCreatorLabel(comp.automations[0])).toBe('', 'a built-in never saved has no creator');
  expect(comp.automationCreatorLabel(comp.automations[2])).toBe('akhan');
  await Promise.resolve();
  await Promise.resolve();
  expect(comp.automationCreatorLabel(comp.automations[2])).toBe('akhan@example.com');
  expect(comp.$root.getUserById).toHaveBeenCalledTimes(1);
});

test('params are shaped for the server\'s strict decoder', () => {
  comp.initAssistant(automationParams());
  const a = {
    automationKind: 'alert_triage',
    params: { filter: '  ', groupBy: [' rule.name ', ''], maxGroupsPerScan: '', maxFailures: '5', floor: '2026-09-25T00:00:00Z', stray: 'x' },
  };

  expect(comp.automationParams(a)).toEqual({ groupBy: ['rule.name'], maxFailures: 5, floor: '2026-09-25T00:00:00Z' });

  expect(comp.automationParams({ automationKind: 'nope', params: { anything: 1 } })).toEqual({ anything: 1 });
});

test('kinds come from the server', () => {
  comp.initAssistant(automationParams());
  expect(comp.automationKindItems()).toEqual([{ title: 'Alert Triage', value: 'alert_triage' }]);

  const params = agenticParams();
  params.availableAutomationKinds = [{ name: 'k', displayName: 'K', paramSchema: { json: { type: 'object', properties: {} } } }];
  comp.initAssistant(params);
  expect(comp.automationKindItems()).toEqual([{ title: 'K', value: 'k' }]);
  expect(comp.automationKindLabel('alert_triage')).toBe('alert_triage', 'an unknown kind shows its name');

  comp.initAssistant(agenticParams());
  expect(comp.automationKindItems()).toEqual([], 'none published, none offered');
});

test('the settings form is built from the kind\'s paramSchema, required fields first', () => {
  comp.initAssistant(automationParams());
  const fields = comp.automationKindFields('alert_triage');

  expect(fields.map(f => f.key)).toEqual(['groupBy', 'filter', 'maxGroupsPerScan', 'maxFailures', 'floor']);
  expect(fields[0]).toMatchObject({ label: 'Group By', type: 'array', required: true });
  expect(fields[2]).toMatchObject({ label: 'Max Groups Per Scan', type: 'integer', default: 25, required: false });
  expect(comp.automationKindFields('nope')).toEqual([]);
  expect(comp.automationParamDefaults('alert_triage')).toEqual({ groupBy: [], filter: '', maxGroupsPerScan: 25, maxFailures: 3, floor: '' });
});

test('an automation is only valid when the server would accept it', () => {
  comp.initAssistant(automationParams());
  const valid = { displayName: 'x', automationKind: 'alert_triage', agent: 'Hunter', intervalSeconds: 60, params: { groupBy: ['rule.name'] } };
  expect(comp.automationValid(valid)).toBe(true);

  expect(comp.automationValid({ ...valid, displayName: '  ' })).toBe(false);
  expect(comp.automationValid({ ...valid, displayName: 'x'.repeat(101) })).toBe(false);
  expect(comp.automationValid({ ...valid, intervalSeconds: 0 })).toBe(false);
  expect(comp.automationValid({ ...valid, agent: '' })).toBe(false);
  expect(comp.automationValid({ ...valid, params: { groupBy: [] } })).toBe(false, 'groupBy is required');
  expect(comp.automationValid({ ...valid, automationKind: 'nope' })).toBe(false, 'the server looks the kind up on every save');
});

test('an automation of an unknown kind cannot be toggled', async () => {
  seedAutomations();
  const put = mockPapi('put', {});

  await comp.toggleAutomationEnabled(comp.automations[1]);

  expect(put).not.toHaveBeenCalled();
  expect(comp.automations[1].enabled).toBe(true);
});

test('a system automation cannot be deleted, directly or through the confirmation', async () => {
  seedAutomations();
  const del = mockPapi('delete', {});

  await comp.removeAutomation(comp.automations[0]);
  comp.confirmDelete('automation', comp.automations[0]);
  await comp.performDelete();

  expect(del).not.toHaveBeenCalled();
  expect(comp.automations.length).toBe(3);
});

test('deleting a custom automation asks first and only proceeds on confirm', async () => {
  seedAutomations();
  const custom = comp.automations[2];
  comp.automationRuns[custom.id] = { runs: [] };
  const del = mockPapi('delete', {});
  mockReload(storedAutomations().slice(0, 2));

  comp.confirmDelete('automation', custom);
  expect(comp.confirmDeleteDialog).toBe(true);
  expect(comp.deleteTarget).toEqual({ kind: 'automation', item: custom });

  comp.cancelDelete();
  expect(comp.confirmDeleteDialog).toBe(false);
  expect(comp.deleteTarget).toBeNull();
  expect(del).not.toHaveBeenCalled();

  comp.confirmDelete('automation', custom);
  await comp.performDelete();
  expect(del).toHaveBeenCalledWith('assistant/automations/' + CRITICAL_ID);
  expect(comp.confirmDeleteDialog).toBe(false);
  expect(comp.automations.map(a => a.id)).not.toContain(CRITICAL_ID);
  expect(comp.automationRuns[CRITICAL_ID]).toBeUndefined();
});

test('a failed delete keeps the automation', async () => {
  seedAutomations();
  mockPapi('delete', null, new Error('boom'));

  await comp.removeAutomation(comp.automations[2]);

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.automations.length).toBe(3);
});

test('deleting an agent goes through the same confirmation', async () => {
  comp.initAssistant(agenticParams());
  const del = mockPapi('delete', {});

  comp.confirmDelete('agent', comp.agents[1]);
  expect(del).not.toHaveBeenCalled();

  await comp.performDelete();
  expect(del).toHaveBeenCalledWith('assistant/agents/Hunter');
  expect(comp.agents.map(a => a.name)).toEqual(['Coordinator']);
});

test('deleting a skill goes through the same confirmation', async () => {
  comp.initAssistant(agenticParams());
  const del = mockPapi('delete', {});
  const skill = comp.skills.find(s => s.name === 'cases');

  comp.confirmDelete('skill', skill);
  expect(del).not.toHaveBeenCalled();
  expect(comp.deleteTitle()).toBe(comp.i18n.agentStudioDeleteSkillTitle);
  expect(comp.deleteConfirmText()).toBe(comp.i18n.agentStudioDeleteSkillConfirm);

  await comp.performDelete();
  expect(del).toHaveBeenCalledWith('assistant/skills/cases');
  expect(comp.skills.map(s => s.name)).toEqual(['hunt']);
});

test('performDelete with nothing pending is a no-op', async () => {
  seedAutomations();
  const del = mockPapi('delete', {});

  await comp.performDelete();

  expect(del).not.toHaveBeenCalled();
  expect(comp.automations.length).toBe(3);
});

test('formatInterval picks the largest whole unit', () => {
  expect(comp.formatInterval(45)).toBe('45 seconds');
  expect(comp.formatInterval(300)).toBe('5 minutes');
  expect(comp.formatInterval(3600)).toBe('1 hours');
  expect(comp.formatInterval(90)).toBe('90 seconds');
});

test('only enabled agents can handle an automation', () => {
  const params = agenticParams();
  params.availableAgents[1].enabled = false;
  comp.initAssistant(params);

  expect(comp.automationAgentItems()).toEqual(['Coordinator']);
});

test('editing an automation goes through a draft and commits on save', async () => {
  seedAutomations();
  const row = comp.automations[2];
  const toggleExpand = jest.fn();
  const get = mockPapi('get', runHistory([]));

  comp.onToggleAutomation(row, toggleExpand, {});
  expect(toggleExpand).toHaveBeenCalled();
  expect(get).toHaveBeenCalledWith('assistant/automations/' + CRITICAL_ID + '/runs', { params: { limit: 20, offset: 0 } });
  expect(comp.automationDirty(row)).toBe(false);

  comp.automationDrafts[row.id].intervalSeconds = 600;
  comp.automationDrafts[row.id].params.maxGroupsPerScan = 5;
  // Enabled, so it needs a known agent to stay valid.
  comp.automationDrafts[row.id].agent = 'Hunter';
  expect(comp.automationDirty(row)).toBe(true);
  expect(comp.automations[2].intervalSeconds).toBe(900, 'the table shows the committed value until saved');
  expect(comp.automations[2].params.maxGroupsPerScan).toBe(10, 'params are drafted too');

  const saved = JSON.parse(JSON.stringify(comp.automationDrafts[row.id]));
  const put = mockPapi('put', {});
  mockReload([comp.automations[0], comp.automations[1], saved]);
  comp.expandedAutomations = [row.id];
  await comp.saveAutomation(row);

  expect(put).toHaveBeenCalledWith('assistant/automations/' + CRITICAL_ID, comp.automationPayload(saved));
  expect(comp.automations[2].intervalSeconds).toBe(600);
  expect(comp.automations[2].params.maxGroupsPerScan).toBe(5);
  expect(comp.expandedAutomations).toEqual([]);
  expect(comp.automationDrafts[row.id]).toBeUndefined();
});

test("a built-in's interval is editable and sent on save", async () => {
  seedAutomations();
  const row = comp.automations[0];
  comp.automationDrafts[row.id] = Object.assign(JSON.parse(JSON.stringify(row)), { intervalSeconds: 120 });
  comp.expandedAutomations = [row.id];
  expect(comp.automationDirty(row)).toBe(true);

  const put = mockPapi('put', {});
  const saved = Object.assign({}, storedAutomations()[0], { intervalSeconds: 120 });
  mockReload([saved].concat(storedAutomations().slice(1)));
  await comp.saveAutomation(row);

  expect(put).toHaveBeenCalledWith('assistant/automations/' + TRIAGE_ID, expect.objectContaining({ intervalSeconds: 120, isSystem: true }));
  expect(comp.automations[0].intervalSeconds).toBe(120);
  expect(comp.automationDrafts[row.id]).toBeUndefined();
});

test('a refused save keeps the editor open with its draft', async () => {
  seedAutomations();
  const row = comp.automations[2];
  comp.automationDrafts[row.id] = Object.assign(JSON.parse(JSON.stringify(row)), { agent: 'Hunter', intervalSeconds: 600 });
  comp.expandedAutomations = [row.id];
  mockPapi('put', null, new Error('ERROR_AUTOMATION_PARAMS_INVALID'));

  await comp.saveAutomation(row);

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.expandedAutomations).toEqual([row.id]);
  expect(comp.automationDrafts[row.id].intervalSeconds).toBe(600);
  expect(comp.automations[2].intervalSeconds).toBe(900);
});

test('an invalid draft is not saved', async () => {
  seedAutomations();
  const row = comp.automations[0];
  comp.automationDrafts[row.id] = JSON.parse(JSON.stringify(row));
  comp.automationDrafts[row.id].intervalSeconds = 0;
  const put = mockPapi('put', {});

  await comp.saveAutomation(row);

  expect(put).not.toHaveBeenCalled();
  expect(comp.automations[0].intervalSeconds).toBe(300);
  expect(comp.automationDrafts[row.id]).toBeDefined();
});

test('duplicating an automation creates a disabled custom copy', async () => {
  seedAutomations();
  const post = mockPapi('post', {});
  const copy = { id: 'new-id', displayName: 'Alert Triage (copy)', automationKind: 'alert_triage', isSystem: false, enabled: false };
  mockReload(storedAutomations().concat([copy]));

  await comp.duplicateAutomation(comp.automations[0]);

  const body = post.mock.calls[0][1];
  expect(post.mock.calls[0][0]).toBe('assistant/automations');
  expect(body).toMatchObject({ displayName: 'Alert Triage (copy)', isSystem: false, enabled: false, agent: 'Investigator' });
  expect(body.params).toEqual(comp.automations[0].params);
  expect(comp.automations[3].id).toBe('new-id');
});

test('creating an automation starts from the kind\'s defaults and needs what the server requires', async () => {
  seedAutomations();
  comp.showAddAutomation();
  expect(comp.createAutomationDialog).toBe(true);
  expect(comp.newAutomation).toMatchObject({ automationKind: 'alert_triage', agent: 'Coordinator', enabled: false });
  expect(comp.newAutomation.params.maxGroupsPerScan).toBe(25);

  const post = mockPapi('post', {});
  comp.newAutomation.displayName = ' Suricata Sweep ';
  await comp.saveNewAutomation();
  expect(post).not.toHaveBeenCalled();

  mockReload(storedAutomations().concat([{ id: 'new-id', displayName: 'Suricata Sweep' }]));
  comp.newAutomation.params.groupBy = ['rule.name'];
  comp.newAutomation.params.filter = 'event.module:suricata';
  await comp.saveNewAutomation();
  expect(post).toHaveBeenCalledWith('assistant/automations', expect.objectContaining({
    displayName: 'Suricata Sweep', isSystem: false, params: { groupBy: ['rule.name'], filter: 'event.module:suricata', maxGroupsPerScan: 25, maxFailures: 3 },
  }));
  expect(comp.createAutomationDialog).toBe(false);
  expect(comp.tab).toBe('automations');
  expect(comp.automations[3].id).toBe('new-id');
});

test('a refused create keeps the dialog open', async () => {
  seedAutomations();
  comp.showAddAutomation();
  comp.newAutomation.displayName = 'x';
  comp.newAutomation.params.groupBy = ['rule.name'];
  mockPapi('post', null, new Error('boom'));

  await comp.saveNewAutomation();

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.createAutomationDialog).toBe(true);
  expect(comp.automations.length).toBe(3);
});

test('choosing another kind starts its settings over', () => {
  comp.initAssistant(automationParams());
  comp.showAddAutomation();
  comp.newAutomation.params.filter = 'x';

  comp.onNewAutomationKind('alert_triage');

  expect(comp.newAutomation.params.filter).toBe('');
});

test('last and next run come from the latest run, and next only while enabled', () => {
  seedAutomations();
  comp.$root.formatDateTime = jest.fn(d => d);

  const row = comp.automations[1];
  comp.automationRuns[row.id] = { runs: [{ id: 'r1', state: 'succeeded', startTime: '2026-09-30T10:00:00.000Z' }] };
  expect(comp.automationLastRun(row)).toBe('2026-09-30T10:00:00.000Z');
  expect(comp.automationNextRun(row)).toBe('2026-09-30T11:00:00.000Z');

  expect(comp.automationNextRun(comp.automations[0])).toBe('', 'disabled and never run');
  expect(comp.automationLastRun(comp.automations[0])).toBe(comp.i18n.never);
});
