// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./agentstudio.js');

let comp;
let originalConsole;

// Assistant client parameters for an enabled, licensed, agentic deployment.
const agenticParams = () => ({
  enabled: true,
  agentic: true,
  availableModels: [
    { displayName: 'Model A', adapter: 'soai', contextLimitLarge: 200000, contextLimitSmall: 8000 },
    { displayName: 'Model B', adapter: 'anthropic', contextLimitSmall: 8000 },
  ],
  availableSkills: [
    // additionalPrompt is intentionally never sent by the backend; include it here
    // to prove the mapping drops it.
    { name: 'hunt', tools: ['query', 'grid'], additionalPrompt: 'should not surface' },
    { name: 'cases', tools: ['createCase'] },
  ],
  availableAgents: [
    { name: 'Coordinator', isOrchestrator: true, allowedSkills: ['hunt'], canDelegateTo: ['Hunter'], agentDescription: 'Routes work' },
    { name: 'Hunter', isOrchestrator: false, allowedSkills: ['hunt', 'cases'], canDelegateTo: [], agentDescription: 'Hunts' },
  ],
  agentMapping: { Coordinator: 'Model A', Hunter: 'Model B' },
});

beforeEach(() => {
  originalConsole = { log: console.log, error: console.error, warn: console.warn };
  console.log = jest.fn();
  console.error = jest.fn();
  console.warn = jest.fn();

  comp = getComponent("agentstudio");
  resetPapi();

  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.loadParameters = jest.fn();
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

test('agentsFromParams maps agent fields and resolves the model from the mapping', () => {
  const rows = comp.agentsFromParams(agenticParams());

  expect(rows).toHaveLength(2);
  const coordinator = rows[0];
  expect(coordinator.id).toBe('Coordinator');
  expect(coordinator.name).toBe('Coordinator');
  expect(coordinator.isOrchestrator).toBe(true);
  expect(coordinator.model).toBe('Model A');
  expect(coordinator.description).toBe('Routes work');
  expect(coordinator.allowedSkills).toEqual(['hunt']);
  expect(coordinator.canDelegateTo).toEqual(['Hunter']);
});

test('agentsFromParams defaults missing fields and handles no agents', () => {
  expect(comp.agentsFromParams({})).toEqual([]);

  const rows = comp.agentsFromParams({
    availableAgents: [{ name: 'Solo' }],
  });
  expect(rows[0].model).toBe('');
  expect(rows[0].description).toBe('');
  expect(rows[0].allowedSkills).toEqual([]);
  expect(rows[0].canDelegateTo).toEqual([]);
  expect(rows[0].isOrchestrator).toBe(false);
});

test('setAgents stores the rows and defaults each to the identity sub-tab', () => {
  comp.setAgents([{ id: 'a1', name: 'A1' }, { id: 'a2', name: 'A2' }]);

  expect(comp.agents).toHaveLength(2);
  expect(comp.agentTabs['a1']).toBe('identity');
  expect(comp.agentTabs['a2']).toBe('identity');
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
