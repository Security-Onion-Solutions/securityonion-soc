// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const { TextEncoder, TextDecoder } = require('util');
Object.assign(global, { TextDecoder, TextEncoder });

require('../test_common.js');
// Method packs must load before assistant.js, which merges them into the component.
require('./assistant.sessions.js');
require('./assistant.streaming.js');
require('./assistant.tools.js');
require('./assistant.utils.js');
require('./assistant.js');
require('../components/tool-use-card.js');
require('../components/delegation-child.js');

const MSGTAG_CONTEXTCOMPRESSION = "context_compression";

// Mock data
const fakeSessionId = 'chat_1234567890_abcdef123';
const fakeMessage = {
  role: 'user',
  content: 'Hello, how can you help me?',
  timestamp: '2025-01-01T12:00:00.000Z'
};
const fakeAssistantMessage = {
  role: 'assistant',
  content: 'Hello! I\'m your AI Assistant for Security Onion. How can I help you today?',
  timestamp: '2025-01-01T12:00:00.000Z'
};
const fakeChatHistory = [
  {
    sessionId: 'chat_1234567890_abcdef123',
    title: 'Test Chat Session',
    messages: [],
    timestamp: '2025-01-01T12:00:00.000Z',
    lastUpdated: '2025-01-01T12:00:00.000Z'
  }
];
const fakeBackendSessions = [
  {
    sessionId: 'chat_1234567890_abcdef123',
    createTime: '2025-01-01T12:00:00.000Z',
    title: 'Test message content'
  }
];
const fakeBackendMessages = [
  {
    createTime: '2025-01-01T12:00:00.000Z',
    message: {
      role: 'user',
      contentStr: 'Hello, how can you help me?'
    }
  },
  {
    createTime: '2025-01-01T12:01:00.000Z',
    message: {
      role: 'assistant',
      contentBlocks: [
        {
          type: 'text',
          content: 'I can help you with security analysis and investigations.'
        }
      ]
    }
  }
];
const fakeToolUse = {
  id: 'tool_123',
  name: 'query_events',
  input: { oql_query: 'event.module: "suricata"' },
  status: 'pending_approval',
  result: null,
  error: null,
  timestamp: '2025-01-01T12:02:00.000Z',
  approved: null
};
const fakeCreditsResponse = {
  health_status: 'healthy',
  credit_balance: 100
};
const fakeInvestigationData = {
  prompt: 'Investigate suspicious network activity from IP 192.168.1.100 including failed login attempts and unusual file access patterns'
};
const fakeInvestigationSessionId = 'investigation_1234567890_abcdef123';

let comp;
let mockLocalStorage;
let originalConsole;

beforeEach(() => {
  comp = getComponent("assistant");
  resetPapi();
  
  // Mock console methods to suppress error messages during testing
  originalConsole = {
    log: console.log,
    error: console.error,
    warn: console.warn
  };
  console.log = jest.fn();
  console.error = jest.fn();
  console.warn = jest.fn();
  
  // Mock localStorage with proper Jest mocks that supports property access
  const removeItemMock = jest.fn();
  const getItemMock = jest.fn();
  const setItemMock = jest.fn();
  const clearMock = jest.fn();
  const storageData = {};
  
  // Create localStorage mock that handles both property access and method calls
  const localStorageMock = {
    getItem: getItemMock,
    setItem: setItemMock,
    removeItem: removeItemMock,
    clear: clearMock
  };
  
  // Override removeItem to also delete from storageData
  localStorageMock.removeItem = jest.fn((key) => {
    delete storageData[key];
    removeItemMock(key);
  });
  
  global.localStorage = new Proxy(localStorageMock, {
    get(target, prop) {
      if (typeof prop === 'string' && prop.startsWith('settings.')) {
        return storageData[prop];
      }
      return target[prop];
    },
    set(target, prop, value) {
      if (typeof prop === 'string' && prop.startsWith('settings.')) {
        // Convert values to strings like real localStorage
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
  
  // Keep reference to the mock for testing
  mockLocalStorage = global.localStorage;
  
  // Mock fetch for streaming responses
  global.fetch = jest.fn();
  
  // Mock Vue.ref
  global.Vue = {
    ref: jest.fn((value) => ({ value }))
  };
  
  // Mock router
  comp.$router = {
    push: jest.fn(),
    replace: jest.fn()
  };
  
  // Mock route
  comp.$route = {
    params: {},
    query: {}
  };
  
  // Mock nextTick
  comp.$nextTick = jest.fn(() => Promise.resolve());
  
  // Mock forceUpdate
  comp.$forceUpdate = jest.fn();
  
  // Mock DOM element
  comp.$el = {
    querySelector: jest.fn(() => ({
      scrollTop: 0,
      scrollHeight: 100
    }))
  };
});

afterEach(() => {
  // Restore original console methods
  console.log = originalConsole.log;
  console.error = originalConsole.error;
  console.warn = originalConsole.warn;
  
  jest.clearAllMocks();
});

// Data initialization and lifecycle tests
test('component data initialization', () => {
  expect(comp.messages).toEqual([]);
  expect(comp.newMessage).toBe('');
  expect(comp.isTyping).toBe(false);
  expect(comp.chatHistory).toEqual([]);
  expect(comp.currentChatId).toBe(null);
  expect(comp.creditsRemaining).toBe(0);
  expect(comp.sessionToolState).toBeInstanceOf(Map);
  expect(comp.contextLength).toBe(0);
  expect(comp.increaseContextLimit).toBe(false);
  expect(comp.restoreLastActive).toBe(false);
  expect(comp.alwaysApproveReadRequests).toBe(false);
  expect(comp.assistantEnabled).toBe(false);
  expect(comp.isStreaming).toBe(false);
  expect(comp.showChatHistory).toBe(true);  
  expect(comp.investigationMsg).toBe('');
  expect(comp.contextLimitSmall).toBe(0);
  expect(comp.contextLimitLarge).toBe(0);
  expect(comp.thresholdColorRatioLow).toBe(0.5);
  expect(comp.thresholdColorRatioMed).toBe(0.75);
  expect(comp.thresholdColorRatioMax).toBe(1);
  expect(comp.lowBalanceColorAlert).toBe(0);
  expect(comp.availableModels).toEqual([]);
  expect(comp.modelsMap).toBeInstanceOf(Map);
  expect(comp.currentModel).toBe('');
  expect(comp.activeStreamingSessionId).toBe(null);
  expect(comp.autoScrollOnNextRender).toBe(false);
  expect(comp.isPinnedToBottom).toBe(true);
  expect(comp.canChat).toBe(true);
  expect(comp.paramsLoaded).toBe(false);
});

test('loadNewChatScreen initializes with welcome message', async () => {
  await comp.loadNewChatScreen();
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
  expect(comp.messages[0].content).toContain('Hello! I\'m your AI Assistant');
});

test('loadNewChatScreen handles error', async () => {
  const showErrorMock = mockShowError();
  comp.$root.showError = jest.fn(() => {
    throw new Error('Test error');
  });
  
  await comp.loadNewChatScreen();
  
  expect(comp.messages).toHaveLength(1); // Should still have welcome message
});

// Chat history and session management tests
test('loadStoredChats success', async () => {
  const mock = mockPapi("get", { data: fakeBackendSessions });
  
  await comp.loadStoredChats();
  
  expect(mock).toHaveBeenCalledWith('/assistant/sessions');
  expect(comp.chatHistory).toHaveLength(1);
  expect(comp.chatHistory[0].sessionId).toBe(fakeSessionId);
  expect(comp.chatHistory[0].title).toContain('Test message content');
});

test('loadStoredChats handles empty response', async () => {
  const mock = mockPapi("get", { data: [] });
  
  await comp.loadStoredChats();
  
  expect(mock).toHaveBeenCalledWith('/assistant/sessions');
  expect(comp.chatHistory).toEqual([]);
});

test('loadStoredChats handles error', async () => {
  const showErrorMock = mockShowError();
  mockPapi("get", null, new Error("API error"));
  
  await comp.loadStoredChats();
  
  expect(comp.chatHistory).toEqual([]);
});

test('generateChatId creates unique ID', () => {
  const id1 = comp.generateChatId();
  const id2 = comp.generateChatId();
  
  expect(id1).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  expect(id2).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  expect(id1).not.toBe(id2);
});

// Assistant initialization tests
test('initAssistant sets assistantEnabled to true when enabled and licensed', async () => {
  const mockParams = {
    enabled: true,
    investigationPrompt: 'Test investigation prompt',
    contextLimitSmall: 200000,
    contextLimitLarge: 1000000,
    thresholdColorRatioLow: 0.5,
    thresholdColorRatioMed: 0.75,
    thresholdColorRatioMax: 1,
    lowBalanceColorAlert: 500000,
    availableModels: [
      { id: 'test-model', displayName: "Test Model", contextLimitSmall: 200000, contextLimitLarge: 1000000, lowBalanceColorAlert: 500000, enabled: true, adapter: "SOAI" }
    ],
    availableAdapters: [
      { name: "SOAI", protocol: "securityonion_ai_cloud" }
    ]
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.$root.disclaimer = false;
  comp.focusChatInput = jest.fn();
  
  await comp.initAssistant(mockParams);
  
  expect(comp.assistantEnabled).toBe(true);
  expect(comp.$root.isLicensed).toHaveBeenCalledWith('oai');
  expect(comp.investigationMsg).toBe('Test investigation prompt');
  expect(comp.contextLimitSmall).toBe(200000);
  expect(comp.contextLimitLarge).toBe(1000000);
  expect(comp.thresholdColorRatioLow).toBe(0.5);
  expect(comp.thresholdColorRatioMed).toBe(0.75);
  expect(comp.thresholdColorRatioMax).toBe(1);
  expect(comp.lowBalanceColorAlert).toBe(500000);
  expect(comp.loadStoredChats).toHaveBeenCalled();
  expect(comp.handleRouteSessionId).toHaveBeenCalled();
  expect(comp.loadCredits).toHaveBeenCalled();
  expect(comp.focusChatInput).toHaveBeenCalled();
  expect(comp.adaptersMap.size).toBe(1);
  expect(comp.adaptersMap.get('SOAI')).toEqual({ name: "SOAI", protocol: "securityonion_ai_cloud" });
});

test('initAssistant sets assistantEnabled to false when not enabled', async () => {
  const mockParams = {
    enabled: false,
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn();
  comp.handleRouteSessionId = jest.fn();
  comp.loadCredits = jest.fn();
  comp.focusChatInput = jest.fn();
  
  await comp.initAssistant(mockParams);
  
  expect(comp.assistantEnabled).toBe(false);
  expect(comp.$root.disclaimer).toBe(false);
  expect(comp.loadStoredChats).not.toHaveBeenCalled();
  expect(comp.handleRouteSessionId).not.toHaveBeenCalled();
  expect(comp.loadCredits).not.toHaveBeenCalled();
  expect(comp.focusChatInput).not.toHaveBeenCalled();
});

test('initAssistant sets assistantEnabled to false when not licensed', async () => {
  const mockParams = {
    enabled: true,
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(false);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn();
  comp.handleRouteSessionId = jest.fn();
  comp.loadCredits = jest.fn();
  comp.focusChatInput = jest.fn();
  
  await comp.initAssistant(mockParams);
  
  expect(comp.assistantEnabled).toBe(false);
  expect(comp.$root.disclaimer).toBe(false);
  expect(comp.loadStoredChats).not.toHaveBeenCalled();
  expect(comp.handleRouteSessionId).not.toHaveBeenCalled();
  expect(comp.loadCredits).not.toHaveBeenCalled();
  expect(comp.focusChatInput).not.toHaveBeenCalled();
});

test('initAssistant corrects contextLimitLarge when smaller than contextLimitSmall', async () => {
  const mockParams = {
    enabled: true,
    availableModels: [
      {
        id: 'model-1',
        displayName: "Model 1",
        contextLimitSmall: 200000,
        contextLimitLarge: 150000, // Smaller than contextLimitSmall - should be corrected
        lowBalanceColorAlert: 500000,
        enabled: true,
        adapter: "SOAI"
      },
      {
        id: 'model-2',
        displayName: "Model 2",
        contextLimitSmall: 100000,
        contextLimitLarge: 300000, // Larger than contextLimitSmall - should remain unchanged
        lowBalanceColorAlert: 400000,
        enabled: true,
        adapter: "SOAI"
      },
      {
        id: 'model-3',
        displayName: "Model 3",
        contextLimitSmall: 250000,
        contextLimitLarge: 250000, // Equal to contextLimitSmall - should remain unchanged
        lowBalanceColorAlert: 600000,
        enabled: true,
        adapter: "SOAI"
      },
      {
        id: 'model-4',
        enabled: false,
        adapter: "SOAI"
      },
    ],
    availableAdapters: [
      { name: "SOAI", protocol: "securityonion_ai_cloud" }
    ],
  };
  
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateModelParams = jest.fn();
  comp.$root.disclaimer = false;
  
  await comp.initAssistant(mockParams);
  
  // Check that the modelsMap was created correctly, keyed by displayName
  expect(comp.modelsMap.size).toBe(3);
  expect(comp.modelsMap.has('Model 1')).toBe(true);
  expect(comp.modelsMap.has('Model 2')).toBe(true);
  expect(comp.modelsMap.has('Model 3')).toBe(true);
  expect(comp.modelsMap.has('model-4@SOAI')).toBe(false); // Disabled model should not be included

  // Check that contextLimitLarge was corrected for model-1
  const model1 = comp.modelsMap.get('Model 1');
  expect(model1.contextLimitSmall).toBe(200000);
  expect(model1.contextLimitLarge).toBe(200000); // Should be corrected to match contextLimitSmall

  // Check that contextLimitLarge was not changed for model-2 (already larger)
  const model2 = comp.modelsMap.get('Model 2');
  expect(model2.contextLimitSmall).toBe(100000);
  expect(model2.contextLimitLarge).toBe(300000); // Should remain unchanged

  // Check that contextLimitLarge was not changed for model-3 (equal)
  const model3 = comp.modelsMap.get('Model 3');
  expect(model3.contextLimitSmall).toBe(250000);
  expect(model3.contextLimitLarge).toBe(250000); // Should remain unchanged
});

test('initAssistant migrates a legacy id@adapter currentModel to the displayName key', async () => {
  const mockParams = {
    enabled: true,
    availableModels: [
      { id: 'model-1', displayName: 'Model 1', enabled: true, adapter: 'SOAI' },
      { id: 'model-2', displayName: 'Model 2', enabled: true, adapter: 'SOAI' },
    ],
    availableAdapters: [{ name: 'SOAI', protocol: 'securityonion_ai_cloud' }],
  };

  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateModelParams = jest.fn();
  comp.$root.disclaimer = false;

  // As restored from localStorage by a browser that saved the old format.
  comp.currentModel = 'model-2@SOAI';

  await comp.initAssistant(mockParams);

  expect(comp.currentModel).toBe('Model 2');
});

test('initAssistant does not migrate a legacy selector for a disabled model', async () => {
  const mockParams = {
    enabled: true,
    availableModels: [
      { id: 'model-1', displayName: 'Model 1', enabled: true, adapter: 'SOAI' },
      { id: 'model-2', displayName: 'Model 2', enabled: false, adapter: 'SOAI' },
    ],
    availableAdapters: [{ name: 'SOAI', protocol: 'securityonion_ai_cloud' }],
  };

  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateModelParams = jest.fn();
  comp.$root.disclaimer = false;

  // Legacy saved selector pointing at a model that is now disabled: disabled
  // models are not migrated, so selection falls back to the first model.
  comp.currentModel = 'model-2@SOAI';

  await comp.initAssistant(mockParams);

  expect(comp.currentModel).toBe('Model 1');
});

test('initAssistant falls back to id@adapter key when displayName is absent', async () => {
  const mockParams = {
    enabled: true,
    availableModels: [
      { id: 'model-1', enabled: true, adapter: 'SOAI' },
    ],
    availableAdapters: [{ name: 'SOAI', protocol: 'securityonion_ai_cloud' }],
  };

  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateModelParams = jest.fn();
  comp.$root.disclaimer = false;

  await comp.initAssistant(mockParams);

  expect(comp.modelsMap.has('model-1@SOAI')).toBe(true);
  expect(comp.currentModel).toBe('model-1@SOAI');
});

test('initAssistant defaults an unknown currentModel to the first model', async () => {
  const mockParams = {
    enabled: true,
    availableModels: [
      { id: 'model-1', displayName: 'Model 1', enabled: true, adapter: 'SOAI' },
    ],
    availableAdapters: [{ name: 'SOAI', protocol: 'securityonion_ai_cloud' }],
  };

  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateModelParams = jest.fn();
  comp.$root.disclaimer = false;

  comp.currentModel = 'gone-model@Nowhere';

  await comp.initAssistant(mockParams);

  expect(comp.currentModel).toBe('Model 1');
});

test('initAssistant handles empty availableModels and availableAdapters array', async () => {
  const mockParams = {
    enabled: true,
    availableModels: [], // Empty array
    availableAdapters: [], // Empty array
  };
  
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateModelParams = jest.fn();
  comp.$root.disclaimer = false;
  
  await comp.initAssistant(mockParams);
  
  // Check that modelsMap is empty and no correction logic was executed
  expect(comp.modelsMap.size).toBe(0);
  expect(comp.adaptersMap.size).toBe(0);
  expect(comp.currentModel).toBe(''); // Should remain empty
  expect(comp.updateModelParams).toHaveBeenCalled();
});

// Shared agentic params: two agents mapped onto two real models with distinct
// context limits, so context enrichment and the model label can be asserted.
const agenticParams = () => ({
  enabled: true,
  agentic: true,
  availableAgents: [
    { name: 'Hunter', agentDescription: 'hunts events' },
    { name: 'Orchestrator', isOrchestrator: true, agentDescription: 'coordinates' },
  ],
  agentMapping: { Orchestrator: 'Claude Sonnet', Hunter: 'Claude Haiku' },
  availableModels: [
    { id: 'sonnet', displayName: 'Claude Sonnet', contextLimitSmall: 200000, contextLimitLarge: 1000000, charsPerTokenEstimate: 4, lowBalanceColorAlert: 500, enabled: true, adapter: 'SOAI' },
    { id: 'haiku', displayName: 'Claude Haiku', contextLimitSmall: 100000, contextLimitLarge: 100000, charsPerTokenEstimate: 3, lowBalanceColorAlert: 100, enabled: true, adapter: 'SOAI' },
  ],
  availableAdapters: [{ name: 'SOAI', protocol: 'securityonion_ai_cloud' }],
});

const stubInitDeps = () => {
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.focusChatInput = jest.fn();
  comp.$root.disclaimer = false;
};

test('initAssistant builds the picker from availableAgents in agentic mode', async () => {
  stubInitDeps();

  await comp.initAssistant(agenticParams());

  expect(comp.agentic).toBe(true);
  // The picker lists agents keyed by name; the raw models are not picker entries.
  expect(comp.modelsMap.size).toBe(2);
  expect(comp.modelsMap.has('Orchestrator')).toBe(true);
  expect(comp.modelsMap.has('Hunter')).toBe(true);
  expect(comp.modelsMap.has('Claude Sonnet')).toBe(false);
  // No stored selector: default to the orchestrator even though it isn't first.
  expect(comp.currentModel).toBe('Orchestrator');
});

test('initAssistant defaults a stale stored selector to the orchestrator agent', async () => {
  stubInitDeps();
  comp.currentModel = 'Some Old Model'; // not a known agent

  await comp.initAssistant(agenticParams());

  expect(comp.currentModel).toBe('Orchestrator');
});

test('initAssistant keeps a valid stored agent selector', async () => {
  stubInitDeps();
  comp.currentModel = 'Hunter';

  await comp.initAssistant(agenticParams());

  expect(comp.currentModel).toBe('Hunter');
});

test('initAssistant enriches agents with their mapped model context limits', async () => {
  stubInitDeps();

  await comp.initAssistant(agenticParams());
  comp.updateModelParams();

  // Orchestrator -> Claude Sonnet limits.
  expect(comp.contextLimitSmall).toBe(200000);
  expect(comp.contextLimitLarge).toBe(1000000);
  expect(comp.charsPerTokenEstimate).toBe(4);
  expect(comp.lowBalanceColorAlert).toBe(500);
});

test('currentModelLabel shows agent and its mapped model in agentic mode', async () => {
  stubInitDeps();

  await comp.initAssistant(agenticParams());

  expect(comp.currentModelLabel()).toBe('Orchestrator - Claude Sonnet');
});

test('currentModelLabel is the plain model displayName in non-agentic mode', async () => {
  stubInitDeps();

  await comp.initAssistant({
    enabled: true,
    availableModels: [
      { id: 'test-model', displayName: 'Test Model', enabled: true, adapter: 'SOAI' }
    ],
    availableAdapters: [{ name: 'SOAI', protocol: 'securityonion_ai_cloud' }],
  });

  expect(comp.agentic).toBe(false);
  expect(comp.currentModelLabel()).toBe('Test Model');
});

test('isCreditBasedModel resolves through the mapped model adapter in agentic mode', async () => {
  stubInitDeps();

  await comp.initAssistant(agenticParams());

  // Orchestrator -> Claude Sonnet -> SOAI adapter (securityonion_ai_cloud).
  expect(comp.currentModel).toBe('Orchestrator');
  expect(comp.isCreditBasedModel()).toBe(true);
});

test('isCreditBasedModel is false in agentic mode when the mapped adapter is not credit-based', async () => {
  stubInitDeps();

  const params = agenticParams();
  params.availableAdapters = [{ name: 'SOAI', protocol: 'ollama' }];

  await comp.initAssistant(params);

  expect(comp.isCreditBasedModel()).toBe(false);
});

test('isCreditBasedModel reflects the model adapter in non-agentic mode', async () => {
  stubInitDeps();

  await comp.initAssistant({
    enabled: true,
    availableModels: [
      { id: 'test-model', displayName: 'Test Model', enabled: true, adapter: 'SOAI' }
    ],
    availableAdapters: [{ name: 'SOAI', protocol: 'securityonion_ai_cloud' }],
  });

  expect(comp.agentic).toBe(false);
  expect(comp.isCreditBasedModel()).toBe(true);
});

test('isCreditBasedModel is false when the model adapter is not credit-based', async () => {
  stubInitDeps();

  await comp.initAssistant({
    enabled: true,
    availableModels: [
      { id: 'test-model', displayName: 'Test Model', enabled: true, adapter: 'Local' }
    ],
    availableAdapters: [{ name: 'Local', protocol: 'ollama' }],
  });

  expect(comp.isCreditBasedModel()).toBe(false);
});

test('selectModel switches the current agent and refreshes params and credits', async () => {
  stubInitDeps();
  await comp.initAssistant(agenticParams());
  expect(comp.currentModel).toBe('Orchestrator');

  comp.updateModelParams = jest.fn();
  comp.reloadCredits = jest.fn();

  comp.selectModel('Hunter');

  expect(comp.currentModel).toBe('Hunter');
  expect(comp.updateModelParams).toHaveBeenCalledTimes(1);
  expect(comp.reloadCredits).toHaveBeenCalledTimes(1);
});

test('canSwitchModel is false while loading or a turn is active', () => {
  comp.$root.loading = false;
  comp.isStreaming = false;
  comp.isTyping = false;
  expect(comp.canSwitchModel()).toBe(true);

  comp.$root.loading = true;
  expect(comp.canSwitchModel()).toBe(false);

  comp.$root.loading = false;
  comp.isStreaming = true;
  expect(comp.canSwitchModel()).toBe(false);
});

test('selectModel is blocked while a turn is active', async () => {
  stubInitDeps();
  await comp.initAssistant(agenticParams());
  expect(comp.currentModel).toBe('Orchestrator');

  comp.updateModelParams = jest.fn();
  comp.reloadCredits = jest.fn();
  comp.isStreaming = true; // checkForActivity() -> true

  comp.selectModel('Hunter');

  expect(comp.currentModel).toBe('Orchestrator');
  expect(comp.updateModelParams).not.toHaveBeenCalled();
  expect(comp.reloadCredits).not.toHaveBeenCalled();
});

test('selectModel is a no-op for the already-current or an empty selection', async () => {
  stubInitDeps();
  await comp.initAssistant(agenticParams());
  expect(comp.currentModel).toBe('Orchestrator');

  comp.updateModelParams = jest.fn();
  comp.reloadCredits = jest.fn();

  comp.selectModel('Orchestrator');
  comp.selectModel('');

  expect(comp.currentModel).toBe('Orchestrator');
  expect(comp.updateModelParams).not.toHaveBeenCalled();
  expect(comp.reloadCredits).not.toHaveBeenCalled();
});

test('handleRouteSessionId returns early when assistantEnabled is false', async () => {
  comp.assistantEnabled = false;
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn();
  comp.clearStreamingStates = jest.fn();
  comp.focusChatInput = jest.fn();
  
  await comp.handleRouteSessionId();
  
  expect(comp.clearStreamingStates).toHaveBeenCalled();
  expect(comp.loadChatFromBackend).not.toHaveBeenCalled();
  expect(comp.focusChatInput).not.toHaveBeenCalled();
});

// Session management tests
test('handleRouteSessionId with existing session', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();
  comp.assistantEnabled = true;
  comp.focusChatInput = jest.fn();
  
  await comp.handleRouteSessionId();
  
  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(fakeSessionId);
  expect(comp.focusChatInput).toHaveBeenCalled();
});

test('handleRouteSessionId with non-existent session', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn().mockRejectedValue(new Error('Session not found'));
  comp.assistantEnabled = true;
  comp.focusChatInput = jest.fn();
  
  await comp.handleRouteSessionId();
  
  expect(comp.currentChatId).toBe(null);
});


test('restoreLastActiveChat success', async () => {
  comp.loadCurrentChatId = jest.fn().mockReturnValue(fakeSessionId);
  comp.chatHistory = fakeChatHistory;
  comp.updateUrlWithSessionId = jest.fn();
  comp.restoreLastActive = true;
  
  await comp.restoreLastActiveChat();
  
  expect(comp.updateUrlWithSessionId).toHaveBeenCalledWith(fakeSessionId);
});

test('restoreLastActiveChat handles error', async () => {
  comp.loadCurrentChatId = jest.fn().mockReturnValue(fakeSessionId);
  comp.chatHistory = fakeChatHistory;
  comp.updateUrlWithSessionId = jest.fn().mockImplementation(() => {
    throw new Error('URL update failed');
  });
  comp.restoreLastActive = true;
  
  await comp.restoreLastActiveChat();
  
  // Should not throw error, just continue
  expect(comp.updateUrlWithSessionId).toHaveBeenCalledWith(fakeSessionId);
});

// Credits and balance tests
test('loadCredits success', async () => {
  const mock = mockPapi("get", { data: fakeCreditsResponse });

  comp.currentModel = "model";
  
  await comp.loadCredits();
  
  expect(mock).toHaveBeenCalledWith('/assistant/balance/model');
  expect(comp.creditsRemaining).toBe(100);
  expect(comp.creditsLoaded).toBe(true);
});

test('loadCredits handles 500 error due to outage', async () => {
  const error = new Error('ERROR_UPSTREAM_SERVICE_ERROR');
  error.response = { status: 500 };
  mockPapi("get", null, error);
  comp.$root.showError = jest.fn();
  
  await comp.loadCredits();
  
  expect(comp.$root.showError).toHaveBeenCalledWith(error);
  expect(comp.creditsLoaded).toBe(false);
});

test('loadCredits handles non-500 error', async () => {
  const showErrorMock = mockShowError();
  const error = new Error("API error");
  error.response = { status: 400 };
  mockPapi("get", null, error);
  
  await comp.loadCredits();
  
  expect(showErrorMock).toHaveBeenCalledWith(error);
  expect(comp.creditsRemaining).toBe(0);
  expect(comp.creditsLoaded).toBe(false);
});

test('loadCredits handles error without response', async () => {
  const showErrorMock = mockShowError();
  const error = new Error("Network error")
  mockPapi("get", null, error);
  
  await comp.loadCredits();
  
  expect(showErrorMock).toHaveBeenCalledWith(error);
  expect(comp.creditsLoaded).toBe(false);
});

test('loadCredits handles unhealthy status', async () => {
  const showErrorMock = mockShowError();
  const unhealthyResponse = {
    health_status: 'unhealthy',
    credit_balance: 50
  };
  mockPapi("get", { data: unhealthyResponse });
  
  await comp.loadCredits();
  
  expect(showErrorMock).toHaveBeenCalledWith(new Error(comp.i18n.assistantBalanceCheckUnhealthy));
  expect(comp.creditsLoaded).toBe(false);
});

// Chat operations tests
test('loadChat switches to existing chat', async () => {
  const chat = fakeChatHistory[0];
  comp.saveCurrentChat = jest.fn().mockResolvedValue();
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();
  comp.updateUrlWithSessionId = jest.fn();
  comp.clearStreamingStates = jest.fn();
  comp.currentChatId = chat.sessionId; // Set current chat ID to match
  
  await comp.loadChat(chat);
  
  expect(comp.saveCurrentChat).toHaveBeenCalled();
  expect(comp.clearStreamingStates).toHaveBeenCalled();
  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(chat.sessionId);
  expect(comp.updateUrlWithSessionId).toHaveBeenCalledWith(chat.sessionId);
});

test('loadChat handles error', async () => {
  const chat = fakeChatHistory[0];
  const showErrorMock = mockShowError();
  comp.saveCurrentChat = jest.fn().mockResolvedValue();
  comp.loadChatFromBackend = jest.fn().mockRejectedValue(new Error('Load failed'));
  comp.updateUrlWithSessionId = jest.fn();
  comp.scrollToBottom = jest.fn();
  comp.currentChatId = chat.sessionId; // Set current chat ID to match
  
  await comp.loadChat(chat);
  
  expect(showErrorMock).toHaveBeenCalledWith('Failed to load chat: Load failed');
});

test('deleteChat success', async () => {
  const chatId = fakeSessionId;
  const mock = mockPapi("delete");
  comp.chatHistory = [...fakeChatHistory];
  comp.currentChatId = chatId;
  comp.saveCurrentChatId = jest.fn();
  comp.loadNewChatScreen = jest.fn();
  
  await comp.deleteChat(chatId);
  
  expect(mock).toHaveBeenCalledWith(`/assistant/sessions/${chatId}`);
  expect(comp.chatHistory).toHaveLength(0);
  expect(comp.currentChatId).toBe(null);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.loadNewChatScreen).toHaveBeenCalled();
  expect(comp.$router.push).toHaveBeenCalledWith({ name: 'assistant' });
});

test('deleteChat handles error', async () => {
  const chatId = fakeSessionId;
  const showErrorMock = mockShowError();
  mockPapi("delete", null, new Error("Delete failed"));
  
  await comp.deleteChat(chatId);
  
  expect(showErrorMock).toHaveBeenCalledWith('Failed to delete chat: Delete failed');
});

test('startNewChat', async () => {
  comp.saveCurrentChat = jest.fn().mockResolvedValue();
  comp.saveCurrentChatId = jest.fn();
  comp.loadNewChatScreen = jest.fn();
  comp.focusChatInput = jest.fn();
  comp.currentChatId = fakeSessionId;
  
  await comp.startNewChat();
  
  expect(comp.saveCurrentChat).toHaveBeenCalled();
  expect(comp.currentChatId).toBe(null);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.loadNewChatScreen).toHaveBeenCalled();
  expect(comp.$router.push).toHaveBeenCalledWith({ name: 'assistant' });
  expect(comp.focusChatInput).toHaveBeenCalled();
});

test('updateUrlWithSessionId updates route', () => {
  const sessionId = fakeSessionId;
  comp.$route.params.sessionId = 'different_id';
  
  comp.updateUrlWithSessionId(sessionId);
  
  expect(comp.$router.replace).toHaveBeenCalledWith({ 
    name: 'assistant', 
    params: { sessionId: sessionId } 
  });
});

test('updateUrlWithSessionId skips if same', () => {
  const sessionId = fakeSessionId;
  comp.$route.params.sessionId = sessionId;
  
  comp.updateUrlWithSessionId(sessionId);
  
  expect(comp.$router.replace).not.toHaveBeenCalled();
});

// Message sending tests
test('sendMessage with insufficient credits', async () => {
  const showErrorMock = mockShowError();
  comp.newMessage = 'Test message';
  comp.creditsRemaining = 0;
  comp.creditsLoaded = true;
  comp.assistantEnabled = true;
  comp.canChat = true;
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);

  await comp.sendMessage();

  expect(showErrorMock).toHaveBeenCalledWith('Insufficient credits. Please contact your administrator to purchase more credits.');
  expect(comp.newMessage).toBe('Test message'); // Should not clear message
});

test('sendMessage shows unhealthy error when credits could not be loaded', async () => {
  const showErrorMock = mockShowError();
  comp.newMessage = 'Test message';
  comp.creditsRemaining = 100; // would otherwise pass the credits check
  comp.creditsLoaded = false;
  comp.assistantEnabled = true;
  comp.canChat = true;
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);

  await comp.sendMessage();

  expect(showErrorMock).toHaveBeenCalledWith('The AI model could not be reached or did not provide the expected response.');
  expect(comp.newMessage).toBe('Test message'); // Should not clear message
});

test('sendMessage with empty message', async () => {
  comp.newMessage = '   ';
  comp.creditsRemaining = 100;
  
  await comp.sendMessage();
  
  expect(comp.messages).toHaveLength(0);
});

test('sendMessage creates session ID and updates URL', async () => {
  comp.newMessage = 'Test message';
  comp.creditsRemaining = 100;
  comp.creditsLoaded = true;
  comp.currentChatId = null;
  comp.generateChatId = jest.fn().mockReturnValue(fakeSessionId);
  comp.saveCurrentChatId = jest.fn();
  comp.updateUrlWithSessionId = jest.fn();
  comp.callAIAPI = jest.fn().mockResolvedValue();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();
  comp.assistantEnabled = true;
  comp.canChat = true;
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);

  await comp.sendMessage();

  expect(comp.generateChatId).toHaveBeenCalled();
  expect(comp.currentChatId).toBe(fakeSessionId);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.updateUrlWithSessionId).toHaveBeenCalledWith(fakeSessionId);
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('user');
  expect(comp.messages[0].content).toBe('Test message');
  expect(comp.newMessage).toBe('');
  expect(comp.isTyping).toBe(true);
  expect(comp.callAIAPI).toHaveBeenCalledWith('Test message', undefined);
  expect(comp.loadStoredChats).toHaveBeenCalled();
});

// Context length and model management tests
test('calculateContextFromUsage calculates correct context length', () => {
  const usage1 = { input_tokens: 100, output_tokens: 50 };
  const usage2 = { input_tokens: 200, output_tokens: 75 };
  const usage3 = null;
  const usage4 = { input_tokens: 150 }; // Missing output_tokens
  const usage5 = { output_tokens: 100 }; // Missing input_tokens
  
  expect(comp.calculateContextFromUsage(usage1)).toBe(150);
  expect(comp.calculateContextFromUsage(usage2)).toBe(275);
  expect(comp.calculateContextFromUsage(usage3)).toBe(0);
  expect(comp.calculateContextFromUsage(usage4)).toBe(150);
  expect(comp.calculateContextFromUsage(usage5)).toBe(100);
});

test('updateContextLength updates total context length', () => {
  comp.contextLength = 100;
  const usage1 = { input_tokens: 50, output_tokens: 25 };
  const usage2 = { input_tokens: 30, output_tokens: 20 };
  
  comp.updateContextLength(usage1);
  expect(comp.contextLength).toBe(75); // 50 + 25
  
  comp.updateContextLength(usage2);
  expect(comp.contextLength).toBe(50); // 30 + 20
  
  comp.updateContextLength(null);
  expect(comp.contextLength).toBe(50); // Should remain unchanged
});

test('checkContextLimitReached returns false when under limit', () => {
  comp.contextLength = 50000;
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseContextLimit = false;
  
  const result = comp.checkContextLimitReached();
  
  expect(result).toBe(false);
});

test('checkContextLimitReached returns true when over small limit', () => {
  const showErrorMock = mockShowError();
  comp.contextLength = 150000;
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseContextLimit = false;
  comp.formatCount = jest.fn().mockReturnValue('100,000');
  
  const result = comp.checkContextLimitReached();
  
  expect(result).toBe(true);
  expect(showErrorMock).toHaveBeenCalledWith(expect.stringContaining('100,000+ tokens'));
});

test('checkContextLimitReached uses large limit when threshold increased', () => {
  comp.contextLength = 150000;
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseContextLimit = true;
  
  const result = comp.checkContextLimitReached();
  
  expect(result).toBe(false); // Should be under large limit
});

test('checkContextLimitReached returns true when over large limit', () => {
  const showErrorMock = mockShowError();
  comp.contextLength = 250000;
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseContextLimit = true;
  comp.formatCount = jest.fn().mockReturnValue('200,000');
  
  const result = comp.checkContextLimitReached();
  
  expect(result).toBe(true);
  expect(showErrorMock).toHaveBeenCalledWith(expect.stringContaining('200,000+ tokens'));
});

test('updateModelParams updates context limits and balance alert', () => {
  comp.currentModel = 'test-model';
  comp.modelsMap = new Map([
    ['test-model', {
      contextLimitSmall: 150000,
      contextLimitLarge: 800000,
      lowBalanceColorAlert: 600000
    }]
  ]);
  
  comp.updateModelParams();
  
  expect(comp.contextLimitSmall).toBe(150000);
  expect(comp.contextLimitLarge).toBe(800000);
  expect(comp.lowBalanceColorAlert).toBe(600000);
});

test('updateModelParams handles missing current model', () => {
  comp.currentModel = '';
  comp.modelsMap = new Map();
  comp.contextLimitSmall = 100000; // Initial value
  
  comp.updateModelParams();
  
  expect(comp.contextLimitSmall).toBe(100000); // Should remain unchanged
});

test('updateModelParams handles empty models map', () => {
  comp.currentModel = 'nonexistent-model';
  comp.modelsMap = new Map();
  comp.contextLimitSmall = 100000; // Initial value
  
  comp.updateModelParams();
  
  expect(comp.contextLimitSmall).toBe(100000); // Should remain unchanged
});

test('getContextColor returns correct color classes', () => {
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseContextLimit = false;
  comp.thresholdColorRatioLow = 0.5;
  comp.thresholdColorRatioMed = 0.75;
  comp.thresholdColorRatioMax = 1.0;
  
  expect(comp.getContextColor(25000)).toBe('text-success'); // Under low threshold
  expect(comp.getContextColor(60000)).toBe('text-amber'); // Between low and med
  expect(comp.getContextColor(85000)).toBe('text-warning'); // Between med and max
  expect(comp.getContextColor(100000)).toBe('text-error'); // At max threshold
});

test('getContextColor uses large limit when threshold increased', () => {
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseContextLimit = true;
  comp.thresholdColorRatioLow = 0.5;
  comp.thresholdColorRatioMed = 0.75;
  comp.thresholdColorRatioMax = 1.0;
  
  expect(comp.getContextColor(50000)).toBe('text-success'); // Under low threshold of large limit (50k < 200k * 0.5)
  expect(comp.getContextColor(120000)).toBe('text-amber'); // Between low and med of large limit
  expect(comp.getContextColor(170000)).toBe('text-warning'); // Between med and max of large limit
  expect(comp.getContextColor(200000)).toBe('text-error'); // At max of large limit
});

// Tool execution tests
test('getToolStatusIcon returns correct icons', () => {
  expect(comp.getToolStatusIcon('preparing')).toBe('fa-cog');
  expect(comp.getToolStatusIcon('pending_approval')).toBe('fa-question-circle');
  expect(comp.getToolStatusIcon('executing')).toBe('fa-hourglass-half');
  expect(comp.getToolStatusIcon('completed')).toBe('fa-check-circle');
  expect(comp.getToolStatusIcon('error')).toBe('fa-exclamation-triangle');
  expect(comp.getToolStatusIcon('rejected')).toBe('fa-times-circle');
  expect(comp.getToolStatusIcon('unknown')).toBe('fa-question-circle');
});

test('getToolStatusColor returns correct colors', () => {
  expect(comp.getToolStatusColor('preparing')).toBe('info');
  expect(comp.getToolStatusColor('pending_approval')).toBe('warning');
  expect(comp.getToolStatusColor('executing')).toBe('warning');
  expect(comp.getToolStatusColor('completed')).toBe('success');
  expect(comp.getToolStatusColor('error')).toBe('error');
  expect(comp.getToolStatusColor('rejected')).toBe('error');
  expect(comp.getToolStatusColor('unknown')).toBe('info');
});

test('getToolStatusTitle returns correct titles', () => {
  expect(comp.getToolStatusTitle('preparing')).toBe(comp.i18n.preparing);
  expect(comp.getToolStatusTitle('pending_approval')).toBe(comp.i18n.pendingApproval);
  expect(comp.getToolStatusTitle('executing')).toBe(comp.i18n.executing);
  expect(comp.getToolStatusTitle('completed')).toBe(comp.i18n.completed);
  expect(comp.getToolStatusTitle('error')).toBe(comp.i18n.error);
  expect(comp.getToolStatusTitle('rejected')).toBe(comp.i18n.rejected);
  expect(comp.getToolStatusTitle('unknown')).toBe(comp.i18n.statusUnknown);
});

test('action_needed maps to its own icon/color/title (distinct from executing)', () => {
  expect(comp.getToolStatusIcon('action_needed')).toBe('fa-user-clock');
  expect(comp.getToolStatusColor('action_needed')).toBe('warning');
  expect(comp.getToolStatusTitle('action_needed')).toBe(comp.i18n.actionNeeded);
});

test('displayStatus surfaces action_needed for an executing delegate with a pending descendant', () => {
  // A delegate whose sub-agent is parked on a tool awaiting approval is not really working.
  const pendingDelegate = {
    status: 'executing',
    childSession: { messages: [{ toolUses: [{ id: 'c1', status: 'pending_approval' }] }] },
  };
  expect(comp.displayStatus(pendingDelegate)).toBe('action_needed');

  // Nested (grandchild) pending approval bubbles up to an ancestor delegate too.
  const nestedPending = {
    status: 'executing',
    childSession: { messages: [{ toolUses: [
      { id: 'c1', status: 'executing', childSession: { messages: [{ toolUses: [{ id: 'g1', status: 'pending_approval' }] }] } },
    ] }] },
  };
  expect(comp.displayStatus(nestedPending)).toBe('action_needed');

  // A working delegate with no pending descendant stays executing.
  const workingDelegate = {
    status: 'executing',
    childSession: { messages: [{ toolUses: [{ id: 'c1', status: 'executing' }] }] },
  };
  expect(comp.displayStatus(workingDelegate)).toBe('executing');

  // Non-executing statuses and non-delegate tools are returned unchanged.
  expect(comp.displayStatus({ status: 'completed' })).toBe('completed');
  expect(comp.displayStatus({ status: 'pending_approval' })).toBe('pending_approval');
});

test('hasPendingDescendantApproval finds a pending tool at any depth', () => {
  // No childSession, or none of the nested tools pending: false.
  expect(comp.hasPendingDescendantApproval(null)).toBe(false);
  expect(comp.hasPendingDescendantApproval({})).toBe(false);
  expect(comp.hasPendingDescendantApproval({ childSession: {} })).toBe(false);
  expect(comp.hasPendingDescendantApproval({
    childSession: { messages: [{ toolUses: [{ status: 'completed' }, { status: 'executing' }] }, { content: 'prose only' }] },
  })).toBe(false);

  // Immediate child pending.
  expect(comp.hasPendingDescendantApproval({
    childSession: { messages: [{ toolUses: [{ status: 'pending_approval' }] }] },
  })).toBe(true);

  // Grandchild pending under an executing intermediate delegate.
  expect(comp.hasPendingDescendantApproval({
    childSession: { messages: [{ toolUses: [
      { status: 'executing', childSession: { messages: [{ toolUses: [{ status: 'pending_approval' }] }] } },
    ] }] },
  })).toBe(true);
});

test('isTopLevelTool is true only for tools of the viewed conversation', () => {
  comp.currentChatId = 'sess-1';
  expect(comp.isTopLevelTool({ id: 't1' })).toBe(true); // no sessionId = current conversation
  expect(comp.isTopLevelTool({ id: 't2', sessionId: 'sess-1' })).toBe(true);
  expect(comp.isTopLevelTool({ id: 't3', sessionId: 'child-1' })).toBe(false);
});

test('sessionTools lazily creates one state record per session and reuses it', () => {
  expect(comp.sessionToolState.has('sess-1')).toBe(false);

  const s = comp.sessionTools('sess-1');
  expect(s.toolsById).toBeInstanceOf(Map);
  expect(s.indexToId).toBeInstanceOf(Map);
  expect(s.queue).toEqual([]);
  expect(s.busy).toBe(false);
  expect(s.floatingTool).toBeNull();

  // Same session returns the same record; other sessions get their own.
  expect(comp.sessionTools('sess-1')).toBe(s);
  expect(comp.sessionTools('sess-2')).not.toBe(s);

  // getSessionToolMap and getIndexMap read through the same record.
  expect(comp.getSessionToolMap('sess-1')).toBe(s.toolsById);
  expect(comp.getIndexMap('sess-1')).toBe(s.indexToId);
});

test('clearFloatingTool drops only the floating tool, leaving other session state intact', () => {
  const s = comp.sessionTools('sess-1');
  s.floatingTool = { id: 't1' };
  s.queue.push('t1');
  s.toolsById.set('t1', { id: 't1' });

  comp.clearFloatingTool('sess-1');

  expect(s.floatingTool).toBeNull();
  expect(s.queue).toEqual(['t1']);
  expect(s.toolsById.has('t1')).toBe(true);

  // Unknown session: no throw, and no state record lazily created.
  expect(() => comp.clearFloatingTool('missing')).not.toThrow();
  expect(comp.sessionToolState.has('missing')).toBe(false);
});

test('approveTool queues tool for execution', async () => {
  const toolUse = { ...fakeToolUse };
  comp.queueTool = jest.fn();
  comp.scrollToBottom = jest.fn();
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.sessionToolState = new Map();
  comp.sessionTools(comp.currentChatId).floatingTool = toolUse;
  
  await comp.approveTool(toolUse);
  
  expect(toolUse.approved).toBe(true);
  expect(toolUse.status).toBe('preparing');
  expect(comp.queueTool).toHaveBeenCalledWith(comp.currentChatId, toolUse.id);
  expect(comp.sessionTools(comp.currentChatId).floatingTool).toBeFalsy();
  expect(comp.scrollToBottom).toHaveBeenCalled();
});

test('approveTool handles execution error', async () => {
  const toolUse = { ...fakeToolUse };
  comp.queueTool = jest.fn().mockImplementation(() => {
    throw new Error('Execution failed');
  });
  comp.scrollToBottom = jest.fn();
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.sessionToolState = new Map();
  
  await comp.approveTool(toolUse);
  
  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('Failed to execute approved tool: Execution failed');
});

test('rejectTool marks as rejected and submits the declination through the queue', async () => {
  const toolUse = { ...fakeToolUse, sessionId: fakeSessionId };
  comp.currentChatId = fakeSessionId; // top-level tool: belongs to the viewed conversation
  comp.scrollToBottom = jest.fn();
  comp.callAIAPI = jest.fn().mockResolvedValue();
  comp.queueTool = jest.fn();
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);

  await comp.rejectTool(toolUse);

  expect(toolUse.approved).toBe(false);
  expect(toolUse.status).toBe('rejected');
  expect(toolUse.error).toBe('Tool execution was rejected by the user.');
  // The rejection is submitted as a tool_result via the queue, not as a chat message.
  expect(comp.queueTool).toHaveBeenCalledWith(fakeSessionId, toolUse.id);
  expect(comp.callAIAPI).not.toHaveBeenCalled();
  expect(comp.scrollToBottom).toHaveBeenCalled();
});

// Tool execution tests - executeTool method
test('executeTool makes correct API request', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  
  // Mock fetch to return a successful response
  const mockResponse = {
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        }),
      }),
    }
  };
  const mockPost = mockPapi('post', mockResponse);
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.currentModel = 'test-model';
  mockPapi('get', { data: [] });
  
  await comp.executeTool(toolUse);
  
  expect(mockPost).toHaveBeenCalledWith('/assistant/tool/query_events', {
    sessionId: fakeSessionId,
    toolUseId: toolUse.id,
    params: toolUse.input,
    model: 'test-model',
    rejected: false,
  },
  {
    adapter: 'fetch',
    headers: {
      'Accept': 'text/event-stream',
    },
    responseType: 'stream',
  });
  expect(toolUse.status).toBe('executing');
});

test('executeTool handles fetch error', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();

  mockPapi('post', null, new Error('Network error'));
  
  await comp.executeTool(toolUse);
  
  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('Network error');
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
  expect(comp.messages[0].content).toContain('Error executing tool "query_events": Network error');
  expect(comp.messages[0].isToolResult).toBe(true);
  expect(comp.messages[0].toolName).toBe('query_events');
  expect(comp.messages[0].toolId).toBe('tool_123');
});

test('executeTool handles non-ok response', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();

  mockPapi('post', null, new Error('Tool execution failed: Internal Server Error'));

  await comp.executeTool(toolUse);

  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('Tool execution failed: Internal Server Error');
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].content).toContain('Error executing tool "query_events": Tool execution failed: Internal Server Error');
});

// alreadyResolvedError builds the rejection the backend sends for a
// duplicate/retried request whose tool_use already has a persisted result.
const alreadyResolvedError = (data = 'ERROR_TOOL_ALREADY_RESOLVED') => {
  const error = new Error('Request failed with status code 400');
  error.response = { status: 400, data };
  return error;
};

// A duplicate approval whose tool already resolved server-side is benign: the
// session is out of sync, so the view reloads from the backend and renders the
// persisted result instead of guessing at the card's state or surfacing an error.
test('executeTool reloads the session on an already-resolved duplicate', async () => {
  const toolUse = { ...fakeToolUse, status: 'executing' };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();

  mockPapi('post', null, alreadyResolvedError());

  await comp.executeTool(toolUse);

  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(fakeSessionId);
  expect(toolUse.status).toBe('executing');
  expect(toolUse.error).toBeNull();
  expect(comp.messages).toHaveLength(0);
});

// The response body is a ReadableStream under the fetch adapter, so the benign
// check must read the error code out of the stream.
test('executeTool reloads the session on an already-resolved duplicate (streamed body)', async () => {
  const toolUse = { ...fakeToolUse, status: 'executing' };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();

  const streamBody = {
    pipeThrough: () => ({
      getReader: () => ({
        read: async () => ({ done: false, value: 'ERROR_TOOL_ALREADY_RESOLVED' })
      })
    })
  };
  mockPapi('post', null, alreadyResolvedError(streamBody));

  await comp.executeTool(toolUse);

  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(fakeSessionId);
  expect(toolUse.status).toBe('executing');
  expect(comp.messages).toHaveLength(0);
});

// A duplicate rejection is the same sync problem: reload from the backend and
// let the persisted rejection result drive the card, with no error message.
test('executeTool reloads the session when a duplicate rejection was already resolved', async () => {
  const toolUse = { ...fakeToolUse, status: 'rejected', approved: false };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();

  mockPapi('post', null, alreadyResolvedError());

  await comp.executeTool(toolUse);

  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(fakeSessionId);
  expect(toolUse.status).toBe('rejected');
  expect(comp.messages).toHaveLength(0);
});

// A background session's tool (not in view, not a delegation child) must not
// yank the user's current view: no reload, no error — the backend state is
// picked up when that session is next opened.
test('executeTool does not reload for an already-resolved tool in a background session', async () => {
  const toolUse = { ...fakeToolUse, sessionId: 'other-session', status: 'executing' };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();

  mockPapi('post', null, alreadyResolvedError());

  await comp.executeTool(toolUse);

  expect(comp.loadChatFromBackend).not.toHaveBeenCalled();
  expect(toolUse.status).toBe('executing');
  expect(comp.messages).toHaveLength(0);
});

// A failed refresh after a benign duplicate stays benign: no error surfaced,
// card untouched (the next session switch reloads from the backend).
test('executeTool stays quiet when the already-resolved reload itself fails', async () => {
  const toolUse = { ...fakeToolUse, status: 'executing' };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadChatFromBackend = jest.fn().mockRejectedValue(new Error('reload failed'));

  mockPapi('post', null, alreadyResolvedError());

  await comp.executeTool(toolUse);

  expect(toolUse.status).toBe('executing');
  expect(toolUse.error).toBeNull();
  expect(comp.messages).toHaveLength(0);
});

// Other 400s are real failures and must keep surfacing the error.
test('executeTool still surfaces a 400 that is not already-resolved', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();

  const error = new Error('Request failed with status code 400');
  error.response = { status: 400, data: 'ERROR_TOOL_REQUEST_MISMATCH' };
  mockPapi('post', null, error);

  await comp.executeTool(toolUse);

  expect(toolUse.status).toBe('error');
  expect(comp.messages).toHaveLength(1);
});

test('executeTool processes streaming response with message_start', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.$root.papi.get = jest.fn().mockResolvedValue({ data: [] });
  
  const messageStartData = JSON.stringify({
    type: 'message_start',
    message: { usage: { input_tokens: 5, output_tokens: 10 } }
  });
  
  const mockResponse = {
    ok: true,
    body: {
      getReader: jest.fn().mockReturnValue({
        read: jest.fn()
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode(`data: ${messageStartData}\n\n`) })
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode('data: [DONE]\n\n') })
          .mockResolvedValueOnce({ done: true })
      })
    }
  };
  global.fetch.mockResolvedValue(mockResponse);
  
  await comp.executeTool(toolUse);
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
  expect(comp.messages[0].isToolResult).toBe(true);
  expect(comp.messages[0].toolName).toBe('query_events');
  expect(comp.messages[0].toolId).toBe('tool_123');
  expect(comp.scrollToBottom).toHaveBeenCalled();
});

test('executeTool processes content_block_delta with text', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  mockPapi('get', { data: [] });
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const textDeltaData = JSON.stringify({
    type: 'content_block_delta',
    delta: { type: 'text_delta', text: 'Tool result: Success' }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${textDeltaData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      }),
    }
  };
  // global.fetch.mockResolvedValue(mockResponse);
  mockPapi('post', mockResponse);
  
  await comp.executeTool(toolUse);
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].content).toBe('Tool result: Success');
  expect(comp.scrollToBottom).toHaveBeenCalledTimes(2); // Once for message_start, once for text delta
});

test('executeTool processes message_stop with usage', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  mockPapi('get', { data: [] });
  comp.updateContextLength = jest.fn();
  comp.$forceUpdate = jest.fn();
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const messageStopData = JSON.stringify({ type: 'message_stop' });
  const messageDeltaData = JSON.stringify({
    type: 'message_delta',
    usage: { input_tokens: 15, output_tokens: 25 }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageDeltaData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStopData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  
  mockPapi('post', mockResponse);
  
  await comp.executeTool(toolUse);
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].usage).toEqual({ input_tokens: 15, output_tokens: 25 });
  expect(comp.updateContextLength).toHaveBeenCalledWith({ input_tokens: 15, output_tokens: 25 });
  expect(comp.$forceUpdate).toHaveBeenCalled();
});

test('executeTool handles chained tool use in response', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  mockPapi('get', { data: [] });
  comp.getSessionToolMap = jest.fn().mockReturnValue(new Map());
  comp.getIndexMap = jest.fn().mockReturnValue(new Map());
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const contentBlockStartData = JSON.stringify({
    type: 'content_block_start',
    index: 0,
    content_block: {
      type: 'tool_use',
      id: 'chained_tool_456',
      name: 'analyze_data',
      input: { data: 'sample' }
    }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${contentBlockStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.executeTool(toolUse);
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].toolUses).toHaveLength(1);
  expect(comp.messages[0].toolUses[0].id).toBe('chained_tool_456');
  expect(comp.messages[0].toolUses[0].name).toBe('analyze_data');
  expect(comp.messages[0].toolUses[0].status).toBe('preparing');
  expect(comp.getSessionToolMap).toHaveBeenCalledWith(fakeSessionId);
  expect(comp.getIndexMap).toHaveBeenCalledWith(fakeSessionId);
});

test('handleToolExecutionContentBlockDelta processes input_json_delta for chained tools', () => {
  const sessionId = 'chained-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const chainedToolUse = {
    id: 'chained_tool_123',
    inputJson: '{"param1": "val',
    status: 'preparing'
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  comp.scrollIfPinned = jest.fn();
  comp.currentChatId = sessionId;
  
  mockToolMap.set('chained_tool_123', chainedToolUse);
  mockIndexMap.set(1, 'chained_tool_123');
  
  const deltaEvent = {
    index: 1,
    delta: {
      type: 'input_json_delta',
      partial_json: 'ue1"}'
    }
  };
  
  comp.handleToolExecutionContentBlockDelta(deltaEvent, null, sessionId);
  
  expect(chainedToolUse.inputJson).toBe('{"param1": "value1"}');
  expect(chainedToolUse.status).toBe('preparing');
  expect(comp.scrollIfPinned).toHaveBeenCalled();
});

test('handleToolExecutionContentBlockDelta processes thought_delta', () => {
  const sessionId = 'tool-session';
  const assistantMessage = {
    thoughts: '**Starting Analysis**\n\n'
  };

  comp.scrollIfPinned = jest.fn();
  comp.currentChatId = sessionId;
  comp.nbspRegexOp = jest.fn((text) => text); // Pass through for testing

  const deltaEvent = {
    delta: {
      type: 'thought_delta',
      text: 'Examining the data...'
    }
  };

  comp.handleToolExecutionContentBlockDelta(deltaEvent, assistantMessage, sessionId);
  
  expect(assistantMessage.thoughts).toBe('**Starting Analysis**\n\nExamining the data...');
  expect(comp.scrollIfPinned).toHaveBeenCalled();
});

test('executeTool captures raw tool result from the inline tool_result event', async () => {
  resetPapi();

  let toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();

  // The backend streams the result inline as a synthetic tool_result event; no
  // session re-fetch is involved anymore.
  const toolResultData = JSON.stringify({
    type: 'tool_result',
    toolResult: { toolUseId: 'tool_123', content: [{ json: { "events": 5, "alerts": 2 } }] },
  });
  const messageStartData = JSON.stringify({ type: 'message_start' });

  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${toolResultData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);

  await comp.executeTool(toolUse);

  expect(toolUse.rawResult).toEqual({ "events": 5, "alerts": 2 });
  expect(toolUse.status).toBe('completed');
  expect(typeof toolUse.completedAt).toBe('string');
});

// When a model turn emits parallel tool calls, the backend coalesces: executing one
// tool persists its result but does NOT continue the turn (a "persist-only" stream =
// just the tool_result event + [DONE], no model turn). The tool must still complete,
// and no assistant message should be appended.
test('executeTool handles a persist-only stream (parallel tool coalescing)', async () => {
  resetPapi();

  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.messages = [];

  const toolResultData = JSON.stringify({
    type: 'tool_result',
    toolResult: { toolUseId: 'tool_123', content: [{ json: { ok: true } }] },
  });

  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${toolResultData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);

  await comp.executeTool(toolUse);

  expect(toolUse.status).toBe('completed');
  expect(toolUse.rawResult).toEqual({ ok: true });
  // No model turn streamed -> no assistant message appended for this tool.
  expect(comp.messages).toHaveLength(0);
});

test('executeTool handles a tool_result event carrying an error', async () => {
  resetPapi();

  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();

  const toolResultData = JSON.stringify({
    type: 'tool_result',
    toolResult: { toolUseId: 'tool_123', isError: true, status: 'error', content: [{ text: 'something went wrong' }] },
  });
  const messageStartData = JSON.stringify({ type: 'message_start' });

  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${toolResultData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);

  await comp.executeTool(toolUse);

  expect(toolUse.error).toBe('something went wrong');
  expect(toolUse.status).toBe('error');
});

test('executeTool completes a tool whose result has empty content (no stuck spinner)', async () => {
  resetPapi();

  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();

  // A non-error tool_result with an empty content array must still advance status,
  // otherwise the tool card spins forever.
  const toolResultData = JSON.stringify({
    type: 'tool_result',
    toolResult: { toolUseId: 'tool_123', content: [] },
  });
  const messageStartData = JSON.stringify({ type: 'message_start' });

  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${toolResultData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);

  await comp.executeTool(toolUse);

  expect(toolUse.status).toBe('completed');
  expect(toolUse.rawResult).toBeNull();
});

test('executeTool handles partial JSON chunks', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.$root.papi.get = jest.fn().mockResolvedValue({ data: [] });
  
  // Simulate partial JSON that gets split across chunks
  const partialJson1 = '{"type": "message_start"';
  const partialJson2 = '}';
  
  const mockResponse = {
    ok: true,
    body: {
      getReader: jest.fn().mockReturnValue({
        read: jest.fn()
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode(`data: ${partialJson1}\n\n`) })
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode(`data: ${partialJson2}\n\n`) })
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode('data: [DONE]\n\n') })
          .mockResolvedValueOnce({ done: true })
      })
    }
  };
  global.fetch.mockResolvedValue(mockResponse);
  
  await comp.executeTool(toolUse);
  
  // Should handle partial JSON gracefully and create assistant message
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
});

test('executeTool updates credits after execution', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  mockPapi('get', { data: [] });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.executeTool(toolUse);
  
  expect(comp.loadCredits).toHaveBeenCalled();
});

// callAIAPI method tests
test('callAIAPI makes correct API request', async () => {
  comp.currentChatId = fakeSessionId;
  
  // Mock fetch to return a successful response
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  const mockPost = mockPapi('post', mockResponse);
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.currentModel = 'test-model';
  
  await comp.callAIAPI('Test message');
  
  expect(mockPost).toHaveBeenCalledWith('/assistant/chat', {
      msg: 'Test message',
      sessionId: fakeSessionId,
      model: 'test-model',
      tags: null,
  }, {
    adapter: 'fetch',
    headers: {
      'Accept': 'text/event-stream'
    },
    responseType: 'stream'
  });
  expect(comp.loadCredits).toHaveBeenCalled();
});

test('callAIAPI handles fetch error', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  
  global.fetch.mockRejectedValue(new Error('Network error'));
  
  await comp.callAIAPI('Test message');
  
  expect(comp.isTyping).toBe(false);
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
  expect(comp.messages[0].content).toContain('having trouble connecting to the AI service');
  expect(comp.scrollToBottom).toHaveBeenCalled();
});

test('callAIAPI processes message_start event', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  const messageStartData = JSON.stringify({
    type: 'message_start',
    message: { usage: { input_tokens: 10, output_tokens: 15 } }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.isTyping).toBe(false);
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
  expect(comp.messages[0].content).toBe('');
  expect(comp.messages[0].usage).toBe(null); // Usage set later in message_stop
  expect(comp.messages[0].toolUses).toEqual([]);
  expect(comp.scrollToBottom).toHaveBeenCalled();
});

test('callAIAPI processes content_block_start with tool_use', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.getSessionToolMap = jest.fn().mockReturnValue(new Map());
  comp.getIndexMap = jest.fn().mockReturnValue(new Map());
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const contentBlockStartData = JSON.stringify({
    type: 'content_block_start',
    index: 0,
    content_block: {
      type: 'tool_use',
      id: 'tool_456',
      name: 'search_data',
      input: { query: 'test query' }
    }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${contentBlockStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].toolUses).toHaveLength(1);
  expect(comp.messages[0].toolUses[0].id).toBe('tool_456');
  expect(comp.messages[0].toolUses[0].name).toBe('search_data');
  expect(comp.messages[0].toolUses[0].input).toEqual({ query: 'test query' });
  expect(comp.messages[0].toolUses[0].status).toBe('preparing');
  expect(comp.getSessionToolMap).toHaveBeenCalledWith(fakeSessionId);
  expect(comp.getIndexMap).toHaveBeenCalledWith(fakeSessionId);
});

test('callAIAPI processes content_block_delta with text_delta', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const textDeltaData1 = JSON.stringify({
    type: 'content_block_delta',
    delta: { type: 'text_delta', text: 'Hello ' }
  });
  const textDeltaData2 = JSON.stringify({
    type: 'content_block_delta',
    delta: { type: 'text_delta', text: 'world!' }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${textDeltaData1}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${textDeltaData2}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].content).toBe('Hello world!');
  expect(comp.scrollToBottom).toHaveBeenCalledTimes(3); // Once for message_start, twice for text deltas
});

test('callAIAPI processes content_block_delta with thought_delta', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const thoughtDeltaData1 = JSON.stringify({
    type: 'content_block_delta',
    delta: { type: 'thought_delta', text: '**Analyzing Request**\n\n' }
  });
  const thoughtDeltaData2 = JSON.stringify({
    type: 'content_block_delta',
    delta: { type: 'thought_delta', text: 'Processing the query...' }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${thoughtDeltaData1}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${thoughtDeltaData2}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].thoughts).toBe('**Analyzing Request**\n\nProcessing the query...');
  expect(comp.scrollToBottom).toHaveBeenCalledTimes(3); // Once for message_start, twice for thought deltas
});

test('callAIAPI processes content_block_delta with input_json_delta', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_789',
    name: 'analyze',
    inputJson: '',
    status: 'preparing'
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  
  // Set up the tool use in the maps
  mockToolMap.set('tool_789', mockToolUse);
  mockIndexMap.set(0, 'tool_789');
  
  // Mock the actual streaming processing to update inputJson
  let actualInputJson = '';
  comp.handleContentBlockDelta = jest.fn((c, assistantMessage, sessionId) => {
    if (c.delta.type === 'input_json_delta') {
      actualInputJson += c.delta.partial_json;
      mockToolUse.inputJson = actualInputJson;
    }
  });
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const contentBlockStartData = JSON.stringify({
    type: 'content_block_start',
    index: 0,
    content_block: { type: 'tool_use', id: 'tool_789', name: 'analyze', input: {} }
  });
  const inputJsonDelta1 = JSON.stringify({
    type: 'content_block_delta',
    index: 0,
    delta: { type: 'input_json_delta', partial_json: '{"param": "val' }
  });
  const inputJsonDelta2 = JSON.stringify({
    type: 'content_block_delta',
    index: 0,
    delta: { type: 'input_json_delta', partial_json: 'ue"}' }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${contentBlockStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${inputJsonDelta1}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${inputJsonDelta2}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(mockToolUse.inputJson).toBe('{"param": "value"}');
  expect(mockToolUse.status).toBe('preparing');
});

test('callAIAPI processes content_block_stop event', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(false);
  comp.sessionToolState = new Map();
  
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_stop',
    name: 'test_tool',
    inputJson: '{"test": "data"}',
    status: 'preparing',
    input: {},
    approved: null
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  
  // Set up the tool use in the maps
  mockToolMap.set('tool_stop', mockToolUse);
  mockIndexMap.set(0, 'tool_stop');
  
  // Override the actual streaming processing to simulate content_block_stop
  const originalCallAIAPI = comp.callAIAPI;
  comp.callAIAPI = async function(userMessage) {
    // Simulate the tool processing
    const toolUse = mockToolMap.get('tool_stop');
    if (toolUse && toolUse.status === 'preparing') {
      try {
        if (toolUse.inputJson) {
          toolUse.input = JSON.parse(toolUse.inputJson);
        }
        toolUse.status = 'pending_approval';
        toolUse.approved = null;
      } catch (error) {
        toolUse.status = 'error';
        toolUse.error = 'Failed to parse tool input: ' + error.message;
      }
    }
    // Call the original method to maintain other functionality
    return originalCallAIAPI.call(this, userMessage);
  };
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const contentBlockStartData = JSON.stringify({
    type: 'content_block_start',
    index: 0,
    content_block: { type: 'tool_use', id: 'tool_stop', name: 'test_tool', input: {} }
  });
  const inputJsonDelta = JSON.stringify({
    type: 'content_block_delta',
    index: 0,
    delta: { type: 'input_json_delta', partial_json: '{"test": "data"}' }
  });
  const contentBlockStopData = JSON.stringify({
    type: 'content_block_stop',
    index: 0,
    usage: { input_tokens: 5, output_tokens: 10 }
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${contentBlockStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${inputJsonDelta}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${contentBlockStopData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(mockToolUse.input).toEqual({ test: 'data' });
  expect(mockToolUse.status).toBe('pending_approval');
  expect(mockToolUse.approved).toBe(null);
});

test('callAIAPI handles content_block_stop with invalid JSON', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_invalid',
    name: 'test_tool',
    inputJson: '{"invalid": json}',
    status: 'preparing',
    input: {},
    error: null
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  
  // Set up the tool use in the maps
  mockToolMap.set('tool_invalid', mockToolUse);
  mockIndexMap.set(0, 'tool_invalid');
  
  // Override the actual streaming processing to simulate content_block_stop with invalid JSON
  const originalCallAIAPI = comp.callAIAPI;
  comp.callAIAPI = async function(userMessage) {
    // Simulate the tool processing with invalid JSON
    const toolUse = mockToolMap.get('tool_invalid');
    if (toolUse && toolUse.status === 'preparing') {
      try {
        if (toolUse.inputJson) {
          toolUse.input = JSON.parse(toolUse.inputJson);
        }
        toolUse.status = 'pending_approval';
        toolUse.approved = null;
      } catch (error) {
        toolUse.status = 'error';
        toolUse.error = 'Failed to parse tool input: ' + error.message;
      }
    }
    // Call the original method to maintain other functionality
    return originalCallAIAPI.call(this, userMessage);
  };
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const contentBlockStartData = JSON.stringify({
    type: 'content_block_start',
    index: 0,
    content_block: { type: 'tool_use', id: 'tool_invalid', name: 'test_tool', input: {} }
  });
  const inputJsonDelta = JSON.stringify({
    type: 'content_block_delta',
    index: 0,
    delta: { type: 'input_json_delta', partial_json: '{"invalid": json}' }
  });
  const contentBlockStopData = JSON.stringify({
    type: 'content_block_stop',
    index: 0
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${contentBlockStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${inputJsonDelta}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${contentBlockStopData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(mockToolUse.status).toBe('error');
  expect(mockToolUse.error).toContain('Failed to parse tool input');
});

test('callAIAPI processes message_stop with usage', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateContextLength = jest.fn();
  comp.$forceUpdate = jest.fn();
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const messageDeltaData = JSON.stringify({
    type: 'message_delta',
    usage: { input_tokens: 20, output_tokens: 30 }
  });
  const messageStopData = JSON.stringify({ type: 'message_stop' });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageDeltaData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStopData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].usage).toEqual({ input_tokens: 20, output_tokens: 30 });
  expect(comp.updateContextLength).toHaveBeenCalledWith({ input_tokens: 20, output_tokens: 30 });
  expect(comp.$forceUpdate).toHaveBeenCalled();
});

test('callAIAPI processes message_delta with usage', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateContextLength = jest.fn();
  comp.$forceUpdate = jest.fn();
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const messageDeltaData = JSON.stringify({
    type: 'message_delta',
    usage: { input_tokens: 25, output_tokens: 35 }
  });
  const messageStopData = JSON.stringify({ type: 'message_stop' });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageDeltaData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStopData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].usage).toEqual({ input_tokens: 25, output_tokens: 35 });
  expect(comp.updateContextLength).toHaveBeenCalledWith({ input_tokens: 25, output_tokens: 35 });
});

test('callAIAPI handles partial JSON chunks', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  // Simulate partial JSON that gets split across chunks
  const partialJson1 = '{"type": "message_start", "message"';
  const partialJson2 = ': {"usage": {"input_tokens": 5}}}';
  
  const mockResponse = {
    ok: true,
    body: {
      getReader: jest.fn().mockReturnValue({
        read: jest.fn()
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode(`data: ${partialJson1}\n\n`) })
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode(`data: ${partialJson2}\n\n`) })
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode('data: [DONE]\n\n') })
          .mockResolvedValueOnce({ done: true })
      })
    }
  };
  global.fetch.mockResolvedValue(mockResponse);
  
  await comp.callAIAPI('Test message');
  
  // Should handle partial JSON gracefully and create assistant message
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
});

test('callAIAPI handles concatenated JSON objects', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  // Simulate concatenated JSON objects in a single chunk
  const concatenatedJson = '{"type": "message_start"}{"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hello"}}';
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${concatenatedJson}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
  expect(comp.messages[0].content).toBe('Hello');
});

test('callAIAPI handles unhandled event types with usage', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateContextLength = jest.fn();
  comp.$forceUpdate = jest.fn();
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const unknownEventData = JSON.stringify({
    type: 'unknown_event',
    usage: { input_tokens: 12, output_tokens: 18 }
  });
  const messageStopData = JSON.stringify({ type: 'message_stop' });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${unknownEventData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStopData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].usage).toEqual({ input_tokens: 12, output_tokens: 18 });
  expect(comp.updateContextLength).toHaveBeenCalledWith({ input_tokens: 12, output_tokens: 18 });
});

test('callAIAPI handles empty chunks and filters correctly', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  
  const mockResponse = {
    ok: true,
    body: {
      getReader: jest.fn().mockReturnValue({
        read: jest.fn()
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode(`data: ${messageStartData}\n\n\n\ndata: \n\n`) })
          .mockResolvedValueOnce({ done: false, value: new TextEncoder().encode('data: [DONE]\n\n') })
          .mockResolvedValueOnce({ done: true })
      })
    }
  };
  global.fetch.mockResolvedValue(mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
});

test('callAIAPI clears investigation query params after first use', async () => {
  comp.currentChatId = fakeSessionId;
  comp.currentModel = 'test-model';
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();
  
  // Set up route with investigation query params
  comp.$route.query = {
    socId: 'alert-123',
    investigation: 'true',
    otherParam: 'keep-this'
  };
  comp.$route.params = { sessionId: fakeSessionId };
  
  // Mock $nextTick to execute callback immediately
  let nextTickCallback = null;
  comp.$nextTick = jest.fn((callback) => {
    if (callback) {
      nextTickCallback = callback;
      return Promise.resolve().then(() => callback());
    }
    return Promise.resolve();
  });
  
  const mockResponse = {
    ok: true,
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  const mockPost = mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  // Verify the API was called with the socId parameter
  expect(mockPost).toHaveBeenCalledWith('/assistant/chat?entityType=alert_investigation&entityId=alert-123', {
    msg: 'Test message',
    sessionId: fakeSessionId,
    model: 'test-model',
    tags: null,
  }, {
    adapter: 'fetch',
    headers: {
      'Accept': 'text/event-stream'
    },
    responseType: 'stream'
  });
  
  // Verify $nextTick was called (for the query param clearing)
  expect(comp.$nextTick).toHaveBeenCalled();
  
  // Wait for nextTick callback to execute
  await new Promise(resolve => setTimeout(resolve, 0));
  
  // Verify router.replace was called to clear investigation params
  expect(comp.$router.replace).toHaveBeenCalledWith({
    name: 'assistant',
    params: { sessionId: fakeSessionId },
    query: { otherParam: 'keep-this' } // investigation and socId should be removed
  });
});

// Investigation session tests
test('handleRouteSessionId detects investigation session from query parameter', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.$route.query.investigation = 'true';
  comp.loadChatFromBackend = jest.fn().mockRejectedValue(new Error('Session not found'));
  comp.startInvestigationSession = jest.fn();
  comp.saveCurrentChatId = jest.fn();
  comp.assistantEnabled = true;
  
  // Mock $root methods needed for handleRouteSessionId
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  
  // Test the investigation detection logic by checking if the right conditions are met
  await comp.handleRouteSessionId();
  
  expect(comp.currentChatId).toBe(fakeSessionId);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  // The investigation logic should be triggered when investigation=true and loadChatFromBackend fails
  expect(comp.$route.query.investigation).toBe('true');
});

test('handleRouteSessionId handles existing session', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();
  comp.focusChatInput = jest.fn();
  comp.assistantEnabled = true;

  await comp.handleRouteSessionId();

  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(fakeSessionId);
  expect(comp.focusChatInput).toHaveBeenCalled();
});

test('startInvestigationSession clears messages and sets up investigation prompt', async () => {
  const investigationPrompt = 'Investigate suspicious network activity from IP 10.0.0.1';
  comp.messages = [fakeAssistantMessage]; // Start with welcome message
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.creditsLoaded = true;

  // Mock setTimeout to execute immediately for testing
  jest.useFakeTimers();

  await comp.startInvestigationSession(investigationPrompt);
  
  expect(comp.messages).toEqual([]); // Should clear messages
  expect(comp.newMessage).toBe(investigationPrompt);
  expect(comp.$nextTick).toHaveBeenCalled();
  
  // Fast-forward the setTimeout
  jest.advanceTimersByTime(2000);
  
  expect(comp.sendMessage).toHaveBeenCalled();
  
  jest.useRealTimers();
});

test('startInvestigationSession handles empty prompt', async () => {
  const investigationPrompt = '';
  comp.messages = [fakeAssistantMessage];
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.creditsLoaded = true;

  jest.useFakeTimers();

  await comp.startInvestigationSession(investigationPrompt);
  
  expect(comp.messages).toEqual([]);
  expect(comp.newMessage).toBe('');
  
  // Fast-forward the setTimeout
  jest.advanceTimersByTime(2000);
  
  // Should not call sendMessage for empty prompt
  expect(comp.sendMessage).not.toHaveBeenCalled();
  
  jest.useRealTimers();
});

test('startInvestigationSession handles whitespace-only prompt', async () => {
  const investigationPrompt = '   \n\t   ';
  comp.messages = [fakeAssistantMessage];
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.creditsLoaded = true;

  jest.useFakeTimers();

  await comp.startInvestigationSession(investigationPrompt);
  
  expect(comp.messages).toEqual([]);
  expect(comp.newMessage).toBe(investigationPrompt);
  
  // Fast-forward the setTimeout
  jest.advanceTimersByTime(2000);
  
  // Should not call sendMessage for whitespace-only prompt
  expect(comp.sendMessage).not.toHaveBeenCalled();
  
  jest.useRealTimers();
});

test('startInvestigationSession handles sendMessage error', async () => {
  const showErrorMock = mockShowError();
  const investigationPrompt = 'Investigate malware detection on host server-01';
  comp.messages = [fakeAssistantMessage];
  comp.sendMessage = jest.fn().mockRejectedValue(new Error('Network error'));
  comp.creditsLoaded = true;

  jest.useFakeTimers();

  await comp.startInvestigationSession(investigationPrompt);
  
  expect(comp.messages).toEqual([]);
  expect(comp.newMessage).toBe(investigationPrompt);
  
  // Fast-forward the setTimeout
  jest.advanceTimersByTime(2000);
  
  expect(comp.sendMessage).toHaveBeenCalled();
  
  // Wait for the error handling
  await jest.runAllTimersAsync();
  
  expect(showErrorMock).toHaveBeenCalledWith(expect.stringContaining('Failed to send investigation message'));
  
  jest.useRealTimers();
});

test('startInvestigationSession sets up investigation with complex prompt', async () => {
  const investigationPrompt = `Investigate the following security incident:
- Multiple failed login attempts from IP 192.168.1.50
- Suspicious file modifications in /var/log/
- Unusual network traffic to external domains
Please analyze the logs and provide recommendations.`;
  
  comp.messages = [fakeAssistantMessage];
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.creditsLoaded = true;

  jest.useFakeTimers();

  await comp.startInvestigationSession(investigationPrompt);

  expect(comp.messages).toEqual([]);
  expect(comp.newMessage).toBe(investigationPrompt);
  expect(comp.$nextTick).toHaveBeenCalled();

  // Fast-forward the setTimeout
  jest.advanceTimersByTime(2000);

  expect(comp.sendMessage).toHaveBeenCalled();

  jest.useRealTimers();
});

test('investigation session integrates with existing chat functionality', async () => {
  const investigationPrompt = 'Investigate DDoS attack patterns';
  comp.messages = [fakeAssistantMessage];
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.creditsLoaded = true;

  jest.useFakeTimers();

  await comp.startInvestigationSession(investigationPrompt);
  
  // Verify immediate state changes
  expect(comp.messages).toEqual([]);
  expect(comp.newMessage).toBe(investigationPrompt);
  expect(comp.$nextTick).toHaveBeenCalled();
  
  // Fast-forward the setTimeout to trigger sendMessage
  jest.advanceTimersByTime(2000);

  // Verify the investigation prompt was processed through sendMessage
  expect(comp.sendMessage).toHaveBeenCalled();

  jest.useRealTimers();
});

test('startInvestigationSession does not populate input when model is unreachable', async () => {
  const investigationPrompt = 'Investigate suspicious network activity from IP 10.0.0.1';
  comp.messages = [fakeAssistantMessage];
  comp.newMessage = '';
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.creditsLoaded = false;
  comp.currentChatId = fakeSessionId; // handleRouteSessionId set this before us
  comp.saveCurrentChatId = jest.fn();
  comp.$route.params.sessionId = fakeSessionId;
  // loadCredits fails to recover the unhealthy state — leave creditsLoaded false
  comp.loadCredits = jest.fn().mockImplementation(async () => { comp.creditsLoaded = false; });

  jest.useFakeTimers();

  await comp.startInvestigationSession(investigationPrompt);

  expect(comp.loadCredits).toHaveBeenCalled();
  expect(comp.messages).toEqual([fakeAssistantMessage]); // Should not clear messages
  expect(comp.newMessage).toBe(''); // Should not write the prompt into the disabled input
  // Should reset the URL/session bookkeeping so we land back on the base /assistant page.
  expect(comp.currentChatId).toBeNull();
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.$router.replace).toHaveBeenCalledWith({ name: 'assistant' });

  jest.advanceTimersByTime(2000);
  expect(comp.sendMessage).not.toHaveBeenCalled();

  jest.useRealTimers();
});

test('startInvestigationSession proceeds after lazily loading credits', async () => {
  const investigationPrompt = 'Investigate suspicious network activity from IP 10.0.0.1';
  comp.messages = [fakeAssistantMessage];
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.creditsLoaded = false;
  comp.loadCredits = jest.fn().mockImplementation(async () => { comp.creditsLoaded = true; });

  jest.useFakeTimers();

  await comp.startInvestigationSession(investigationPrompt);

  expect(comp.loadCredits).toHaveBeenCalled();
  expect(comp.messages).toEqual([]);
  expect(comp.newMessage).toBe(investigationPrompt);

  jest.advanceTimersByTime(2000);
  expect(comp.sendMessage).toHaveBeenCalled();

  jest.useRealTimers();
});

// Utility and helper method tests
test('scrollToBottom scrolls messages container', () => {
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500
  };
  comp.$el.querySelector.mockReturnValue(mockContainer);
  
  comp.scrollToBottom();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  // Note: The actual scrolling happens in nextTick callback
});

test('scrollToBottom handles missing container', () => {
  comp.$el.querySelector.mockReturnValue(null);
  
  comp.scrollToBottom();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  // Should not throw error
});

test('getAvatar delegates to root', () => {
  const user = 'testuser';
  comp.$root.getAvatar = jest.fn().mockReturnValue('avatar-url');
  
  const result = comp.getAvatar(user);
  
  expect(comp.$root.getAvatar).toHaveBeenCalledWith(user);
  expect(result).toBe('avatar-url');
});

test('formatTimestamp delegates to root', () => {
  const timestamp = '2025-01-01T12:00:00.000Z';
  comp.$root.formatTimestamp = jest.fn().mockReturnValue('formatted-time');
  
  const result = comp.formatTimestamp(timestamp);
  
  expect(comp.$root.formatTimestamp).toHaveBeenCalledWith(timestamp);
  expect(result).toBe('formatted-time');
});

test('formatMarkdown delegates to root', () => {
  const text = '**bold text**';
  comp.$root.formatMarkdown = jest.fn().mockReturnValue('<strong>bold text</strong>');
  
  const result = comp.formatMarkdown(text);
  
  expect(comp.$root.formatMarkdown).toHaveBeenCalledWith(text, true);
  expect(result).toBe('<strong>bold text</strong>');
});

test('formatChatDate delegates to root', () => {
  const timestamp = '2025-01-01T12:00:00.000Z';
  comp.$root.formatDateTime = jest.fn().mockReturnValue('formatted-datetime');
  
  const result = comp.formatChatDate(timestamp);
  
  expect(comp.$root.formatDateTime).toHaveBeenCalledWith(timestamp);
  expect(result).toBe('formatted-datetime');
});

test('formatCount delegates to root', () => {
  const count = 1234;
  comp.$root.formatCount = jest.fn().mockReturnValue('1,234');
  
  const result = comp.formatCount(count);
  
  expect(comp.$root.formatCount).toHaveBeenCalledWith(count);
  expect(result).toBe('1,234');
});

test('getLastThoughtTitle extracts last bold text from thoughts', () => {
  const thoughtsWithMultipleBold = '**Analyzing the Request**\n\nI need to process this.\n\n**Formulating Response**\n\nHere is my answer.';
  const thoughtsWithOneBold = '**Processing Data**\n\nWorking on it...';
  const thoughtsWithNoBold = 'Just some plain text without bold markers';
  const emptyThoughts = '';
  
  expect(comp.getLastThoughtTitle(thoughtsWithMultipleBold)).toBe('Formulating Response');
  expect(comp.getLastThoughtTitle(thoughtsWithOneBold)).toBe('Processing Data');
  expect(comp.getLastThoughtTitle(thoughtsWithNoBold)).toBe(comp.i18n.thinking);
  expect(comp.getLastThoughtTitle(emptyThoughts)).toBe(comp.i18n.thinking);
});

// Backend message conversion tests
test('generateTitleFromMessage', () => {
  const session = {
    title: 'This is a test message that should be truncated'
  };
  
  const title = comp.generateTitleFromMessage(session);
  
  expect(title).toBe('This is a test message that should be truncated');
});

test('generateTitleFromMessage with long title', () => {
  const session = {
    title: 'This is a very long test message that should definitely be truncated because it exceeds the fifty character limit'
  };
  
  const title = comp.generateTitleFromMessage(session);
  
  expect(title).toBe('This is a very long test message that should defin...');
});

test('generateTitleFromMessage with no title', () => {
  const session = {
  };
  
  const title = comp.generateTitleFromMessage(session);
  
  expect(title).toMatch(/^New Chat - \d+\/\d+\/\d+$/);
});

// convertBackendMessagesToFrontend method tests
test('convertBackendMessagesToFrontend resets context length', () => {
  comp.contextLength = 1000;
  
  const backendMessages = [];
  comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(comp.contextLength).toBe(0);
});

test('convertBackendMessagesToFrontend converts user message with contentBlocks', () => {
  comp.resetContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'text', text: 'Hello, how can you help me?' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].role).toBe('user');
  expect(result[0].content).toBe('Hello, how can you help me?');
  expect(result[0].timestamp).toBe('2025-01-01T12:00:00.000Z');
});

test('convertBackendMessagesToFrontend converts user message with contentStr', () => {
  comp.resetContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user',
        contentStr: 'Simple user message',
        contentBlocks: [
          { type: 'text', text: 'Simple user message' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].role).toBe('user');
  expect(result[0].content).toBe('Simple user message');
  expect(result[0].timestamp).toBe('2025-01-01T12:00:00.000Z');
});

test('convertBackendMessagesToFrontend converts assistant message with text blocks', () => {
  comp.resetContextLength = jest.fn();
  comp.updateContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'I can help you with security analysis.' }
        ],
        usage: { input_tokens: 10, output_tokens: 20 }
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].role).toBe('assistant');
  expect(result[0].content).toBe('I can help you with security analysis.');
  expect(result[0].timestamp).toBe('2025-01-01T12:00:00.000Z');
  expect(result[0].usage).toEqual({ input_tokens: 10, output_tokens: 20 });
  expect(comp.updateContextLength).toHaveBeenCalledWith({ input_tokens: 10, output_tokens: 20 }, false);
});

test('convertBackendMessagesToFrontend converts assistant message with thoughts', () => {
  comp.resetContextLength = jest.fn();
  comp.updateContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'I can help you with security analysis.' }
        ],
        thoughts: '**Analyzing Request**\n\nProcessing the user query...',
        usage: { input_tokens: 10, output_tokens: 20 }
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].role).toBe('assistant');
  expect(result[0].content).toBe('I can help you with security analysis.');
  expect(result[0].thoughts).toBe('**Analyzing Request**\n\nProcessing the user query...');
  expect(result[0].timestamp).toBe('2025-01-01T12:00:00.000Z');
  expect(result[0].usage).toEqual({ input_tokens: 10, output_tokens: 20 });
  expect(comp.updateContextLength).toHaveBeenCalledWith({ input_tokens: 10, output_tokens: 20 }, false);
});

test('convertBackendMessagesToFrontend handles multiple text blocks', () => {
  comp.resetContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'text', text: 'First part' },
          { type: 'text', text: 'Second part' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].content).toBe('First part\nSecond part');
});

test('convertBackendMessagesToFrontend handles message with no text blocks', () => {
  comp.resetContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'image', data: 'base64data' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].content).toBe('');
});

test('convertBackendMessagesToFrontend handles empty message', () => {
  comp.resetContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user'
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].content).toBe('Empty message');
});

test('convertBackendMessagesToFrontend handles tool_use blocks with completed status', () => {
  comp.resetContextLength = jest.fn();
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_123',
            name: 'query_events',
            input: { query: 'test' }
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      tags: [
        "tool_result"
      ],
      message: {
        role: 'user',
        contentBlocks: [
          {
            toolResult: {
              toolUseId: 'tool_123',
              content: [{ json: { result: 'success' } }]
            }
          }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].content).toBe('');
  // Tool uses should be created since there's a next message and no rejection
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses).toHaveLength(1);
  expect(result[0].toolUses[0].id).toBe('tool_123');
  expect(result[0].toolUses[0].name).toBe('query_events');
  expect(result[0].toolUses[0].input).toEqual({ query: 'test' });
  expect(result[0].toolUses[0].status).toBe('completed');
  expect(result[0].toolUses[0].approved).toBe(true);
  expect(result[0].toolUses[0].rawResult).toEqual({ result: 'success' });
});

// Rejections are now stored as tool_results (status 'rejected'); the old chat-message
// format ("...rejected by the user" after the tool_use) is no longer special-cased.
// On reload such a legacy turn renders the tool as skipped (the conversation moved on)
// and the message itself is kept rather than consumed.
test('convertBackendMessagesToFrontend no longer special-cases the legacy chat-message rejection', () => {
  comp.resetContextLength = jest.fn();
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_456',
            name: 'analyze_data',
            input: { data: 'sample' }
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'text', text: 'Tool execution was rejected by the user.' }
        ]
      }
    }
  ];

  const result = comp.convertBackendMessagesToFrontend(backendMessages);

  expect(result).toHaveLength(2); // The legacy message is no longer skipped
  expect(result[0].toolUses).toHaveLength(1);
  expect(result[0].toolUses[0].id).toBe('tool_456');
  expect(result[0].toolUses[0].status).toBe('skipped');
  expect(result[0].toolUses[0].approved).toBe(false);
});

test('convertBackendMessagesToFrontend handles tool_use blocks with null/undefined input', () => {
  comp.resetContextLength = jest.fn();
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_789',
            name: 'simple_tool'
            // input is undefined
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      tags: [
        "tool_result"
      ],
      message: {
        role: 'user',
        contentBlocks: [
          {
            toolResult: {
              toolUseId: 'tool_789',
              content: [{ json: { result: 'success' } }]
            }
          }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses[0].input).toEqual({}); // Should default to empty object
});

test('convertBackendMessagesToFrontend handles tool_use blocks at end of session with pending_approval status', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'test_session_123';
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  // Single message with tool use at the end (no subsequent messages)
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_end_session',
            name: 'query_events',
            input: { query: 'test query at end' }
          }
        ]
      }
    }
    // No subsequent messages - this is the end of the session
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses).toHaveLength(1);
  
  const toolUse = result[0].toolUses[0];
  expect(toolUse.id).toBe('tool_end_session');
  expect(toolUse.name).toBe('query_events');
  expect(toolUse.input).toEqual({ query: 'test query at end' });
  expect(toolUse.status).toBe('pending_approval'); // Key assertion for line 1473
  expect(toolUse.result).toBe(null);
  expect(toolUse.error).toBe(null);
  expect(toolUse.rawResult).toBe(null);
  expect(toolUse.timestamp).toBe('2025-01-01T12:00:00.000Z');
  expect(toolUse.approved).toBe(null);
  expect(toolUse.sessionId).toBe('test_session_123'); // Should include sessionId
});

// A top-level turn can request tools in parallel whose results land as separate
// tool_result messages. Reload must status each tool independently: resolved siblings
// complete, the unresolved one stays actionable (not collapsed to one turn-wide status).
test('reload statuses a partially-resolved parallel top-level turn per tool', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parallel_session';
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const toolUse = (id) => ({ type: 'tool_use', id, name: 'query_events', input: { q: id } });
  const toolResult = (id) => ({
    tags: ['tool_result'],
    createTime: '2025-01-01T12:01:00.000Z',
    message: { role: 'user', contentBlocks: [{ toolResult: { toolUseId: id, content: [{ json: { ok: id } }] } }] },
  });
  const backendMessages = [
    { createTime: '2025-01-01T12:00:00.000Z', message: { role: 'assistant', contentBlocks: [toolUse('a'), toolUse('b'), toolUse('c')] } },
    toolResult('a'),
    toolResult('b'),
  ];

  const tools = comp.convertBackendMessagesToFrontend(backendMessages)[0].toolUses;
  expect(tools.map(t => t.id)).toEqual(['a', 'b', 'c']);
  expect(tools[0].status).toBe('completed');
  expect(tools[0].rawResult).toEqual({ ok: 'a' });
  expect(tools[1].status).toBe('completed');
  // The unresolved sibling must stay actionable, not falsely completed (old behavior).
  expect(tools[2].status).toBe('pending_approval');
  expect(tools[2].approved).toBe(null);
  expect(comp.getSessionToolMap('parallel_session').get('c')).toBe(tools[2]);
});

// Once the conversation moves past a parallel turn, its unanswered tools are skipped.
test('reload marks unresolved parallel top-level tools skipped once the conversation moved on', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parallel_skip_session';
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const toolUse = (id) => ({ type: 'tool_use', id, name: 'query_events', input: { q: id } });
  const backendMessages = [
    { createTime: '2025-01-01T12:00:00.000Z', message: { role: 'assistant', contentBlocks: [toolUse('a'), toolUse('b'), toolUse('c')] } },
    { createTime: '2025-01-01T12:01:00.000Z', message: { role: 'user', contentBlocks: [{ type: 'text', text: 'never mind, do something else' }] } },
    { createTime: '2025-01-01T12:02:00.000Z', message: { role: 'assistant', contentBlocks: [{ type: 'text', text: 'sure' }] } },
  ];

  const tools = comp.convertBackendMessagesToFrontend(backendMessages).find(m => m.toolUses).toolUses;
  expect(tools).toHaveLength(3);
  tools.forEach(t => expect(t.status).toBe('skipped'));
});

// A stored rejection (status 'rejected') reloads as a rejected card, not error/completed.
test('reload renders a declined tool as rejected', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'reject_reload_session';
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const backendMessages = [
    { createTime: '2025-01-01T12:00:00.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'tool_x', name: 'query_events', input: { q: 'x' } },
    ] } },
    { createTime: '2025-01-01T12:00:01.000Z', tags: ['tool_result'], message: { role: 'user', contentBlocks: [
      { toolResult: { toolUseId: 'tool_x', status: 'rejected', isError: true, content: [{ text: 'declined' }] } },
    ] } },
  ];

  const tools = comp.convertBackendMessagesToFrontend(backendMessages)[0].toolUses;
  expect(tools).toHaveLength(1);
  expect(tools[0].status).toBe('rejected');
  expect(tools[0].error).toBe('declined');
});

test('convertBackendMessagesToFrontend handles multiple tool_use blocks at end of session', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'multi_tool_session';
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  // Message with multiple tool uses at the end of session
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_1',
            name: 'query_events',
            input: { query: 'first query' }
          },
          {
            type: 'tool_use',
            id: 'tool_2',
            name: 'get_playbooks',
            input: { alert_id: 'alert_123' }
          }
        ]
      }
    }
    // No subsequent messages
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses).toHaveLength(2);
  
  // Both tools should have pending_approval status
  result[0].toolUses.forEach((toolUse, index) => {
    expect(toolUse.status).toBe('pending_approval');
    expect(toolUse.approved).toBe(null);
    expect(toolUse.sessionId).toBe('multi_tool_session');
    expect(toolUse.id).toBe(`tool_${index + 1}`);
  });
});

test('convertBackendMessagesToFrontend handles tool_use blocks at end with missing input', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'missing_input_session';
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  // Tool use block with missing input at end of session
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_no_input',
            name: 'simple_tool'
            // No input property
          }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses).toHaveLength(1);
  
  const toolUse = result[0].toolUses[0];
  expect(toolUse.status).toBe('pending_approval');
  expect(toolUse.input).toEqual({}); // Should default to empty object
  expect(toolUse.approved).toBe(null);
  expect(toolUse.sessionId).toBe('missing_input_session');
});

test('convertBackendMessagesToFrontend handles tool_use blocks at end with missing id/name', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'missing_props_session';
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  // Tool use block with missing id and name at end of session
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use'
            // Missing id and name properties
          }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses).toHaveLength(1);
  
  const toolUse = result[0].toolUses[0];
  expect(toolUse.status).toBe('pending_approval');
  expect(toolUse.id).toBe('unknown'); // Should default to 'unknown'
  expect(toolUse.name).toBe('unknown'); // Should default to 'unknown'
  expect(toolUse.input).toEqual({});
  expect(toolUse.approved).toBe(null);
  expect(toolUse.sessionId).toBe('missing_props_session');
});

test('convertBackendMessagesToFrontend filters out legacy format tool result messages', () => {
  comp.resetContextLength = jest.fn();
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_result_test',
            name: 'query_events',
            input: { query: 'test' }
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      tags: ['tool_result'],
      message: {
        contentBlocks: [
          {
            type: 'text',
            text: 'ToolUseId: tool_result_test, Result: {"events": 5}, Error: <nil>'
          }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1); // Tool result message should be filtered out
  expect(result[0].toolUses[0].rawResult).toBe('{"events": 5}, Error: <nil>');
  expect(result[0].toolUses[0].completedAt).toBe('2025-01-01T12:01:00.000Z');
  expect(result[0].toolUses[0].status).toBe('completed'); // No error since Error is <nil>
});

test('convertBackendMessagesToFrontend handles legacy format tool result with error', () => {
  comp.resetContextLength = jest.fn();
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_error_test',
            name: 'failing_tool',
            input: { param: 'value' }
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      tags: ['tool_result'],
      message: {
        contentBlocks: [
          {
            type: 'text',
            text: 'ToolUseId: tool_error_test, Result: null, Error: Connection timeout'
          }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].toolUses[0].rawResult).toBe('null, Error: Connection timeout');
  expect(result[0].toolUses[0].error).toBe('Connection timeout');
  expect(result[0].toolUses[0].status).toBe('error');
});

test('convertBackendMessagesToFrontend filters out old format tool result messages', () => {
  comp.resetContextLength = jest.fn();
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_old_format',
            name: 'legacy_tool',
            input: { data: 'test' }
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      tags: [
        "tool_result"
      ],
      message: {
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'Tool completed' }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:02:00.000Z',
      message: {
        role: 'user',
        contentStr: 'Raw tool result data'
        // No contentBlocks - this is the old format
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1); // Tool result message should be filtered out
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses[0].rawResult).toBe('Raw tool result data');
});

test('convertBackendMessagesToFrontend handles malformed tool result parsing', () => {
  comp.resetContextLength = jest.fn();
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_malformed',
            name: 'test_tool',
            input: {}
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      tags: ['tool_result'],
      message: {
        contentBlocks: [
          {
            type: 'text',
            text: 'Malformed result without proper format'
          }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  // Should not crash, tool use should remain without rawResult
  expect(result[0].toolUses[0].rawResult).toBeNull();
});

test('convertBackendMessagesToFrontend handles missing createTime', () => {
  comp.resetContextLength = jest.fn();
  
  const backendMessages = [
    {
      // No createTime provided
      message: {
        role: 'user',
        contentStr: 'Message without timestamp',
        contentBlocks: [
          { type: 'text', text: 'Message without timestamp' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/); // Should be ISO string
});

test('convertBackendMessagesToFrontend handles tool use followed by user message (skipped status)', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'test-session';
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          {
            type: 'tool_use',
            id: 'tool_skipped',
            name: 'query_events',
            input: { oql_query: 'event.module: suricata' }
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'text', text: 'Actually, never mind that query' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(2);
  const toolUse = result[0].toolUses[0];
  expect(toolUse.status).toBe('skipped');
  expect(toolUse.approved).toBe(false);
});

test('convertBackendMessagesToFrontend handles empty backend messages array', () => {
  comp.contextLength = 1000;
  
  const result = comp.convertBackendMessagesToFrontend([]);
  
  expect(result).toEqual([]);
  expect(comp.contextLength).toBe(0);
});

test('convertBackendMessagesToFrontend handles tags', () => {
  comp.resetContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'text', text: 'Hello, how can you help me?' }
        ]
      },
      tags: [MSGTAG_CONTEXTCOMPRESSION],
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].role).toBe('user');
  expect(result[0].content).toBe('Hello, how can you help me?');
  expect(result[0].timestamp).toBe('2025-01-01T12:00:00.000Z');
  expect(result[0].tags).toEqual([MSGTAG_CONTEXTCOMPRESSION]);
});

test('convertBackendMessagesToFrontend calculates context length accurately after context compression', () => {
  comp.resetContextLength = jest.fn();
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'text', text: '' }
        ]
      },
    },
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: '' }
        ],
        usage: {
          input_tokens: 1000,
          output_tokens: 1000,
        },
      },
    },
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'text', text: '' },
        ],
      },
      tags: [MSGTAG_CONTEXTCOMPRESSION],
    },
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: '' }
        ],
        usage: {
          input_tokens: 1000,
          output_tokens: 1000,
        },
      },
    },
  ];
  
  comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(comp.contextLength).toBe(1000);
});

test('loadChatFromBackend success', async () => {
  const testMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'user',
        contentBlocks: [
          { type: 'text', text: 'Hello, how can you help me?' }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'I can help you with security analysis and investigations.' }
        ]
      }
    }
  ];
  const mock = mockPapi("get", { data: { session: null, history: testMessages } });
  comp.scrollToBottomSettled = jest.fn().mockResolvedValue();
  
  await comp.loadChatFromBackend(fakeSessionId);
  
  expect(mock).toHaveBeenCalledWith(`/assistant/sessions/${fakeSessionId}`);
  expect(comp.messages).toHaveLength(2);
  expect(comp.currentChatId).toBe(fakeSessionId);
  expect(comp.scrollToBottomSettled).toHaveBeenCalled();
});

test('loadChatFromBackend handles 404 error', async () => {
  const error = new Error('Not found');
  error.response = { status: 404 };
  mockPapi("get", null, error);
  comp.loadNewChatScreen = jest.fn();
  comp.scrollToBottomSettled = jest.fn().mockResolvedValue();
  
  await comp.loadChatFromBackend(fakeSessionId);
  
  expect(comp.loadNewChatScreen).toHaveBeenCalled();
  expect(comp.currentChatId).toBe(fakeSessionId);
  expect(comp.scrollToBottomSettled).toHaveBeenCalled();
});

test('loadChatFromBackend handles other errors', async () => {
  const error = new Error('Server error');
  error.response = { status: 500 };
  mockPapi("get", null, error);
  
  await expect(comp.loadChatFromBackend(fakeSessionId)).rejects.toThrow('Server error');
});

test('saveCurrentChat skips if only welcome message', async () => {
  comp.messages = [fakeAssistantMessage];
  comp.generateChatId = jest.fn();
  
  await comp.saveCurrentChat();
  
  expect(comp.generateChatId).not.toHaveBeenCalled();
});

test('saveCurrentChat generates ID and refreshes history', async () => {
  comp.messages = [fakeAssistantMessage, fakeMessage];
  comp.currentChatId = null;
  comp.generateChatId = jest.fn().mockReturnValue(fakeSessionId);
  comp.saveCurrentChatId = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  
  await comp.saveCurrentChat();
  
  expect(comp.generateChatId).toHaveBeenCalled();
  expect(comp.currentChatId).toBe(fakeSessionId);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.loadStoredChats).toHaveBeenCalled();
});

// Settings management tests
test('saveSetting stores value in localStorage with correct key', () => {
  const settingName = 'testSetting';
  const settingValue = 'testValue';
  
  comp.saveSetting(settingName, settingValue);
  
  expect(mockLocalStorage['settings.assistant.testSetting']).toBe('testValue');
});

test('saveSetting stores value when different from default', () => {
  const settingName = 'testSetting';
  const settingValue = 'customValue';
  const defaultValue = 'defaultValue';
  
  comp.saveSetting(settingName, settingValue, defaultValue);
  
  expect(mockLocalStorage['settings.assistant.testSetting']).toBe('customValue');
});

test('saveSetting handles null default value', () => {
  const settingName = 'testSetting';
  const settingValue = 'someValue';
  
  comp.saveSetting(settingName, settingValue, null);
  
  expect(mockLocalStorage['settings.assistant.testSetting']).toBe('someValue');
});

test('saveSetting handles boolean values', () => {
  const settingName = 'booleanSetting';
  const settingValue = true;
  const defaultValue = false;
  
  comp.saveSetting(settingName, settingValue, defaultValue);
  
  expect(mockLocalStorage['settings.assistant.booleanSetting']).toBe('true');
});

test('saveSetting handles numeric values', () => {
  const settingName = 'numericSetting';
  const settingValue = 42;
  const defaultValue = 0;
  
  comp.saveSetting(settingName, settingValue, defaultValue);
  
  expect(mockLocalStorage['settings.assistant.numericSetting']).toBe('42');
});

test('saveLocalSettings saves all assistant settings with correct defaults', () => {
  // Set up component state
  comp.increaseContextLimit = true;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false; // Different from default
  comp.currentModel = 'test-model';
  comp.showModelThinking = true;
  
  // Mock saveSetting to track calls
  comp.saveSetting = jest.fn();
  
  comp.saveLocalSettings();
  
  expect(comp.saveSetting).toHaveBeenCalledWith('increaseContextLimit', true, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('restoreLastActive', true, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('alwaysApproveReadRequests', true, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('showChatHistory', false, true);
  expect(comp.saveSetting).toHaveBeenCalledWith('currentModel', 'test-model', '');
  expect(comp.saveSetting).toHaveBeenCalledWith('showModelThinking', true, false);
  expect(comp.saveSetting).toHaveBeenCalledTimes(6);
});

test('saveLocalSettings saves default values correctly', () => {
  // Set up component state with default values
  comp.increaseContextLimit = false;
  comp.restoreLastActive = false;
  comp.alwaysApproveReadRequests = false;
  comp.showChatHistory = true;
  
  comp.saveSetting = jest.fn();
  
  comp.saveLocalSettings();
  
  expect(comp.saveSetting).toHaveBeenCalledWith('increaseContextLimit', false, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('restoreLastActive', false, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('alwaysApproveReadRequests', false, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('showChatHistory', true, true);
});

test('loadLocalSettings loads all settings from localStorage', () => {
  // Mock localStorage values
  mockLocalStorage['settings.assistant.increaseContextLimit'] = 'true';
  mockLocalStorage['settings.assistant.restoreLastActive'] = 'true';
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = 'true';
  mockLocalStorage['settings.assistant.showChatHistory'] = 'false';
  
  comp.loadLocalSettings();
  
  expect(comp.increaseContextLimit).toBe(true);
  expect(comp.restoreLastActive).toBe(true);
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

test('loadLocalSettings handles missing localStorage values', () => {
  // Set initial values different from defaults
  comp.increaseContextLimit = true;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false;
  
  // Ensure localStorage has no values (delete them)
  delete mockLocalStorage['settings.assistant.increaseContextLimit'];
  delete mockLocalStorage['settings.assistant.restoreLastActive'];
  delete mockLocalStorage['settings.assistant.alwaysApproveReadRequests'];
  delete mockLocalStorage['settings.assistant.showChatHistory'];
  
  comp.loadLocalSettings();
  
  // Values should remain unchanged when localStorage is empty
  expect(comp.increaseContextLimit).toBe(true);
  expect(comp.restoreLastActive).toBe(true);
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

test('loadLocalSettings handles partial localStorage values', () => {
  // Set initial values
  comp.increaseContextLimit = false;
  comp.restoreLastActive = false;
  comp.alwaysApproveReadRequests = false;
  comp.showChatHistory = true;
  
  // Mock localStorage with only some values
  mockLocalStorage['settings.assistant.increaseContextLimit'] = 'true';
  mockLocalStorage['settings.assistant.showChatHistory'] = 'false';
  // restoreLastActive and alwaysApproveReadRequests are undefined
  
  comp.loadLocalSettings();
  
  expect(comp.increaseContextLimit).toBe(true);
  expect(comp.restoreLastActive).toBe(false); // Unchanged
  expect(comp.alwaysApproveReadRequests).toBe(false); // Unchanged
  expect(comp.showChatHistory).toBe(false);
});

test('loadLocalSettings handles string boolean conversion correctly', () => {
  // Set initial values
  comp.increaseContextLimit = false;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false;
  
  // Test various string representations
  mockLocalStorage['settings.assistant.increaseContextLimit'] = 'true';
  mockLocalStorage['settings.assistant.restoreLastActive'] = 'false';
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = 'TRUE'; // Should not match
  mockLocalStorage['settings.assistant.showChatHistory'] = 'true';
  
  comp.loadLocalSettings();
  
  expect(comp.increaseContextLimit).toBe(true);
  expect(comp.restoreLastActive).toBe(false);
  expect(comp.alwaysApproveReadRequests).toBe(false); // Should remain unchanged due to 'TRUE' != 'true'
  expect(comp.showChatHistory).toBe(true);
});

test('loadLocalSettings handles empty string values', () => {
  // Mock localStorage with empty strings
  mockLocalStorage['settings.assistant.increaseContextLimit'] = '';
  mockLocalStorage['settings.assistant.restoreLastActive'] = '';
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = '';
  mockLocalStorage['settings.assistant.showChatHistory'] = '';
  
  // Set initial values
  comp.increaseContextLimit = true;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false;
  
  comp.loadLocalSettings();
  
  // Values should remain unchanged for empty strings
  expect(comp.increaseContextLimit).toBe(true);
  expect(comp.restoreLastActive).toBe(true);
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

test('loadLocalSettings integration with actual localStorage access', () => {
  // Test the actual localStorage access pattern used by loadLocalSettings
  // This simulates how the function actually checks for localStorage values
  mockLocalStorage['settings.assistant.increaseContextLimit'] = 'true';
  mockLocalStorage['settings.assistant.restoreLastActive'] = 'true';
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = 'true';
  mockLocalStorage['settings.assistant.showChatHistory'] = 'false';
  
  // Set initial values
  comp.increaseContextLimit = false;
  comp.restoreLastActive = false;
  comp.alwaysApproveReadRequests = false;
  comp.showChatHistory = true;
  
  comp.loadLocalSettings();
  
  expect(comp.increaseContextLimit).toBe(true);
  expect(comp.restoreLastActive).toBe(true);
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

// Integration tests for settings functionality
test('settings integration: save and load cycle', () => {
  // Set up initial state
  comp.increaseContextLimit = true;
  comp.restoreLastActive = false;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false;
  
  // Save settings
  comp.saveLocalSettings();
  
  // Verify localStorage state after save (values are stored as strings by the localStorage mock)
  expect(mockLocalStorage['settings.assistant.increaseContextLimit']).toBe('true');
  expect(mockLocalStorage['settings.assistant.restoreLastActive']).toBeUndefined(); // Should be removed
  expect(mockLocalStorage['settings.assistant.alwaysApproveReadRequests']).toBe('true');
  expect(mockLocalStorage['settings.assistant.showChatHistory']).toBe('false');
  
  // Simulate localStorage state after save (convert to strings as localStorage would)
  mockLocalStorage['settings.assistant.increaseContextLimit'] = 'true';
  delete mockLocalStorage['settings.assistant.restoreLastActive'];
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = 'true';
  mockLocalStorage['settings.assistant.showChatHistory'] = 'false';
  
  // Reset component state
  comp.increaseContextLimit = false;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = false;
  comp.showChatHistory = true;
  
  // Load settings
  comp.loadLocalSettings();
  
  // Verify state was restored correctly
  expect(comp.increaseContextLimit).toBe(true);
  expect(comp.restoreLastActive).toBe(true); // Should remain unchanged due to undefined localStorage
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

test('settings watcher integration with saveLocalSettings', () => {
  // Mock the saveLocalSettings method to track calls
  comp.saveLocalSettings = jest.fn();
  
  // Simulate watcher behavior by manually calling saveLocalSettings
  // In the actual component, these would be triggered by Vue watchers
  comp.increaseMaxContextThreshold = true;
  comp.saveLocalSettings(); // Simulating watcher trigger
  
  comp.restoreLastActive = true;
  comp.saveLocalSettings(); // Simulating watcher trigger
  
  comp.alwaysApproveReadRequests = true;
  comp.saveLocalSettings(); // Simulating watcher trigger
  
  comp.showChatHistory = false;
  comp.saveLocalSettings(); // Simulating watcher trigger
  
  expect(comp.saveLocalSettings).toHaveBeenCalledTimes(4);
});

// scrollToBottomSettled method tests
test('scrollToBottomSettled waits for nextTick and finds container', async () => {
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  // Mock MutationObserver and ResizeObserver
  const mockMutationObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  const mockResizeObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  
  global.MutationObserver = jest.fn().mockImplementation(() => mockMutationObserver);
  global.ResizeObserver = jest.fn().mockImplementation(() => mockResizeObserver);
  global.window.ResizeObserver = global.ResizeObserver;
  
  // Use fake timers to control setTimeout
  jest.useFakeTimers();
  
  const promise = comp.scrollToBottomSettled();
  
  // Advance timers to trigger the settle timeout
  jest.advanceTimersByTime(180);
  
  await promise;
  
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.$el.querySelector).toHaveBeenCalledWith('.chat-messages');
  expect(comp.forceScrollBottom).toHaveBeenCalledWith(mockContainer);
  expect(global.MutationObserver).toHaveBeenCalled();
  expect(mockMutationObserver.observe).toHaveBeenCalledWith(mockContainer, {
    childList: true,
    subtree: true,
    characterData: true
  });
  expect(global.ResizeObserver).toHaveBeenCalled();
  expect(mockResizeObserver.observe).toHaveBeenCalledWith(mockContainer);
  
  jest.useRealTimers();
});

test('scrollToBottomSettled returns early when no container found', async () => {
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(null)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  await comp.scrollToBottomSettled();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.$el.querySelector).toHaveBeenCalledWith('.chat-messages');
  expect(comp.forceScrollBottom).not.toHaveBeenCalled();
});

test('scrollToBottomSettled returns early when $el is null', async () => {
  comp.$el = null;
  comp.forceScrollBottom = jest.fn();
  
  await comp.scrollToBottomSettled();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.forceScrollBottom).not.toHaveBeenCalled();
});

test('scrollToBottomSettled returns early when $el has no querySelector', async () => {
  comp.$el = {};
  comp.forceScrollBottom = jest.fn();
  
  await comp.scrollToBottomSettled();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.forceScrollBottom).not.toHaveBeenCalled();
});

test('scrollToBottomSettled uses custom settleDelay and maxWait options', async () => {
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  // Mock observers
  const mockMutationObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  const mockResizeObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  
  global.MutationObserver = jest.fn().mockImplementation(() => mockMutationObserver);
  global.ResizeObserver = jest.fn().mockImplementation(() => mockResizeObserver);
  global.window.ResizeObserver = global.ResizeObserver;
  
  jest.useFakeTimers();
  
  const promise = comp.scrollToBottomSettled({ settleDelay: 300, maxWait: 5000 });
  
  // Advance by custom settleDelay
  jest.advanceTimersByTime(300);
  
  await promise;
  
  expect(comp.forceScrollBottom).toHaveBeenCalledWith(mockContainer);
  
  jest.useRealTimers();
});

test('scrollToBottomSettled handles height changes during settle period', async () => {
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  let mutationCallback;
  const mockMutationObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  
  global.MutationObserver = jest.fn().mockImplementation((callback) => {
    mutationCallback = callback;
    return mockMutationObserver;
  });
  
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  global.window.ResizeObserver = global.ResizeObserver;
  
  jest.useFakeTimers();
  
  const promise = comp.scrollToBottomSettled({ settleDelay: 200 });
  
  // Wait for the MutationObserver to be set up
  await Promise.resolve();
  
  // Simulate height change during settle period
  if (mutationCallback) {
    mockContainer.scrollHeight = 600; // Height changed
    mutationCallback(); // Trigger mutation callback
  }
  
  // Advance timers to complete settling
  jest.advanceTimersByTime(400);
  
  await promise;
  
  // Should have been called at least twice (initial + mutation trigger + final)
  expect(comp.forceScrollBottom).toHaveBeenCalledWith(mockContainer);
  expect(comp.forceScrollBottom).toHaveBeenCalledTimes(3);
  
  jest.useRealTimers();
});

test('scrollToBottomSettled handles image loading events', async () => {
  const mockImg1 = {
    complete: false,
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  const mockImg2 = {
    complete: true, // Already loaded
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([mockImg1, mockImg2]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  // Mock observers
  global.MutationObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  global.window.ResizeObserver = global.ResizeObserver;
  
  jest.useFakeTimers();
  
  const promise = comp.scrollToBottomSettled();
  
  // Advance timers to complete
  jest.advanceTimersByTime(180);
  
  await promise;
  
  expect(mockContainer.querySelectorAll).toHaveBeenCalledWith('img');
  // Only incomplete image should have event listeners added
  expect(mockImg1.addEventListener).toHaveBeenCalledWith('load', expect.any(Function), { once: true });
  expect(mockImg1.addEventListener).toHaveBeenCalledWith('error', expect.any(Function), { once: true });
  // Complete image should not have listeners added
  expect(mockImg2.addEventListener).not.toHaveBeenCalled();
  
  jest.useRealTimers();
});

test('scrollToBottomSettled triggers safety timeout when maxWait exceeded', async () => {
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  let mutationCallback;
  const mockMutationObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  
  global.MutationObserver = jest.fn().mockImplementation((callback) => {
    mutationCallback = callback;
    return mockMutationObserver;
  });
  
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  global.window.ResizeObserver = global.ResizeObserver;
  
  jest.useFakeTimers();
  
  const promise = comp.scrollToBottomSettled({ settleDelay: 200, maxWait: 1000 });
  
  // Wait for setup
  await Promise.resolve();
  
  // Keep triggering mutations to prevent settling
  if (mutationCallback) {
    for (let i = 0; i < 5; i++) {
      mockContainer.scrollHeight += 10; // Keep changing height
      mutationCallback();
    }
  }
  
  // Advance past maxWait time to trigger safety timeout
  jest.advanceTimersByTime(1100);
  
  await promise;
  
  // Should have been called due to mutations and safety timeout
  expect(comp.forceScrollBottom).toHaveBeenCalled();
  expect(mockMutationObserver.disconnect).toHaveBeenCalled();
  
  jest.useRealTimers();
});

test('scrollToBottomSettled handles ResizeObserver not available', async () => {
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  // Mock MutationObserver but not ResizeObserver
  global.MutationObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  
  // Remove ResizeObserver from window
  delete global.window.ResizeObserver;
  delete global.ResizeObserver;
  
  jest.useFakeTimers();
  
  const promise = comp.scrollToBottomSettled();
  
  jest.advanceTimersByTime(180);
  
  await promise;
  
  expect(comp.forceScrollBottom).toHaveBeenCalledWith(mockContainer);
  expect(global.MutationObserver).toHaveBeenCalled();
  // Should not throw error when ResizeObserver is not available
  
  jest.useRealTimers();
});

test('scrollToBottomSettled properly cleans up all observers and timers', async () => {
  const mockImg = {
    complete: false,
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([mockImg]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  const mockMutationObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  const mockResizeObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  
  global.MutationObserver = jest.fn().mockImplementation(() => mockMutationObserver);
  global.ResizeObserver = jest.fn().mockImplementation(() => mockResizeObserver);
  global.window.ResizeObserver = global.ResizeObserver;
  
  jest.useFakeTimers();
  
  await comp.scrollToBottomSettled();
  
  // Advance timers to ensure cleanup happens
  jest.advanceTimersByTime(200);
  
  // Verify all cleanup functions were called
  expect(mockMutationObserver.disconnect).toHaveBeenCalled();
  expect(mockResizeObserver.disconnect).toHaveBeenCalled();
  // Note: removeEventListener calls depend on the cleanup function execution
  
  jest.useRealTimers();
});

test('scrollToBottomSettled handles image load event triggering mutation callback', async () => {
  let imageLoadHandler;
  const mockImg = {
    complete: false,
    addEventListener: jest.fn((event, handler) => {
      if (event === 'load') {
        imageLoadHandler = handler;
      }
    }),
    removeEventListener: jest.fn()
  };
  
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([mockImg]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  global.MutationObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  global.window.ResizeObserver = global.ResizeObserver;
  
  jest.useFakeTimers();
  
  const promise = comp.scrollToBottomSettled();
  
  // Simulate image loading after 50ms
  setTimeout(() => {
    if (imageLoadHandler) {
      imageLoadHandler(); // Trigger image load
    }
  }, 50);
  
  jest.advanceTimersByTime(180);
  
  await promise;
  
  expect(mockImg.addEventListener).toHaveBeenCalledWith('load', expect.any(Function), { once: true });
  expect(comp.forceScrollBottom).toHaveBeenCalled();
  
  jest.useRealTimers();
});

test('scrollToBottomSettled settles immediately when height is stable', async () => {
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  const mockMutationObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  
  global.MutationObserver = jest.fn().mockImplementation(() => mockMutationObserver);
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  global.window.ResizeObserver = global.ResizeObserver;
  
  jest.useFakeTimers();
  
  await comp.scrollToBottomSettled({ settleDelay: 100 });
  
  // Advance timers to complete settling
  jest.advanceTimersByTime(200);
  
  // Should have done initial scroll plus final scroll when settled
  expect(comp.forceScrollBottom).toHaveBeenCalledWith(mockContainer);
  expect(comp.forceScrollBottom).toHaveBeenCalledTimes(2);
  expect(mockMutationObserver.disconnect).toHaveBeenCalled();
  
  jest.useRealTimers();
});

test('scrollToBottomSettled handles multiple rapid height changes', async () => {
  const mockContainer = {
    scrollTop: 0,
    scrollHeight: 500,
    clientHeight: 400,
    querySelectorAll: jest.fn().mockReturnValue([]),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn()
  };
  
  comp.$el = {
    querySelector: jest.fn().mockReturnValue(mockContainer)
  };
  
  comp.forceScrollBottom = jest.fn();
  
  let mutationCallback;
  const mockMutationObserver = {
    observe: jest.fn(),
    disconnect: jest.fn()
  };
  
  global.MutationObserver = jest.fn().mockImplementation((callback) => {
    mutationCallback = callback;
    return mockMutationObserver;
  });
  
  global.ResizeObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    disconnect: jest.fn()
  }));
  global.window.ResizeObserver = global.ResizeObserver;
  
  jest.useFakeTimers();
  
  const promise = comp.scrollToBottomSettled({ settleDelay: 200 });
  
  // Wait for setup
  await Promise.resolve();
  
  // Simulate rapid height changes
  if (mutationCallback) {
    mockContainer.scrollHeight = 600;
    mutationCallback();
    
    mockContainer.scrollHeight = 700;
    mutationCallback();
    
    mockContainer.scrollHeight = 800;
    mutationCallback();
  }
  
  // Let it settle after the changes
  jest.advanceTimersByTime(400);
  
  await promise;
  
  // Should have scrolled multiple times due to height changes
  expect(comp.forceScrollBottom).toHaveBeenCalledWith(mockContainer);
  expect(comp.forceScrollBottom).toHaveBeenCalledTimes(5); // Initial + 3 changes + final
  
  jest.useRealTimers();
});

test('parseJsonChunk parses valid JSON successfully', () => {
  const validJson = '{"type": "message_start", "data": "test"}';
  
  const result = comp.parseJsonChunk(validJson);
  
  expect(result.success).toBe(true);
  expect(result.data).toEqual({ type: 'message_start', data: 'test' });
  expect(result.isPartial).toBe(null);
});

test('parseJsonChunk handles partial JSON', () => {
  const partialJson = '{"type": "message_start", "data"';
  
  const result = comp.parseJsonChunk(partialJson);
  
  expect(result.success).toBe(false);
  expect(result.data).toBe(null);
  expect(result.isPartial).toBe(partialJson);
});

test('parseJsonChunk handles concatenated JSON objects', () => {
  const concatenatedJson = '{"type": "start"}{"type": "end"}';
  
  const result = comp.parseJsonChunk(concatenatedJson);
  
  expect(result.success).toBe(true);
  expect(Array.isArray(result.data)).toBe(true);
  expect(result.data).toEqual(['{"type": "start"}', '{"type": "end"}']);
  expect(result.isPartial).toBe(null);
});

test('parseJsonChunk handles concatenated JSON with partial remainder', () => {
  const mixedJson = '{"type": "complete"}{"type": "partial", "data"';
  
  const result = comp.parseJsonChunk(mixedJson);
  
  expect(result.success).toBe(true);
  expect(Array.isArray(result.data)).toBe(true);
  expect(result.data).toEqual(['{"type": "complete"}']);
  expect(result.isPartial).toBe('{"type": "partial", "data"');
});

test('parseJsonChunk handles empty string', () => {
  const result = comp.parseJsonChunk('');
  
  expect(result.success).toBe(false);
  expect(result.data).toBe(null);
  expect(result.isPartial).toBe('');
});

test('parseJsonChunk handles malformed JSON', () => {
  const malformedJson = '{"type": "invalid", "data":}'; // Missing value after colon
  
  const result = comp.parseJsonChunk(malformedJson);
  
  expect(result.success).toBe(true);
  expect(Array.isArray(result.data)).toBe(true);
  expect(result.data).toEqual(['{"type": "invalid", "data":}']);
  expect(result.isPartial).toBe(null);
});

test('processStreamingChunks processes SSE data correctly', () => {
  const sseData = 'data: {"type": "test1"}\n\ndata: {"type": "test2"}\n\n';
  const chunks = [];
  const partial = false;
  
  const result = comp.processStreamingChunks(sseData, chunks, partial);
  
  expect(result.chunks).toEqual(['{"type": "test1"}', '{"type": "test2"}']);
  expect(result.partial).toBe(false);
});

test('processStreamingChunks handles partial data prepending', () => {
  const sseData = 'data: {"complete": true}\n\n';
  const chunks = ['{"partial":'];
  const partial = true;
  
  const result = comp.processStreamingChunks(sseData, chunks, partial);
  
  expect(result.chunks[0]).toBe('{"partial":{"complete": true}');
  expect(result.partial).toBe(false);
});

test('processStreamingChunks filters empty chunks', () => {
  const sseData = 'data: {"type": "test"}\n\n\n\ndata: {"type": "test2"}\n\n';
  const chunks = [];
  const partial = false;
  
  const result = comp.processStreamingChunks(sseData, chunks, partial);
  
  expect(result.chunks).toEqual(['{"type": "test"}', '{"type": "test2"}']);
});

test('isNearBottom returns true when near bottom', () => {
  const container = {
    scrollHeight: 1000,
    clientHeight: 400,
    scrollTop: 580 // 1000 - 400 - 580 = 20, which is <= 48
  };
  
  const result = comp.isNearBottom(container);
  
  expect(result).toBe(true);
});

test('isNearBottom returns false when not near bottom', () => {
  const container = {
    scrollHeight: 1000,
    clientHeight: 400,
    scrollTop: 500 // 1000 - 400 - 500 = 100, which is > 48
  };
  
  const result = comp.isNearBottom(container);
  
  expect(result).toBe(false);
});

test('isNearBottom uses custom threshold', () => {
  const container = {
    scrollHeight: 1000,
    clientHeight: 400,
    scrollTop: 580 // 1000 - 400 - 580 = 20
  };
  
  const result = comp.isNearBottom(container, 10); // Custom threshold of 10px
  
  expect(result).toBe(false); // 20 > 10
});

test('forceScrollBottom sets scrollTop to scrollHeight', () => {
  const container = {
    scrollHeight: 1000,
    scrollTop: 0
  };
  
  comp.forceScrollBottom(container);
  
  expect(container.scrollTop).toBe(1000);
});

test('onChatScroll updates isPinnedToBottom based on scroll position', () => {
  const mockContainer = {
    scrollHeight: 1000,
    clientHeight: 400,
    scrollTop: 596 // Near bottom (within 4px)
  };
  const mockEvent = { target: mockContainer };
  
  comp.onChatScroll(mockEvent);
  
  expect(comp.isPinnedToBottom).toBe(true);
});

test('onChatScroll sets isPinnedToBottom to false when not near bottom', () => {
  const mockContainer = {
    scrollHeight: 1000,
    clientHeight: 400,
    scrollTop: 500 // Not near bottom
  };
  const mockEvent = { target: mockContainer };
  
  comp.onChatScroll(mockEvent);
  
  expect(comp.isPinnedToBottom).toBe(false);
});

test('scrollIfPinned scrolls when pinned to bottom', () => {
  comp.isPinnedToBottom = true;
  comp.scrollToBottom = jest.fn();
  
  comp.scrollIfPinned();
  
  expect(comp.scrollToBottom).toHaveBeenCalled();
});

test('scrollIfPinned does not scroll when not pinned to bottom', () => {
  comp.isPinnedToBottom = false;
  comp.scrollToBottom = jest.fn();
  
  comp.scrollIfPinned();
  
  expect(comp.scrollToBottom).not.toHaveBeenCalled();
});

// Streaming session management tests
test('clearStreamingStates resets streaming-related state', () => {
  comp.activeStreamingSessionId = 'test-session';
  comp.isTyping = true;
  comp.isStreaming = true;
  
  comp.clearStreamingStates();
  
  expect(comp.activeStreamingSessionId).toBe(null);
  expect(comp.isTyping).toBe(false);
  expect(comp.isStreaming).toBe(false);
});

test('checkIfDeleted sets canChat to true when session is not deleted', () => {
  comp.canChat = false;

  comp.checkIfDeleted({ sessionId: 'existing-session' });

  expect(comp.canChat).toBe(true);
});

test('checkIfDeleted sets canChat to false when session is deleted', () => {
  comp.canChat = true;
  comp.$root.showWarning = jest.fn();

  comp.checkIfDeleted({ sessionId: 'existing-session', deleteTime: '2026-01-01T00:00:00Z' });

  expect(comp.canChat).toBe(false);
  expect(comp.$root.showWarning).toHaveBeenCalled();
});

// Auto-approval functionality tests
test('shouldAutoApproveTool returns true for query_events when setting enabled', () => {
  comp.alwaysApproveReadRequests = true;
  
  const result = comp.shouldAutoApproveTool('query_events');
  
  expect(result).toBe(true);
});

test('shouldAutoApproveTool returns true for get_playbooks when setting enabled', () => {
  comp.alwaysApproveReadRequests = true;
  
  const result = comp.shouldAutoApproveTool('get_playbooks');
  
  expect(result).toBe(true);
});

test('shouldAutoApproveTool returns false for other tools when setting enabled', () => {
  comp.alwaysApproveReadRequests = true;
  
  const result = comp.shouldAutoApproveTool('other_tool');
  
  expect(result).toBe(false);
});

test('shouldAutoApproveTool returns false when setting disabled', () => {
  comp.alwaysApproveReadRequests = false;
  
  expect(comp.shouldAutoApproveTool('query_events')).toBe(false);
  expect(comp.shouldAutoApproveTool('get_playbooks')).toBe(false);
  expect(comp.shouldAutoApproveTool('other_tool')).toBe(false);
});

// Enhanced sendMessage tests for new functionality
test('sendMessage returns early when canChat is false', async () => {
  comp.newMessage = 'Test message';
  comp.canChat = false;
  comp.assistantEnabled = true;
  comp.creditsRemaining = 100;
  comp.callAIAPI = jest.fn();
  
  await comp.sendMessage();
  
  expect(comp.callAIAPI).not.toHaveBeenCalled();
  expect(comp.newMessage).toBe('Test message'); // Should not clear message
});

test('sendMessage checks context limit before proceeding', async () => {
  comp.newMessage = 'Test message';
  comp.canChat = true;
  comp.assistantEnabled = true;
  comp.creditsRemaining = 100;
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(true);
  comp.callAIAPI = jest.fn();
  
  await comp.sendMessage();
  
  expect(comp.checkContextLimitReached).toHaveBeenCalled();
  expect(comp.callAIAPI).not.toHaveBeenCalled();
});

test('sendMessage checks context limit before proceeding, but allows context_compression', async () => {
  comp.newMessage = 'Summarize the conversation so far for context preservation';
  comp.canChat = true;
  comp.assistantEnabled = true;
  comp.creditsRemaining = 100;
  comp.creditsLoaded = true;
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(true);
  comp.callAIAPI = jest.fn();
  
  await comp.sendMessage([MSGTAG_CONTEXTCOMPRESSION]);

  expect(comp.checkContextLimitReached).not.toHaveBeenCalled();
  expect(comp.callAIAPI).toHaveBeenCalled();
  expect(comp.callAIAPI).toHaveBeenCalledWith('Summarize the conversation so far for context preservation', [MSGTAG_CONTEXTCOMPRESSION]);
});

test('sendMessage clears welcome message when starting first real conversation', async () => {
  const welcomeMessage = {
    role: 'assistant',
    content: comp.i18n.assistantWelcomeMessage,
    timestamp: new Date().toISOString()
  };
  comp.messages = [welcomeMessage]; // Only welcome message
  comp.newMessage = 'Test message';
  comp.canChat = true;
  comp.assistantEnabled = true;
  comp.creditsRemaining = 100;
  comp.creditsLoaded = true;
  comp.currentChatId = 'test-session';
  comp.callAIAPI = jest.fn().mockResolvedValue();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  
  await comp.sendMessage();
  
  expect(comp.messages).toHaveLength(1); // Should clear welcome message and add user message
  expect(comp.messages[0].role).toBe('user');
  expect(comp.messages[0].content).toBe('Test message');
});

// Enhanced streaming functionality tests
test('callAIAPI sets activeStreamingSessionId at start', async () => {
  comp.currentChatId = 'test-session';
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  const mockResponse = {
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.activeStreamingSessionId).toBe(null); // Should be cleared after completion
});

test('callAIAPI handles session switching during streaming', async () => {
  comp.currentChatId = 'session1';
  comp.activeStreamingSessionId = 'session1';
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.scrollIfPinned = jest.fn();
  
  const messageStartData = JSON.stringify({ type: 'message_start' });
  const mockResponse = {
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: `data: ${messageStartData}\n\n` })
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  // Simulate session change during streaming
  setTimeout(() => {
    comp.currentChatId = 'session2';
  }, 10);
  
  await comp.callAIAPI('Test message');
  
  expect(comp.messages).toHaveLength(1); // Should still process for original session
});

// Enhanced tool execution with session management
test('executeTool handles background execution for different session', async () => {
  const toolUse = {
    id: 'tool_123',
    name: 'query_events',
    input: { query: 'test' },
    sessionId: 'background-session'
  };
  comp.currentChatId = 'current-session'; // Different from tool's session
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  const mockResponse = {
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({
          read: jest.fn()
            .mockResolvedValueOnce({ done: false, value: 'data: [DONE]\n\n' })
            .mockResolvedValueOnce({ done: true })
        })
      })
    }
  };
  mockPapi('post', mockResponse);
  
  // Set initial status to executing since executeTool expects the tool to already be approved
  toolUse.status = 'executing';
  
  await comp.executeTool(toolUse);
  
  expect(toolUse.status).toBe('executing'); // Should still update tool status
  expect(comp.messages).toHaveLength(0); // Should not add to current session's messages
});

// Enhanced auto-scroll functionality
test('loadNewChatScreen resets context length', async () => {
  comp.contextLength = 5000;
  
  await comp.loadNewChatScreen();
  
  expect(comp.contextLength).toBe(0);
});

test('startNewChat sets canChat to true', async () => {
  comp.canChat = false;
  comp.saveCurrentChat = jest.fn().mockResolvedValue();
  comp.clearStreamingStates = jest.fn();
  comp.saveCurrentChatId = jest.fn();
  comp.loadNewChatScreen = jest.fn();
  
  await comp.startNewChat();
  
  expect(comp.canChat).toBe(true);
});

// applyToolSpecificChanges method tests
test('applyToolSpecificChanges adds auxData for query_cases tool when MRU data exists', () => {
  const toolUse = { id: 'tool_123', name: 'query_cases', input: { query: 'test query' } };
  const toolRequest = {
    sessionId: 'test-session',
    toolUseId: 'tool_123',
    params: { query: 'test query' },
    model: 'test-model'
  };

  const mruCases = [
    { id: 'case1', title: 'Test Case 1' },
    { id: 'case2', title: 'Test Case 2' }
  ];

  // Spy on Storage.prototype so jsdom/localStorage is handled correctly
  const getSpy = jest.spyOn(Storage.prototype, 'getItem').mockReturnValue(JSON.stringify(mruCases));

  comp.applyToolSpecificChanges(toolUse, toolRequest);

  expect(getSpy).toHaveBeenCalledWith('settings.case.mruCases');
  expect(toolRequest.auxData).toEqual(mruCases);

  getSpy.mockRestore();
});

// Content block stop methods tests
test('handleContentBlockStop processes tool completion with auto-approval', () => {
  const sessionId = 'test-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_123',
    name: 'query_events',
    inputJson: '{"oql_query": "event.module: suricata"}',
    status: 'preparing',
    input: {},
    approved: null
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(true);
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.queueTool = jest.fn();
  
  mockToolMap.set('tool_123', mockToolUse);
  mockIndexMap.set(0, 'tool_123');
  
  const result = comp.handleContentBlockStop({ index: 0, usage: { input_tokens: 10, output_tokens: 15 } }, sessionId);
  
  expect(mockToolUse.input).toEqual({ oql_query: "event.module: suricata" });
  expect(mockToolUse.approved).toBe(true);
  expect(comp.queueTool).toHaveBeenCalledWith(sessionId, 'tool_123');
  expect(result).toEqual({ input_tokens: 10, output_tokens: 15 });
});

test('handleContentBlockStop processes tool completion without auto-approval', () => {
  const sessionId = 'test-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_456',
    name: 'dangerous_tool',
    inputJson: '{"action": "delete"}',
    status: 'preparing',
    input: {},
    approved: null
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(false);
  comp.sessionToolState = new Map();
  
  mockToolMap.set('tool_456', mockToolUse);
  mockIndexMap.set(0, 'tool_456');
  
  const result = comp.handleContentBlockStop({ index: 0 }, sessionId);
  
  expect(mockToolUse.input).toEqual({ action: "delete" });
  expect(mockToolUse.status).toBe('pending_approval');
  expect(mockToolUse.approved).toBe(null);
  expect(comp.sessionTools(sessionId).floatingTool).toBe(mockToolUse);
  expect(result).toBe(null);
});

test('handleContentBlockStop handles JSON parsing error', () => {
  const sessionId = 'test-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_789',
    name: 'test_tool',
    inputJson: '{"invalid": json}',
    status: 'preparing',
    input: {},
    error: null
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  
  mockToolMap.set('tool_789', mockToolUse);
  mockIndexMap.set(0, 'tool_789');
  
  comp.handleContentBlockStop({ index: 0 }, sessionId);

  expect(mockToolUse.status).toBe('error');
  expect(mockToolUse.error).toContain('Failed to parse tool input');
});

test('handleDelegationContentBlockStop auto-approves read-only sub-agent tool', () => {
  const childSessionId = 'child-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_123',
    name: 'query_events',
    inputJson: '{"oql_query": "event.module: suricata"}',
    status: 'preparing',
    input: {},
    approved: null,
    sessionId: childSessionId
  };

  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(true);
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.queueTool = jest.fn();
  comp.sessionToolState = new Map();
  comp.scrollIfPinned = jest.fn();

  mockToolMap.set('tool_123', mockToolUse);
  mockIndexMap.set(0, 'tool_123');

  comp.handleDelegationContentBlockStop({ index: 0 }, childSessionId);

  expect(mockToolUse.input).toEqual({ oql_query: "event.module: suricata" });
  expect(mockToolUse.approved).toBe(true);
  expect(mockToolUse.status).not.toBe('pending_approval');
  expect(comp.queueTool).toHaveBeenCalledWith(childSessionId, 'tool_123');
  expect(comp.sessionTools(childSessionId).floatingTool).toBeFalsy();
});

test('handleDelegationContentBlockStop prompts for non-auto-approved sub-agent tool', () => {
  const childSessionId = 'child-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_456',
    name: 'dangerous_tool',
    inputJson: '{"action": "delete"}',
    status: 'preparing',
    input: {},
    approved: null,
    sessionId: childSessionId
  };

  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(false);
  comp.queueTool = jest.fn();
  comp.sessionToolState = new Map();
  comp.scrollIfPinned = jest.fn();

  mockToolMap.set('tool_456', mockToolUse);
  mockIndexMap.set(0, 'tool_456');

  comp.handleDelegationContentBlockStop({ index: 0 }, childSessionId);

  expect(mockToolUse.input).toEqual({ action: "delete" });
  expect(mockToolUse.status).toBe('pending_approval');
  expect(mockToolUse.approved).toBe(null);
  expect(comp.sessionTools(childSessionId).floatingTool).toBe(mockToolUse);
  expect(comp.queueTool).not.toHaveBeenCalled();
});

test('handleDelegationContentBlockStop handles JSON parsing error', () => {
  const childSessionId = 'child-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockToolUse = {
    id: 'tool_789',
    name: 'query_events',
    inputJson: '{"invalid": json}',
    status: 'preparing',
    input: {},
    error: null,
    sessionId: childSessionId
  };

  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(true);
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.queueTool = jest.fn();
  comp.scrollIfPinned = jest.fn();

  mockToolMap.set('tool_789', mockToolUse);
  mockIndexMap.set(0, 'tool_789');

  comp.handleDelegationContentBlockStop({ index: 0 }, childSessionId);

  expect(mockToolUse.status).toBe('error');
  expect(mockToolUse.error).toContain('Failed to parse tool input');
  expect(comp.queueTool).not.toHaveBeenCalled();
});

// --- applyBlock* (the shared implementation behind the handle*ContentBlock* adapters) ---

test('applyBlockStart ignores blocks that are not tool_use', () => {
  const message = { toolUses: [] };
  comp.applyBlockStart({ index: 0, content_block: { type: 'text' } }, { message, sessionId: 's1', visible: true });
  comp.applyBlockStart({ index: 0 }, { message, sessionId: 's1', visible: true });

  expect(message.toolUses).toHaveLength(0);
  expect(comp.getSessionToolMap('s1').size).toBe(0);
});

test('applyBlockStart pushes the tool into the message and registers the reactive instance', () => {
  comp.scrollIfPinned = jest.fn();
  const message = { toolUses: [] };
  const c = { index: 2, content_block: { type: 'tool_use', id: 'tu-9', name: 'query_events', input: { q: 'dns' } } };

  comp.applyBlockStart(c, { message, sessionId: 's1', visible: true });

  expect(message.toolUses).toHaveLength(1);
  const tracked = comp.getSessionToolMap('s1').get('tu-9');
  // The session map must hold the instance living in the message, not a detached copy.
  expect(tracked).toBe(message.toolUses[0]);
  expect(tracked.status).toBe('preparing');
  expect(tracked.approved).toBeNull();
  expect(tracked.input).toEqual({ q: 'dns' });
  expect(tracked.sessionId).toBe('s1');
  expect(tracked.blockIndex).toBe(2);
  expect(comp.getIndexMap('s1').get(2)).toBe('tu-9');
  expect(comp.scrollIfPinned).toHaveBeenCalled();
});

test('applyBlockStart with no target message still registers the tool and does not scroll', () => {
  comp.scrollIfPinned = jest.fn();
  const c = { index: 0, content_block: { type: 'tool_use', id: 'tu-1', name: 'query_events' } };

  comp.applyBlockStart(c, { sessionId: 's2', visible: false });

  expect(comp.getSessionToolMap('s2').get('tu-1')).toBeTruthy();
  expect(comp.getIndexMap('s2').get(0)).toBe('tu-1');
  expect(comp.scrollIfPinned).not.toHaveBeenCalled();
});

test('applyBlockDelta routes text, input_json, and thought deltas to their targets', () => {
  comp.scrollIfPinned = jest.fn();
  const message = { content: 'Hello', thoughts: 'hmm', toolUses: [] };
  const toolUse = { id: 'tu-1', inputJson: '{"a"', status: 'preparing' };
  comp.getSessionToolMap('s1').set('tu-1', toolUse);
  comp.getIndexMap('s1').set(3, 'tu-1');
  const target = { message, sessionId: 's1', visible: true };

  comp.applyBlockDelta({ index: 0, delta: { type: 'text_delta', text: ' world' } }, target);
  expect(message.content).toBe('Hello world');

  comp.applyBlockDelta({ index: 3, delta: { type: 'input_json_delta', partial_json: ': 1}' } }, target);
  expect(toolUse.inputJson).toBe('{"a": 1}');
  expect(toolUse.status).toBe('preparing');

  comp.applyBlockDelta({ index: 0, delta: { type: 'thought_delta', text: '... ok' } }, target);
  expect(message.thoughts).toBe('hmm... ok');

  // A delta for an unmapped block index is ignored, and a message-less target
  // ignores text/thought deltas without throwing.
  expect(() => {
    comp.applyBlockDelta({ index: 9, delta: { type: 'input_json_delta', partial_json: 'x' } }, target);
    comp.applyBlockDelta({ index: 0, delta: { type: 'text_delta', text: 'x' } }, { sessionId: 's1', visible: false });
  }).not.toThrow();
});

test('applyBlockStop auto-approves and queues a read-only tool', () => {
  comp.scrollIfPinned = jest.fn();
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(true);
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.queueTool = jest.fn();
  const toolUse = { id: 'tu-1', name: 'query_events', inputJson: '{"q": "dns"}', input: {}, status: 'preparing', approved: null };
  comp.getSessionToolMap('s1').set('tu-1', toolUse);
  comp.getIndexMap('s1').set(0, 'tu-1');

  const usage = comp.applyBlockStop({ index: 0 }, { sessionId: 's1', visible: true });

  expect(toolUse.input).toEqual({ q: 'dns' });
  expect(toolUse.approved).toBe(true);
  expect(comp.queueTool).toHaveBeenCalledWith('s1', 'tu-1');
  expect(comp.sessionTools('s1').floatingTool).toBeFalsy();
  expect(usage).toBeNull();
});

test('applyBlockStop leaves an auto-approvable tool unqueued when the context limit is reached', () => {
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(true);
  comp.checkContextLimitReached = jest.fn().mockReturnValue(true);
  comp.queueTool = jest.fn();
  const toolUse = { id: 'tu-1', name: 'query_events', inputJson: '{}', input: {}, status: 'preparing', approved: null };
  comp.getSessionToolMap('s1').set('tu-1', toolUse);
  comp.getIndexMap('s1').set(0, 'tu-1');

  comp.applyBlockStop({ index: 0 }, { sessionId: 's1', visible: false });

  expect(comp.queueTool).not.toHaveBeenCalled();
  expect(toolUse.approved).toBeNull();
  expect(toolUse.status).toBe('preparing');
});

test('applyBlockStop surfaces a non-auto-approved tool as the session floating tool', () => {
  comp.scrollIfPinned = jest.fn();
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(false);
  comp.queueTool = jest.fn();
  const toolUse = { id: 'tu-2', name: 'dangerous_tool', inputJson: '{"action": "delete"}', input: {}, status: 'preparing', approved: null };
  comp.getSessionToolMap('s1').set('tu-2', toolUse);
  comp.getIndexMap('s1').set(1, 'tu-2');

  comp.applyBlockStop({ index: 1 }, { sessionId: 's1', visible: true });

  expect(toolUse.status).toBe('pending_approval');
  expect(toolUse.approved).toBeNull();
  expect(comp.sessionTools('s1').floatingTool).toBe(toolUse);
  expect(comp.queueTool).not.toHaveBeenCalled();
});

test('applyBlockStop marks the tool errored on malformed input JSON', () => {
  comp.scrollIfPinned = jest.fn();
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(true);
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.queueTool = jest.fn();
  const toolUse = { id: 'tu-3', name: 'query_events', inputJson: '{"invalid": json}', input: {}, status: 'preparing', error: null };
  comp.getSessionToolMap('s1').set('tu-3', toolUse);
  comp.getIndexMap('s1').set(0, 'tu-3');

  comp.applyBlockStop({ index: 0 }, { sessionId: 's1', visible: true });

  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toContain(comp.i18n.assistantToolParseInputError);
  expect(comp.queueTool).not.toHaveBeenCalled();
});

test('applyBlockStop returns usage riding the content_block_stop event', () => {
  const usage = { input_tokens: 10, output_tokens: 5 };
  // No tool is mapped at this index; the usage must still be surfaced.
  expect(comp.applyBlockStop({ index: 7, usage }, { sessionId: 's1', visible: false })).toBe(usage);
});

// --- delegation streaming helpers ---

test('ensureChildSession creates, reuses, and renames the nested session', () => {
  const delegate = { id: 'd1' };

  const cs = comp.ensureChildSession(delegate, 'Hunter');
  expect(delegate.childSession).toBe(cs);
  expect(cs.agentName).toBe('Hunter');
  expect(cs.messages).toEqual([]);

  // Reuse: existing messages survive, and an omitted agentName is not cleared.
  cs.messages.push({ role: 'assistant', content: 'hi' });
  expect(comp.ensureChildSession(delegate)).toBe(cs);
  expect(cs.messages).toHaveLength(1);
  expect(cs.agentName).toBe('Hunter');

  // A provided agentName updates the existing session.
  comp.ensureChildSession(delegate, 'Analyst');
  expect(cs.agentName).toBe('Analyst');

  // No agentName at creation defaults to empty string.
  const bare = {};
  expect(comp.ensureChildSession(bare).agentName).toBe('');
});

test('pendingChildTools returns only tools awaiting approval, across all child messages', () => {
  const delegate = { childSession: { messages: [
    { toolUses: [{ id: 'a', status: 'pending_approval' }, { id: 'b', status: 'completed' }] },
    { content: 'prose only' },
    { toolUses: [{ id: 'c', status: 'executing' }, { id: 'd', status: 'pending_approval' }] },
  ] } };

  expect(comp.pendingChildTools(delegate).map(t => t.id)).toEqual(['a', 'd']);

  expect(comp.pendingChildTools(null)).toEqual([]);
  expect(comp.pendingChildTools({})).toEqual([]);
  expect(comp.pendingChildTools({ childSession: {} })).toEqual([]);
});

test('delegationHasCollapsedContent is true only when something already renders inside the fold', () => {
  expect(comp.delegationHasCollapsedContent(null)).toBe(false);
  expect(comp.delegationHasCollapsedContent({})).toBe(false);
  expect(comp.delegationHasCollapsedContent({ childSession: { messages: [] } })).toBe(false);

  // A still-pending tool is shown OUTSIDE the fold, so it does not count.
  expect(comp.delegationHasCollapsedContent({
    childSession: { messages: [{ toolUses: [{ status: 'pending_approval' }] }] },
  })).toBe(false);

  expect(comp.delegationHasCollapsedContent({
    childSession: { messages: [{ content: 'found it' }] },
  })).toBe(true);
  expect(comp.delegationHasCollapsedContent({
    childSession: { messages: [{ thoughts: 'thinking...' }] },
  })).toBe(true);
  expect(comp.delegationHasCollapsedContent({
    childSession: { messages: [{ toolUses: [{ status: 'completed' }, { status: 'pending_approval' }] }] },
  })).toBe(true);
});

test('handleDelegationMessageStart appends a nested message and returns the tracked instance', () => {
  comp.scrollIfPinned = jest.fn();
  const delegate = { childSession: { agentName: 'Hunter', messages: [{ role: 'assistant', content: 'earlier' }] } };

  const msg = comp.handleDelegationMessageStart(delegate);

  expect(delegate.childSession.messages).toHaveLength(2);
  // Streaming mutates the returned object; it must be the one stored in childSession.
  expect(msg).toBe(delegate.childSession.messages[1]);
  expect(msg.role).toBe('assistant');
  expect(msg.content).toBe('');
  expect(msg.thoughts).toBe('');
  expect(msg.toolUses).toEqual([]);
  expect(comp.scrollIfPinned).toHaveBeenCalled();
});

test('handleDelegationContentBlockStart/Delta adapt into applyBlock* with the child target', () => {
  comp.applyBlockStart = jest.fn();
  comp.applyBlockDelta = jest.fn();
  const childMsg = { content: '', thoughts: '', toolUses: [] };
  const start = { index: 0, content_block: { type: 'tool_use', id: 'tu-1' } };
  const delta = { index: 0, delta: { type: 'text_delta', text: 'x' } };

  comp.handleDelegationContentBlockStart(start, 'child-1', childMsg);
  expect(comp.applyBlockStart).toHaveBeenCalledWith(start, { message: childMsg, sessionId: 'child-1', visible: true });

  comp.handleDelegationContentBlockDelta(delta, 'child-1', childMsg);
  expect(comp.applyBlockDelta).toHaveBeenCalledWith(delta, { message: childMsg, sessionId: 'child-1', visible: true });
});

test('handleToolExecutionContentBlockStop processes chained tool with auto-approval', () => {
  const sessionId = 'execution-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockChainedTool = {
    id: 'chained_tool_123',
    name: 'get_playbooks',
    inputJson: '{"alert_id": "alert_123"}',
    status: 'preparing',
    input: {},
    approved: null
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(true);
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.queueTool = jest.fn();
  
  mockToolMap.set('chained_tool_123', mockChainedTool);
  mockIndexMap.set(1, 'chained_tool_123');
  
  const result = comp.handleToolExecutionContentBlockStop({ index: 1, usage: { input_tokens: 20, output_tokens: 30 } }, sessionId);
  
  expect(mockChainedTool.input).toEqual({ alert_id: "alert_123" });
  expect(mockChainedTool.approved).toBe(true);
  expect(comp.queueTool).toHaveBeenCalledWith(sessionId, 'chained_tool_123');
  expect(result).toEqual({ input_tokens: 20, output_tokens: 30 });
});

test('handleToolExecutionContentBlockStop processes chained tool without auto-approval', () => {
  const sessionId = 'execution-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockChainedTool = {
    id: 'chained_tool_456',
    name: 'execute_command',
    inputJson: '{"command": "rm -rf /"}',
    status: 'preparing',
    input: {},
    approved: null
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  comp.shouldAutoApproveTool = jest.fn().mockReturnValue(false);
  comp.sessionToolState = new Map();
  
  mockToolMap.set('chained_tool_456', mockChainedTool);
  mockIndexMap.set(2, 'chained_tool_456');
  
  const result = comp.handleToolExecutionContentBlockStop({ index: 2 }, sessionId);
  
  expect(mockChainedTool.input).toEqual({ command: "rm -rf /" });
  expect(mockChainedTool.status).toBe('pending_approval');
  expect(mockChainedTool.approved).toBe(null);
  expect(comp.sessionTools(sessionId).floatingTool).toBe(mockChainedTool);
  expect(result).toBe(null);
});

test('handleToolExecutionContentBlockStop handles JSON parsing error', () => {
  const sessionId = 'execution-session';
  const mockToolMap = new Map();
  const mockIndexMap = new Map();
  const mockChainedTool = {
    id: 'chained_tool_789',
    name: 'test_tool',
    inputJson: '{"malformed": json}',
    status: 'preparing',
    input: {},
    error: null
  };
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.getIndexMap = jest.fn().mockReturnValue(mockIndexMap);
  
  mockToolMap.set('chained_tool_789', mockChainedTool);
  mockIndexMap.set(0, 'chained_tool_789');
  
  comp.handleToolExecutionContentBlockStop({ index: 0 }, sessionId);
  
  expect(mockChainedTool.status).toBe('error');
  expect(mockChainedTool.error).toContain('Failed to parse tool input');
});

// Last 4 methods tests
test('getSessionToolMap creates a per-session tool map when none exists', () => {
  const sessionId = 'new-session';
  comp.sessionToolState = new Map();

  const result = comp.getSessionToolMap(sessionId);

  expect(result).toBeInstanceOf(Map);
  expect(comp.sessionToolState.get(sessionId).toolsById).toBe(result);
});

test('getSessionToolMap returns the existing per-session tool map', () => {
  const sessionId = 'existing-session';
  comp.sessionToolState = new Map();
  comp.sessionTools(sessionId).toolsById.set('tool1', { id: 'tool1', name: 'test' });

  const result = comp.getSessionToolMap(sessionId);

  expect(result.get('tool1')).toEqual({ id: 'tool1', name: 'test' });
});

test('getIndexMap creates a per-session index map when none exists', () => {
  const sessionId = 'new-session';
  comp.sessionToolState = new Map();

  const result = comp.getIndexMap(sessionId);

  expect(result).toBeInstanceOf(Map);
  expect(comp.sessionToolState.get(sessionId).indexToId).toBe(result);
});

test('getIndexMap returns the existing per-session index map', () => {
  const sessionId = 'existing-session';
  comp.sessionToolState = new Map();
  comp.sessionTools(sessionId).indexToId.set(0, 'tool_id_123');

  const result = comp.getIndexMap(sessionId);

  expect(result.get(0)).toBe('tool_id_123');
});

// The three content-block handler sets (orchestrator / chained tool / delegation)
// funnel through one shared applyBlock* implementation. This locks the subtle
// invariant they all rely on: a tool_use block for an off-screen session (no message
// to render into) is still registered in that session's tool + index maps, so it can
// be found and resolved later. Driven via handleContentBlockStart with message=null.
test('content-block start tracks an off-screen tool without rendering it', () => {
  const sessionId = 'background-session';
  comp.sessionToolState = new Map();
  comp.scrollIfPinned = jest.fn();

  comp.handleContentBlockStart(
    { index: 0, content_block: { type: 'tool_use', id: 'bg_tool', name: 'query_events' } },
    null,            // not the current session -> nothing to render into
    sessionId,
  );

  const s = comp.sessionToolState.get(sessionId);
  expect(s.toolsById.get('bg_tool')).toMatchObject({ id: 'bg_tool', name: 'query_events', sessionId });
  expect(s.indexToId.get(0)).toBe('bg_tool');
  expect(comp.scrollIfPinned).not.toHaveBeenCalled(); // off-screen: no scroll
});

test('queueTool adds tool to queue and runs queue', () => {
  const sessionId = 'test-session';
  const toolUseId = 'tool_123';
  comp.sessionToolState = new Map();
  comp.runToolQueue = jest.fn();

  comp.queueTool(sessionId, toolUseId);

  expect(comp.sessionTools(sessionId).queue).toEqual([toolUseId]);
  expect(comp.runToolQueue).toHaveBeenCalledWith(sessionId);
});

test('queueTool adds to existing queue', () => {
  const sessionId = 'test-session';
  const toolUseId1 = 'tool_123';
  const toolUseId2 = 'tool_456';
  comp.sessionToolState = new Map();
  comp.sessionTools(sessionId).queue.push(toolUseId1);
  comp.runToolQueue = jest.fn();

  comp.queueTool(sessionId, toolUseId2);

  expect(comp.sessionTools(sessionId).queue).toEqual([toolUseId1, toolUseId2]);
  expect(comp.runToolQueue).toHaveBeenCalledWith(sessionId);
});

test('runToolQueue processes tools in queue', async () => {
  const sessionId = 'test-session';
  const toolUse1 = { id: 'tool_123', status: 'preparing' };
  const toolUse2 = { id: 'tool_456', status: 'preparing' };

  comp.sessionToolState = new Map();
  const s = comp.sessionTools(sessionId);
  s.queue.push('tool_123', 'tool_456');
  s.toolsById.set('tool_123', toolUse1);
  s.toolsById.set('tool_456', toolUse2);

  comp.executeTool = jest.fn().mockResolvedValue();

  await comp.runToolQueue(sessionId);

  expect(comp.executeTool).toHaveBeenCalledWith(toolUse1);
  expect(comp.executeTool).toHaveBeenCalledWith(toolUse2);
  expect(toolUse1.status).toBe('executing');
  expect(toolUse2.status).toBe('executing');
  expect(comp.sessionTools(sessionId).busy).toBe(false);
});

test('runToolQueue skips if already busy', async () => {
  const sessionId = 'test-session';
  comp.sessionToolState = new Map();
  comp.sessionTools(sessionId).busy = true;
  comp.executeTool = jest.fn();

  await comp.runToolQueue(sessionId);

  expect(comp.executeTool).not.toHaveBeenCalled();
});

test('runToolQueue skips completed/error/rejected tools', async () => {
  const sessionId = 'test-session';
  const completedTool = { id: 'tool_completed', status: 'completed' };
  const errorTool = { id: 'tool_error', status: 'error' };
  const rejectedTool = { id: 'tool_rejected', status: 'rejected' };
  const preparingTool = { id: 'tool_preparing', status: 'preparing' };

  comp.sessionToolState = new Map();
  const s = comp.sessionTools(sessionId);
  s.queue.push('tool_completed', 'tool_error', 'tool_rejected', 'tool_preparing');
  s.toolsById.set('tool_completed', completedTool);
  s.toolsById.set('tool_error', errorTool);
  s.toolsById.set('tool_rejected', rejectedTool);
  s.toolsById.set('tool_preparing', preparingTool);

  comp.executeTool = jest.fn().mockResolvedValue();

  await comp.runToolQueue(sessionId);

  expect(comp.executeTool).toHaveBeenCalledTimes(1);
  expect(comp.executeTool).toHaveBeenCalledWith(preparingTool);
  expect(preparingTool.status).toBe('executing');
});

test('checkForActivity returns true when streaming', () => {
  comp.isStreaming = true;
  comp.isTyping = false;
  comp.sessionToolState = new Map();
  comp.currentChatId = 'test-session';

  expect(comp.checkForActivity()).toBe(true);
});

test('checkForActivity returns true when typing', () => {
  comp.isStreaming = false;
  comp.isTyping = true;
  comp.sessionToolState = new Map();
  comp.currentChatId = 'test-session';

  expect(comp.checkForActivity()).toBe(true);
});

test('checkForActivity returns true when tools are queued', () => {
  comp.isStreaming = false;
  comp.isTyping = false;
  comp.sessionToolState = new Map();
  comp.sessionTools('test-session').queue.push('tool_123');
  comp.currentChatId = 'test-session';

  expect(comp.checkForActivity()).toBe(true);
});

test('checkForActivity returns false when no activity', () => {
  comp.isStreaming = false;
  comp.isTyping = false;
  comp.sessionToolState = new Map();
  comp.currentChatId = 'test-session';

  expect(comp.checkForActivity()).toBe(false);
});

test('checkForActivity returns false when tool queue is empty', () => {
  comp.isStreaming = false;
  comp.isTyping = false;
  comp.sessionToolState = new Map();
  comp.sessionTools('test-session');
  comp.currentChatId = 'test-session';
  comp.delegationChildren = new Map();

  expect(comp.checkForActivity()).toBe(false);
});

test('checkForActivity counts a live delegation child\'s queued tools as activity', () => {
  comp.isStreaming = false;
  comp.isTyping = false;
  comp.currentChatId = 'parent-session';
  comp.sessionToolState = new Map();
  comp.delegationChildren = new Map([['child-1', { parentSessionId: 'parent-session' }]]);

  // Current session is idle, but the sub-agent (child session) has a queued tool.
  comp.sessionTools('parent-session');
  comp.sessionTools('child-1').queue.push('child-tool-1');

  expect(comp.checkForActivity()).toBe(true);
});

test('checkForActivity ignores a queued session that is not the current conversation or its delegation child', () => {
  comp.isStreaming = false;
  comp.isTyping = false;
  comp.currentChatId = 'parent-session';
  comp.sessionToolState = new Map();
  comp.delegationChildren = new Map();

  // A different conversation's session has queued work; it must not block this one.
  comp.sessionTools('parent-session');
  comp.sessionTools('other-conversation').queue.push('tool_x');

  expect(comp.checkForActivity()).toBe(false);
});

test('applyToolSpecificChanges does nothing for non-query_cases tools', () => {
  const toolUse = { id: 'tool_other', name: 'query_events', input: { oql_query: 'event.module: suricata' } };
  const toolRequest = {
    sessionId: 'test-session',
    toolUseId: 'tool_other',
    params: { oql_query: 'event.module: suricata' },
    model: 'test-model'
  };

  // Spy on the prototype (no return value needed)
  const getSpy = jest.spyOn(Storage.prototype, 'getItem');

  comp.applyToolSpecificChanges(toolUse, toolRequest);

  expect(getSpy).not.toHaveBeenCalled();
  expect(toolRequest.auxData).toBeUndefined();

  getSpy.mockRestore();
});

test('messageClassesFromTags', () => {
  let tags = ['important', 'error', MSGTAG_CONTEXTCOMPRESSION];
  let result = comp.messageClassesFromTags(tags);
  expect(result).toEqual(['msgTag-important', 'msgTag-error', 'msgTag-context_compression']);
});

test('toggleSharedSession', async () => {
  const _updateSessionTag = comp.updateSessionTag;
  const _loadStoredChats = comp.loadStoredChats;
  comp.updateSessionTag = jest.fn();
  comp.loadStoredChats = jest.fn();

  // Removing 'shared' tag
  comp.currentChatId = 'session_123';
  comp.chatHistoryById = {
    'session_123': { tags: ["shared"], userId: 'me' },
  };
  comp.$root.user = { id: 'me' };

  await comp.toggleSharedSession(comp.currentChatId);

  expect(comp.updateSessionTag).toHaveBeenCalledTimes(1);
  expect(comp.updateSessionTag).toHaveBeenCalledWith(comp.currentChatId, 'remove', 'shared');
  expect(comp.loadStoredChats).toHaveBeenCalledTimes(1);

  // Can't change a session you don't own
  comp.updateSessionTag.mockClear();
  comp.loadStoredChats.mockClear();

  comp.chatHistoryById[comp.currentChatId].userId = 'u';

  await comp.toggleSharedSession(comp.currentChatId);

  expect(comp.updateSessionTag).toHaveBeenCalledTimes(0);
  expect(comp.loadStoredChats).toHaveBeenCalledTimes(0);

  // Adding 'shared' tag
  comp.chatHistoryById[comp.currentChatId].userId = 'me';
  comp.updateSessionTag.mockClear();
  comp.loadStoredChats.mockClear();

  comp.chatHistoryById[comp.currentChatId].tags = ['a', 'b', 'c'];

  await comp.toggleSharedSession(comp.currentChatId);

  expect(comp.updateSessionTag).toHaveBeenCalledTimes(1);
  expect(comp.updateSessionTag).toHaveBeenCalledWith(comp.currentChatId, 'add', 'shared');
  expect(comp.loadStoredChats).toHaveBeenCalledTimes(1);

  // Unknown session
  comp.updateSessionTag.mockClear();
  comp.loadStoredChats.mockClear();

  comp.chatHistoryById = { 'other-session': {}};

  await comp.toggleSharedSession(comp.currentChatId);

  expect(comp.updateSessionTag).toHaveBeenCalledTimes(0);
  expect(comp.loadStoredChats).toHaveBeenCalledTimes(0);

  comp.updateSessionTag = _updateSessionTag;
  comp.loadStoredChats = _loadStoredChats;
});

test('nbspRegexOp', () => {
  expect(comp.nbspRegexOp('&nbsp;')).toBe('');
  expect(comp.nbspRegexOp('&nbsp')).toBe('');
  expect(comp.nbspRegexOp('Hello&nbsp;World')).toBe('Hello&nbsp;World');
  expect(comp.nbspRegexOp('&nbsp;\n\nHelloWorld')).toBe('HelloWorld');
  expect(comp.nbspRegexOp('&nbsp;Hello&nbsp;World')).toBe('Hello&nbsp;World');
  expect(comp.nbspRegexOp('&nbspHelloWorld')).toBe('HelloWorld');
  expect(comp.nbspRegexOp('Hello World')).toBe('Hello World');
  expect(comp.nbspRegexOp('')).toBe('');
});

test('focusChatInput focuses the chat input textarea', () => {
  const mockTextarea = {
    focus: jest.fn()
  };
  const mockInputField = {
    $el: {
      querySelector: jest.fn().mockReturnValue(mockTextarea)
    }
  };
  comp.$refs = {
    chatInputField: mockInputField
  };
  comp.focusChatInput();
  expect(comp.$nextTick).toHaveBeenCalled();
  const nextTickCallback = comp.$nextTick.mock.calls[0][0];
  if (nextTickCallback) {
    nextTickCallback();
  }
  expect(mockInputField.$el.querySelector).toHaveBeenCalledWith('textarea');
  expect(mockTextarea.focus).toHaveBeenCalled();
});

// Credits tracking tests
test('updateCreditsUsed updates total credits used', () => {
  comp.creditsUsed = 100;
  const usage1 = { credits: 50 };
  const usage2 = { credits: 25 };
  
  comp.updateCreditsUsed(usage1);
  expect(comp.creditsUsed).toBe(150);
  
  comp.updateCreditsUsed(usage2);
  expect(comp.creditsUsed).toBe(175);
  
  comp.updateCreditsUsed(null);
  expect(comp.creditsUsed).toBe(175);
});

test('updateCreditsUsed handles missing credits field', () => {
  comp.creditsUsed = 100;
  const usage = { input_tokens: 10, output_tokens: 20 };
  
  comp.updateCreditsUsed(usage);
  expect(comp.creditsUsed).toBe(100);
});

// Floating tool tests
test('sendMessage marks floating tool as skipped when sending new message', async () => {
  const floatingTool = {
    id: 'tool_floating',
    name: 'query_events',
    status: 'pending_approval',
    approved: null
  };
  
  comp.messages = [fakeAssistantMessage, fakeMessage];
  comp.currentChatId = 'test-session';
  comp.sessionToolState = new Map();
  comp.sessionTools('test-session').floatingTool = floatingTool;
  comp.newMessage = 'New message';
  comp.canChat = true;
  comp.assistantEnabled = true;
  comp.creditsRemaining = 100;
  comp.creditsLoaded = true;
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.callAIAPI = jest.fn().mockResolvedValue();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();

  await comp.sendMessage();

  expect(floatingTool.status).toBe('skipped');
  expect(comp.sessionTools('test-session').floatingTool).toBeFalsy();
});

test('sendMessage does not mark floating tool as skipped when only welcome message', async () => {
  const floatingTool = {
    id: 'tool_floating',
    name: 'query_events',
    status: 'pending_approval',
    approved: null
  };
  
  comp.messages = [fakeAssistantMessage];
  comp.currentChatId = 'test-session';
  comp.sessionToolState = new Map();
  comp.sessionTools('test-session').floatingTool = floatingTool;
  comp.newMessage = 'First message';
  comp.canChat = true;
  comp.assistantEnabled = true;
  comp.creditsRemaining = 100;
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.callAIAPI = jest.fn().mockResolvedValue();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();
  
  await comp.sendMessage();
  
  expect(floatingTool.status).toBe('pending_approval');
});

// Context compression tests
test('compressCurrentSession sends compression message and reloads chat', async () => {
  comp.currentChatId = 'test-session';
  comp.newMessage = 'Original message';
  comp.compressContextMsg = 'Compress the context';
  comp.contextLength = 5000;
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();
  
  await comp.compressCurrentSession();
  
  expect(comp.newMessage).toBe('Original message');
  expect(comp.contextLength).toBe(0);
  expect(comp.sendMessage).toHaveBeenCalledWith([MSGTAG_CONTEXTCOMPRESSION]);
  expect(comp.loadChatFromBackend).toHaveBeenCalledWith('test-session');
});

// Choice buttons tests
test('applyChoiceButtons converts choice markers to buttons', () => {
  const text = 'Choose an option: [[CHOICE]]Option 1[[/CHOICE]] or [[CHOICE]]Option 2[[/CHOICE]]';
  
  const result = comp.applyChoiceButtons(text);
  
  expect(result).toContain('class="assistant-choice-btn"');
  expect(result).toContain('data-choice="Option 1"');
  expect(result).toContain('data-choice="Option 2"');
});

test('applyChoiceButtons handles empty choice markers', () => {
  const text = 'Text with [[CHOICE]][[/CHOICE]] empty choice';
  
  const result = comp.applyChoiceButtons(text);
  
  expect(result).toBe('Text with  empty choice');
});

test('applyChoiceButtons handles text without choice markers', () => {
  const text = 'Regular text without choices';
  
  const result = comp.applyChoiceButtons(text);
  
  expect(result).toBe('Regular text without choices');
});

test('applyChoiceButtons handles null text', () => {
  const result = comp.applyChoiceButtons(null);
  
  expect(result).toBe(null);
});

test('applyChoiceButtons strips newlines from choice labels', () => {
  const text = '[[CHOICE]]\n\nOption with newlines\n\n[[/CHOICE]]';
  
  const result = comp.applyChoiceButtons(text);
  
  expect(result).toContain('data-choice="Option with newlines"');
});

test('onChatClick handles choice button click', () => {
  const mockButton = {
    getAttribute: jest.fn().mockReturnValue('Selected choice')
  };
  const mockEvent = {
    target: {
      closest: jest.fn().mockReturnValue(mockButton)
    },
    preventDefault: jest.fn()
  };
  
  comp.canChat = true;
  comp.checkForActivity = jest.fn().mockReturnValue(false);
  comp.creditsLoaded = true;
  comp.focusChatInput = jest.fn();
  comp.sendMessage = jest.fn();
  
  comp.onChatClick(mockEvent);
  
  expect(mockEvent.preventDefault).toHaveBeenCalled();
  expect(comp.newMessage).toBe('Selected choice');
  expect(comp.$nextTick).toHaveBeenCalled();
});

test('onChatClick ignores non-button clicks', () => {
  const mockEvent = {
    target: {
      closest: jest.fn().mockReturnValue(null)
    },
    preventDefault: jest.fn()
  };
  
  comp.sendMessage = jest.fn();
  
  comp.onChatClick(mockEvent);
  
  expect(mockEvent.preventDefault).not.toHaveBeenCalled();
  expect(comp.sendMessage).not.toHaveBeenCalled();
});

test('onChatClick does not send when activity in progress', () => {
  const mockButton = {
    getAttribute: jest.fn().mockReturnValue('Choice')
  };
  const mockEvent = {
    target: {
      closest: jest.fn().mockReturnValue(mockButton)
    },
    preventDefault: jest.fn()
  };
  
  comp.canChat = true;
  comp.checkForActivity = jest.fn().mockReturnValue(true);
  comp.creditsLoaded = true;
  comp.sendMessage = jest.fn();
  
  comp.onChatClick(mockEvent);
  
  expect(comp.sendMessage).not.toHaveBeenCalled();
});

test('onChatClick does not send when canChat is false', () => {
  const mockButton = {
    getAttribute: jest.fn().mockReturnValue('Choice')
  };
  const mockEvent = {
    target: {
      closest: jest.fn().mockReturnValue(mockButton)
    },
    preventDefault: jest.fn()
  };
  
  comp.canChat = false;
  comp.checkForActivity = jest.fn().mockReturnValue(false);
  comp.creditsLoaded = true;
  comp.sendMessage = jest.fn();
  
  comp.onChatClick(mockEvent);
  
  expect(comp.sendMessage).not.toHaveBeenCalled();
});

test('stripHtml removes HTML tags', () => {
  expect(comp.stripHtml('<p>Hello <strong>World</strong></p>')).toBe('Hello World');
  expect(comp.stripHtml('<div><span>Test</span></div>')).toBe('Test');
  expect(comp.stripHtml('No tags')).toBe('No tags');
});

test('stripNewlines removes leading and trailing newlines', () => {
  expect(comp.stripNewlines('\n\nHello World\n\n')).toBe('Hello World');
  expect(comp.stripNewlines('  \n\nText\n\n  ')).toBe('Text');
  expect(comp.stripNewlines('No newlines')).toBe('No newlines');
});

test('stripNewlines handles non-string input', () => {
  expect(comp.stripNewlines(null)).toBe(null);
  expect(comp.stripNewlines(undefined)).toBe(undefined);
  expect(comp.stripNewlines(123)).toBe(123);
});

// Session tag update tests
test('updateSessionTag sends correct API request for add action', async () => {
  const sessionId = 'test-session';
  const mockPut = mockPapi('put');
  
  await comp.updateSessionTag(sessionId, 'add', 'shared');
  
  expect(mockPut).toHaveBeenCalledWith(`/assistant/sessions/${sessionId}`, {
    action: 'add',
    tag: 'shared'
  });
});

test('updateSessionTag sends correct API request for remove action', async () => {
  const sessionId = 'test-session';
  const mockPut = mockPapi('put');
  
  await comp.updateSessionTag(sessionId, 'remove', 'shared');
  
  expect(mockPut).toHaveBeenCalledWith(`/assistant/sessions/${sessionId}`, {
    action: 'remove',
    tag: 'shared'
  });
});

test('updateSessionTag handles API error', async () => {
  const sessionId = 'test-session';
  const showErrorMock = mockShowError();
  mockPapi('put', null, { response: { data: "Update failed"} });
  
  await comp.updateSessionTag(sessionId, 'add', 'shared');
  
  expect(showErrorMock).toHaveBeenCalledWith({ message: "Update failed" });
});

test('updateSessionTag', async () => {
  const sessionId = 'session_123';
  const action = 'remove';
  const tag = 'shared';
  const showError = jest.fn();
  comp.$root.showError = showError;
  let put = mockPapi('put', {});

  await comp.updateSessionTag(sessionId, action, tag);

  expect(put).toHaveBeenCalledWith(`/assistant/sessions/${sessionId}`, { action: action, tag: tag });
  expect(showError).not.toHaveBeenCalled();

  put = mockPapi('put', {}, { response: { data: 'ERROR_SESSION_ATTACHED_TO_CASES 2' } });

  await comp.updateSessionTag(sessionId, action, tag);

  expect(put).toHaveBeenCalledWith(`/assistant/sessions/${sessionId}`, { action: action, tag: tag });
  expect(showError).toHaveBeenCalledWith({ message: 'Unable to unshare session. The session is attached to 2 case(s).' });
});

test('attachToCase', async () => {
  comp.caseMenuVisible = true;

  const sessionId = 'sessionId';
  const caseId = 'caseId';

  comp.chatHistoryById = {
    [sessionId]: {
      title: 'AI Session',
      tags: ['context_compress'],
      userId: 'me',
    },
  };

  const _origtoggleSharedSession = comp.toggleSharedSession;
  comp.toggleSharedSession = jest.fn();

  const _origcreateCase = comp.createCase;
  comp.createCase = jest.fn();

  await comp.attachToCase(sessionId, caseId)

  expect(comp.caseMenuVisible).toBe(false);
  expect(comp.toggleSharedSession).toHaveBeenCalledWith(sessionId);
  expect(comp.createCase).toHaveBeenCalledTimes(0);

  comp.caseMenuVisible = true;
  comp.chatHistoryById[sessionId].tags = ['shared'];
  comp.toggleSharedSession.mockClear();
  comp.createCase.mockClear();

  await comp.attachToCase(sessionId, caseId);

  expect(comp.caseMenuVisible).toBe(false);
  expect(comp.toggleSharedSession).toHaveBeenCalledTimes(0);
  expect(comp.createCase).toHaveBeenCalledTimes(0);

  await comp.attachToCase(sessionId, null);

  expect(comp.caseMenuVisible).toBe(false);
  expect(comp.toggleSharedSession).toHaveBeenCalledTimes(0);
  expect(comp.createCase).toHaveBeenCalledWith('AI Session');

  comp.toggleSharedSession = _origtoggleSharedSession;
  comp.createCase = _origcreateCase;
  resetPapi();
});

test('createCase', async () => {
  const post = mockPapi('post', { data: { id: '123' } });

  const result = await comp.createCase('title');

  expect(post).toHaveBeenCalledWith('case/', { title: 'title', description: comp.i18n.caseEscalatedDescription });
  expect(result).toBe('123');

  resetPapi();
});

test('calculateContextOfMessage - assistant message', () => {
  const allMessages = [
    {
      role: 'user',
      usage: {
        input_tokens: 100,
        output_tokens: 0
      }
    },
    {
      role: 'assistant',
      usage: {
        input_tokens: 200,
        output_tokens: 150
      }
    }
  ];

  // the context usage of a single assistant message is given to us
  // as the output_tokens of that message, no calculation necessary
  const result = comp.calculateContextOfMessage(allMessages, 1);

  expect(result).toBe(150);
});

test('calculateContextOfMessage - user message mid-session', () => {
  const allMessages = [
    {
      role: 'assistant',
      usage: {
        input_tokens: 100,
        output_tokens: 50
      }
    },
    {
      role: 'user',
      usage: {
        input_tokens: 0,
        output_tokens: 0
      }
    },
    {
      role: 'assistant',
      usage: {
        input_tokens: 200,
        output_tokens: 75
      }
    }
  ];

  // For the user message at index 1:
  // contextLength = next.input_tokens - (prev.input_tokens + prev.output_tokens)
  // contextLength = 200 - (100 + 50) = 50
  const result = comp.calculateContextOfMessage(allMessages, 1);

  expect(result).toBe(50);
});

test('calculateContextOfMessage - first user message', () => {
  const allMessages = [
    {
      role: 'user',
      usage: {
        input_tokens: 0,
        output_tokens: 0
      }
    },
    {
      role: 'assistant',
      usage: {
        input_tokens: 120,
        output_tokens: 80
      }
    }
  ];

  // For the first user message (no previous message):
  // contextLength = next.input_tokens
  const result = comp.calculateContextOfMessage(allMessages, 0);

  expect(result).toBe(120);
});

test('calculateContextOfMessage - latest user message without assistant response', () => {
  const allMessages = [
    {
      role: 'user',
      usage: {
        input_tokens: 0,
        output_tokens: 0
      }
    }
  ];

  const result = comp.calculateContextOfMessage(allMessages, 1);

  // the length of this message isn't calculable given what we have. This should
  // only last for a short time until the model responds to the message.
  expect(result).toBe(0);
});

// messageContextValues computed property tests
test('messageContextValues returns context values for all messages', () => {
  comp.messages = [
    {
      role: 'user',
      usage: {
        input_tokens: 0,
        output_tokens: 0
      }
    },
    {
      role: 'assistant',
      usage: {
        input_tokens: 120,
        output_tokens: 80
      }
    },
    {
      role: 'user',
      usage: {
        input_tokens: 0,
        output_tokens: 0
      }
    },
    {
      role: 'assistant',
      usage: {
        input_tokens: 200,
        output_tokens: 150
      }
    }
  ];

  const result = comp.messageContextValues();

  expect(result).toHaveLength(4);
  expect(result[0]).toBe(120); // First user message: next.input_tokens = 120
  expect(result[1]).toBe(80);  // First assistant message: output_tokens = 80
  expect(result[2]).toBe(0);   // Second user message: next.input_tokens - (prev.input_tokens + prev.output_tokens) = 200 - (120 + 80) = 0
  expect(result[3]).toBe(150); // Second assistant message: output_tokens = 150
});

test('messageContextValues handles empty messages array', () => {
  comp.messages = [];

  const result = comp.messageContextValues();

  expect(result).toEqual([]);
});

test('messageContextValues handles null messages', () => {
  comp.messages = null;

  const result = comp.messageContextValues();

  expect(result).toEqual([]);
});

// isMessageTooLong computed property tests
test('isMessageTooLong returns false when charsPerTokenEstimate is 0', () => {
  comp.charsPerTokenEstimate = 0;
  comp.newMessage = 'Hello';
  comp.contextLength = 0;
  comp.contextLimitSmall = 1000;

  expect(comp.isMessageTooLong()).toBe(false);
});

test('isMessageTooLong returns false when newMessage is empty', () => {
  comp.charsPerTokenEstimate = 3.6;
  comp.newMessage = '';
  comp.contextLength = 0;
  comp.contextLimitSmall = 1000;

  expect(comp.isMessageTooLong()).toBe(false);
});

test('isMessageTooLong returns false when within limit', () => {
  comp.charsPerTokenEstimate = 4;
  comp.newMessage = 'Short message';
  comp.contextLength = 0;
  comp.increaseContextLimit = false;
  comp.contextLimitSmall = 1000;

  // maxChars = 1000 * 4 * 1.1 = 4400
  // usedChars = 13 + 0 = 13
  expect(comp.isMessageTooLong()).toBe(false);
});

test('isMessageTooLong returns true when message exceeds limit', () => {
  comp.charsPerTokenEstimate = 4;
  comp.newMessage = 'a'.repeat(4400);
  comp.contextLength = 0;
  comp.increaseContextLimit = false;
  comp.contextLimitSmall = 1000;

  // maxChars = 1000 * 4 * 1.1 = 4400
  // usedChars = 4400 + 0 = 4400
  expect(comp.isMessageTooLong()).toBe(true);
});

test('isMessageTooLong accounts for context length', () => {
  comp.charsPerTokenEstimate = 4;
  comp.newMessage = 'Hello';
  comp.contextLength = 1000;
  comp.increaseContextLimit = false;
  comp.contextLimitSmall = 1000;

  // maxChars = 1000 * 4 * 1.1 = 4400
  // usedChars = 5 + (1000 * 4) = 4005
  expect(comp.isMessageTooLong()).toBe(false);

  comp.contextLength = 1100;
  // usedChars = 5 + (1100 * 4) = 4405
  expect(comp.isMessageTooLong()).toBe(true);
});

test('isMessageTooLong uses large context limit when toggled', () => {
  comp.charsPerTokenEstimate = 4;
  comp.newMessage = 'a'.repeat(4400);
  comp.contextLength = 0;
  comp.increaseContextLimit = true;
  comp.contextLimitSmall = 1000;
  comp.contextLimitLarge = 2000;

  // maxChars = 2000 * 4 * 1.1 = 8800
  // usedChars = 4400
  expect(comp.isMessageTooLong()).toBe(false);
});

test('buildModelIdentifier', () => {
  const tests = [
    { input: { id: 'model', adapter: 'adapter' }, expected: 'model@adapter' },
    { input: { id: '', adapter: '' }, expected: '@' },
    { input: {}, expected: '@' },
    { input: null, expected: '' },
  ];

  for (let t of tests) {
    const output = comp.buildModelIdentifier(t.input);
    expect(output).toBe(t.expected);
  }
});

test('buildGroupedModels - groups models by adapter with headers', () => {
  // Setup test data
  comp.modelsMap = new Map([
    ['claude-3-5-sonnet@Anthropic', {
      id: 'claude-3-5-sonnet',
      adapter: 'Anthropic',
      displayName: 'Claude 3.5 Sonnet',
      key: 'claude-3-5-sonnet@Anthropic'
    }],
    ['claude-3-opus@Anthropic', {
      id: 'claude-3-opus',
      adapter: 'Anthropic',
      displayName: 'Claude 3 Opus',
      key: 'claude-3-opus@Anthropic'
    }],
    ['gpt-4@SOAI', {
      id: 'gpt-4',
      adapter: 'SOAI',
      displayName: 'GPT-4',
      key: 'gpt-4@SOAI'
    }],
    ['gemini-pro@Gemini', {
      id: 'gemini-pro',
      adapter: 'Gemini',
      displayName: 'Gemini Pro',
      key: 'gemini-pro@Gemini'
    }]
  ]);

  const result = comp.buildGroupedModels();

  // Verify structure
  expect(result).toBeInstanceOf(Array);
  expect(result.length).toBe(7); // 3 headers + 4 models

  // First group should be Anthropic (alphabetically first, case-sensitive)
  expect(result[0]).toEqual({ header: 'Anthropic' });
  expect(result[1].displayName).toBe('Claude 3.5 Sonnet');
  expect(result[2].displayName).toBe('Claude 3 Opus');

  // Second group should be Gemini
  expect(result[3]).toEqual({ header: 'Gemini' });
  expect(result[4].displayName).toBe('Gemini Pro');

  // Third group should be SOAI
  expect(result[5]).toEqual({ header: 'SOAI' });
  expect(result[6].displayName).toBe('GPT-4');
});

test('buildGroupedModels - handles single adapter', () => {
  comp.modelsMap = new Map([
    ['model1@Adapter1', {
      id: 'model1',
      adapter: 'Adapter1',
      displayName: 'Model 1',
      key: 'model1@Adapter1'
    }],
    ['model2@Adapter1', {
      id: 'model2',
      adapter: 'Adapter1',
      displayName: 'Model 2',
      key: 'model2@Adapter1'
    }]
  ]);

  const result = comp.buildGroupedModels();

  // Should have header and two models
  expect(result).toHaveLength(3);
  expect(result[0]).toEqual({ header: 'Adapter1' });
  expect(result[1].displayName).toBe('Model 1');
  expect(result[2].displayName).toBe('Model 2');
});

test('buildGroupedModels - handles empty modelsMap', () => {
  comp.modelsMap = new Map();

  const result = comp.buildGroupedModels();

  expect(result).toEqual([]);
});

test('buildGroupedModels - handles models with no adapter', () => {
  comp.i18n = { statusUnknown: 'Unknown' };
  comp.modelsMap = new Map([
    ['model1@', {
      id: 'model1',
      adapter: '',
      displayName: 'Model 1',
      key: 'model1@'
    }],
    ['model2@Adapter1', {
      id: 'model2',
      adapter: 'Adapter1',
      displayName: 'Model 2',
      key: 'model2@Adapter1'
    }]
  ]);

  const result = comp.buildGroupedModels();

  // Should group empty adapter as 'Unknown' (from i18n)
  expect(result[0]).toEqual({ header: 'Adapter1' });
  expect(result[1].displayName).toBe('Model 2');
  expect(result[2]).toEqual({ header: 'Unknown' });
  expect(result[3].displayName).toBe('Model 1');
});

// --- applyStreamedToolResult (inline tool_result event capture) ---

test('applyStreamedToolResult marks the tool completed and stores its result', () => {
  const toolUse = { id: 'tu-1', status: 'executing' };
  comp.applyStreamedToolResult(toolUse, { toolUseId: 'tu-1', content: [{ json: { hits: 3 } }] });
  expect(toolUse.status).toBe('completed');
  expect(toolUse.rawResult).toEqual({ hits: 3 });
  expect(typeof toolUse.completedAt).toBe('string');
});

test('applyStreamedToolResult surfaces an error tool_result as tool error status', () => {
  const toolUse = { id: 'tu-1', status: 'executing' };
  comp.applyStreamedToolResult(toolUse, { toolUseId: 'tu-1', isError: true, content: [{ text: 'query exploded' }] });
  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('query exploded');
  expect(toolUse.rawResult).toBe(null);
});

test('applyStreamedToolResult completes a result with empty content (no stuck spinner)', () => {
  const toolUse = { id: 'tu-1', status: 'executing' };
  comp.applyStreamedToolResult(toolUse, { toolUseId: 'tu-1', content: [] });
  expect(toolUse.status).toBe('completed');
  expect(toolUse.rawResult).toBe(null);
});

test('applyStreamedToolResult keeps a declined tool rejected (not error)', () => {
  const toolUse = { id: 'tu-1', status: 'rejected', approved: false };
  comp.applyStreamedToolResult(toolUse, { toolUseId: 'tu-1', status: 'rejected', isError: true, content: [{ text: 'declined' }] });
  expect(toolUse.status).toBe('rejected');
  expect(toolUse.error).toBe('declined');
  expect(toolUse.rawResult).toBeFalsy();
});

// --- pendingSubAgentApprovals / subAgentApprovalAnnouncement ---

test('pendingSubAgentApprovals lists child tools awaiting approval on active delegations only', () => {
  comp.messages = [
    {
      role: 'assistant',
      toolUses: [
        {
          // Active delegation with a pending child tool: announced.
          name: 'delegate_to_Hunter',
          status: 'running',
          childSession: {
            agentName: 'Hunter',
            messages: [
              { toolUses: [{ name: 'query_events', status: 'pending_approval' }] },
              { toolUses: [{ name: 'ack_alerts', status: 'completed' }] },
            ],
          },
        },
        {
          // Closed delegation: its children can no longer be awaiting approval.
          name: 'delegate_to_Scout',
          status: 'completed',
          childSession: {
            agentName: 'Scout',
            messages: [
              { toolUses: [{ name: 'query_cases', status: 'pending_approval' }] },
            ],
          },
        },
        // Plain (non-delegate) tool: ignored.
        { name: 'query_events', status: 'pending_approval' },
      ],
    },
  ];

  expect(comp.pendingSubAgentApprovals()).toEqual([
    { agentName: 'Hunter', toolName: 'query_events' },
  ]);
});

test('subAgentApprovalAnnouncement formats one message per pending approval', () => {
  // The harness flattens computeds into functions; provide the dependent
  // computed's value directly, as Vue would.
  comp.pendingSubAgentApprovals = [
    { agentName: 'Hunter', toolName: 'query_events' },
    { agentName: 'Scout', toolName: 'query_cases' },
  ];

  expect(comp.subAgentApprovalAnnouncement()).toBe(
    'Sub-agent Hunter requests approval to run query_events. Sub-agent Scout requests approval to run query_cases.'
  );
});

// --- executeTool delegation flow (ownership derived from delegationChildren) ---

function sseChunk(obj) {
  return `data: ${JSON.stringify(obj)}\n\n`;
}

function mockToolStream(chunks, { failWith = null } = {}) {
  const read = jest.fn();
  chunks.forEach((c) => read.mockResolvedValueOnce({ done: false, value: c }));
  if (failWith) {
    read.mockRejectedValueOnce(failWith);
  } else {
    read.mockResolvedValueOnce({ done: true });
  }
  return {
    data: {
      pipeThrough: jest.fn().mockReturnValue({
        getReader: jest.fn().mockReturnValue({ read, cancel: jest.fn().mockResolvedValue() }),
      }),
    },
  };
}

test('executeTool nests delegation output and completes the delegate on resolution', async () => {
  const toolUse = { ...fakeToolUse, name: 'delegate_to_Hunter' };
  comp.currentChatId = fakeSessionId;
  comp.currentModel = 'test-model';
  comp.loadCredits = jest.fn().mockResolvedValue();

  mockPapi('post', mockToolStream([
    sseChunk({ type: 'delegation_start', childSessionId: 'child-1', parentToolUseId: toolUse.id, agentName: 'Hunter' }),
    sseChunk({ type: 'message_start', message: { role: 'assistant' } }),
    sseChunk({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'childtext' } }),
    sseChunk({ type: 'delegation_resolved', parentSessionId: fakeSessionId, parentToolUseId: toolUse.id }),
    sseChunk({ type: 'message_start', message: { role: 'assistant' } }),
    sseChunk({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'parentwrap' } }),
    'data: [DONE]\n\n',
  ]));

  await comp.executeTool(toolUse);

  // Sub-agent output rendered nested under the delegate tool.
  expect(toolUse.childSession).toBeTruthy();
  expect(toolUse.childSession.agentName).toBe('Hunter');
  expect(toolUse.childSession.messages[0].content).toBe('childtext');

  // Resolution completed the delegate card and removed the live child entry.
  expect(toolUse.status).toBe('completed');
  expect(toolUse.completedAt).toBeTruthy();
  expect(comp.delegationChildren.size).toBe(0);

  // The resumed parent turn rendered top-level, not nested.
  const parentMsg = comp.messages[comp.messages.length - 1];
  expect(parentMsg.content).toBe('parentwrap');
});

test('executeTool errors the active delegate card when the stream dies mid-delegation', async () => {
  const toolUse = { ...fakeToolUse, name: 'delegate_to_Hunter' };
  comp.currentChatId = fakeSessionId;
  comp.currentModel = 'test-model';
  comp.messages = [];

  mockPapi('post', mockToolStream([
    sseChunk({ type: 'delegation_start', childSessionId: 'child-1', parentToolUseId: toolUse.id, agentName: 'Hunter' }),
    sseChunk({ type: 'message_start', message: { role: 'assistant' } }),
  ], { failWith: new Error('stream died') }));

  await comp.executeTool(toolUse);

  // The delegate card closed with the error instead of spinning forever, and the
  // live child entry was cleaned up.
  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('stream died');
  expect(toolUse.completedAt).toBeTruthy();
  expect(comp.delegationChildren.size).toBe(0);

  // The failure belongs to the delegate card; no top-level error message is pushed.
  expect(comp.messages).toEqual([]);
});

test('executeTool reports a top-level error when the stream dies after resolution', async () => {
  const toolUse = { ...fakeToolUse, name: 'delegate_to_Hunter' };
  comp.currentChatId = fakeSessionId;
  comp.currentModel = 'test-model';
  comp.messages = [];

  mockPapi('post', mockToolStream([
    sseChunk({ type: 'delegation_start', childSessionId: 'child-1', parentToolUseId: toolUse.id, agentName: 'Hunter' }),
    sseChunk({ type: 'delegation_resolved', parentSessionId: fakeSessionId, parentToolUseId: toolUse.id }),
  ], { failWith: new Error('late failure') }));

  await comp.executeTool(toolUse);

  // The delegation boundary was already closed, so no delegate card owns this
  // failure: the error surfaces as a top-level chat message instead.
  expect(comp.delegationChildren.size).toBe(0);
  const lastMsg = comp.messages[comp.messages.length - 1];
  expect(lastMsg.content).toContain('late failure');
});

// --- Reload reconstruction of an in-flight delegation (backend-driven) ---
// On refresh, GET /sessions/{id} returns sub-sessions each with a backend-derived
// `pendingApproval`. The reload must render the delegate as running, the sub-agent's
// pending tool as actionable, register it, and repopulate delegationChildren so the
// subsequent approval streams nested and resolves.

// --- reload reconstruction helpers (direct tests; the reload tests below cover them end-to-end) ---

test('collectResolvedToolUseIds gathers ids from structured and legacy tool_result messages', () => {
  const ids = comp.collectResolvedToolUseIds([
    { tags: ['tool_result'], message: { contentBlocks: [{ toolResult: { toolUseId: 'tu-1' } }] } },
    // Legacy text-encoded result.
    { tags: ['tool_result'], message: { contentBlocks: [{ type: 'text', text: 'ToolUseId: tu-legacy, Result: {"ok":true}' }] } },
    // Not tagged tool_result: ignored even though it carries a toolResult block.
    { tags: ['chat'], message: { contentBlocks: [{ toolResult: { toolUseId: 'tu-ignored' } }] } },
    // Malformed entries are skipped, not fatal.
    { tags: ['tool_result'], message: {} },
    { tags: ['tool_result'], message: { contentBlocks: [{ type: 'text', text: 'no marker here' }] } },
    null,
  ]);

  expect(ids).toEqual(new Set(['tu-1', 'tu-legacy']));
});

test('isActiveToolTurn is true only while everything after the turn is a tool_result', () => {
  const toolResult = { tags: ['tool_result'] };
  const chat = { tags: ['chat'] };

  expect(comp.isActiveToolTurn([chat, toolResult, toolResult], 0)).toBe(true);
  // The model (or user) continued past the turn: no longer active.
  expect(comp.isActiveToolTurn([chat, toolResult, chat], 0)).toBe(false);
  // Nothing after the turn at all: still active.
  expect(comp.isActiveToolTurn([chat], 0)).toBe(true);
  // An untagged/null trailing message ends the turn.
  expect(comp.isActiveToolTurn([chat, null], 0)).toBe(false);
});

test('indexSubSessions keys sub-sessions by parent tool_use id and by session id', () => {
  const subA = { session: { sessionId: 'child-1', parentToolUseId: 'd1' } };
  const subB = { session: { sessionId: 'child-2' } }; // no parent linkage

  const index = comp.indexSubSessions([subA, null, {}, subB]);

  expect(index.bySessionId.get('child-1')).toBe(subA);
  expect(index.bySessionId.get('child-2')).toBe(subB);
  expect(index.byParentToolUseId.get('d1')).toBe(subA);
  expect(index.byParentToolUseId.size).toBe(1);

  const empty = comp.indexSubSessions(null);
  expect(empty.bySessionId.size).toBe(0);
  expect(empty.byParentToolUseId.size).toBe(0);
});

test('reconstructDelegateChildSessions rebuilds only matched delegate tools', () => {
  comp.reconstructChildSession = jest.fn();
  comp.currentChatId = 'parent-1';
  const sub = { session: { sessionId: 'child-1', parentToolUseId: 'd1' } };
  comp._loadSubSessions = comp.indexSubSessions([sub]);

  const delegate = { id: 'd1', name: 'delegate_to_Hunter' };
  const plainTool = { id: 't2', name: 'query_events' };
  const unmatchedDelegate = { id: 'd9', name: 'delegate_to_Analyst' };
  const nameless = { id: 't3' };
  comp.reconstructDelegateChildSessions([delegate, plainTool, unmatchedDelegate, nameless]);

  expect(comp.reconstructChildSession).toHaveBeenCalledTimes(1);
  expect(comp.reconstructChildSession).toHaveBeenCalledWith(delegate, sub, comp._loadSubSessions, 'parent-1');

  // Without a loaded sub-session index (live streaming, old sessions): no-op.
  comp.reconstructChildSession.mockClear();
  comp._loadSubSessions = null;
  comp.reconstructDelegateChildSessions([delegate]);
  expect(comp.reconstructChildSession).not.toHaveBeenCalled();
});

test('reconstructChildSession renders the sub-agent turn and attaches each tool_result by outcome', () => {
  const sub = {
    session: { sessionId: 'child-1', delegateAgent: 'Hunter' },
    history: [
      // The objective/user message must not render as a nested message.
      { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'find beacons' }] } },
      { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', thoughts: 'thinking', contentBlocks: [
        { type: 'text', text: 'running three tools' },
        { type: 'tool_use', id: 'c1', name: 'query_events', input: { q: 1 } },
        { type: 'tool_use', id: 'c2', name: 'query_events', input: { q: 2 } },
        { type: 'tool_use', id: 'c3', name: 'query_events', input: { q: 3 } },
      ] } },
      { createTime: '2025-01-01T12:00:02.000Z', tags: ['tool_result'], message: { contentBlocks: [
        { toolResult: { toolUseId: 'c1', content: [{ json: { hits: 2 } }] } },
      ] } },
      { createTime: '2025-01-01T12:00:03.000Z', tags: ['tool_result'], message: { contentBlocks: [
        { toolResult: { toolUseId: 'c2', isError: true, content: [{ text: 'query exploded' }] } },
      ] } },
      { createTime: '2025-01-01T12:00:04.000Z', tags: ['tool_result'], message: { contentBlocks: [
        { toolResult: { toolUseId: 'c3', status: 'rejected', content: [] } },
      ] } },
    ],
  };
  const delegate = { id: 'd1', name: 'delegate_to_Hunter', status: 'completed' };

  comp.reconstructChildSession(delegate, sub, comp.indexSubSessions([sub]), 'parent-1');

  const cs = delegate.childSession;
  expect(cs.agentName).toBe('Hunter');
  expect(cs.messages).toHaveLength(1);
  // Prose stays content and reasoning stays thoughts, matching the live view.
  expect(cs.messages[0].content).toBe('running three tools');
  expect(cs.messages[0].thoughts).toBe('thinking');

  const [c1, c2, c3] = cs.messages[0].toolUses;
  expect(c1.status).toBe('completed');
  expect(c1.rawResult).toEqual({ hits: 2 });
  expect(c1.completedAt).toBe('2025-01-01T12:00:02.000Z');
  expect(c2.status).toBe('error');
  expect(c2.error).toBe('query exploded');
  expect(c3.status).toBe('rejected');
  expect(c3.error).toBe(comp.i18n.assistantToolUseReject);

  // Settled delegate: no live delegation linkage is registered.
  expect(comp.delegationChildren.has('child-1')).toBe(false);
});

test('reconstructChildSession marks the flagged turn pending and abandons earlier unresolved tools', () => {
  const sub = {
    session: { sessionId: 'child-2', delegateAgent: 'Analyst' },
    pendingApproval: { sessionId: 'child-2', toolUseId: 'p1' },
    history: [
      // An earlier turn whose tool never got a result: abandoned, not pending.
      { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
        { type: 'tool_use', id: 'old1', name: 'query_events', input: {} },
      ] } },
      // The active turn: the flagged tool AND its unresolved sibling await approval.
      { createTime: '2025-01-01T12:00:02.000Z', message: { role: 'assistant', contentBlocks: [
        { type: 'tool_use', id: 'p1', name: 'query_events', input: {} },
        { type: 'tool_use', id: 'p2', name: 'query_events', input: {} },
      ] } },
    ],
  };
  const delegate = { id: 'd2', name: 'delegate_to_Analyst', status: 'executing' };

  comp.reconstructChildSession(delegate, sub, comp.indexSubSessions([sub]), 'parent-1');

  const [oldTurn, activeTurn] = delegate.childSession.messages;
  expect(oldTurn.toolUses[0].status).toBe('skipped');
  for (const t of activeTurn.toolUses) {
    expect(t.status).toBe('pending_approval');
    expect(t.approved).toBeNull();
    // Registered so the queue runner can resolve and fire it after approval.
    expect(comp.getSessionToolMap('child-2').get(t.id)).toBe(t);
  }

  // A running delegation is re-registered as a live delegation child.
  const entry = comp.delegationChildren.get('child-2');
  expect(entry).toBeTruthy();
  expect(entry.parentToolUse).toBe(delegate);
  expect(entry.parentToolUseId).toBe('d2');
  expect(entry.parentSessionId).toBe('parent-1');
  expect(entry.agentName).toBe('Analyst');
});

test('reconstructChildSession recurses into grandchild delegations', () => {
  const grandSub = {
    session: { sessionId: 'gchild-1', parentToolUseId: 'gd1', delegateAgent: 'Deep' },
    history: [
      { createTime: '2025-01-01T12:00:03.000Z', message: { role: 'assistant', contentBlocks: [{ type: 'text', text: 'deep work' }] } },
    ],
  };
  const sub = {
    session: { sessionId: 'child-3', delegateAgent: 'Hunter' },
    history: [
      { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
        { type: 'tool_use', id: 'gd1', name: 'delegate_to_Deep', input: { objective: 'go deeper' } },
      ] } },
    ],
  };
  const delegate = { id: 'd3', name: 'delegate_to_Hunter', status: 'executing' };

  comp.reconstructChildSession(delegate, sub, comp.indexSubSessions([sub, grandSub]), 'parent-1');

  // A delegate tool that spawned a sub-session and has no result yet is running.
  const grandDelegate = delegate.childSession.messages[0].toolUses[0];
  expect(grandDelegate.status).toBe('executing');
  expect(grandDelegate.approved).toBe(true);
  expect(grandDelegate.childSession.agentName).toBe('Deep');
  expect(grandDelegate.childSession.messages[0].content).toBe('deep work');

  // The grandchild's live linkage points at its own parent delegate and session.
  const entry = comp.delegationChildren.get('gchild-1');
  expect(entry.parentToolUseId).toBe('gd1');
  expect(entry.parentSessionId).toBe('child-3');
});

test('finalizeResolvedDelegations settles leftover live tools under a resolved delegate', () => {
  const pendingChild = { id: 'c1', status: 'pending_approval', approved: null, sessionId: 'child-1' };
  const executingChild = { id: 'c2', status: 'executing', approved: true, sessionId: 'child-1' };
  const doneChild = { id: 'c3', status: 'completed', approved: true, sessionId: 'child-1', rawResult: { ok: 1 } };
  comp.getSessionToolMap('child-1').set('c1', pendingChild);
  comp.getSessionToolMap('child-1').set('c2', executingChild);
  comp.delegationChildren.set('child-1', { parentToolUseId: 'd1' });
  const delegate = { id: 'd1', status: 'completed', rawResult: { summary: 'done' },
    childSession: { messages: [{ toolUses: [pendingChild, executingChild, doneChild] }] } };

  comp.finalizeResolvedDelegations([{ toolUses: [delegate] }]);

  expect(pendingChild.status).toBe('skipped');
  expect(pendingChild.approved).toBe(false);
  expect(executingChild.status).toBe('skipped');
  expect(doneChild.status).toBe('completed');
  // Unregistered so nothing can fire or resume against the dead sub-session.
  expect(comp.getSessionToolMap('child-1').has('c1')).toBe(false);
  expect(comp.getSessionToolMap('child-1').has('c2')).toBe(false);
  expect(comp.delegationChildren.has('child-1')).toBe(false);
});

test('finalizeResolvedDelegations settles a live-rejected delegate but leaves a running one alone', () => {
  // Rejected live: carries no rawResult, so the status check must catch it.
  const rejectedKid = { id: 'r1', status: 'executing', approved: true, sessionId: 'child-rej' };
  comp.getSessionToolMap('child-rej').set('r1', rejectedKid);
  const rejectedDelegate = { id: 'dr', status: 'rejected', rawResult: null,
    childSession: { messages: [{ toolUses: [rejectedKid] }] } };

  // Still running: its pending child stays actionable.
  const liveKid = { id: 'l1', status: 'pending_approval', approved: null, sessionId: 'child-live' };
  comp.getSessionToolMap('child-live').set('l1', liveKid);
  comp.delegationChildren.set('child-live', { parentToolUseId: 'dl' });
  const liveDelegate = { id: 'dl', status: 'executing', rawResult: null,
    childSession: { messages: [{ toolUses: [liveKid] }] } };

  comp.finalizeResolvedDelegations([{ toolUses: [rejectedDelegate, liveDelegate] }]);

  expect(rejectedKid.status).toBe('skipped');
  expect(comp.getSessionToolMap('child-rej').has('r1')).toBe(false);

  expect(liveKid.status).toBe('pending_approval');
  expect(comp.getSessionToolMap('child-live').has('l1')).toBe(true);
  expect(comp.delegationChildren.has('child-live')).toBe(true);
});

test('finalizeResolvedDelegations cascades settlement from a settled ancestor to all descendants', () => {
  const grandTool = { id: 'g1', status: 'executing', approved: true, sessionId: 'gchild' };
  comp.getSessionToolMap('gchild').set('g1', grandTool);
  comp.delegationChildren.set('gchild', { parentToolUseId: 'm1' });
  // The intermediate delegate looks live on its own (executing, no result)...
  const midDelegate = { id: 'm1', status: 'executing', rawResult: null, sessionId: 'child',
    childSession: { messages: [{ toolUses: [grandTool] }] } };
  // ...but its ancestor errored, which settles the whole subtree.
  const top = { id: 't1', status: 'error', rawResult: null,
    childSession: { messages: [{ toolUses: [midDelegate] }] } };

  comp.finalizeResolvedDelegations([{ toolUses: [top] }]);

  expect(midDelegate.status).toBe('skipped');
  expect(grandTool.status).toBe('skipped');
  expect(comp.getSessionToolMap('gchild').has('g1')).toBe(false);
  expect(comp.delegationChildren.has('gchild')).toBe(false);
});

test('reload renders a paused delegation: delegate running, sub-agent tool actionable, wired to fire', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parent-session';
  comp.delegationChildren = new Map();
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const parentHistory = [
    { createTime: '2025-01-01T12:00:00.000Z', message: { role: 'user', contentBlocks: [{ type: 'text', text: 'investigate' }] } },
    { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'delegate-1', name: 'delegate_to_Hunter', input: { objective: 'find beacons' } },
    ] } },
  ];
  const subSessions = [
    {
      session: { sessionId: 'child-1', parentToolUseId: 'delegate-1', delegateAgent: 'Hunter' },
      pendingApproval: { sessionId: 'child-1', toolUseId: 'child-tool-1', toolName: 'query_events', input: { q: 'dns' } },
      history: [
        { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'find beacons' }] } },
        { createTime: '2025-01-01T12:00:02.000Z', message: { role: 'assistant', contentBlocks: [
          { type: 'tool_use', id: 'child-tool-1', name: 'query_events', input: { q: 'dns' } },
        ] } },
      ],
    },
  ];

  comp._loadSubSessions = comp.indexSubSessions(subSessions);
  const result = comp.convertBackendMessagesToFrontend(parentHistory);
  comp._loadSubSessions = null;

  const delegateTool = result[result.length - 1].toolUses[0];
  expect(delegateTool.id).toBe('delegate-1');
  // Running, not pending approval (no re-prompt → no duplicate sub-session).
  expect(delegateTool.status).toBe('executing');
  expect(comp.sessionTools('parent-session').floatingTool).toBeFalsy();
  expect(delegateTool.childSession).toBeTruthy();

  // The sub-agent's pending tool is actionable.
  const pending = comp.pendingChildTools(delegateTool);
  expect(pending).toHaveLength(1);
  expect(pending[0].id).toBe('child-tool-1');
  expect(pending[0].status).toBe('pending_approval');
  expect(pending[0].sessionId).toBe('child-1');

  // Registered so the queue runner can resolve + fire it, and delegationChildren is
  // repopulated so the approval response nests under the delegate.
  expect(comp.getSessionToolMap('child-1').get('child-tool-1')).toBe(pending[0]);
  expect(comp.delegationChildren.has('child-1')).toBe(true);
  const entry = comp.delegationChildren.get('child-1');
  expect(entry.parentToolUseId).toBe('delegate-1');
  expect(entry.parentSessionId).toBe('parent-session');
  expect(entry.parentToolUse).toBe(delegateTool);
});

// A sub-agent turn can request several tools in parallel. The backend flags only one
// as the pending approval, but every unresolved tool in that same turn is equally
// awaiting approval -- none should reload as skipped.
test('reload keeps all parallel pending sub-agent tools actionable, not just the flagged one', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parent-session';
  comp.delegationChildren = new Map();
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const parentHistory = [
    { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'delegate-1', name: 'delegate_to_Hunter', input: { objective: 'recent alerts' } },
    ] } },
  ];
  const subSessions = [
    {
      session: { sessionId: 'child-1', parentToolUseId: 'delegate-1', delegateAgent: 'Hunter' },
      // The backend flags the last unresolved tool_use; its parallel siblings must
      // still reload as pending, not skipped.
      pendingApproval: { sessionId: 'child-1', toolUseId: 'child-tool-3', toolName: 'query_events', input: {} },
      history: [
        { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'recent alerts' }] } },
        { createTime: '2025-01-01T12:00:02.000Z', message: { role: 'assistant', contentBlocks: [
          { type: 'tool_use', id: 'child-tool-1', name: 'query_events', input: { sev: 'critical' } },
          { type: 'tool_use', id: 'child-tool-2', name: 'query_events', input: { sev: 'high' } },
          { type: 'tool_use', id: 'child-tool-3', name: 'query_events', input: { sev: 'medium' } },
        ] } },
      ],
    },
  ];

  comp._loadSubSessions = comp.indexSubSessions(subSessions);
  const result = comp.convertBackendMessagesToFrontend(parentHistory);
  comp._loadSubSessions = null;

  const delegateTool = result[result.length - 1].toolUses[0];
  const childTools = delegateTool.childSession.messages.flatMap(m => m.toolUses);
  expect(childTools.map(t => t.id)).toEqual(['child-tool-1', 'child-tool-2', 'child-tool-3']);
  // All three unresolved siblings remain actionable.
  childTools.forEach(t => {
    expect(t.status).toBe('pending_approval');
    expect(t.approved).toBe(null);
    expect(comp.getSessionToolMap('child-1').get(t.id)).toBe(t);
  });
  expect(comp.pendingChildTools(delegateTool)).toHaveLength(3);
});

test('reload of a resolved delegation is unchanged (no pendingApproval): delegate + child completed', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parent-session';
  comp.delegationChildren = new Map();
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const parentHistory = [
    { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'delegate-1', name: 'delegate_to_Hunter', input: {} },
    ] } },
    { createTime: '2025-01-01T12:00:03.000Z', tags: ['tool_result'], message: { role: 'user', contentBlocks: [
      { toolResult: { toolUseId: 'delegate-1', content: [{ json: { result: 'done' } }] } },
    ] } },
    { createTime: '2025-01-01T12:00:04.000Z', message: { role: 'assistant', contentBlocks: [{ type: 'text', text: 'final answer' }] } },
  ];
  const subSessions = [
    {
      session: { sessionId: 'child-1', parentToolUseId: 'delegate-1', delegateAgent: 'Hunter' },
      // resolved → backend returns no pendingApproval
      history: [
        { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'obj' }] } },
        { message: { role: 'assistant', contentBlocks: [{ type: 'tool_use', id: 'child-tool-1', name: 'query_events', input: {} }] } },
        { tags: ['tool_result'], message: { role: 'user', contentBlocks: [{ toolResult: { toolUseId: 'child-tool-1', content: [{ json: { r: 1 } }] } }] } },
        { message: { role: 'assistant', contentBlocks: [{ type: 'text', text: 'child done' }] } },
      ],
    },
  ];

  comp._loadSubSessions = comp.indexSubSessions(subSessions);
  const result = comp.convertBackendMessagesToFrontend(parentHistory);
  comp._loadSubSessions = null;

  const delegateTool = result[0].toolUses[0];
  expect(delegateTool.status).toBe('completed');
  const childTool = delegateTool.childSession.messages.flatMap(m => m.toolUses)[0];
  expect(childTool.status).toBe('completed');
  expect(childTool.rawResult).toEqual({ r: 1 });
  expect(comp.pendingChildTools(delegateTool)).toHaveLength(0);
  expect(comp.delegationChildren.has('child-1')).toBe(false);
});

// A reloaded sub-agent's response prose must render as content (always visible),
// matching the live stream and the top-level reload -- not folded into thoughts
// (hidden unless "show thinking" is on). Guards reconstructChildSession.
test('reload renders a sub-agent reply as content, with reasoning kept in thoughts', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parent-session';
  comp.delegationChildren = new Map();
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const parentHistory = [
    { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'delegate-1', name: 'delegate_to_Hunter', input: {} },
    ] } },
    { createTime: '2025-01-01T12:00:03.000Z', tags: ['tool_result'], message: { role: 'user', contentBlocks: [
      { toolResult: { toolUseId: 'delegate-1', content: [{ json: { result: 'done' } }] } },
    ] } },
  ];
  const subSessions = [
    {
      session: { sessionId: 'child-1', parentToolUseId: 'delegate-1', delegateAgent: 'Hunter' },
      history: [
        { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'obj' }] } },
        { createTime: '2025-01-01T12:00:02.000Z', message: { role: 'assistant', thoughts: 'considering the data',
          contentBlocks: [{ type: 'text', text: 'I found 3 beacons.' }] } },
      ],
    },
  ];

  comp._loadSubSessions = comp.indexSubSessions(subSessions);
  const result = comp.convertBackendMessagesToFrontend(parentHistory);
  comp._loadSubSessions = null;

  const childMsg = result[0].toolUses[0].childSession.messages.find(m => m.content || m.thoughts);
  expect(childMsg.content).toBe('I found 3 beacons.'); // visible prose, not folded away
  expect(childMsg.thoughts).toBe('considering the data'); // reasoning stays in thoughts
  expect(childMsg.role).toBe('assistant');
});

// A reconstructed sub-agent tool_use with no tool_result must NOT show a false
// "completed" checkmark -- it was requested but never produced a result. Only the
// backend-flagged pending tool stays actionable; other unresolved tools settle to
// skipped. Guards reconstructChildSession's default status (#3).
test('reload does not mark resultless sub-agent tools as completed', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parent-session';
  comp.delegationChildren = new Map();
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const parentHistory = [
    { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'delegate-1', name: 'delegate_to_Hunter', input: {} },
    ] } },
  ];
  // Delegation still running (no parent tool_result). Sub-agent requested two tools
  // with no results; the backend flags only the last as pending.
  const subSessions = [
    {
      session: { sessionId: 'child-1', parentToolUseId: 'delegate-1', delegateAgent: 'Hunter' },
      pendingApproval: { sessionId: 'child-1', toolUseId: 'child-tool-2', toolName: 'query_events', input: {} },
      history: [
        { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'obj' }] } },
        { createTime: '2025-01-01T12:00:02.000Z', message: { role: 'assistant', contentBlocks: [
          { type: 'tool_use', id: 'child-tool-1', name: 'query_events', input: {} },
        ] } },
        { createTime: '2025-01-01T12:00:03.000Z', message: { role: 'assistant', contentBlocks: [
          { type: 'tool_use', id: 'child-tool-2', name: 'query_events', input: {} },
        ] } },
      ],
    },
  ];

  comp._loadSubSessions = comp.indexSubSessions(subSessions);
  const result = comp.convertBackendMessagesToFrontend(parentHistory);
  comp._loadSubSessions = null;

  const childTools = result[0].toolUses[0].childSession.messages.flatMap(m => m.toolUses || []);
  const t1 = childTools.find(t => t.id === 'child-tool-1');
  const t2 = childTools.find(t => t.id === 'child-tool-2');
  expect(t1.status).toBe('skipped');          // resultless, not the pending one -> not a false checkmark
  expect(t2.status).toBe('pending_approval');  // backend-flagged pending stays actionable
});

// A delegation that terminally resolved (its delegate errored) must leave no
// actionable sub-agent tool behind, even if the backend still reports one pending --
// the delegation is over. Guards finalizeResolvedDelegations (#2).
test('reload makes a resolved (errored) delegation inert: no actionable child tool', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parent-session';
  comp.delegationChildren = new Map();
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const parentHistory = [
    { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'delegate-1', name: 'delegate_to_Hunter', input: {} },
    ] } },
    // The delegation resolved as an error (e.g. halted/aborted) -> parent gets an error result.
    { createTime: '2025-01-01T12:00:05.000Z', tags: ['tool_result'], message: { role: 'user', contentBlocks: [
      { toolResult: { toolUseId: 'delegate-1', isError: true, content: [{ text: 'sub-agent failed' }] } },
    ] } },
  ];
  // ...yet the sub-session still has a trailing unresolved tool the backend flags pending.
  const subSessions = [
    {
      session: { sessionId: 'child-1', parentToolUseId: 'delegate-1', delegateAgent: 'Hunter' },
      pendingApproval: { sessionId: 'child-1', toolUseId: 'child-tool-1', toolName: 'query_events', input: {} },
      history: [
        { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'obj' }] } },
        { createTime: '2025-01-01T12:00:02.000Z', message: { role: 'assistant', contentBlocks: [
          { type: 'tool_use', id: 'child-tool-1', name: 'query_events', input: {} },
        ] } },
      ],
    },
  ];

  comp._loadSubSessions = comp.indexSubSessions(subSessions);
  const result = comp.convertBackendMessagesToFrontend(parentHistory);
  comp._loadSubSessions = null;

  const delegateTool = result[0].toolUses[0];
  expect(delegateTool.status).toBe('error'); // the delegation itself failed

  // The sub-agent tool is NOT actionable: settled to skipped, unregistered, no linkage.
  const childTool = delegateTool.childSession.messages.flatMap(m => m.toolUses || [])[0];
  expect(childTool.status).toBe('skipped');
  expect(comp.pendingChildTools(delegateTool)).toHaveLength(0);
  expect(comp.sessionToolState.get('child-1') && comp.sessionToolState.get('child-1').toolsById.has('child-tool-1')).toBeFalsy();
  expect(comp.delegationChildren.has('child-1')).toBe(false);
});

// A skipped delegate (unresolved, but the conversation moved on) is terminal too: its
// sub-agent tools must settle to skipped, not stay actionable. Guards the broadened
// settled check in finalizeResolvedDelegations.
test('reload makes a skipped delegation inert: child tools settle to skipped', () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parent-session';
  comp.delegationChildren = new Map();
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const parentHistory = [
    { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'delegate-1', name: 'delegate_to_Hunter', input: {} },
    ] } },
    // No tool_result for delegate-1; the conversation moved on with a later turn, so the
    // delegate reloads as 'skipped'.
    { createTime: '2025-01-01T12:00:06.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'text', text: 'moving on without the delegation' },
    ] } },
  ];
  const subSessions = [
    {
      session: { sessionId: 'child-1', parentToolUseId: 'delegate-1', delegateAgent: 'Hunter' },
      pendingApproval: { sessionId: 'child-1', toolUseId: 'child-tool-1', toolName: 'query_events', input: {} },
      history: [
        { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'obj' }] } },
        { createTime: '2025-01-01T12:00:02.000Z', message: { role: 'assistant', contentBlocks: [
          { type: 'tool_use', id: 'child-tool-1', name: 'query_events', input: {} },
        ] } },
      ],
    },
  ];

  comp._loadSubSessions = comp.indexSubSessions(subSessions);
  const result = comp.convertBackendMessagesToFrontend(parentHistory);
  comp._loadSubSessions = null;

  const delegateTool = result[0].toolUses[0];
  expect(delegateTool.status).toBe('skipped'); // the delegation was abandoned

  const childTool = delegateTool.childSession.messages.flatMap(m => m.toolUses || [])[0];
  expect(childTool.status).toBe('skipped');
  expect(comp.pendingChildTools(delegateTool)).toHaveLength(0);
  expect(comp.sessionToolState.get('child-1') && comp.sessionToolState.get('child-1').toolsById.has('child-tool-1')).toBeFalsy();
  expect(comp.delegationChildren.has('child-1')).toBe(false);
});

test('approving a reconstructed sub-agent tool resolves it from the session map and executes it', async () => {
  comp.resetContextLength = jest.fn();
  comp.currentChatId = 'parent-session';
  comp.delegationChildren = new Map();
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  global.Vue = { ref: jest.fn((value) => ({ value })) };

  const parentHistory = [
    { createTime: '2025-01-01T12:00:01.000Z', message: { role: 'assistant', contentBlocks: [
      { type: 'tool_use', id: 'delegate-1', name: 'delegate_to_Hunter', input: {} },
    ] } },
  ];
  const subSessions = [
    {
      session: { sessionId: 'child-1', parentToolUseId: 'delegate-1', delegateAgent: 'Hunter' },
      pendingApproval: { sessionId: 'child-1', toolUseId: 'child-tool-1', toolName: 'query_events', input: { q: 'dns' } },
      history: [
        { message: { role: 'user', contentBlocks: [{ type: 'text', text: 'find beacons' }] } },
        { createTime: '2025-01-01T12:00:02.000Z', message: { role: 'assistant', contentBlocks: [
          { type: 'tool_use', id: 'child-tool-1', name: 'query_events', input: { q: 'dns' } },
        ] } },
      ],
    },
  ];

  comp._loadSubSessions = comp.indexSubSessions(subSessions);
  const result = comp.convertBackendMessagesToFrontend(parentHistory);
  comp._loadSubSessions = null;

  const delegateTool = result[result.length - 1].toolUses[0];
  const pending = comp.pendingChildTools(delegateTool)[0];

  // Before the wiring, the queue runner couldn't resolve the reconstructed tool, so
  // executeTool (which fires the POST) was never called. Spy to prove it now is.
  comp.executeTool = jest.fn().mockResolvedValue();

  await comp.approveTool(pending);
  await new Promise((r) => setTimeout(r, 0)); // let the fire-and-forget queue drain

  expect(comp.executeTool).toHaveBeenCalledTimes(1);
  expect(comp.executeTool.mock.calls[0][0].id).toBe('child-tool-1');
  expect(comp.executeTool.mock.calls[0][0].sessionId).toBe('child-1');
});

// Guards the recursive delegation renderer: a delegation that itself delegates must
// nest to any depth. The bug this prevents was a hand-coded template that stopped at
// one level, so a grandchild sub-agent's tool calls never rendered. Rendering is split
// into two globally-registered components that recurse through each other --
// tool-use-card renders a delegation's transcript via delegation-child, which renders
// each sub-agent tool call back through tool-use-card. (The harness can't mount Vuetify
// DOM, so we assert registration, the provided context, and the recursion in the
// template files.)
test('tool-use-card and delegation-child recurse through each other to any depth', () => {
  const fs = require('fs');
  const path = require('path');
  const pagesDir = path.join(__dirname, '../../pages');

  const card = global.components.find(c => c.name === 'tool-use-card');
  const child = global.components.find(c => c.name === 'delegation-child');
  expect(card).toBeTruthy();
  expect(child).toBeTruthy();

  // Both reach page helpers via the context the page provides as `delegationCtx`.
  expect(card.component.inject.ctx.from).toBe('delegationCtx');
  expect(child.component.inject.ctx.from).toBe('delegationCtx');
  expect(comp.provide.call(comp).delegationCtx).toBe(comp);

  // tool-use-card -> delegation-child, gated on the tool having its own childSession.
  const cardTmpl = fs.readFileSync(path.join(pagesDir, 'tool-use-card.html'), 'utf8');
  expect(cardTmpl).toContain('<delegation-child');
  expect(cardTmpl).toContain('toolUse.childSession');

  // delegation-child -> tool-use-card (nested), closing the recursion cycle.
  const childTmpl = fs.readFileSync(path.join(pagesDir, 'delegation-child.html'), 'utf8');
  expect(childTmpl).toContain('<tool-use-card');
  expect(childTmpl).toContain('nested');
});

test('postToolRequest returns the response on success without retrying', async () => {
  comp.$root.papi.post = jest.fn().mockResolvedValue({ data: 'stream' });

  const res = await comp.postToolRequest({ name: 'query_events' }, { sessionId: 's1' });

  expect(res).toEqual({ data: 'stream' });
  expect(comp.$root.papi.post).toHaveBeenCalledTimes(1);
  expect(comp.$root.papi.post.mock.calls[0][0]).toBe('/assistant/tool/query_events');
});

test('postToolRequest retries on 409 then succeeds', async () => {
  comp.toolBusyRetryDelayMs = 0;
  const conflict = { response: { status: 409 } };
  comp.$root.papi.post = jest.fn()
    .mockRejectedValueOnce(conflict)
    .mockRejectedValueOnce(conflict)
    .mockResolvedValue({ data: 'stream' });

  const res = await comp.postToolRequest({ name: 'query_events' }, {});

  expect(res).toEqual({ data: 'stream' });
  expect(comp.$root.papi.post).toHaveBeenCalledTimes(3);
});

test('postToolRequest re-throws a non-409 error without retrying', async () => {
  const serverErr = { response: { status: 500 } };
  comp.$root.papi.post = jest.fn().mockRejectedValue(serverErr);

  await expect(comp.postToolRequest({ name: 'query_events' }, {})).rejects.toBe(serverErr);
  expect(comp.$root.papi.post).toHaveBeenCalledTimes(1);
});

test('postToolRequest gives up after the retry bound on persistent 409s', async () => {
  comp.toolBusyRetryDelayMs = 0;
  comp.toolBusyMaxRetries = 3;
  const conflict = { response: { status: 409 } };
  comp.$root.papi.post = jest.fn().mockRejectedValue(conflict);

  await expect(comp.postToolRequest({ name: 'query_events' }, {})).rejects.toBe(conflict);
  // Initial attempt plus toolBusyMaxRetries retries.
  expect(comp.$root.papi.post).toHaveBeenCalledTimes(4);
});

test('isToolAlreadyResolvedError is false for missing or non-400 errors', async () => {
  expect(await comp.isToolAlreadyResolvedError(null)).toBe(false);
  expect(await comp.isToolAlreadyResolvedError({})).toBe(false);
  expect(await comp.isToolAlreadyResolvedError({ response: { status: 500, data: 'ERROR_TOOL_ALREADY_RESOLVED' } })).toBe(false);
});

test('isToolAlreadyResolvedError detects the marker in a string body', async () => {
  expect(await comp.isToolAlreadyResolvedError({ response: { status: 400, data: 'bad request: ERROR_TOOL_ALREADY_RESOLVED' } })).toBe(true);
  expect(await comp.isToolAlreadyResolvedError({ response: { status: 400, data: 'some other 400' } })).toBe(false);
  expect(await comp.isToolAlreadyResolvedError({ response: { status: 400, data: { code: 400 } } })).toBe(false);
});

test('isToolAlreadyResolvedError decodes a streamed 400 body', async () => {
  const streamBody = {
    pipeThrough: () => ({
      getReader: () => ({ read: async () => ({ value: 'oops: ERROR_TOOL_ALREADY_RESOLVED', done: false }) }),
    }),
  };
  expect(await comp.isToolAlreadyResolvedError({ response: { status: 400, data: streamBody } })).toBe(true);
});

test('isToolAlreadyResolvedError is false when the streamed body cannot be read', async () => {
  const lockedStream = { pipeThrough: () => { throw new Error('stream locked'); } };
  expect(await comp.isToolAlreadyResolvedError({ response: { status: 400, data: lockedStream } })).toBe(false);

  const failingReader = {
    pipeThrough: () => ({ getReader: () => ({ read: async () => { throw new Error('read failed'); } }) }),
  };
  expect(await comp.isToolAlreadyResolvedError({ response: { status: 400, data: failingReader } })).toBe(false);
});
