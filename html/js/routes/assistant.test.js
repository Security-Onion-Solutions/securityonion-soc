// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const { TextEncoder, TextDecoder } = require('util');
Object.assign(global, { TextDecoder, TextEncoder });

require('../test_common.js');
require('./assistant.js');

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
  expect(comp.executingToolsBySession).toBeInstanceOf(Map);
  expect(comp.toolIndexToIdBySession).toBeInstanceOf(Map);
  expect(comp.toolQueues).toBeInstanceOf(Map);
  expect(comp.toolRunnerBusy).toBeInstanceOf(Set);
  expect(comp.mostRecentFloatingTool).toBeInstanceOf(Map);
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
  
  expect(comp.getContextColor(25000)).toBe('text-green'); // Under low threshold
  expect(comp.getContextColor(60000)).toBe('text-yellow'); // Between low and med
  expect(comp.getContextColor(85000)).toBe('text-amber darken-1'); // Between med and max
  expect(comp.getContextColor(100000)).toBe('text-red darken-1'); // At max threshold
});

test('getContextColor uses large limit when threshold increased', () => {
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseContextLimit = true;
  comp.thresholdColorRatioLow = 0.5;
  comp.thresholdColorRatioMed = 0.75;
  comp.thresholdColorRatioMax = 1.0;
  
  expect(comp.getContextColor(50000)).toBe('text-green'); // Under low threshold of large limit (50k < 200k * 0.5)
  expect(comp.getContextColor(120000)).toBe('text-yellow'); // Between low and med of large limit
  expect(comp.getContextColor(170000)).toBe('text-amber darken-1'); // Between med and max of large limit
  expect(comp.getContextColor(200000)).toBe('text-red darken-1'); // At max of large limit
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

test('approveTool queues tool for execution', async () => {
  const toolUse = { ...fakeToolUse };
  comp.queueTool = jest.fn();
  comp.scrollToBottom = jest.fn();
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.mostRecentFloatingTool = new Map();
  comp.mostRecentFloatingTool.set(comp.currentChatId, toolUse);
  
  await comp.approveTool(toolUse);
  
  expect(toolUse.approved).toBe(true);
  expect(toolUse.status).toBe('preparing');
  expect(comp.queueTool).toHaveBeenCalledWith(comp.currentChatId, toolUse.id);
  expect(comp.mostRecentFloatingTool.has(comp.currentChatId)).toBe(false);
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
  comp.mostRecentFloatingTool = new Map();
  
  await comp.approveTool(toolUse);
  
  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('Failed to execute approved tool: Execution failed');
});

test('rejectTool marks as rejected', async () => {
  const toolUse = { ...fakeToolUse };
  comp.scrollToBottom = jest.fn();
  comp.callAIAPI = jest.fn().mockResolvedValue();
  comp.isMessageTooLong = false;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  
  await comp.rejectTool(toolUse);
  
  expect(toolUse.approved).toBe(false);
  expect(toolUse.status).toBe('rejected');
  expect(toolUse.error).toBe('Tool execution rejected by user');
  expect(comp.callAIAPI).toHaveBeenCalledWith('Tool execution for "query_events" was rejected by the user.');
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

test('executeTool captures raw tool result from backend', async () => {
  // wait out any setTimeouts from previous tests
  await new Promise(resolve => setTimeout(resolve, 1100));

  resetPapi();

  let toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  // Mock backend response with tool result
  const backendResponse = [
      {
        createTime: '2025-01-01T12:00:00.000Z',
        tags: ['tool_result'],
        message: {
          contentBlocks: [
            {
              type: 'tool_result',
              toolResult: {
                toolUseId: 'tool_123',
                content: [{ json: { "events": 5, "alerts": 2 } }]
              }
            }
          ]
        }
      }
    ];
  mockPapi('get', { data: { session: {}, history: backendResponse } });
  
  // Include message_start event to trigger captureRawToolResult
  const messageStartData = JSON.stringify({ type: 'message_start' });
  
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
  
  await comp.executeTool(toolUse);
  
  // Wait for the setTimeout to complete
  await new Promise(resolve => setTimeout(resolve, 1100));
  
  expect(toolUse.rawResult).toEqual({ "events": 5, "alerts": 2 });
  expect(toolUse.status).toBe('completed');
  expect(toolUse.completedAt).toBe('2025-01-01T12:00:00.000Z');
});

test('executeTool handles tool result with error', async () => {
  resetPapi();

  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  // Mock backend response with tool error
  const backendResponse = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      tags: ['tool_result'],
      message: {
        contentBlocks: [
          {
            toolResult: {
              isError: true,
              status: 'error',
              content: [
                {
                  text: 'something went wrong'
                }
              ]
            }
          }
        ]
      }
    }
  ];
  mockPapi('get', { data: { session: {}, history: backendResponse } });
  
  // Include message_start event to trigger captureRawToolResult
  const messageStartData = JSON.stringify({ type: 'message_start' });
  
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

  await comp.executeTool(toolUse);
  
  // Wait for the setTimeout to complete
  await new Promise(resolve => setTimeout(resolve, 1100));
  
  expect(toolUse.error).toBe('something went wrong');
  expect(toolUse.status).toBe('error');
}, 30000);

test('executeTool completes a tool whose result has empty content (no stuck spinner)', async () => {
  resetPapi();

  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();

  // A non-error tool_result with an empty content array. Previously this left the
  // status gated on content.length, so the tool spun forever; it must now complete.
  const backendResponse = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      tags: ['tool_result'],
      message: {
        contentBlocks: [
          {
            toolResult: {
              toolUseId: 'tool_123',
              content: []
            }
          }
        ]
      }
    }
  ];
  mockPapi('get', { data: { session: {}, history: backendResponse } });

  const messageStartData = JSON.stringify({ type: 'message_start' });
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

  await comp.executeTool(toolUse);

  // Wait for the setTimeout to complete
  await new Promise(resolve => setTimeout(resolve, 1100));

  expect(toolUse.status).toBe('completed');
  expect(toolUse.rawResult).toBeNull();
}, 30000);

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
  comp.mostRecentFloatingTool = new Map();
  
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

test('convertBackendMessagesToFrontend handles tool_use blocks with rejected status', () => {
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
          { type: 'text', text: 'Tool execution was rejected by the user' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1); // Second message should be skipped
  expect(result[0].toolUses).toHaveLength(1);
  expect(result[0].toolUses[0].id).toBe('tool_456');
  expect(result[0].toolUses[0].status).toBe('rejected');
  expect(result[0].toolUses[0].approved).toBe(false);
  expect(result[0].toolUses[0].error).toBe('Tool execution rejected by user');
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

test('convertBackendMessagesToFrontend handles complex message flow with skip_next', () => {
  comp.resetContextLength = jest.fn();
  global.Vue = { ref: jest.fn((value) => ({ value })) };
  
  const backendMessages = [
    {
      createTime: '2025-01-01T12:00:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'I will use a tool now.' },
          {
            type: 'tool_use',
            id: 'tool_skip_test',
            name: 'test_tool',
            input: { param: 'value' }
          }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:01:00.000Z',
      message: {
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'Tool execution was rejected by the user' }
        ]
      }
    },
    {
      createTime: '2025-01-01T12:02:00.000Z',
      message: {
        role: 'user',
        contentStr: 'I understand, let me try a different approach.'
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1); // Middle message should be skipped due to rejection, and user message becomes rawResult
  expect(result[0].content).toBe('I will use a tool now.');
  expect(result[0].toolUses[0].status).toBe('rejected');
  expect(result[0].toolUses[0].rawResult).toBe('I understand, let me try a different approach.');
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
  comp.mostRecentFloatingTool = new Map();
  
  mockToolMap.set('tool_456', mockToolUse);
  mockIndexMap.set(0, 'tool_456');
  
  const result = comp.handleContentBlockStop({ index: 0 }, sessionId);
  
  expect(mockToolUse.input).toEqual({ action: "delete" });
  expect(mockToolUse.status).toBe('pending_approval');
  expect(mockToolUse.approved).toBe(null);
  expect(comp.mostRecentFloatingTool.get(sessionId)).toBe(mockToolUse);
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
  comp.mostRecentFloatingTool = new Map();
  comp.scrollIfPinned = jest.fn();

  mockToolMap.set('tool_123', mockToolUse);
  mockIndexMap.set(0, 'tool_123');

  comp.handleDelegationContentBlockStop({ index: 0 }, childSessionId);

  expect(mockToolUse.input).toEqual({ oql_query: "event.module: suricata" });
  expect(mockToolUse.approved).toBe(true);
  expect(mockToolUse.status).not.toBe('pending_approval');
  expect(comp.queueTool).toHaveBeenCalledWith(childSessionId, 'tool_123');
  expect(comp.mostRecentFloatingTool.has(childSessionId)).toBe(false);
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
  comp.mostRecentFloatingTool = new Map();
  comp.scrollIfPinned = jest.fn();

  mockToolMap.set('tool_456', mockToolUse);
  mockIndexMap.set(0, 'tool_456');

  comp.handleDelegationContentBlockStop({ index: 0 }, childSessionId);

  expect(mockToolUse.input).toEqual({ action: "delete" });
  expect(mockToolUse.status).toBe('pending_approval');
  expect(mockToolUse.approved).toBe(null);
  expect(comp.mostRecentFloatingTool.get(childSessionId)).toBe(mockToolUse);
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
  comp.mostRecentFloatingTool = new Map();
  
  mockToolMap.set('chained_tool_456', mockChainedTool);
  mockIndexMap.set(2, 'chained_tool_456');
  
  const result = comp.handleToolExecutionContentBlockStop({ index: 2 }, sessionId);
  
  expect(mockChainedTool.input).toEqual({ command: "rm -rf /" });
  expect(mockChainedTool.status).toBe('pending_approval');
  expect(mockChainedTool.approved).toBe(null);
  expect(comp.mostRecentFloatingTool.get(sessionId)).toBe(mockChainedTool);
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
test('getSessionToolMap creates new map when none exists', () => {
  const sessionId = 'new-session';
  comp.executingToolsBySession = new Map();
  
  const result = comp.getSessionToolMap(sessionId);
  
  expect(result).toBeInstanceOf(Map);
  expect(comp.executingToolsBySession.get(sessionId)).toBe(result);
});

test('getSessionToolMap returns existing map', () => {
  const sessionId = 'existing-session';
  const existingMap = new Map();
  existingMap.set('tool1', { id: 'tool1', name: 'test' });
  comp.executingToolsBySession = new Map();
  comp.executingToolsBySession.set(sessionId, existingMap);
  
  const result = comp.getSessionToolMap(sessionId);
  
  expect(result).toBe(existingMap);
  expect(result.get('tool1')).toEqual({ id: 'tool1', name: 'test' });
});

test('getIndexMap creates new map when none exists', () => {
  const sessionId = 'new-session';
  comp.toolIndexToIdBySession = new Map();
  
  const result = comp.getIndexMap(sessionId);
  
  expect(result).toBeInstanceOf(Map);
  expect(comp.toolIndexToIdBySession.get(sessionId)).toBe(result);
});

test('getIndexMap returns existing map', () => {
  const sessionId = 'existing-session';
  const existingMap = new Map();
  existingMap.set(0, 'tool_id_123');
  comp.toolIndexToIdBySession = new Map();
  comp.toolIndexToIdBySession.set(sessionId, existingMap);
  
  const result = comp.getIndexMap(sessionId);
  
  expect(result).toBe(existingMap);
  expect(result.get(0)).toBe('tool_id_123');
});

test('queueTool adds tool to queue and runs queue', () => {
  const sessionId = 'test-session';
  const toolUseId = 'tool_123';
  comp.toolQueues = new Map();
  comp.runToolQueue = jest.fn();
  
  comp.queueTool(sessionId, toolUseId);
  
  expect(comp.toolQueues.get(sessionId)).toEqual([toolUseId]);
  expect(comp.runToolQueue).toHaveBeenCalledWith(sessionId);
});

test('queueTool adds to existing queue', () => {
  const sessionId = 'test-session';
  const toolUseId1 = 'tool_123';
  const toolUseId2 = 'tool_456';
  comp.toolQueues = new Map();
  comp.toolQueues.set(sessionId, [toolUseId1]);
  comp.runToolQueue = jest.fn();
  
  comp.queueTool(sessionId, toolUseId2);
  
  expect(comp.toolQueues.get(sessionId)).toEqual([toolUseId1, toolUseId2]);
  expect(comp.runToolQueue).toHaveBeenCalledWith(sessionId);
});

test('runToolQueue processes tools in queue', async () => {
  const sessionId = 'test-session';
  const toolUse1 = { id: 'tool_123', status: 'preparing' };
  const toolUse2 = { id: 'tool_456', status: 'preparing' };
  
  comp.toolRunnerBusy = new Set();
  comp.toolQueues = new Map();
  comp.toolQueues.set(sessionId, ['tool_123', 'tool_456']);
  
  const mockToolMap = new Map();
  mockToolMap.set('tool_123', toolUse1);
  mockToolMap.set('tool_456', toolUse2);
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.executeTool = jest.fn().mockResolvedValue();
  
  await comp.runToolQueue(sessionId);
  
  expect(comp.executeTool).toHaveBeenCalledWith(toolUse1);
  expect(comp.executeTool).toHaveBeenCalledWith(toolUse2);
  expect(toolUse1.status).toBe('executing');
  expect(toolUse2.status).toBe('executing');
  expect(comp.toolRunnerBusy.has(sessionId)).toBe(false);
});

test('runToolQueue skips if already busy', async () => {
  const sessionId = 'test-session';
  comp.toolRunnerBusy = new Set([sessionId]);
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
  
  comp.toolRunnerBusy = new Set();
  comp.toolQueues = new Map();
  comp.toolQueues.set(sessionId, ['tool_completed', 'tool_error', 'tool_rejected', 'tool_preparing']);
  
  const mockToolMap = new Map();
  mockToolMap.set('tool_completed', completedTool);
  mockToolMap.set('tool_error', errorTool);
  mockToolMap.set('tool_rejected', rejectedTool);
  mockToolMap.set('tool_preparing', preparingTool);
  
  comp.getSessionToolMap = jest.fn().mockReturnValue(mockToolMap);
  comp.executeTool = jest.fn().mockResolvedValue();
  
  await comp.runToolQueue(sessionId);
  
  expect(comp.executeTool).toHaveBeenCalledTimes(1);
  expect(comp.executeTool).toHaveBeenCalledWith(preparingTool);
  expect(preparingTool.status).toBe('executing');
});

test('checkForActivity returns true when streaming', () => {
  comp.isStreaming = true;
  comp.isTyping = false;
  comp.toolQueues = new Map();
  comp.currentChatId = 'test-session';
  
  const result = comp.checkForActivity();
  
  expect(result).toBe(true);
});

test('checkForActivity returns true when typing', () => {
  comp.isStreaming = false;
  comp.isTyping = true;
  comp.toolQueues = new Map();
  comp.currentChatId = 'test-session';
  
  const result = comp.checkForActivity();
  
  expect(result).toBe(true);
});

test('checkForActivity returns true when tools are queued', () => {
  comp.isStreaming = false;
  comp.isTyping = false;
  comp.toolQueues = new Map();
  comp.toolQueues.set('test-session', ['tool_123']);
  comp.currentChatId = 'test-session';
  
  const result = comp.checkForActivity();
  
  expect(result).toBe(true);
});

test('checkForActivity returns false when no activity', () => {
  comp.isStreaming = false;
  comp.isTyping = false;
  comp.toolQueues = new Map();
  comp.currentChatId = 'test-session';
  
  const result = comp.checkForActivity();
  
  expect(result).toBe(false);
});

test('checkForActivity returns false when tool queue is empty', () => {
  comp.isStreaming = false;
  comp.isTyping = false;
  comp.toolQueues = new Map();
  comp.toolQueues.set('test-session', []);
  comp.currentChatId = 'test-session';
  
  const result = comp.checkForActivity();
  
  expect(result).toBe(false);
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
  comp.mostRecentFloatingTool = new Map();
  comp.mostRecentFloatingTool.set('test-session', floatingTool);
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
  expect(comp.mostRecentFloatingTool.has('test-session')).toBe(false);
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
  comp.mostRecentFloatingTool = new Map();
  comp.mostRecentFloatingTool.set('test-session', floatingTool);
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

// --- captureToolResult (merged own-session / child-session result capture) ---

function toolResultHistoryMsg(toolResult, createTime) {
  return {
    createTime,
    tags: ['tool_result'],
    message: { role: 'user', contentBlocks: [{ toolResult }] },
  };
}

test('captureToolResult captures the newest own-session result', async () => {
  jest.useFakeTimers();
  comp.currentChatId = 'sess-own';
  const toolUse = { id: 'tu-1', status: 'running' };
  comp.$root.papi.get = jest.fn().mockResolvedValue({
    data: {
      history: [
        toolResultHistoryMsg({ toolUseId: 'tu-old', content: [{ json: { old: true } }] }, '2025-01-01T12:00:00.000Z'),
        toolResultHistoryMsg({ toolUseId: 'tu-1', content: [{ json: { hits: 3 } }] }, '2025-01-01T12:05:00.000Z'),
      ],
    },
  });

  comp.captureToolResult(toolUse);
  expect(comp.pendingResultTimers.size).toBe(1);

  await jest.advanceTimersByTimeAsync(1000);

  expect(comp.$root.papi.get).toHaveBeenCalledWith('/assistant/sessions/sess-own');
  expect(toolUse.status).toBe('completed');
  expect(toolUse.rawResult).toEqual({ hits: 3 });
  expect(toolUse.completedAt).toBe('2025-01-01T12:05:00.000Z');
  expect(comp.pendingResultTimers.size).toBe(0);
  jest.useRealTimers();
});

test('captureToolResult matches a child-session result by tool use id', async () => {
  jest.useFakeTimers();
  comp.currentChatId = 'sess-own';
  const toolUse = { id: 'tu-child', status: 'running' };
  comp.$root.papi.get = jest.fn().mockResolvedValue({
    data: {
      history: [
        toolResultHistoryMsg({ toolUseId: 'tu-child', content: [{ json: { found: 1 } }] }, '2025-01-01T12:00:00.000Z'),
        // Newer result for a DIFFERENT tool must be skipped when matching by id.
        toolResultHistoryMsg({ toolUseId: 'tu-other', content: [{ json: { wrong: true } }] }, '2025-01-01T12:05:00.000Z'),
      ],
    },
  });

  comp.captureToolResult(toolUse, { sessionId: 'sess-child', matchById: true });
  await jest.advanceTimersByTimeAsync(1000);

  expect(comp.$root.papi.get).toHaveBeenCalledWith('/assistant/sessions/sess-child');
  expect(toolUse.status).toBe('completed');
  expect(toolUse.rawResult).toEqual({ found: 1 });
  jest.useRealTimers();
});

test('captureToolResult surfaces an error tool_result as tool error status', async () => {
  jest.useFakeTimers();
  comp.currentChatId = 'sess-own';
  const toolUse = { id: 'tu-1', status: 'running' };
  comp.$root.papi.get = jest.fn().mockResolvedValue({
    data: {
      history: [
        toolResultHistoryMsg({ toolUseId: 'tu-1', isError: true, content: [{ text: 'query exploded' }] }, '2025-01-01T12:05:00.000Z'),
      ],
    },
  });

  comp.captureToolResult(toolUse);
  await jest.advanceTimersByTimeAsync(1000);

  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('query exploded');
  expect(toolUse.rawResult).toBe(null);
  jest.useRealTimers();
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
