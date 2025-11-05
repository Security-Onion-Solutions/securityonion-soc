// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const { TextEncoder, TextDecoder } = require('util');
Object.assign(global, { TextDecoder, TextEncoder });

require('../test_common.js');
require('./assistant.js');

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
  expect(comp.executingTools).toBeInstanceOf(Map);
  expect(comp.contextLength).toBe(0);
  expect(comp.increaseMaxContextThreshold).toBe(false);
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
  
  expect(id1).toMatch(/^chat_\d+_[a-z0-9]+$/);
  expect(id2).toMatch(/^chat_\d+_[a-z0-9]+$/);
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
      { id: 'test-model', displayName: "Test Model", contextLimitSmall: 200000, contextLimitLarge: 1000000, lowBalanceColorAlert: 500000 }
    ]
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.$root.disclaimer = false;
  
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
});

test('initAssistant sets assistantEnabled to false when not enabled', async () => {
  const mockParams = {
    enabled: false,
    availableModels: []
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn();
  comp.handleRouteSessionId = jest.fn();
  comp.loadCredits = jest.fn();
  
  await comp.initAssistant(mockParams);
  
  expect(comp.assistantEnabled).toBe(false);
  expect(comp.$root.disclaimer).toBe(false);
  expect(comp.loadStoredChats).not.toHaveBeenCalled();
  expect(comp.handleRouteSessionId).not.toHaveBeenCalled();
  expect(comp.loadCredits).not.toHaveBeenCalled();
});

test('initAssistant sets assistantEnabled to false when not licensed', async () => {
  const mockParams = {
    enabled: true,
    availableModels: []
  };
  comp.$root.isLicensed = jest.fn().mockReturnValue(false);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn();
  comp.handleRouteSessionId = jest.fn();
  comp.loadCredits = jest.fn();
  
  await comp.initAssistant(mockParams);
  
  expect(comp.assistantEnabled).toBe(false);
  expect(comp.$root.disclaimer).toBe(false);
  expect(comp.loadStoredChats).not.toHaveBeenCalled();
  expect(comp.handleRouteSessionId).not.toHaveBeenCalled();
  expect(comp.loadCredits).not.toHaveBeenCalled();
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
        lowBalanceColorAlert: 500000
      },
      {
        id: 'model-2',
        displayName: "Model 2",
        contextLimitSmall: 100000,
        contextLimitLarge: 300000, // Larger than contextLimitSmall - should remain unchanged
        lowBalanceColorAlert: 400000
      },
      {
        id: 'model-3',
        displayName: "Model 3",
        contextLimitSmall: 250000,
        contextLimitLarge: 250000, // Equal to contextLimitSmall - should remain unchanged
        lowBalanceColorAlert: 600000
      }
    ]
  };
  
  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.showDisclaimer = jest.fn();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.handleRouteSessionId = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.updateModelParams = jest.fn();
  comp.$root.disclaimer = false;
  
  await comp.initAssistant(mockParams);
  
  // Check that the modelsMap was created correctly
  expect(comp.modelsMap.size).toBe(3);
  expect(comp.modelsMap.has('model-1')).toBe(true);
  expect(comp.modelsMap.has('model-2')).toBe(true);
  expect(comp.modelsMap.has('model-3')).toBe(true);
  
  // Check that contextLimitLarge was corrected for model-1
  const model1 = comp.modelsMap.get('model-1');
  expect(model1.contextLimitSmall).toBe(200000);
  expect(model1.contextLimitLarge).toBe(200000); // Should be corrected to match contextLimitSmall
  
  // Check that contextLimitLarge was not changed for model-2 (already larger)
  const model2 = comp.modelsMap.get('model-2');
  expect(model2.contextLimitSmall).toBe(100000);
  expect(model2.contextLimitLarge).toBe(300000); // Should remain unchanged
  
  // Check that contextLimitLarge was not changed for model-3 (equal)
  const model3 = comp.modelsMap.get('model-3');
  expect(model3.contextLimitSmall).toBe(250000);
  expect(model3.contextLimitLarge).toBe(250000); // Should remain unchanged
});

test('initAssistant handles empty availableModels array', async () => {
  const mockParams = {
    enabled: true,
    availableModels: [] // Empty array
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
  expect(comp.currentModel).toBe(''); // Should remain empty
  expect(comp.updateModelParams).toHaveBeenCalled();
});

test('handleRouteSessionId returns early when assistantEnabled is false', async () => {
  comp.assistantEnabled = false;
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn();
  comp.clearStreamingStates = jest.fn();
  
  await comp.handleRouteSessionId();
  
  expect(comp.clearStreamingStates).toHaveBeenCalled();
  expect(comp.loadChatFromBackend).not.toHaveBeenCalled();
});

// Session management tests
test('handleRouteSessionId with existing session', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();
  comp.assistantEnabled = true;
  
  await comp.handleRouteSessionId();
  
  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(fakeSessionId);
});

test('handleRouteSessionId with non-existent session', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn().mockRejectedValue(new Error('Session not found'));
  comp.assistantEnabled = true;
  
  await comp.handleRouteSessionId();
  
  expect(comp.currentChatId).toBe(fakeSessionId);
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
  
  await comp.loadCredits();
  
  expect(mock).toHaveBeenCalledWith('/assistant/balance');
  expect(comp.creditsRemaining).toBe(100);
});

test('loadCredits handles error', async () => {
  const showErrorMock = mockShowError();
  mockPapi("get", null, new Error("API error"));
  
  await comp.loadCredits();
  
  expect(comp.creditsRemaining).toBe(0);
});

test('loadCredits handles unhealthy status', async () => {
  const showErrorMock = mockShowError();
  const unhealthyResponse = {
    health_status: 'unhealthy',
    credit_balance: 50
  };
  mockPapi("get", { data: unhealthyResponse });
  
  await comp.loadCredits();
  
  expect(showErrorMock).toHaveBeenCalledWith('Error loading credits from API: The AI model could not be reached. Support for local AI models is coming soon.');
  expect(comp.creditsRemaining).toBe(0); // Should remain 0 when unhealthy
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
  comp.currentChatId = fakeSessionId;
  
  await comp.startNewChat();
  
  expect(comp.saveCurrentChat).toHaveBeenCalled();
  expect(comp.currentChatId).toBe(null);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.loadNewChatScreen).toHaveBeenCalled();
  expect(comp.$router.push).toHaveBeenCalledWith({ name: 'assistant' });
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
  comp.assistantEnabled = true;
  comp.canChat = true;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  
  await comp.sendMessage();
  
  expect(showErrorMock).toHaveBeenCalledWith('Insufficient credits. Please contact your administrator to purchase more credits.');
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
  comp.currentChatId = null;
  comp.generateChatId = jest.fn().mockReturnValue(fakeSessionId);
  comp.saveCurrentChatId = jest.fn();
  comp.updateUrlWithSessionId = jest.fn();
  comp.callAIAPI = jest.fn().mockResolvedValue();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();
  comp.assistantEnabled = true;
  comp.canChat = true;
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
  expect(comp.callAIAPI).toHaveBeenCalledWith('Test message');
  expect(comp.loadStoredChats).toHaveBeenCalled();
});

test('sendMessage handles API error', async () => {
  const showErrorMock = mockShowError();
  comp.newMessage = 'Test message';
  comp.creditsRemaining = 100;
  comp.currentChatId = fakeSessionId;
  comp.callAIAPI = jest.fn().mockRejectedValue(new Error('API failed'));
  comp.scrollToBottom = jest.fn();
  comp.assistantEnabled = true;
  comp.canChat = true;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  
  await comp.sendMessage();
  
  expect(showErrorMock).toHaveBeenCalledWith('Failed to get AI response: API failed');
  expect(comp.isTyping).toBe(false);
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
  expect(comp.contextLength).toBe(175); // 100 + 50 + 25
  
  comp.updateContextLength(usage2);
  expect(comp.contextLength).toBe(225); // 175 + 30 + 20
  
  comp.updateContextLength(null);
  expect(comp.contextLength).toBe(225); // Should remain unchanged
});

test('checkContextLimitReached returns false when under limit', () => {
  comp.contextLength = 50000;
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseMaxContextThreshold = false;
  
  const result = comp.checkContextLimitReached();
  
  expect(result).toBe(false);
});

test('checkContextLimitReached returns true when over small limit', () => {
  const showErrorMock = mockShowError();
  comp.contextLength = 150000;
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseMaxContextThreshold = false;
  comp.formatCount = jest.fn().mockReturnValue('100,000');
  
  const result = comp.checkContextLimitReached();
  
  expect(result).toBe(true);
  expect(showErrorMock).toHaveBeenCalledWith(expect.stringContaining('100,000+ tokens'));
});

test('checkContextLimitReached uses large limit when threshold increased', () => {
  comp.contextLength = 150000;
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseMaxContextThreshold = true;
  
  const result = comp.checkContextLimitReached();
  
  expect(result).toBe(false); // Should be under large limit
});

test('checkContextLimitReached returns true when over large limit', () => {
  const showErrorMock = mockShowError();
  comp.contextLength = 250000;
  comp.contextLimitSmall = 100000;
  comp.contextLimitLarge = 200000;
  comp.increaseMaxContextThreshold = true;
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
  comp.increaseMaxContextThreshold = false;
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
  comp.increaseMaxContextThreshold = true;
  comp.thresholdColorRatioLow = 0.5;
  comp.thresholdColorRatioMed = 0.75;
  comp.thresholdColorRatioMax = 1.0;
  
  expect(comp.getContextColor(50000)).toBe('text-green'); // Under low threshold of large limit
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

test('approveTool executes tool', async () => {
  const toolUse = { ...fakeToolUse };
  comp.executeTool = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  
  await comp.approveTool(toolUse);
  
  expect(toolUse.approved).toBe(true);
  expect(toolUse.status).toBe('executing');
  expect(comp.executeTool).toHaveBeenCalledWith(toolUse);
  expect(comp.scrollToBottom).toHaveBeenCalled();
});

test('approveTool handles execution error', async () => {
  const toolUse = { ...fakeToolUse };
  comp.executeTool = jest.fn().mockRejectedValue(new Error('Execution failed'));
  comp.scrollToBottom = jest.fn();
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  
  await comp.approveTool(toolUse);
  
  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('Failed to execute approved tool: Execution failed');
});

test('rejectTool marks as rejected', async () => {
  const toolUse = { ...fakeToolUse };
  comp.scrollToBottom = jest.fn();
  comp.callAIAPI = jest.fn().mockResolvedValue();
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
  expect(comp.messages[0].content.value).toBe('Tool result: Success');
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
  expect(comp.messages[0].usage.value).toEqual({ input_tokens: 15, output_tokens: 25 });
  expect(comp.updateContextLength).toHaveBeenCalledWith({ input_tokens: 15, output_tokens: 25 });
  expect(comp.$forceUpdate).toHaveBeenCalled();
});

test('executeTool handles chained tool use in response', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  mockPapi('get', { data: [] });
  comp.executingTools = new Map();
  
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
  expect(comp.messages[0].toolUses.value).toHaveLength(1);
  expect(comp.messages[0].toolUses.value[0].id).toBe('chained_tool_456');
  expect(comp.messages[0].toolUses.value[0].name).toBe('analyze_data');
  expect(comp.messages[0].toolUses.value[0].status).toBe('preparing');
  expect(comp.executingTools.get('chained_tool_456')).toBeDefined();
  expect(comp.executingTools.get(`block_0_${fakeSessionId}`)).toBeDefined();
});

test('executeTool captures raw tool result from backend', async () => {
  // wait out any setTimeouts from previous tests
  await new Promise(resolve => setTimeout(resolve, 1100));

  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  // Mock backend response with tool result
  const backendResponse = {
    data: [
      {
        createTime: '2025-01-01T12:00:00.000Z',
        tags: ['tool_result'],
        message: {
          contentBlocks: [
            {
              type: 'text',
              text: 'ToolUseId: tool_123, Result: {"events": 5, "alerts": 2}, Error: <nil>'
            }
          ]
        }
      }
    ]
  };
  mockPapi('get', backendResponse);
  
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
  
  expect(toolUse.rawResult).toBe('{"events": 5, "alerts": 2}, Error: <nil>');
  expect(toolUse.status).toBe('completed');
  expect(toolUse.completedAt).toBe('2025-01-01T12:00:00.000Z');
});

test('executeTool handles tool result with error', async () => {
  const toolUse = { ...fakeToolUse };
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  
  // Mock backend response with tool error
  const backendResponse = {
    data: [
      {
        createTime: '2025-01-01T12:00:00.000Z',
        tags: ['tool_result'],
        message: {
          contentBlocks: [
            {
              type: 'text',
              text: 'ToolUseId: tool_123, Result: null, Error: Query timeout'
            }
          ]
        }
      }
    ]
  };
  mockPapi('get', backendResponse);
  
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
  
  expect(toolUse.error).toBe('Query timeout');
  expect(toolUse.status).toBe('error');
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
  expect(comp.messages[0].content.value).toBe('');
  expect(comp.messages[0].usage.value).toBe(null); // Usage set later in message_stop
  expect(comp.messages[0].toolUses.value).toEqual([]);
  expect(comp.scrollToBottom).toHaveBeenCalled();
});

test('callAIAPI processes content_block_start with tool_use', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.executingTools = new Map();
  
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
  expect(comp.messages[0].toolUses.value).toHaveLength(1);
  expect(comp.messages[0].toolUses.value[0].id).toBe('tool_456');
  expect(comp.messages[0].toolUses.value[0].name).toBe('search_data');
  expect(comp.messages[0].toolUses.value[0].input).toEqual({ query: 'test query' });
  expect(comp.messages[0].toolUses.value[0].status).toBe('preparing');
  expect(comp.executingTools.get('tool_456')).toBeDefined();
  expect(comp.executingTools.get(`block_0_${fakeSessionId}`)).toBeDefined();
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
  expect(comp.messages[0].content.value).toBe('Hello world!');
  expect(comp.scrollToBottom).toHaveBeenCalledTimes(3); // Once for message_start, twice for text deltas
});

test('callAIAPI processes content_block_delta with input_json_delta', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.executingTools = new Map();
  
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
  
  const toolUse = comp.executingTools.get(`block_0_${fakeSessionId}`);
  expect(toolUse).toBeDefined();
  expect(toolUse.inputJson).toBe('{"param": "value"}');
  expect(toolUse.status).toBe('preparing');
});

test('callAIAPI processes content_block_stop event', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.executingTools = new Map();
  
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
  
  const toolUse = comp.executingTools.get(`block_0_${fakeSessionId}`);
  expect(toolUse).toBeDefined();
  expect(toolUse.input).toEqual({ test: 'data' });
  expect(toolUse.status).toBe('pending_approval');
  expect(toolUse.approved).toBe(null);
});

test('callAIAPI handles content_block_stop with invalid JSON', async () => {
  comp.currentChatId = fakeSessionId;
  comp.scrollToBottom = jest.fn();
  comp.loadCredits = jest.fn().mockResolvedValue();
  comp.executingTools = new Map();
  
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
  
  const toolUse = comp.executingTools.get(`block_0_${fakeSessionId}`);
  expect(toolUse).toBeDefined();
  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toContain('Failed to parse tool input');
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
  expect(comp.messages[0].usage.value).toEqual({ input_tokens: 20, output_tokens: 30 });
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
  expect(comp.messages[0].usage.value).toEqual({ input_tokens: 25, output_tokens: 35 });
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
  expect(comp.messages[0].content.value).toBe('Hello');
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
  expect(comp.messages[0].usage.value).toEqual({ input_tokens: 12, output_tokens: 18 });
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

test('handleRouteSessionId handles non-investigation session with existing messages', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.$route.query.investigation = 'false'; // Not an investigation
  comp.loadChatFromBackend = jest.fn().mockRejectedValue(new Error('Session not found'));
  comp.loadNewChatScreen = jest.fn();
  comp.saveCurrentChatId = jest.fn();
  comp.messages = [fakeMessage, fakeAssistantMessage]; // More than 1 message
  comp.assistantEnabled = true;
  
  await comp.handleRouteSessionId();
  
  expect(comp.currentChatId).toBe(fakeSessionId);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.loadNewChatScreen).toHaveBeenCalled();
});

test('startInvestigationSession clears messages and sets up investigation prompt', async () => {
  const investigationPrompt = 'Investigate suspicious network activity from IP 10.0.0.1';
  comp.messages = [fakeAssistantMessage]; // Start with welcome message
  comp.sendMessage = jest.fn().mockResolvedValue();
  
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
  expect(result[0].usage.value).toEqual({ input_tokens: 10, output_tokens: 20 });
  expect(comp.updateContextLength).toHaveBeenCalledWith({ input_tokens: 10, output_tokens: 20 });
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
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'Tool completed successfully' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0].content).toBe('');
  // Tool uses should be created since there's a next message and no rejection
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses.value).toHaveLength(1);
  expect(result[0].toolUses.value[0].id).toBe('tool_123');
  expect(result[0].toolUses.value[0].name).toBe('query_events');
  expect(result[0].toolUses.value[0].input).toEqual({ query: 'test' });
  expect(result[0].toolUses.value[0].status).toBe('completed');
  expect(result[0].toolUses.value[0].approved).toBe(true);
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
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'Tool execution was rejected by the user' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1); // Second message should be skipped
  expect(result[0].toolUses.value).toHaveLength(1);
  expect(result[0].toolUses.value[0].id).toBe('tool_456');
  expect(result[0].toolUses.value[0].status).toBe('rejected');
  expect(result[0].toolUses.value[0].approved).toBe(false);
  expect(result[0].toolUses.value[0].error).toBe('Tool execution rejected by user');
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
        role: 'assistant',
        contentBlocks: [
          { type: 'text', text: 'Tool completed' }
        ]
      }
    }
  ];
  
  const result = comp.convertBackendMessagesToFrontend(backendMessages);
  
  expect(result).toHaveLength(1);
  expect(result[0]).toHaveProperty('toolUses');
  expect(result[0].toolUses.value[0].input).toEqual({}); // Should default to empty object
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
  expect(result[0].toolUses.value).toHaveLength(1);
  
  const toolUse = result[0].toolUses.value[0];
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
  expect(result[0].toolUses.value).toHaveLength(2);
  
  // Both tools should have pending_approval status
  result[0].toolUses.value.forEach((toolUse, index) => {
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
  expect(result[0].toolUses.value).toHaveLength(1);
  
  const toolUse = result[0].toolUses.value[0];
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
  expect(result[0].toolUses.value).toHaveLength(1);
  
  const toolUse = result[0].toolUses.value[0];
  expect(toolUse.status).toBe('pending_approval');
  expect(toolUse.id).toBe('unknown'); // Should default to 'unknown'
  expect(toolUse.name).toBe('unknown'); // Should default to 'unknown'
  expect(toolUse.input).toEqual({});
  expect(toolUse.approved).toBe(null);
  expect(toolUse.sessionId).toBe('missing_props_session');
});

test('convertBackendMessagesToFrontend filters out new format tool result messages', () => {
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
  expect(result[0].toolUses.value[0].rawResult).toBe('{"events": 5}, Error: <nil>');
  expect(result[0].toolUses.value[0].completedAt).toBe('2025-01-01T12:01:00.000Z');
  expect(result[0].toolUses.value[0].status).toBe('completed'); // No error since Error is <nil>
});

test('convertBackendMessagesToFrontend handles new format tool result with error', () => {
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
  expect(result[0].toolUses.value[0].rawResult).toBe('null, Error: Connection timeout');
  expect(result[0].toolUses.value[0].error).toBe('Connection timeout');
  expect(result[0].toolUses.value[0].status).toBe('error');
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
  expect(result[0].toolUses.value[0].rawResult).toBe('Raw tool result data');
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
  expect(result[0].toolUses.value[0].rawResult).toBeNull();
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
  expect(result[0].toolUses.value[0].status).toBe('rejected');
  expect(result[0].toolUses.value[0].rawResult).toBe('I understand, let me try a different approach.');
});

test('convertBackendMessagesToFrontend handles empty backend messages array', () => {
  comp.contextLength = 1000;
  
  const result = comp.convertBackendMessagesToFrontend([]);
  
  expect(result).toEqual([]);
  expect(comp.contextLength).toBe(0);
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
  const mock = mockPapi("get", { data: testMessages });
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
  comp.increaseMaxContextThreshold = true;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false; // Different from default
  comp.currentModel = 'test-model';
  
  // Mock saveSetting to track calls
  comp.saveSetting = jest.fn();
  
  comp.saveLocalSettings();
  
  expect(comp.saveSetting).toHaveBeenCalledWith('increaseMaxContextThreshold', true, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('restoreLastActive', true, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('alwaysApproveReadRequests', true, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('showChatHistory', false, true);
  expect(comp.saveSetting).toHaveBeenCalledWith('currentModel', 'test-model', '');
  expect(comp.saveSetting).toHaveBeenCalledTimes(5);
});

test('saveLocalSettings saves default values correctly', () => {
  // Set up component state with default values
  comp.increaseMaxContextThreshold = false;
  comp.restoreLastActive = false;
  comp.alwaysApproveReadRequests = false;
  comp.showChatHistory = true;
  
  comp.saveSetting = jest.fn();
  
  comp.saveLocalSettings();
  
  expect(comp.saveSetting).toHaveBeenCalledWith('increaseMaxContextThreshold', false, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('restoreLastActive', false, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('alwaysApproveReadRequests', false, false);
  expect(comp.saveSetting).toHaveBeenCalledWith('showChatHistory', true, true);
});

test('loadLocalSettings loads all settings from localStorage', () => {
  // Mock localStorage values
  mockLocalStorage['settings.assistant.increaseMaxContextThreshold'] = 'true';
  mockLocalStorage['settings.assistant.restoreLastActive'] = 'true';
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = 'true';
  mockLocalStorage['settings.assistant.showChatHistory'] = 'false';
  
  comp.loadLocalSettings();
  
  expect(comp.increaseMaxContextThreshold).toBe(true);
  expect(comp.restoreLastActive).toBe(true);
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

test('loadLocalSettings handles missing localStorage values', () => {
  // Set initial values different from defaults
  comp.increaseMaxContextThreshold = true;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false;
  
  // Ensure localStorage has no values (delete them)
  delete mockLocalStorage['settings.assistant.increaseMaxContextThreshold'];
  delete mockLocalStorage['settings.assistant.restoreLastActive'];
  delete mockLocalStorage['settings.assistant.alwaysApproveReadRequests'];
  delete mockLocalStorage['settings.assistant.showChatHistory'];
  
  comp.loadLocalSettings();
  
  // Values should remain unchanged when localStorage is empty
  expect(comp.increaseMaxContextThreshold).toBe(true);
  expect(comp.restoreLastActive).toBe(true);
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

test('loadLocalSettings handles partial localStorage values', () => {
  // Set initial values
  comp.increaseMaxContextThreshold = false;
  comp.restoreLastActive = false;
  comp.alwaysApproveReadRequests = false;
  comp.showChatHistory = true;
  
  // Mock localStorage with only some values
  mockLocalStorage['settings.assistant.increaseMaxContextThreshold'] = 'true';
  mockLocalStorage['settings.assistant.showChatHistory'] = 'false';
  // restoreLastActive and alwaysApproveReadRequests are undefined
  
  comp.loadLocalSettings();
  
  expect(comp.increaseMaxContextThreshold).toBe(true);
  expect(comp.restoreLastActive).toBe(false); // Unchanged
  expect(comp.alwaysApproveReadRequests).toBe(false); // Unchanged
  expect(comp.showChatHistory).toBe(false);
});

test('loadLocalSettings handles string boolean conversion correctly', () => {
  // Set initial values
  comp.increaseMaxContextThreshold = false;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false;
  
  // Test various string representations
  mockLocalStorage['settings.assistant.increaseMaxContextThreshold'] = 'true';
  mockLocalStorage['settings.assistant.restoreLastActive'] = 'false';
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = 'TRUE'; // Should not match
  mockLocalStorage['settings.assistant.showChatHistory'] = 'true';
  
  comp.loadLocalSettings();
  
  expect(comp.increaseMaxContextThreshold).toBe(true);
  expect(comp.restoreLastActive).toBe(false);
  expect(comp.alwaysApproveReadRequests).toBe(false); // Should remain unchanged due to 'TRUE' != 'true'
  expect(comp.showChatHistory).toBe(true);
});

test('loadLocalSettings handles empty string values', () => {
  // Mock localStorage with empty strings
  mockLocalStorage['settings.assistant.increaseMaxContextThreshold'] = '';
  mockLocalStorage['settings.assistant.restoreLastActive'] = '';
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = '';
  mockLocalStorage['settings.assistant.showChatHistory'] = '';
  
  // Set initial values
  comp.increaseMaxContextThreshold = true;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false;
  
  comp.loadLocalSettings();
  
  // Values should remain unchanged for empty strings
  expect(comp.increaseMaxContextThreshold).toBe(true);
  expect(comp.restoreLastActive).toBe(true);
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

test('loadLocalSettings integration with actual localStorage access', () => {
  // Test the actual localStorage access pattern used by loadLocalSettings
  // This simulates how the function actually checks for localStorage values
  mockLocalStorage['settings.assistant.increaseMaxContextThreshold'] = 'true';
  mockLocalStorage['settings.assistant.restoreLastActive'] = 'true';
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = 'true';
  mockLocalStorage['settings.assistant.showChatHistory'] = 'false';
  
  // Set initial values
  comp.increaseMaxContextThreshold = false;
  comp.restoreLastActive = false;
  comp.alwaysApproveReadRequests = false;
  comp.showChatHistory = true;
  
  comp.loadLocalSettings();
  
  expect(comp.increaseMaxContextThreshold).toBe(true);
  expect(comp.restoreLastActive).toBe(true);
  expect(comp.alwaysApproveReadRequests).toBe(true);
  expect(comp.showChatHistory).toBe(false);
});

test('openOptionsMenu finds and clicks expansion panel', () => {
  const mockPanelTitle = {
    click: jest.fn()
  };
  const mockOptionsPanel = {
    querySelector: jest.fn().mockReturnValue(mockPanelTitle)
  };
  const mockOptionsHeader = {
    scrollIntoView: jest.fn()
  };
  
  // Mock querySelector to return different elements based on selector
  comp.$el.querySelector = jest.fn((selector) => {
    if (selector === '[data-aid="assistant_options"]') {
      return mockOptionsPanel;
    } else if (selector === '#chatOptionsHeader') {
      return mockOptionsHeader;
    }
    return null;
  });
  
  comp.openOptionsMenu();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  
  // Execute the nextTick callback manually for testing
  const nextTickCallback = comp.$nextTick.mock.calls[0][0];
  if (nextTickCallback) {
    nextTickCallback();
  }
  
  expect(comp.$el.querySelector).toHaveBeenCalledWith('[data-aid="assistant_options"]');
  expect(mockOptionsPanel.querySelector).toHaveBeenCalledWith('.v-expansion-panel-title');
  expect(mockPanelTitle.click).toHaveBeenCalled();
  expect(comp.$el.querySelector).toHaveBeenCalledWith('#chatOptionsHeader');
  expect(mockOptionsHeader.scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'center' });
});

test('openOptionsMenu handles missing options panel', () => {
  const mockOptionsHeader = {
    scrollIntoView: jest.fn()
  };
  
  comp.$el.querySelector = jest.fn((selector) => {
    if (selector === '[data-aid="assistant_options"]') {
      return null; // Panel not found
    } else if (selector === '#chatOptionsHeader') {
      return mockOptionsHeader;
    }
    return null;
  });
  
  comp.openOptionsMenu();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  
  // Execute the nextTick callback manually for testing
  const nextTickCallback = comp.$nextTick.mock.calls[0][0];
  if (nextTickCallback) {
    nextTickCallback();
  }
  
  expect(comp.$el.querySelector).toHaveBeenCalledWith('[data-aid="assistant_options"]');
  expect(comp.$el.querySelector).toHaveBeenCalledWith('#chatOptionsHeader');
  expect(mockOptionsHeader.scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'center' });
  // Should not throw error when panel is missing
});

test('openOptionsMenu handles missing panel title', () => {
  const mockOptionsPanel = {
    querySelector: jest.fn().mockReturnValue(null) // Panel title not found
  };
  const mockOptionsHeader = {
    scrollIntoView: jest.fn()
  };
  
  comp.$el.querySelector = jest.fn((selector) => {
    if (selector === '[data-aid="assistant_options"]') {
      return mockOptionsPanel;
    } else if (selector === '#chatOptionsHeader') {
      return mockOptionsHeader;
    }
    return null;
  });
  
  comp.openOptionsMenu();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  
  // Execute the nextTick callback manually for testing
  const nextTickCallback = comp.$nextTick.mock.calls[0][0];
  if (nextTickCallback) {
    nextTickCallback();
  }
  
  expect(comp.$el.querySelector).toHaveBeenCalledWith('[data-aid="assistant_options"]');
  expect(mockOptionsPanel.querySelector).toHaveBeenCalledWith('.v-expansion-panel-title');
  expect(comp.$el.querySelector).toHaveBeenCalledWith('#chatOptionsHeader');
  expect(mockOptionsHeader.scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'center' });
  // Should not throw error when panel title is missing
});

test('openOptionsMenu handles missing options header', () => {
  const mockPanelTitle = {
    click: jest.fn()
  };
  const mockOptionsPanel = {
    querySelector: jest.fn().mockReturnValue(mockPanelTitle)
  };
  
  comp.$el.querySelector = jest.fn((selector) => {
    if (selector === '[data-aid="assistant_options"]') {
      return mockOptionsPanel;
    } else if (selector === '#chatOptionsHeader') {
      return null; // Header not found
    }
    return null;
  });
  
  comp.openOptionsMenu();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  
  // Execute the nextTick callback manually for testing
  const nextTickCallback = comp.$nextTick.mock.calls[0][0];
  if (nextTickCallback) {
    nextTickCallback();
  }
  
  expect(comp.$el.querySelector).toHaveBeenCalledWith('[data-aid="assistant_options"]');
  expect(mockOptionsPanel.querySelector).toHaveBeenCalledWith('.v-expansion-panel-title');
  expect(mockPanelTitle.click).toHaveBeenCalled();
  expect(comp.$el.querySelector).toHaveBeenCalledWith('#chatOptionsHeader');
  // Should not throw error when header is missing
});

test('openOptionsMenu handles complete DOM element absence', () => {
  comp.$el.querySelector = jest.fn().mockReturnValue(null);
  
  comp.openOptionsMenu();
  
  expect(comp.$nextTick).toHaveBeenCalled();
  
  // Execute the nextTick callback manually for testing
  const nextTickCallback = comp.$nextTick.mock.calls[0][0];
  if (nextTickCallback) {
    nextTickCallback();
  }
  
  expect(comp.$el.querySelector).toHaveBeenCalledWith('[data-aid="assistant_options"]');
  expect(comp.$el.querySelector).toHaveBeenCalledWith('#chatOptionsHeader');
  // Should not throw error when all elements are missing
});

test('openOptionsMenu uses nextTick for DOM manipulation timing', () => {
  comp.openOptionsMenu();
  
  expect(comp.$nextTick).toHaveBeenCalledTimes(1);
  expect(typeof comp.$nextTick.mock.calls[0][0]).toBe('function');
});

test('openOptionsMenu scrollIntoView uses correct options', () => {
  const mockOptionsHeader = {
    scrollIntoView: jest.fn()
  };
  
  comp.$el.querySelector = jest.fn((selector) => {
    if (selector === '#chatOptionsHeader') {
      return mockOptionsHeader;
    }
    return null;
  });
  
  comp.openOptionsMenu();
  
  // Execute the nextTick callback manually for testing
  const nextTickCallback = comp.$nextTick.mock.calls[0][0];
  if (nextTickCallback) {
    nextTickCallback();
  }
  
  expect(mockOptionsHeader.scrollIntoView).toHaveBeenCalledWith({
    behavior: 'smooth',
    block: 'center'
  });
});

// Integration tests for settings functionality
test('settings integration: save and load cycle', () => {
  // Set up initial state
  comp.increaseMaxContextThreshold = true;
  comp.restoreLastActive = false;
  comp.alwaysApproveReadRequests = true;
  comp.showChatHistory = false;
  
  // Save settings
  comp.saveLocalSettings();
  
  // Verify localStorage state after save (values are stored as strings by the localStorage mock)
  expect(mockLocalStorage['settings.assistant.increaseMaxContextThreshold']).toBe('true');
  expect(mockLocalStorage['settings.assistant.restoreLastActive']).toBeUndefined(); // Should be removed
  expect(mockLocalStorage['settings.assistant.alwaysApproveReadRequests']).toBe('true');
  expect(mockLocalStorage['settings.assistant.showChatHistory']).toBe('false');
  
  // Simulate localStorage state after save (convert to strings as localStorage would)
  mockLocalStorage['settings.assistant.increaseMaxContextThreshold'] = 'true';
  delete mockLocalStorage['settings.assistant.restoreLastActive'];
  mockLocalStorage['settings.assistant.alwaysApproveReadRequests'] = 'true';
  mockLocalStorage['settings.assistant.showChatHistory'] = 'false';
  
  // Reset component state
  comp.increaseMaxContextThreshold = false;
  comp.restoreLastActive = true;
  comp.alwaysApproveReadRequests = false;
  comp.showChatHistory = true;
  
  // Load settings
  comp.loadLocalSettings();
  
  // Verify state was restored correctly
  expect(comp.increaseMaxContextThreshold).toBe(true);
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

test('checkIfDeleted sets canChat to false when session not in history', () => {
  const sessionId = 'missing-session';
  comp.chatHistory = [
    { sessionId: 'session1' },
    { sessionId: 'session2' }
  ];
  comp.canChat = true;
  const showWarningMock = jest.fn();
  comp.$root.showWarning = showWarningMock;
  
  comp.checkIfDeleted(sessionId);
  
  expect(comp.canChat).toBe(false);
  expect(showWarningMock).toHaveBeenCalledWith(comp.i18n.assistantChatIsDeleted);
});

test('checkIfDeleted sets canChat to true when session exists in history', () => {
  const sessionId = 'existing-session';
  comp.chatHistory = [
    { sessionId: 'session1' },
    { sessionId: 'existing-session' },
    { sessionId: 'session2' }
  ];
  comp.canChat = false;
  
  comp.checkIfDeleted(sessionId);
  
  expect(comp.canChat).toBe(true);
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
  comp.checkContextLimitReached = jest.fn().mockReturnValue(true);
  comp.callAIAPI = jest.fn();
  
  await comp.sendMessage();
  
  expect(comp.checkContextLimitReached).toHaveBeenCalled();
  expect(comp.callAIAPI).not.toHaveBeenCalled();
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
  comp.currentChatId = 'test-session';
  comp.callAIAPI = jest.fn().mockResolvedValue();
  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();
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

// handleToolExecutionContentBlockStop method tests
test('handleToolExecutionContentBlockStop auto-approves chained tool for query_events', () => {
  const sessionId = 'test-session';
  comp.currentChatId = sessionId;
  comp.alwaysApproveReadRequests = true;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.executeTool = jest.fn();
  comp.scrollIfPinned = jest.fn();
  comp.$nextTick = jest.fn((callback) => callback && callback());
  
  // Set up a chained tool use
  const chainedToolUse = {
    id: 'chained_tool_456',
    name: 'query_events',
    inputJson: '{"oql_query": "event.module: suricata"}',
    status: 'preparing'
  };
  comp.executingTools.set(`block_0_${sessionId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 0,
    usage: { input_tokens: 10, output_tokens: 15 }
  };
  
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, sessionId);
  
  expect(chainedToolUse.input).toEqual({ oql_query: "event.module: suricata" });
  expect(chainedToolUse.status).toBe('executing');
  expect(chainedToolUse.approved).toBe(true);
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.executeTool).toHaveBeenCalledWith(chainedToolUse);
  expect(result).toEqual({ input_tokens: 10, output_tokens: 15 });
});

test('handleToolExecutionContentBlockStop auto-approves chained tool for get_playbooks', () => {
  const sessionId = 'test-session';
  comp.currentChatId = sessionId;
  comp.alwaysApproveReadRequests = true;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.executeTool = jest.fn();
  comp.scrollIfPinned = jest.fn();
  comp.$nextTick = jest.fn((callback) => callback && callback());
  
  // Set up a chained tool use
  const chainedToolUse = {
    id: 'chained_tool_789',
    name: 'get_playbooks',
    inputJson: '{"alert_id": "alert_123"}',
    status: 'preparing'
  };
  comp.executingTools.set(`block_1_${sessionId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 1
  };
  
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, sessionId);
  
  expect(chainedToolUse.input).toEqual({ alert_id: "alert_123" });
  expect(chainedToolUse.status).toBe('executing');
  expect(chainedToolUse.approved).toBe(true);
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.executeTool).toHaveBeenCalledWith(chainedToolUse);
  expect(result).toBe(null);
});

test('handleToolExecutionContentBlockStop sets pending_approval for non-auto-approved tools', () => {
  const sessionId = 'test-session';
  comp.currentChatId = sessionId;
  comp.alwaysApproveReadRequests = true; // Enabled but tool not in auto-approve list
  comp.scrollIfPinned = jest.fn();
  
  // Set up a chained tool use for a non-auto-approved tool
  const chainedToolUse = {
    id: 'chained_tool_other',
    name: 'other_tool',
    inputJson: '{"param": "value"}',
    status: 'preparing'
  };
  comp.executingTools.set(`block_0_${sessionId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 0
  };
  
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, sessionId);
  
  expect(chainedToolUse.input).toEqual({ param: "value" });
  expect(chainedToolUse.status).toBe('pending_approval');
  expect(chainedToolUse.approved).toBe(null);
  expect(result).toBe(null);
});

test('handleToolExecutionContentBlockStop returns early when context limit reached', () => {
  const sessionId = 'test-session';
  comp.currentChatId = sessionId;
  comp.alwaysApproveReadRequests = true;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(true); // Context limit reached
  comp.executeTool = jest.fn();
  
  // Set up a chained tool use
  const chainedToolUse = {
    id: 'chained_tool_limit',
    name: 'query_events',
    inputJson: '{"query": "test"}',
    status: 'preparing'
  };
  comp.executingTools.set(`block_0_${sessionId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 0
  };
  
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, sessionId);
  
  expect(comp.checkContextLimitReached).toHaveBeenCalled();
  expect(comp.executeTool).not.toHaveBeenCalled();
  expect(result).toBeUndefined();
});

test('handleToolExecutionContentBlockStop handles JSON parsing error', () => {
  const sessionId = 'test-session';
  comp.currentChatId = sessionId;
  comp.scrollIfPinned = jest.fn();
  
  // Set up a chained tool use with invalid JSON
  const chainedToolUse = {
    id: 'chained_tool_invalid',
    name: 'test_tool',
    inputJson: '{"invalid": json}', // Invalid JSON
    status: 'preparing'
  };
  comp.executingTools.set(`block_0_${sessionId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 0
  };
  
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, sessionId);
  
  expect(chainedToolUse.status).toBe('error');
  expect(chainedToolUse.error).toContain('Failed to parse tool input');
  expect(result).toBe(null);
});

test('handleToolExecutionContentBlockStop handles missing tool use', () => {
  const sessionId = 'test-session';
  comp.currentChatId = sessionId;
  
  const contentBlockStopEvent = {
    index: 0
  };
  
  // No tool use set up in executingTools
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, sessionId);
  
  expect(result).toBe(null);
});

test('handleToolExecutionContentBlockStop handles tool use not in preparing status', () => {
  const sessionId = 'test-session';
  comp.currentChatId = sessionId;
  
  // Set up a chained tool use that's not in preparing status
  const chainedToolUse = {
    id: 'chained_tool_completed',
    name: 'test_tool',
    inputJson: '{"param": "value"}',
    status: 'completed' // Not preparing
  };
  comp.executingTools.set(`block_0_${sessionId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 0,
    usage: { input_tokens: 5, output_tokens: 10 }
  };
  
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, sessionId);
  
  // Should return usage but not process the tool
  expect(result).toEqual({ input_tokens: 5, output_tokens: 10 });
  expect(chainedToolUse.status).toBe('completed'); // Unchanged
});

test('handleToolExecutionContentBlockStop handles background session execution', () => {
  const backgroundSessionId = 'background-session';
  const currentSessionId = 'current-session';
  comp.currentChatId = currentSessionId; // Different from background session
  comp.alwaysApproveReadRequests = true;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.executeTool = jest.fn();
  comp.scrollIfPinned = jest.fn(); // Should not be called for background session
  comp.$nextTick = jest.fn((callback) => callback && callback());
  
  // Set up a chained tool use for background session
  const chainedToolUse = {
    id: 'background_tool',
    name: 'query_events',
    inputJson: '{"query": "background"}',
    status: 'preparing'
  };
  comp.executingTools.set(`block_0_${backgroundSessionId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 0
  };
  
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, backgroundSessionId);
  
  expect(chainedToolUse.input).toEqual({ query: "background" });
  expect(chainedToolUse.status).toBe('executing');
  expect(chainedToolUse.approved).toBe(true);
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.executeTool).toHaveBeenCalledWith(chainedToolUse);
  expect(comp.scrollIfPinned).not.toHaveBeenCalled(); // Should not update UI for background session
  expect(result).toBe(null);
});

test('handleToolExecutionContentBlockStop uses default session ID when none provided', () => {
  comp.currentChatId = 'default-session';
  comp.alwaysApproveReadRequests = true;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.executeTool = jest.fn();
  comp.scrollIfPinned = jest.fn();
  comp.$nextTick = jest.fn((callback) => callback && callback());
  
  // Set up a chained tool use using current session ID
  const chainedToolUse = {
    id: 'default_tool',
    name: 'query_events',
    inputJson: '{"query": "default"}',
    status: 'preparing'
  };
  comp.executingTools.set(`block_0_${comp.currentChatId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 0
  };
  
  // Call without sessionId parameter (should use currentChatId)
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent);
  
  expect(chainedToolUse.input).toEqual({ query: "default" });
  expect(chainedToolUse.status).toBe('executing');
  expect(chainedToolUse.approved).toBe(true);
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.executeTool).toHaveBeenCalledWith(chainedToolUse);
  expect(comp.scrollIfPinned).toHaveBeenCalled(); // Should update UI for current session
  expect(result).toBe(null);
});

test('handleToolExecutionContentBlockStop handles empty input JSON', () => {
  const sessionId = 'test-session';
  comp.currentChatId = sessionId;
  comp.alwaysApproveReadRequests = true;
  comp.checkContextLimitReached = jest.fn().mockReturnValue(false);
  comp.executeTool = jest.fn();
  comp.scrollIfPinned = jest.fn();
  comp.$nextTick = jest.fn((callback) => callback && callback());
  
  // Set up a chained tool use with empty inputJson
  const chainedToolUse = {
    id: 'empty_input_tool',
    name: 'query_events',
    inputJson: '', // Empty JSON
    status: 'preparing',
    input: {} // Initialize with empty object since inputJson parsing will be skipped
  };
  comp.executingTools.set(`block_0_${sessionId}`, chainedToolUse);
  
  const contentBlockStopEvent = {
    index: 0
  };
  
  const result = comp.handleToolExecutionContentBlockStop(contentBlockStopEvent, sessionId);
  
  expect(chainedToolUse.input).toEqual({}); // Should remain empty object
  expect(chainedToolUse.status).toBe('executing');
  expect(chainedToolUse.approved).toBe(true);
  expect(comp.$nextTick).toHaveBeenCalled();
  expect(comp.executeTool).toHaveBeenCalledWith(chainedToolUse);
  expect(result).toBe(null);
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

