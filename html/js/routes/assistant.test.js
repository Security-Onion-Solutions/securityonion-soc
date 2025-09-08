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
  credit_balance: 100
};

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
  
  // Mock localStorage with proper Jest mocks
  mockLocalStorage = {
    getItem: jest.fn(),
    setItem: jest.fn(),
    removeItem: jest.fn(),
    clear: jest.fn()
  };
  global.localStorage = mockLocalStorage;
  
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
});

test('loadChatHistory initializes with welcome message', async () => {
  await comp.loadChatHistory();
  
  expect(comp.messages).toHaveLength(1);
  expect(comp.messages[0].role).toBe('assistant');
  expect(comp.messages[0].content).toContain('Hello! I\'m your AI Assistant');
});

test('loadChatHistory handles error', async () => {
  const showErrorMock = mockShowError();
  comp.$root.showError = jest.fn(() => {
    throw new Error('Test error');
  });
  
  await comp.loadChatHistory();
  
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


test('loadCurrentChatId handles localStorage error', () => {
  mockLocalStorage.getItem.mockImplementation(() => {
    throw new Error('localStorage error');
  });
  
  const result = comp.loadCurrentChatId();
  
  expect(result).toBe(null);
});

test('generateChatId creates unique ID', () => {
  const id1 = comp.generateChatId();
  const id2 = comp.generateChatId();
  
  expect(id1).toMatch(/^chat_\d+_[a-z0-9]+$/);
  expect(id2).toMatch(/^chat_\d+_[a-z0-9]+$/);
  expect(id1).not.toBe(id2);
});

// Session management tests
test('handleRouteSessionId with existing session', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();
  
  await comp.handleRouteSessionId();
  
  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(fakeSessionId);
});

test('handleRouteSessionId with non-existent session', async () => {
  comp.$route.params.sessionId = fakeSessionId;
  comp.loadChatFromBackend = jest.fn().mockRejectedValue(new Error('Session not found'));
  
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

// Chat operations tests
test('loadChat switches to existing chat', async () => {
  const chat = fakeChatHistory[0];
  comp.saveCurrentChat = jest.fn().mockResolvedValue();
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();
  comp.updateUrlWithSessionId = jest.fn();
  comp.scrollToBottom = jest.fn();
  comp.currentChatId = chat.sessionId; // Set current chat ID to match
  
  await comp.loadChat(chat);
  
  expect(comp.saveCurrentChat).toHaveBeenCalled();
  expect(comp.loadChatFromBackend).toHaveBeenCalledWith(chat.sessionId);
  expect(comp.updateUrlWithSessionId).toHaveBeenCalledWith(chat.sessionId);
  expect(comp.scrollToBottom).toHaveBeenCalled();
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
  comp.loadChatHistory = jest.fn();
  
  await comp.deleteChat(chatId);
  
  expect(mock).toHaveBeenCalledWith(`/assistant/sessions/${chatId}`);
  expect(comp.chatHistory).toHaveLength(0);
  expect(comp.currentChatId).toBe(null);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.loadChatHistory).toHaveBeenCalled();
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
  comp.loadChatHistory = jest.fn();
  comp.currentChatId = fakeSessionId;
  
  await comp.startNewChat();
  
  expect(comp.saveCurrentChat).toHaveBeenCalled();
  expect(comp.currentChatId).toBe(null);
  expect(comp.saveCurrentChatId).toHaveBeenCalled();
  expect(comp.loadChatHistory).toHaveBeenCalled();
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
  
  await comp.sendMessage();
  
  expect(showErrorMock).toHaveBeenCalledWith('Failed to get AI response: API failed');
  expect(comp.isTyping).toBe(false);
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

test('approveTool executes tool', async () => {
  const toolUse = { ...fakeToolUse };
  comp.executeTool = jest.fn().mockResolvedValue();
  comp.scrollToBottom = jest.fn();
  
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
  
  await comp.approveTool(toolUse);
  
  expect(toolUse.status).toBe('error');
  expect(toolUse.error).toBe('Failed to execute approved tool: Execution failed');
});

test('rejectTool marks as rejected', async () => {
  const toolUse = { ...fakeToolUse };
  comp.scrollToBottom = jest.fn();
  comp.callAIAPI = jest.fn().mockResolvedValue();
  
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
  mockPapi('get', { data: [] });
  
  await comp.executeTool(toolUse);
  
  expect(mockPost).toHaveBeenCalledWith('/assistant/tool/query_events', {
    sessionId: fakeSessionId,
    toolUseId: toolUse.id,
    params: toolUse.input  
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
  expect(comp.executingTools.get('block_0')).toBeDefined();
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
  mockPapi('get', backendResponse)
  
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
  
  await comp.callAIAPI('Test message');
  
  expect(mockPost).toHaveBeenCalledWith('/assistant/chat', {
      msg: 'Test message',
      sessionId: fakeSessionId
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
  expect(comp.executingTools.get('block_0')).toBeDefined();
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
  
  const toolUse = comp.executingTools.get('block_0');
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
  
  const toolUse = comp.executingTools.get('block_0');
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
  
  const toolUse = comp.executingTools.get('block_0');
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
  
  expect(comp.$root.formatMarkdown).toHaveBeenCalledWith(text);
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
  expect(result[0].content).toBe('Complex message with tools/attachments');
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
  expect(result[0].content).toBe('Complex message with tools/attachments');
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
          { type: '', content: 'I can help you with security analysis and investigations.' }
        ]
      }
    }
  ];
  const mock = mockPapi("get", { data: testMessages });
  
  await comp.loadChatFromBackend(fakeSessionId);
  
  expect(mock).toHaveBeenCalledWith(`/assistant/sessions/${fakeSessionId}`);
  expect(comp.messages).toHaveLength(2);
  expect(comp.currentChatId).toBe(fakeSessionId);
});

test('loadChatFromBackend handles 404 error', async () => {
  const error = new Error('Not found');
  error.response = { status: 404 };
  mockPapi("get", null, error);
  comp.loadChatHistory = jest.fn();
  
  await comp.loadChatFromBackend(fakeSessionId);
  
  expect(comp.loadChatHistory).toHaveBeenCalled();
  expect(comp.currentChatId).toBe(fakeSessionId);
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