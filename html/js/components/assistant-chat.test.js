// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('../routes/assistant.sessions.js');
require('../routes/assistant.streaming.js');
require('../routes/assistant.tools.js');
require('../routes/assistant.utils.js');
require('./assistant-chat.js');

let comp;

const ENABLED_PARAMS = {
  enabled: true,
  investigationPrompt: 'Investigate {ruleName} from {sourceIp}',
  availableModels: [{ id: 'm1', adapter: 'a1', enabled: true, contextLimitSmall: 1000, charsPerTokenEstimate: 4 }],
  availableAdapters: [{ name: 'a1', protocol: 'local' }],
};

// Params reach the component through $root rather than loadParameters; see the comment
// on startEmbeddedChat.
function serverParams(params) {
  comp.$root.parameters = { assistant: params };
}

function licensed(yes) {
  comp.$root.isLicensed = jest.fn().mockReturnValue(yes);
}

beforeEach(() => {
  resetPapi();
  comp = getComponent("assistant-chat");
  comp.$root.i18n = global.i18n.getLocalizedTranslations('en-US');
  comp.i18n = comp.$root.i18n;
  comp.$emit = jest.fn();
  // The shared harness's $nextTick only supports the callback form; the chat also
  // awaits it, and reads $el when scrolling itself into view.
  comp.$nextTick = (fun) => { if (fun) fun(); return Promise.resolve(); };
  comp.$el = document.createElement('div');
  comp.$root.replaceActionVar = (msg, name, value) => (msg || '').replaceAll('{' + name + '}', value);
  comp.$root.showError = jest.fn();
  // Accepted by default; the gate has its own test.
  localStorage.setItem(ONIONAI_DISCLAIMER_KEY, 'true');

  // Reset the state getComponent flattens onto the shared component object.
  Object.assign(comp, comp.data());
  comp.investigation = null;
  comp.sessionId = null;

  licensed(true);
  serverParams(ENABLED_PARAMS);

  comp.loadStoredChats = jest.fn().mockResolvedValue();
  comp.loadCredits = jest.fn().mockImplementation(async () => { comp.creditsLoaded = true; });
  comp.sendMessage = jest.fn().mockResolvedValue();
  comp.loadChatFromBackend = jest.fn().mockResolvedValue();
});

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test('embeddedIsWhatKeepsTheSharedPacksOffTheUrl', () => {
  // The assistant packs branch on this to leave the URL and the disclaimer to the page
  // that owns them; if it is ever not set, an embedded chat navigates away mid-answer.
  expect(comp.embedded).toBe(true);
});

test('urlAndLastActiveChatAreLeftAloneWhenEmbedded', async () => {
  comp.$router.push = jest.fn();
  localStorage.removeItem('settings.assistant.currentChatId');
  comp.currentChatId = 'chat-1';

  await comp.updateUrlWithSessionId('chat-1');
  comp.saveCurrentChatId();

  expect(comp.$router.push).not.toHaveBeenCalled();
  expect(localStorage.getItem('settings.assistant.currentChatId')).toBeNull();
});

test('startEmbeddedChatStartsAnInvestigation', async () => {
  comp.investigation = { socId: 'evt-1', ruleName: 'ET MALWARE One', sourceIp: '10.0.0.1' };

  await comp.startEmbeddedChat();

  expect(comp.assistantEnabled).toBe(true);
  expect(comp.currentChatId).toMatch(UUID_V4);
  expect(comp.$emit).toHaveBeenCalledWith('session-started', comp.currentChatId);
  // the prompt is sent immediately -- the page's timer exists only to lose a race with
  // the router, which an embedded mount does not have
  expect(comp.sendMessage).toHaveBeenCalled();
  expect(comp.newMessage).toBe('Investigate ET MALWARE One from 10.0.0.1');
  expect(comp.messages).toEqual([]);
  expect(comp.starting).toBe(false);
});

test('theAlertUnderInvestigationIsCarriedInMemoryNotTheUrl', async () => {
  comp.investigation = { socId: 'evt-1', ruleName: 'r', sourceIp: 's' };

  await comp.startEmbeddedChat();

  expect(comp.investigationSocId).toBe('evt-1');
});

test('theInvestigatedAlertIsRecordedOnceAndOnlyOnce', async () => {
  comp.currentChatId = 'chat-1';
  comp.currentModel = 'm1@a1';
  comp.investigationSocId = 'evt-1';
  comp.loadCredits = jest.fn().mockResolvedValue();
  const post = mockPapi('post', { data: {
    pipeThrough: () => ({ getReader: () => ({ read: jest.fn().mockResolvedValue({ done: true }) }) }),
  }});

  await comp.callAIAPI('first');
  await comp.callAIAPI('follow-up');

  expect(post.mock.calls[0][0]).toBe('/assistant/chat?entityType=alert_investigation&entityId=evt-1');
  // a follow-up question must not re-mark the alert as investigated
  expect(post.mock.calls[1][0]).toBe('/assistant/chat');
});

test('startEmbeddedChatResumesAnExistingSession', async () => {
  comp.sessionId = 'chat-existing';
  comp.investigation = { socId: 'evt-1' };

  await comp.startEmbeddedChat();

  expect(comp.loadChatFromBackend).toHaveBeenCalledWith('chat-existing');
  expect(comp.currentChatId).toBe('chat-existing');
  expect(comp.$emit).toHaveBeenCalledWith('session-started', 'chat-existing');
  // resuming means resuming; no second investigation of the same alert
  expect(comp.sendMessage).not.toHaveBeenCalled();
});

test('aDeletedSessionFallsBackToAnEmptyChat', async () => {
  comp.sessionId = 'chat-gone';
  comp.loadChatFromBackend = jest.fn().mockRejectedValue(new Error('404'));

  await comp.startEmbeddedChat();

  expect(comp.startErr).toBe(comp.i18n.assistantUnableToLoadChat);
  expect(comp.messages).toHaveLength(1);
});

test('startEmbeddedChatReportsAnUnavailableAssistant', async () => {
  serverParams({ enabled: false });
  comp.investigation = { socId: 'evt-1' };

  await comp.startEmbeddedChat();

  expect(comp.startErr).toBe(comp.i18n.assistantNotAvailable);
  expect(comp.loadStoredChats).not.toHaveBeenCalled();
  expect(comp.sendMessage).not.toHaveBeenCalled();
});

test('startEmbeddedChatReportsAMissingLicence', async () => {
  licensed(false);
  comp.investigation = { socId: 'evt-1' };

  await comp.startEmbeddedChat();

  expect(comp.startErr).toBe(comp.i18n.assistantNotAvailable);
  expect(comp.sendMessage).not.toHaveBeenCalled();
});

test('startEmbeddedChatWaitsForParameters', async () => {
  comp.$root.parameters = {};
  comp.investigation = { socId: 'evt-1' };

  await comp.startEmbeddedChat();

  expect(comp.startErr).toBe(comp.i18n.assistantNotAvailable);
  expect(comp.loadStoredChats).not.toHaveBeenCalled();
});

// The notice covers sending event data to the OnionAI API, which is what this panel
// does; an inline panel must not become a way around it.
test('nothingIsSentUntilThePrivacyNoticeIsAccepted', async () => {
  localStorage.removeItem(ONIONAI_DISCLAIMER_KEY);
  comp.investigation = { socId: 'evt-1', ruleName: 'r', sourceIp: 's' };

  await comp.startEmbeddedChat();

  expect(comp.startErr).toBe(comp.i18n.assistantDisclaimerRequired);
  expect(comp.sendMessage).not.toHaveBeenCalled();
  expect(comp.loadStoredChats).not.toHaveBeenCalled();
});

test('anUnhealthyModelBlocksTheInvestigationRatherThanSendingIt', async () => {
  comp.investigation = { socId: 'evt-1' };
  comp.loadCredits = jest.fn().mockResolvedValue(); // leaves creditsLoaded false

  await comp.startEmbeddedChat();

  expect(comp.startErr).toBe(comp.i18n.assistantBalanceCheckUnhealthy);
  expect(comp.sendMessage).not.toHaveBeenCalled();
  expect(comp.currentChatId).toBeNull();
});
