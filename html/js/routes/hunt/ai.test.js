// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../../test_common.js');
const { aiMethods } = require('../hunt-bundled.js');

describe('ai.js', () => {
  let mockThis;

  beforeEach(() => {
    mockThis = {
      i18n: {
        aiInvestigationUnableToIdentify: 'Unable to identify the alert for AI investigation.',
        aiTruePositive: 'True Positive',
        aiFalsePositive: 'False Positive',
        aiUncertain: 'Uncertain',
        aiConfidence: 'Confidence',
        clickToOpenChat: 'Click to open chat',
        aiAssessment: 'AI Assessment',
        aiInvestigationCompleted: 'AI investigation completed',
        aiInvestigationInProgress: 'AI investigation in progress',
        startAIInvestigation: 'Start AI investigation',
      },
      aiInvestigations: {},
      $root: {
        showError: jest.fn(),
      },
      saveAIInvestigations: aiMethods.saveAIInvestigations,
      generateInvestigationPrompt: aiMethods.generateInvestigationPrompt,
    };

    // Mock localStorage
    const localStorageMock = (() => {
      let store = {};
      return {
        getItem: jest.fn((key) => {
          return store[key] || null;
        }),
        setItem: jest.fn((key, value) => {
          store[key] = value.toString();
        }),
        clear: jest.fn(() => {
          store = {};
        }),
        removeItem: jest.fn((key) => {
          delete store[key];
        })
      };
    })();
    Object.defineProperty(window, 'localStorage', { value: localStorageMock });
  });

  test('generateInvestigationPrompt', () => {
    const item = {
      'rule.uuid': '1234-5678',
      'rule.name': 'Test Rule',
      'event.severity_label': 'High',
      'soc_timestamp': '2025-08-08T12:00:00Z',
      'source.ip': '192.168.1.1',
      'destination.ip': '8.8.8.8',
      'event.module': 'suricata',
      'event.dataset': 'alert',
      'message': 'This is a test alert.',
      'rule.rule': 'alert http any any -> any any (msg:"Test"; sid:1;)'
    };

    const prompt = mockThis.generateInvestigationPrompt(item);

    expect(prompt).toContain('Alert ID: 1234-5678');
    expect(prompt).toContain('Title: Test Rule');
    expect(prompt).toContain('Severity: High');
    expect(prompt).toContain('Rule: alert http any any -> any any (msg:"Test"; sid:1;)');
    expect(prompt).toContain('Source IP: 192.168.1.1');
    expect(prompt).toContain('Destination IP: 8.8.8.8');
    expect(prompt).toContain('Timestamp: 2025-08-08T12:00:00Z');
    expect(prompt).toContain('INVESTIGATION STEPS:');
  });

  test('startAIInvestigation - new investigation', () => {
    const item = { 'rule.uuid': 'alert-1' };
    window.open = jest.fn();
    const dateNowSpy = jest.spyOn(Date, 'now').mockImplementation(() => 1234567890);

    aiMethods.startAIInvestigation.call(mockThis, {}, item, 0);

    expect(item._aiInvestigationStatus).toBe('investigating');
    expect(mockThis.aiInvestigations['alert-1']).toBeDefined();
    expect(mockThis.aiInvestigations['alert-1'].status).toBe('investigating');
    expect(mockThis.aiInvestigations['alert-1'].chatSessionId).toContain('investigation_alert-1_');
    expect(window.localStorage.setItem).toHaveBeenCalledWith(expect.stringContaining('investigation_investigation_alert-1_'), expect.any(String));
    expect(window.open).toHaveBeenCalledWith(`${window.location.origin}/#/chat/investigation_alert-1_1234567890?investigation=true&alertId=alert-1`, '_blank');
    
    dateNowSpy.mockRestore();
  });

  test('startAIInvestigation - existing completed investigation', () => {
    const item = {
      'rule.uuid': 'alert-2',
      _aiInvestigationStatus: 'completed',
      _aiInvestigationResult: { chatSessionId: 'chat-123' }
    };
    window.open = jest.fn();

    aiMethods.startAIInvestigation.call(mockThis, {}, item, 0);

    expect(window.open).toHaveBeenCalledWith(`${window.location.origin}/#/chat/chat-123`, '_blank');
  });

  test('getAIInvestigationButtonColor', () => {
    mockThis.aiInvestigations = {
      'alert-tp': { assessment: 'true_positive' },
      'alert-fp': { assessment: 'false_positive' },
      'alert-unc': { assessment: 'uncertain' }
    };

    expect(aiMethods.getAIInvestigationButtonColor.call(mockThis, { _aiInvestigationStatus: 'investigating' })).toBe('primary');
    expect(aiMethods.getAIInvestigationButtonColor.call(mockThis, { 'rule.uuid': 'alert-tp', _aiInvestigationStatus: 'completed' })).toBe('red darken-1');
    expect(aiMethods.getAIInvestigationButtonColor.call(mockThis, { 'rule.uuid': 'alert-fp', _aiInvestigationStatus: 'completed' })).toBe('green darken-1');
    expect(aiMethods.getAIInvestigationButtonColor.call(mockThis, { 'rule.uuid': 'alert-unc', _aiInvestigationStatus: 'completed' })).toBe('amber darken-1');
    expect(aiMethods.getAIInvestigationButtonColor.call(mockThis, { _aiInvestigationStatus: 'error' })).toBe('red darken-1');
    expect(aiMethods.getAIInvestigationButtonColor.call(mockThis, {})).toBe('pink-lighten-2');
  });

  test('getAIInvestigationTooltip', () => {
    mockThis.aiInvestigations = {
      'alert-tp': { assessment: 'true_positive', confidence: 95 },
      'alert-fp': { assessment: 'false_positive', confidence: 80 },
      'alert-completed': {}
    };

    expect(aiMethods.getAIInvestigationTooltip.call(mockThis, { 'rule.uuid': 'alert-tp', _aiInvestigationStatus: 'completed' })).toBe('AI Assessment: True Positive (95% Confidence) - Click to open chat');
    expect(aiMethods.getAIInvestigationTooltip.call(mockThis, { 'rule.uuid': 'alert-fp', _aiInvestigationStatus: 'completed' })).toBe('AI Assessment: False Positive (80% Confidence) - Click to open chat');
    expect(aiMethods.getAIInvestigationTooltip.call(mockThis, { 'rule.uuid': 'alert-completed', _aiInvestigationStatus: 'completed' })).toBe('AI investigation completed - Click to open chat');
    expect(aiMethods.getAIInvestigationTooltip.call(mockThis, { _aiInvestigationStatus: 'investigating' })).toBe('AI investigation in progress - Click to open chat');
    expect(aiMethods.getAIInvestigationTooltip.call(mockThis, {})).toBe('Start AI investigation');
  });
});