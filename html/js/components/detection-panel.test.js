// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./detection-panel.js');

let comp;

beforeEach(() => {
  resetPapi();
  comp = getComponent("DetectionPanel");
  comp.detection = {
    id: 'test-123',
    publicId: '1000',
    title: 'Test Detection',
    content: 'alert tcp any any -> any any (msg:"Test"; sid:1000;)',
    language: 'suricata',
    engine: 'suricata',
    isEnabled: true,
    overrides: []
  };
  comp.origDetect = comp.detection;
  comp.zone = 'UTC';
  comp.ackColor = 'primary';
  comp.alertInfo = {
    item: {},
    groupIndex: -1
  };
  comp.emit = jest.fn();
  comp.$root.i18n = global.i18n.getLocalizedTranslations('en-US');
});

test('extractSummary for Suricata', () => {
  comp.detection.content = 'alert tcp any any -> any any (msg:"Test"; classtype:test-class; sid:1000;)';
  comp.prepareDetection();
  expect(comp.extractedSummary).toBe('test-class');
});

test('extractSummary fallback to title', () => {
  comp.detection.content = 'alert tcp any any -> any any (msg:"Test"; sid:1000;)';
  comp.prepareDetection();
  expect(comp.extractedSummary).toBe('Test Detection');
});

test('extractSummary for ElastAlert with YAML description', () => {
  comp.detection.engine = 'elastalert';
  comp.detection.language = 'sigma';
  comp.detection.content = 'description: Test Description\ndetection:\n  condition: selection';
  comp.prepareDetection();
  expect(comp.extractedSummary).toBe('Test Description');
});

test('extractSummary for ElastAlert with description field', () => {
  comp.detection.engine = 'elastalert';
  comp.detection.language = 'sigma';
  comp.detection.content = 'title: Test\ndetection:\n  condition: selection';
  comp.detection.description = 'Field Description';
  comp.prepareDetection();
  expect(comp.extractedSummary).toBe('Field Description');
});

test('extractSummary for ElastAlert fallback to title', () => {
  comp.detection.engine = 'elastalert';
  comp.detection.language = 'sigma';
  comp.detection.content = 'title: Test\ndetection:\n  condition: selection';
  comp.prepareDetection();
  expect(comp.extractedSummary).toBe('Test Detection');
});

test('extractSummary for Yara with description field', () => {
  comp.detection.engine = 'strelka';
  comp.detection.language = 'yara';
  comp.detection.description = 'Yara Description';
  comp.prepareDetection();
  expect(comp.extractedSummary).toBe('Yara Description');
});

test('extractSummary for Yara fallback to title', () => {
  comp.detection.engine = 'strelka';
  comp.detection.language = 'yara';
  comp.prepareDetection();
  expect(comp.extractedSummary).toBe('Test Detection');
});

test('canAddOverride suricata', () => {
  comp.detect = {
    engine: 'suricata',
  };

  expect(comp.canAddOverride()).toBe(true);

  comp.detection.overrides = [
    {
      type: 'modify',
      isEnabled: 'isEnabled',
      createdAt: 'createdAt',
      updatedAt: 'updatedAt',
      customFilter: 'custom filter',
      regex: 'regex',
      value: 'value',
      thresholdType: 'thresholdType',
      track: 'track',
      count: '10',
      seconds: '10',
      ip: 'ip',
    },
    {
      type: 'threshold',
      isEnabled: 'isEnabled',
      createdAt: 'createdAt',
      updatedAt: 'updatedAt',
      customFilter: 'custom filter',
      regex: 'regex',
      value: 'value',
      thresholdType: 'thresholdType',
      track: 'track',
      count: '10',
      seconds: '10',
      ip: 'ip',
    },
    {
      type: 'suppress',
      isEnabled: 'isEnabled',
      createdAt: 'createdAt',
      updatedAt: 'updatedAt',
      customFilter: 'custom filter',
      regex: 'regex',
      value: 'value',
      thresholdType: 'thresholdType',
      track: 'track',
      count: '10',
      seconds: '10',
      ip: 'ip',
    }
  ];

  expect(comp.canAddOverride()).toBe(true);
});

test('canAddOverride strelka', () => {
  comp.detection.engine = 'strelka';

  expect(comp.canAddOverride()).toBe(false);
});

test('canAddOverride elastalert', () => {
  comp.detect = {
    engine: 'elastalert',
  };

  expect(comp.canAddOverride()).toBe(true);

  comp.detection.overrides = [
    {
      type: 'customFilter',
      isEnabled: 'isEnabled',
      createdAt: 'createdAt',
      updatedAt: 'updatedAt',
      customFilter: 'custom filter',
      regex: 'regex',
      value: 'value',
      thresholdType: 'thresholdType',
      track: 'track',
      count: '10',
      seconds: '10',
      ip: 'ip',
    },
  ];

  expect(comp.canAddOverride()).toBe(true);
});

test('tagOverrides', () => {
  comp.detection = {};

  comp.tagOverrides();

  expect(comp.detection.overrides).toStrictEqual([]);

  comp.detection.overrides = [{}, {}, {}];

  comp.tagOverrides();

  for (let i = 0; i < comp.detection.overrides.length; i++) {
    expect(comp.detection.overrides[i]).toStrictEqual({ index: i });
  }
});

test('showAiSummary', () => {
  comp.detection = null;
  expect(comp.showAiSummary()).toBe(false);

  comp.detection = { engine: 'strelka' };
  expect(comp.showAiSummary()).toBe(false);

  comp.detection.aiSummary = 'aiSummary';
  expect(comp.showAiSummary()).toBe(false);

  comp.detection.aiSummaryReviewed = true;
  expect(comp.showAiSummary()).toBe(true);

  comp.detection.aiSummary = '';
  expect(comp.showAiSummary()).toBe(false);

  comp.showUnreviewedAiSummaries = true;

  comp.detection = null;
  expect(comp.showAiSummary()).toBe(false);

  comp.detection = { engine: 'elastalert' };
  expect(comp.showAiSummary()).toBe(false);

  comp.detection.aiSummary = 'aiSummary';
  expect(comp.showAiSummary()).toBe(true);

  comp.detection.aiSummaryReviewed = true;
  expect(comp.showAiSummary()).toBe(true);

  comp.detection.aiSummary = '';
  expect(comp.showAiSummary()).toBe(false);
});

test('validateSuricata success', () => {
  expect(comp.validateSuricata()).toBeNull();
});

test('validateSuricata missing SID', () => {
  comp.detection.content = 'alert tcp any any -> any any (msg:"Test";)';
  expect(comp.validateSuricata()).toBe(comp.i18n.invalidDetectionSuricataMissingSID);
});

test('validateSuricata SID mismatch', () => {
  comp.detection.content = 'alert tcp any any -> any any (msg:"Test"; sid:999;)';
  expect(comp.validateSuricata()).toBe(comp.i18n.invalidDetectionSuricataSIDMismatch);
});

test('validateElastAlert success', () => {
  comp.detection.language = 'sigma';
  comp.detection.engine = 'elastalert';
  comp.detection.publicId = 'test-123';
  comp.detection.content = 'id: test-123\ndetection:\n  condition: selection';
  expect(comp.validateElastAlert()).toBeNull();
});

test('validateElastAlert missing ID', () => {
  comp.detection.language = 'sigma';
  comp.detection.engine = 'elastalert';
  comp.detection.content = 'title: test\ndetection:\n  condition: selection';
  expect(comp.validateElastAlert()).toBe(comp.i18n.invalidDetectionElastAlertMissingID);
});

test('validateElastAlert ID Mismatch', () => {
  comp.detection.language = 'sigma';
  comp.detection.engine = 'elastalert';
  comp.detection.content = 'id: 123\ntitle: test\ndetection:\n  condition: selection';
  expect(comp.validateElastAlert()).toBe(comp.i18n.idMismatchErr);
});

test('validateStrelka success', () => {
  comp.detection.language = 'yara';
  comp.detection.engine = 'strelka';
  comp.detection.content = 'rule test_rule { condition: true }';
  expect(comp.validateStrelka()).toBeNull();
});

test('validateStrelka missing rule name', () => {
  comp.detection.language = 'yara';
  comp.detection.content = 'condition: true';
  expect(comp.validateStrelka()).toBe(comp.i18n.invalidDetectionStrelkaMissingRuleName);
});

test('toggleStatus true success', async () => {
  const updatedDetection = {
    ...comp.detection,
    isEnabled: true
  };
  mockPapi('put', {
    status: 200,
    data: updatedDetection
  });

  comp.detection.isEnabled = true;

  await comp.toggleStatus();
  expect(comp.$root.papi.put).toHaveBeenCalledWith('/detection', updatedDetection, expect.any(Object));
});

test('toggleStatus false success', async () => {
  const updatedDetection = {
    ...comp.detection,
    isEnabled: false
  };

  comp.detection.isEnabled = false;

  await comp.toggleStatus();
  expect(comp.ackExistingDialog).toBe(true);
});

test('toggleStatus error', async () => {
  mockPapi('put', null, {
    response: {
      status: 400,
    },
  });

  await comp.toggleStatus();
  expect(comp.$root.error).toBe(true);
});

test('addNewOverride', async () => {
  comp.createNewOverride();
  comp.newOverride.type = 'modify';
  comp.detection.overrides = null;
  mockPapi('put', {
    data:
    {
      ...comp.detection, overrides: [
        {
          isEnabled: true,
          note: '',
          regex: null,
          type: 'modify',
          value: null,
        },
      ] }
  });

  let expected = { ...comp.detection, overrides: [{
    isEnabled: true,
    note: '',
    regex: null,
    type: 'modify',
    value: null,
  }] };

  await comp.addNewOverride();
  expect(comp.$root.papi.put).toHaveBeenCalledWith('/detection', expected, expect.any(Object));
  expect(comp.newOverride).toBeNull();
});

test('cleanOverrides suricata', () => {
  comp.detection = {
    engine: 'suricata',
    overrides: [
      {
        type: 'modify',
        isEnabled: 'isEnabled',
        createdAt: 'createdAt',
        updatedAt: 'updatedAt',
        customFilter: 'custom filter',
        regex: 'regex',
        value: 'value',
        thresholdType: 'thresholdType',
        track: 'track',
        count: '10',
        seconds: '10',
        ip: 'ip',
      },
      {
        type: 'threshold',
        isEnabled: 'isEnabled',
        createdAt: 'createdAt',
        updatedAt: 'updatedAt',
        customFilter: 'custom filter',
        regex: 'regex',
        value: 'value',
        thresholdType: 'thresholdType',
        track: 'track',
        count: '10',
        seconds: '10',
        ip: 'ip',
      },
      {
        type: 'suppress',
        isEnabled: 'isEnabled',
        createdAt: 'createdAt',
        updatedAt: 'updatedAt',
        customFilter: 'custom filter',
        regex: 'regex',
        value: 'value',
        thresholdType: 'thresholdType',
        track: 'track',
        count: '10',
        seconds: '10',
        ip: 'ip',
      }
    ],
  };

  comp.cleanupOverrides();

  expect(comp.detection.overrides[0]).toStrictEqual({
    type: 'modify',
    isEnabled: 'isEnabled',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    regex: 'regex',
    value: 'value',
  });
  expect(comp.detection.overrides[1]).toStrictEqual({
    type: 'threshold',
    isEnabled: 'isEnabled',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    thresholdType: 'thresholdType',
    track: 'track',
    count: 10,
    seconds: 10,
  });
  expect(comp.detection.overrides[2]).toStrictEqual({
    type: 'suppress',
    isEnabled: 'isEnabled',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    track: 'track',
    ip: 'ip',
  });
});

test('cleanOverrides elastalert', () => {
  comp.detection = {
    engine: 'elastalert',
    overrides: [
      {
        type: 'custom filter',
        isEnabled: 'isEnabled',
        createdAt: 'createdAt',
        updatedAt: 'updatedAt',
        customFilter: 'custom filter',
        regex: 'regex',
        value: 'value',
        thresholdType: 'thresholdType',
        track: 'track',
        count: '10',
        seconds: '10',
        ip: 'ip',
      },
    ],
  };

  comp.cleanupOverrides();

  expect(comp.detection.overrides[0]).toStrictEqual({
    type: 'custom filter',
    isEnabled: 'isEnabled',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
    customFilter: 'custom filter',
  });
});

test('deleteOverride', async () => {
  comp.detection.overrides = [{
    type: 'suppress',
    isEnabled: true,
    index: 0
  }];

  const updatedDetection = {
    ...comp.detection,
    overrides: []
  };
  mockPapi('put', {
    status: 200,
    data: updatedDetection
  });

  await comp.deleteOverride(comp.detection.overrides[0]);
  expect(comp.$root.papi.put).toHaveBeenCalledWith('/detection', updatedDetection, expect.any(Object));
  expect(comp.detection.overrides).toHaveLength(0);
});

test('ack emits event', () => {
  comp.ack(false);
  expect(comp.emit).toHaveBeenCalledWith('ack', [
    comp.alertInfo.item,
    null,
    false,
    null,
    comp.alertInfo.groupIndex,
    true,
    false
  ]);

  comp.ack(true);
  expect(comp.emit).toHaveBeenCalledWith('ack', [
    comp.alertInfo.item,
    null,
    false,
    null,
    comp.alertInfo.groupIndex,
    true,
    true
  ]);
});

test('escalate emits event', () => {
  const event = { preventDefault: jest.fn() };
  comp.escalate(event);
  expect(comp.emit).toHaveBeenCalledWith('chooseCase', [
    event,
    comp.alertInfo.item,
    comp.alertInfo.groupIndex,
    true
  ]);
});

test('closeDetectionPanel emits event', () => {
  comp.closeDetectionPanel();
  expect(comp.emit).toHaveBeenCalledWith('close');
});


test('pickValue', () => {
  let opt = {
    value: 'value',
    altValues: ['alt1', 'alt2'],
  };
  let obj = {
    value: 'value',
    alt1: 'ALT1',
    alt2: 'ALT2',
  }

  let val = comp.pickValue(obj, opt);
  expect(val).toBe('value');

  delete obj.value;

  val = comp.pickValue(obj, opt);
  expect(val).toBe('ALT1');

  delete obj.alt1;

  val = comp.pickValue(obj, opt);
  expect(val).toBe('ALT2');

  delete obj.alt2;

  val = comp.pickValue(obj, opt);
  expect(val).toBe('');

  obj.value = 'track';
  opt.localize = true;

  val = comp.pickValue(obj, opt);
  expect(val).toBe('Track');
});

test('initParams', () => {
  comp.initParams();
  expect(comp.showUnreviewedAiSummaries).toBe(false);

  comp.initParams({
    showUnreviewedAiSummaries: true
  });
  expect(comp.showUnreviewedAiSummaries).toBe(true);
});