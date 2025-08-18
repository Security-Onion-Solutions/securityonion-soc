// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../../test_common.js');
const { playbookMethods } = require('../hunt-bundled.js');

let comp;

beforeEach(() => {
  comp = {
    $root: {
      papi: {
        get: jest.fn(),
        post: jest.fn(),
        put: jest.fn(),
      },
      enableReverseLookup: false,
      batchLookup: jest.fn(),
    },
    i18n: {
      timePickerSample: '2006/01/02 3:04:05 PM',
      timePickerFormat: 'YYYY/MM/DD hh:mm:ss A',
    },
    zone: 'Etc/UTC',
    expandedPlaybookQuestions: {},
    queryVariableSubstitution: playbookMethods.queryVariableSubstitution,
    convertPlaybookQueries: playbookMethods.convertPlaybookQueries,
    askQuestion: playbookMethods.askQuestion,
    buildQuestionRange: playbookMethods.buildQuestionRange,
    getEventTimestamp: playbookMethods.getEventTimestamp,
    isQuestionAggregate: playbookMethods.isQuestionAggregate,
    sortAggregateEvents: playbookMethods.sortAggregateEvents,
    $nextTick: (f) => { f() },
  };
});

test('loadPlaybook', async () => {
  let event = {
    'rule.uuid': '123',
  };

  const playbooks = [{ id: '1', questions: [] }, { id: '2', questions: [] }];

  // The mockPapi function only takes method name, not the papi object
  comp.$root.papi.get = jest.fn().mockResolvedValue({ data: playbooks });
  comp.$root.papi.post = jest.fn().mockResolvedValue({ data: [] });

  await playbookMethods.loadPlaybook.call(comp, event, 0);

  expect(comp.$root.papi.get).toHaveBeenCalledWith('playbook/detection/123');
  expect(event.playbooks).toStrictEqual(playbooks);
  expect(event.playbookLoading).toBe(undefined);
  expect(event.playbookErr).toBe(false);

  // Test error case
  comp.$root.papi.get = jest.fn().mockRejectedValue(new Error('error'));

  event = {
    'rule.uuid': '456',
  };

  await playbookMethods.loadPlaybook.call(comp, event, 0);

  expect(comp.$root.papi.get).toHaveBeenCalledWith('playbook/detection/456');
  expect(comp.$root.papi.get).toHaveBeenCalledTimes(1); // Only this call since we reset the mock
  expect(event.playbookErr).toBe(true);
  expect(event.playbooks).toBe(null);

  event = {};

  await playbookMethods.loadPlaybook.call(comp, event, 0);

  expect(event.playbookErr).toBe(true);

  comp.$root.papi.get.mockClear();

  event = { playbooks: '' };

  await playbookMethods.loadPlaybook.call(comp, event, 0);
  expect(event.playbookErr).toBe(undefined);
  expect(event.playbookLoading).toBe(undefined);
  expect(comp.$root.papi.get).toHaveBeenCalledTimes(0);

  event = { playbookLoading: '' };

  await playbookMethods.loadPlaybook.call(comp, event, 0);
  expect(event.playbooks).toBe(undefined);
  expect(event.playbookErr).toBe(undefined);
  expect(comp.$root.papi.get).toHaveBeenCalledTimes(0);

  event = { playbookErr: true };

  await playbookMethods.loadPlaybook.call(comp, event, 0);
  expect(event.playbooks).toBe(undefined);
  expect(event.playbookLoading).toBe(undefined);
  expect(comp.$root.papi.get).toHaveBeenCalledTimes(0);

  comp.$root.papi.get.mockReset();
});

test('askQuestion', async () => {
  comp.$root.enableReverseLookup = true;
  comp.zone = "Etc/UTC";

  let question = {};
  let event = {
    field: 'present',
    func: function() {}, // not present
  };

  await playbookMethods.askQuestion.call(comp, question, event);

  expect(question.answers.length).toBe(1);
  expect('field' in question.answers[0].payload).toBe(true);
  expect('func' in question.answers[0].payload).toBe(false);

  comp.$root.papi.get = jest.fn().mockResolvedValue({
    data: {
      metrics: {
        biggest: [
          {
            payload: {
              name: 'metric event',
              ip: '1.1.1.1',
            },
          },
        ],
      },
    },
  });

  question = {
    range: '-30d',
    filledOQL: 'OQL Query',
    isAggregate: true,
  };
  event = {
    'soc_timestamp': '2023-10-01T12:00:00Z',
  };

  await playbookMethods.askQuestion.call(comp, question, event);

  expect(question.answers.length).toBe(1);
  expect(question.answers[0].payload.name).toBe('metric event');
  expect('error' in question).toBe(false);

  expect(comp.$root.papi.get).toHaveBeenCalledTimes(1);
  expect(comp.$root.papi.get).toHaveBeenCalledWith('events/', {
    params: {
      query: 'OQL Query',
      range: '2023/09/01 12:00:00 PM - 2023/10/01 12:00:00 PM',
      format: '2006/01/02 3:04:05 PM',
      zone: 'Etc/UTC',
      metricLimit: 5,
      eventLimit: 5,
    },
  });

  expect(comp.$root.batchLookup).toHaveBeenCalledTimes(2);
  expect(comp.$root.batchLookup).toHaveBeenCalledWith(['metric event', '1.1.1.1'], comp);

  comp.$root.papi.get.mockReset();
  comp.$root.papi.get = jest.fn().mockRejectedValue(new Error('something went wrong'));

  question = {
    range: '-30d',
    filledOQL: 'OQL Query',
    isAggregate: false,
  };
  event = {
    'soc_timestamp': '2023-10-01T12:00:00Z',
  };

  await playbookMethods.askQuestion.call(comp, question, event);

  expect(question.answers.length).toBe(0);
  expect('error' in question).toBe(true);
  expect(question.error).toBe(true);

  expect(comp.$root.papi.get).toHaveBeenCalledTimes(1);
  expect(comp.$root.papi.get).toHaveBeenCalledWith('events/', {
    params: {
      query: 'OQL Query | sortby @timestamp',
      range: '2023/09/01 12:00:00 PM - 2023/10/01 12:00:00 PM',
      format: '2006/01/02 3:04:05 PM',
      zone: 'Etc/UTC',
      metricLimit: 5,
      eventLimit: 5,
    },
  });

  comp.$root.enableReverseLookup = false;
  comp.$root.papi.get.mockReset();
});

test('queryVariableSubstitution - handles simple variable substitution', () => {
    const event = {
      'host.name': 'test-host',
      'source.ip': '192.168.1.1'
    };
    const playbooks = [{
      questions: [{
        query: 'hostname: {host.name}\\nsource_ip: {source.ip}'
      }]
    }];

    playbookMethods.queryVariableSubstitution.call(comp, event, playbooks);
    expect(playbooks[0].questions[0].filledQuery).toBe(
      'hostname: test-host\\nsource_ip: 192.168.1.1'
    );
  });

test('queryVariableSubstitution - handles array fields with proper indentation', () => {
    const event = {
      'network.private_ip': ['192.168.1.1', '10.0.0.1'],
      'network.public_ip': ['203.0.113.1']
    };
    const playbooks = [{
      questions: [{
        query: '    private_ips: {network.private_ip}\n    public_ips: {network.public_ip}'
      }]
    }];

    playbookMethods.queryVariableSubstitution.call(comp, event, playbooks);
    expect(playbooks[0].questions[0].filledQuery).toBe(
      '    private_ips:\n        - 192.168.1.1\n        - 10.0.0.1\n    public_ips:\n        - 203.0.113.1'
    );
  });

test('queryVariableSubstitution - handles missing fields with NODATA', () => {
    const event = {
      'host.name': 'test-host'
    };
    const playbooks = [{
      questions: [{
        query: 'hostname: {host.name}\\nip: {missing.field}'
      }]
    }];

    playbookMethods.queryVariableSubstitution.call(comp, event, playbooks);
    expect(playbooks[0].questions[0].filledQuery).toBe(
      'hostname: test-host\\nip: NODATA'
    );
  });

test('queryVariableSubstitution - handles array fields with dashes', () => {
    const event = {
      'network.private_ip': ['192.168.1.1', '10.0.0.1']
    };
    const playbooks = [{
      questions: [{
        query: '    - private_ips: {network.private_ip}'
      }]
    }];

    playbookMethods.queryVariableSubstitution.call(comp, event, playbooks);
    expect(playbooks[0].questions[0].filledQuery).toBe(
      '    - private_ips:\n        - 192.168.1.1\n        - 10.0.0.1'
    );
  });

test('queryVariableSubstitution - handles real-world query format', () => {
  const event = {
    'network.private_ip': ['192.168.1.1', '10.0.0.1'],
    'dns.query_name': 'malicious.com',
    'network.public_ip': ['203.0.113.1'],
    'related.ip': ['203.0.113.1', '192.168.1.2'],
  };
  const playbooks = [{
    questions: [{
      query: `aggregation: false
logsource:
  category: network
  service: dns
detection:
  selection:
       - src_ip: '{network.private_ip}'
       - dns.query.name|contains: '{dns.query_name}'
       - dns.resolved_ip: '{network.public_ip}'
    filter:
      dst_ip: '{related.ip}'
    condition: selection and filter
fields:
    - dns.query.name
    - dns.query.type_name
    - dns.resolved_ip
    - dns.response.code_name`
    }]
  }];

  playbookMethods.queryVariableSubstitution.call(comp, event, playbooks);
  expect(playbooks[0].questions[0].filledQuery).toBe(
    `aggregation: false
logsource:
  category: network
  service: dns
detection:
  selection:
       - src_ip:
           - 192.168.1.1
           - 10.0.0.1
       - dns.query.name|contains: 'malicious.com'
       - dns.resolved_ip:
           - 203.0.113.1
    filter:
      dst_ip:
          - 203.0.113.1
          - 192.168.1.2
    condition: selection and filter
fields:
    - dns.query.name
    - dns.query.type_name
    - dns.resolved_ip
    - dns.response.code_name`
  );
});

test('buildQuestionRange', () => {
  const event = {
    '@timestamp': '2023-10-01T12:00:00Z',
  };

  comp.zone = 'America/Denver';

  let range = playbookMethods.buildQuestionRange.call(comp, event, '+/-30d');
  expect(range).toBe('2023/09/01 06:00:00 AM - 2023/10/31 06:00:00 AM');

  range = playbookMethods.buildQuestionRange.call(comp, event, '-15m');
  expect(range).toBe('2023/10/01 05:45:00 AM - 2023/10/01 06:00:00 AM');

  range = playbookMethods.buildQuestionRange.call(comp, event, '2h');
  expect(range).toBe('2023/10/01 06:00:00 AM - 2023/10/01 08:00:00 AM');

  range = playbookMethods.buildQuestionRange.call(comp, event, '+/-60s');
  expect(range).toBe('2023/10/01 05:59:00 AM - 2023/10/01 06:01:00 AM');

  range = playbookMethods.buildQuestionRange.call(comp, event, '');
  expect(range).toBe('');

  range = playbookMethods.buildQuestionRange.call(comp, event, 'X');
  expect(range).toBe('');

  range = playbookMethods.buildQuestionRange.call(comp, event, '10p');
  expect(range).toBe('');
});

test('toggleAllQuestions', () => {
  let event = {
    questions: [{}, {}, {}]
  };
  let index = 0;
  let expand = true;
  comp.expandedPlaybookQuestions = {};

  // expand
  playbookMethods.toggleAllQuestions.call(comp, event, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [0, 1, 2] });

  // expand a different index
  index = 1;
  playbookMethods.toggleAllQuestions.call(comp, event, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [0, 1, 2], 1: [0, 1, 2] });

  // collapse non-existing index
  index = 2;
  expand = false;
  playbookMethods.toggleAllQuestions.call(comp, event, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [0, 1, 2], 1: [0, 1, 2], 2: [] });

  // collapse existing, expanded index
  index = 0;
  playbookMethods.toggleAllQuestions.call(comp, event, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [], 1: [0, 1, 2], 2: [] });

  // expand existing, partially expanded
  comp.expandedPlaybookQuestions[0] = [1];
  expand = true;
  playbookMethods.toggleAllQuestions.call(comp, event, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [1, 0, 2], 1: [0, 1, 2], 2: [] });

  // no changes when expanding an already expanded group, even if out of order
  playbookMethods.toggleAllQuestions.call(comp, event, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [1, 0, 2], 1: [0, 1, 2], 2: [] });

  // no change when collapsing an already collapsed group
  index = 2;
  expand = false;
  playbookMethods.toggleAllQuestions.call(comp, event, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [1, 0, 2], 1: [0, 1, 2], 2: [] });

  // handle aggregate event
  let aggEvent = {
    newest: event,
  };

  expand = true;
  playbookMethods.toggleAllQuestions.call(comp, aggEvent, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [1, 0, 2], 1: [0, 1, 2], 2: [0, 1, 2] });

  // handle event that doesn't have playbooks yet
  const _setTimeout = global.setTimeout;
  const setTimeoutMock = jest.fn();
  global.setTimeout = setTimeoutMock;

  let emptyEvent = {};
  index = 0;
  expand = true;

  playbookMethods.toggleAllQuestions.call(comp, emptyEvent, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [1, 0, 2], 1: [0, 1, 2], 2: [0, 1, 2] });
  expect(setTimeoutMock).toHaveBeenCalledTimes(1);

  // handle agg event that doesn't have playbooks yet
  aggEvent.newest = emptyEvent;
  setTimeoutMock.mockClear();
  
  playbookMethods.toggleAllQuestions.call(comp, aggEvent, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [1, 0, 2], 1: [0, 1, 2], 2: [0, 1, 2] });
  expect(setTimeoutMock).toHaveBeenCalledTimes(1);
  
  // handle event that's loading playbooks
  emptyEvent.playbookLoading = true;
  emptyEvent.playbooks = null;
  setTimeoutMock.mockClear();
  
  playbookMethods.toggleAllQuestions.call(comp, emptyEvent, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [1, 0, 2], 1: [0, 1, 2], 2: [0, 1, 2] });
  expect(setTimeoutMock).toHaveBeenCalledTimes(1);

  // handle agg event that's loading playbooks
  aggEvent.newest = emptyEvent;
  setTimeoutMock.mockClear();
  
  playbookMethods.toggleAllQuestions.call(comp, aggEvent, index, expand);
  expect(comp.expandedPlaybookQuestions).toStrictEqual({ 0: [1, 0, 2], 1: [0, 1, 2], 2: [0, 1, 2] });
  expect(setTimeoutMock).toHaveBeenCalledTimes(1);

  global.setTimeout = _setTimeout;
});

test('pickQuestionColor', () => {
  let question = {
    error: true,
  };

  let c = playbookMethods.pickQuestionColor(question);
  expect(c).toBe('has-error');

  question = {
    error: false,
  };

  c = playbookMethods.pickQuestionColor(question);
  expect(c).toBe('no-data');

  question = {}

  c = playbookMethods.pickQuestionColor(question);
  expect(c).toBe('no-data');

  question = {
    answers: [],
  };

  c = playbookMethods.pickQuestionColor(question);
  expect(c).toBe('no-data');

  question = {
    answers: [{}],
  };

  c = playbookMethods.pickQuestionColor(question);
  expect(c).toBe('has-answers');

  question = {
    answers: [{}],
    error: false,
  };

  c = playbookMethods.pickQuestionColor(question);
  expect(c).toBe('has-answers');

  question = {
    answers: [{}],
    error: true,
  };

  c = playbookMethods.pickQuestionColor(question);
  expect(c).toBe('has-error');
});

test('sortAggregateEvents', () => {
  let tests = [
    [
      { expectedPos: 1, value: 2 },
      { expectedPos: 2, value: 1 },
      { expectedPos: 0, value: 3 },
    ],
    [
      { expectedPos: 2, value: 40 },
      { expectedPos: 3, value: 30 },
      { expectedPos: 0, value: 60 },
      { value: 10 },
      { expectedPos: 1, value: 50 },
      { expectedPos: 4, value: 20 },
    ],
    [
      { expectedPos: 0, value: 0 },
    ],
  ];

  for (let events of tests) {
    const sortedEvents = playbookMethods.sortAggregateEvents(events);

    if (events.length >= 5) {
      expect(sortedEvents.length).toBe(5);
    } else {
      expect(sortedEvents.length).toBe(events.length);
    }

    for (let i = 0; i < sortedEvents.length; i++) {
      expect(sortedEvents[i].expectedPos).toBe(i);
    }
  }
});

test('buildHuntQuestionParams', () => {
    const question = {
        filledOQL: 'some oql query',
        range: '-1h'
    };
    const event = {
        '@timestamp': '2023-10-26T10:00:00Z'
    };
    comp.dateToRange = jest.fn( (d) => '2023/10/26 10:00:00 AM - 2023/10/26 10:00:00 AM');

    let params = playbookMethods.buildHuntQuestionParams.call(comp, question, event);

    expect(params.name).toBe('hunt');
    expect(params.query.q).toBe('some oql query');
    expect(params.query.t).toBe('2023/10/26 09:00:00 AM - 2023/10/26 10:00:00 AM');

    delete question.range;
    params = playbookMethods.buildHuntQuestionParams.call(comp, question, event);
    expect(params.query.t).toBe('2023/10/26 10:00:00 AM - 2023/10/26 10:00:00 AM');
});

test('getEventTimestamp', () => {
    expect(playbookMethods.getEventTimestamp({ 'event_data.@timestamp': '1' })).toBe('1');
    expect(playbookMethods.getEventTimestamp({ '@timestamp': '2' })).toBe('2');
    expect(playbookMethods.getEventTimestamp({ 'soc_timestamp': '3' })).toBe('3');
    expect(playbookMethods.getEventTimestamp({})).toBe('');
});

test('isQuestionAggregate', () => {
    let question = { isAggregate: true };
    expect(playbookMethods.isQuestionAggregate(question)).toBe(true);

    question = { isAggregate: false };
    expect(playbookMethods.isQuestionAggregate(question)).toBe(false);

    question = { query: 'aggregation: true' };
    expect(playbookMethods.isQuestionAggregate(question)).toBe(true);

    question = { query: 'aggregation: false' };
    expect(playbookMethods.isQuestionAggregate(question)).toBe(false);

    question = { query: 'aggregation: True' };
    expect(playbookMethods.isQuestionAggregate(question)).toBe(true);
});

test('convertPlaybookQueries', async () => {
    const playbooks = [
        { questions: [{ filledQuery: 'q1' }, { filledQuery: 'q2' }] },
        { questions: [{ filledQuery: 'q3' }] }
    ];
    const converted = [
        { query: 'oql1', fields: ['f1'] },
        { query: 'oql2', fields: ['f2'] },
        { query: 'oql3', fields: ['f3'] }
    ];
    comp.$root.papi.post = jest.fn().mockResolvedValue({ data: converted });

    await playbookMethods.convertPlaybookQueries.call(comp, playbooks);

    expect(comp.$root.papi.post).toHaveBeenCalledWith('playbook/convert', ['q1', 'q2', 'q3']);
    expect(playbooks[0].questions[0].filledOQL).toBe('oql1');
    expect(playbooks[0].questions[0].fields).toEqual(['f1']);
    expect(playbooks[0].questions[1].filledOQL).toBe('oql2');
    expect(playbooks[0].questions[1].fields).toEqual(['f2']);
    expect(playbooks[1].questions[0].filledOQL).toBe('oql3');
    expect(playbooks[1].questions[0].fields).toEqual(['f3']);
});