// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
// agentmonitor.js picks from these globals, so they load first, as in index.html.
require('./assistant.sessions.js');
require('./assistant.utils.js');
require('./assistant.tools.js');
require('./assistant.streaming.js');
require('./agentmonitor.js');

let comp;
let originalConsole;

const agenticParams = () => ({ enabled: true, agentic: true, agentMapping: { Investigator: 'claude-sonnet@soai' } });

const TRIAGE_ID = 'a1d3f5b7-9c2e-4e68-8b4a-6f0c2d9e7b13';
const ago = (ms) => new Date(Date.now() - ms).toISOString();

const activity = () => ({
  schedulerRunning: true,
  pool: {
    queued: 1, running: 3, maxConcurrent: 4, maxQueueDepth: 0, peakQueued: 7, peakRunning: 4,
    rejected: 0, deduped: 12, busy: 1,
    agents: [{ name: 'Investigator', queued: 1, running: 2, maxConcurrentInstances: 2 }],
  },
  runs: [{
    id: 'run-live', automationId: TRIAGE_ID, state: 'running', displayName: 'Alert Triage', itemCounts: {},
    items: [
      {
        id: 'item-ps', automationId: TRIAGE_ID, runId: 'run-live', groupKey: 'rule.name:Suspicious PowerShell',
        payload: { groupFilter: 'rule.name:"Suspicious PowerShell"', count: 27 }, state: 'running', attempts: 1,
        sessionIds: ['s-ps'], queued: false, createTime: ago(18000), updateTime: ago(3000),
        phases: [{ sessionId: 's-ps', rootSessionId: 's-ps', agent: 'Investigator', phase: 'waiting_llm' }],
      },
      {
        id: 'item-kerb', automationId: TRIAGE_ID, runId: 'run-live', groupKey: 'rule.name:Kerberoasting',
        payload: {}, state: 'applying', attempts: 1, sessionIds: ['s-kerb'], result: { sessionId: 's-kerb' },
        queued: false, createTime: ago(64000), updateTime: ago(2000), phases: [],
      },
      {
        id: 'item-lsass', automationId: TRIAGE_ID, runId: 'run-live', groupKey: 'rule.name:LSASS Memory Access',
        payload: {}, state: 'running', attempts: 1, sessionIds: [], queued: true,
        createTime: ago(27000), updateTime: ago(27000), phases: [],
      },
      {
        // One attempt died before its session was recorded.
        id: 'item-travel', automationId: TRIAGE_ID, runId: 'run-live', groupKey: 'rule.name:Impossible Travel',
        payload: {}, state: 'running', attempts: 3, sessionIds: ['s-travel-1', 's-travel-2'], queued: false,
        createTime: ago(214000), updateTime: ago(9000),
        phases: [
          { sessionId: 's-travel-2', rootSessionId: 's-travel-2', agent: 'Investigator', phase: 'invoking_tool:delegate_to_Hunter' },
          { sessionId: 's-travel-child', rootSessionId: 's-travel-2', agent: 'Hunter', phase: 'invoking_tool:query_events' },
        ],
      },
    ],
  }],
});

const automations = () => [{ id: TRIAGE_ID, displayName: 'Alert Triage', agent: 'Investigator', automationKind: 'alert_triage' }];

const runHistory = () => ({
  runs: [
    { id: 'run-live', automationId: TRIAGE_ID, state: 'running', startTime: ago(60000), itemCounts: { running: 3 } },
    { id: 'run-1', automationId: TRIAGE_ID, state: 'succeeded', startTime: ago(600000), itemCounts: { done: 1, failed: 1 } },
    { id: 'run-idle', automationId: TRIAGE_ID, state: 'succeeded', startTime: ago(900000), itemCounts: {} },
  ],
  hasMore: false,
});

const runDetails = () => ({
  automationId: TRIAGE_ID, displayName: 'Alert Triage',
  items: [
    {
      id: 'item-mimi', automationId: TRIAGE_ID, runId: 'run-1', groupKey: 'rule.name:Mimikatz', payload: {},
      state: 'done', attempts: 1, sessionIds: ['s-mimi'], result: { sessionId: 's-mimi' }, createTime: ago(320000), updateTime: ago(245000),
    },
    {
      id: 'item-dns', automationId: TRIAGE_ID, runId: 'run-1', groupKey: 'rule.name:DNS Tunneling', payload: {},
      state: 'failed', attempts: 3, sessionIds: ['s-dns'], error: 'no report after 3 attempts', createTime: ago(900000), updateTime: ago(300000),
    },
  ],
  sessions: [
    { sessionId: 's-mimi', itemId: 'item-mimi', outcome: 'report', createTime: ago(300000) },
    { sessionId: 's-dns', itemId: 'item-dns', outcome: 'failed', missing: true },
  ],
});

const runPage = () => ({
  runs: [{
    id: 'run-1', automationId: TRIAGE_ID, displayName: 'Alert Triage', state: 'succeeded',
    startTime: ago(600000), endTime: ago(240000), itemCounts: { done: 1, failed: 1 },
  }],
  total: 1,
  hasMore: false,
});

const session = () => ({
  session: { sessionId: 's-ps', model: 'Investigator' },
  history: [
    { message: { role: 'user', contentStr: 'Investigate the alert below.' }, createTime: ago(17000) },
    {
      message: { role: 'assistant', contentBlocks: [
        { type: 'text', text: 'Checking the host first.' },
        { type: 'tool_use', id: 'tu-1', name: 'query_events', input: { query: 'host.name:WS-1' } },
      ], usage: { output_tokens: 40 } },
      createTime: ago(16000),
    },
    {
      tags: ['tool_result'],
      message: { role: 'user', contentBlocks: [{ toolResult: { toolUseId: 'tu-1', status: 'success', content: [{ json: { hits: 3 } }] } }] },
      createTime: ago(15000),
    },
    {
      message: { role: 'assistant', contentBlocks: [
        { type: 'text', text: 'Now the cases.' },
        { type: 'tool_use', id: 'tu-2', name: 'query_cases', input: {} },
      ] },
      createTime: ago(5000),
    },
  ],
  subSessions: [{ session: { sessionId: 's-ps-child', parentToolUseId: 'none' }, history: [] }],
});

const serve = (overrides = {}) => {
  const responses = Object.assign({
    'assistant/automations/activity': activity(),
    'assistant/automations': automations(),
    'assistant/automations/runs': runPage(),
    ['assistant/automations/' + TRIAGE_ID + '/runs']: runHistory(),
    ['assistant/automations/' + TRIAGE_ID + '/runs/run-1']: runDetails(),
    'assistant/sessions/s-ps': session(),
  }, overrides);
  comp.$root.papi.get = jest.fn(async (url) => {
    if (!(url in responses)) throw new Error('unexpected request ' + url);
    const response = responses[url];
    if (response instanceof Error) throw response;
    return { data: response };
  });
  return comp.$root.papi.get;
};

const settle = () => new Promise(resolve => setTimeout(resolve, 0));

// Mimics the runs table mounting and its first run expanding.
const load = async (params = agenticParams()) => {
  comp.initAssistant(params);
  await settle();
  if (!comp.assistantEnabled || !comp.agentic) return;
  comp.onHistoryOptions({ page: 1, itemsPerPage: 10 });
  await settle();
  if (comp.historyRuns.length) await comp.loadRunItems(comp.historyRuns[0]);
};

const itemById = (id) => comp.items.concat(comp.historyItems()).find(i => i.id === id);

const httpError = (status) => Object.assign(new Error('HTTP ' + status), { response: { status } });

beforeEach(() => {
  originalConsole = { log: console.log, error: console.error, warn: console.warn };
  console.log = jest.fn();
  console.error = jest.fn();
  console.warn = jest.fn();

  comp = getComponent("agentmonitor");
  resetPapi();
  serve();

  comp.$root.isLicensed = jest.fn().mockReturnValue(true);
  comp.$root.user = { id: 'analyst-1', roles: ['analyst'] };
  comp.$root.showError = jest.fn();
  comp.$root.startLoading = jest.fn();
  comp.$root.stopLoading = jest.fn();
  comp.$root.loadParameters = jest.fn();
  comp.$root.formatDateTime = jest.fn(d => d);

  const storageData = {};
  global.localStorage = new Proxy({ removeItem: jest.fn((key) => { delete storageData[key]; }) }, {
    get(target, prop) {
      if (typeof prop === 'string' && prop.startsWith('settings.')) return storageData[prop];
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
  });
});

afterEach(() => {
  comp.stopTick();
  clearTimeout(comp.transcriptRefreshTimer);
  console.log = originalConsole.log;
  console.error = originalConsole.error;
  console.warn = originalConsole.warn;
});

test('reload requests the assistant parameters', () => {
  comp.reload();

  expect(comp.$root.startLoading).toHaveBeenCalled();
  expect(comp.$root.loadParameters).toHaveBeenCalledWith('assistant', comp.initAssistant);
});

test('the page is available only when licensed, enabled and agentic', async () => {
  await load();
  expect(comp.assistantEnabled).toBe(true);
  expect(comp.agentic).toBe(true);
  expect(comp.paramsLoaded).toBe(true);

  comp.initAssistant({ enabled: true, agentic: false });
  expect(comp.agentic).toBe(false);

  comp.initAssistant({ enabled: false, agentic: true });
  expect(comp.assistantEnabled).toBe(false);

  comp.$root.isLicensed = jest.fn().mockReturnValue(false);
  comp.initAssistant(agenticParams());
  expect(comp.assistantEnabled).toBe(false);
});

test('initAssistant tolerates empty parameters and loads nothing', () => {
  comp.initAssistant(null);

  expect(comp.paramsLoaded).toBe(true);
  expect(comp.assistantEnabled).toBeFalsy();
  expect(comp.$root.papi.get).not.toHaveBeenCalled();
});

test('the in-flight table is the open work of every run in flight', async () => {
  await load();

  expect(comp.items.map(i => i.id)).toEqual(['item-ps', 'item-kerb', 'item-lsass', 'item-travel']);
  expect(comp.items[0]).toMatchObject({ automationName: 'Alert Triage', queued: false });
  expect(comp.itemTabs['item-ps']).toBe('details');
  expect(comp.schedulerRunning).toBe(true);
  expect(comp.$root.showError).not.toHaveBeenCalled();
});

test('two runs of one automation list its open items once', () => {
  const data = activity();
  data.runs.push(Object.assign({}, data.runs[0], { id: 'run-other' }));

  comp.applyActivity(data);

  expect(comp.items.length).toBe(4);
});

test('a deleted automation\'s work shows by its id', () => {
  const data = activity();
  data.runs[0].displayName = '';

  comp.applyActivity(data);

  expect(comp.items[0].automationName).toBe(TRIAGE_ID);
});

const runsCall = (get) => get.mock.calls.filter(call => call[0] === 'assistant/automations/runs');

test('run history is a server-paged list of finished runs, counted on its first load', async () => {
  const get = serve();
  await load();

  expect(runsCall(get)).toEqual([['assistant/automations/runs', {
    params: { limit: 10, offset: 0, automationId: '', hideEmpty: true, q: '', count: true },
  }]]);
  expect(comp.historyRuns.map(r => r.id)).toEqual(['run-1']);
  expect(comp.historyRuns[0].automationName).toBe('Alert Triage');
  expect(comp.historyTotal).toBe(1);
  expect(comp.runDurationMs(comp.historyRuns[0])).toBe(360000);
  expect(comp.runItemCount(comp.historyRuns[0], 'failed')).toBe(1);
});

test('a deleted automation\'s runs show by its id', async () => {
  serve({ 'assistant/automations/runs': { runs: [Object.assign(runPage().runs[0], { displayName: '' })], total: 1 } });

  await comp.loadHistory();

  expect(comp.historyRuns[0].automationName).toBe(TRIAGE_ID);
});

test('paging keeps the count; a filter change returns to page one and recounts', async () => {
  const get = serve();
  await load();

  comp.onHistoryOptions({ page: 3, itemsPerPage: 50 });
  await settle();
  expect(runsCall(get).pop()[1].params).toMatchObject({ limit: 50, offset: 100, count: false });

  comp.historySearch = '  10.0.0.1 ';
  comp.historyAutomationId = TRIAGE_ID;
  comp.hideEmptyRuns = false;
  comp.onHistoryFilterChanged();
  await settle();
  expect(comp.historyPage).toBe(1);
  // Off page one, the resulting page change reloads.
  expect(runsCall(get).length).toBe(2);

  comp.onHistoryOptions({ page: 1, itemsPerPage: 50 });
  await settle();
  expect(runsCall(get).pop()[1].params).toEqual({ limit: 50, offset: 0, automationId: TRIAGE_ID, hideEmpty: false, q: '10.0.0.1', count: true });

  comp.onHistoryFilterChanged();
  await settle();
  expect(runsCall(get).length).toBe(4);
});

test('a slower, older page is dropped when a newer one has landed', async () => {
  let release;
  const slow = new Promise(resolve => { release = resolve; });
  comp.$root.papi.get = jest.fn()
    .mockImplementationOnce(() => slow)
    .mockResolvedValueOnce({ data: { runs: [{ id: 'newer', itemCounts: {} }], total: 1 } });

  const first = comp.loadHistory();
  await comp.loadHistory();
  release({ data: { runs: [{ id: 'older', itemCounts: {} }], total: 9 } });
  await first;

  expect(comp.historyRuns.map(r => r.id)).toEqual(['newer']);
  expect(comp.historyTotal).toBe(1);
});

test('a run\'s items load once, when it first expands, newest first', async () => {
  const get = serve();
  await comp.loadHistory();
  const run = comp.historyRuns[0];
  const toggleExpand = jest.fn();

  await comp.onToggleRun(run, false, toggleExpand, 'row');
  await comp.onToggleRun(run, true, toggleExpand, 'row');
  await comp.onToggleRun(run, false, toggleExpand, 'row');

  const opened = get.mock.calls.filter(call => call[0].endsWith('/runs/run-1'));
  expect(opened).toEqual([['assistant/automations/' + TRIAGE_ID + '/runs/run-1', { params: { alertLimit: 1 } }]]);
  expect(toggleExpand).toHaveBeenCalledTimes(3);
  expect(comp.runItemsOf(run).map(i => i.id)).toEqual(['item-mimi', 'item-dns']);
  expect(itemById('item-dns').automationName).toBe('Alert Triage');
  expect(comp.itemTabs['item-dns']).toBe('details');
});

test('a run whose items fail to load collapses again', async () => {
  serve({ ['assistant/automations/' + TRIAGE_ID + '/runs/run-1']: new Error('down') });
  await comp.loadHistory();
  const toggleExpand = jest.fn();

  await comp.onToggleRun(comp.historyRuns[0], false, toggleExpand, 'row');

  expect(toggleExpand).toHaveBeenCalledTimes(2);
  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.runItemsLoading(comp.historyRuns[0])).toBe(false);
});

test('a run\'s items show when each finished as well as how long it took', () => {
  const values = comp.runItemHeaders.map(h => h.value);

  expect(values).toContain('updateTime');
  expect(values).toContain('duration');
  expect(values.indexOf('updateTime')).toBeLessThan(values.indexOf('duration'));
});

test('a link to a run searches for it, shows the section and opens the run', async () => {
  comp.$route.query = { run: 'run-1' };
  comp.collapsedSections = ['agentmonitor-history'];
  localStorage['settings.agentmonitor.collapsedSections'] = JSON.stringify(['agentmonitor-history']);
  const get = serve();

  await load();

  expect(runsCall(get)[0][1].params).toMatchObject({ q: 'run-1', offset: 0, count: true });
  expect(comp.isExpandedSection('agentmonitor-history')).toBe(true);
  expect(comp.expandedRuns).toEqual(['run-1']);
  expect(comp.runItemsOf(comp.historyRuns[0]).map(i => i.id)).toEqual(['item-mimi', 'item-dns']);

  // Later route changes re-apply the same link without clobbering the search.
  comp.historySearch = '';
  comp.applyRoute();
  expect(comp.historySearch).toBe('');
});

test('a link to another run while the page is open searches again from page one', async () => {
  await load();
  comp.historyPage = 1;
  const get = serve();

  comp.$route.query = { run: 'run-2' };
  comp.applyRoute();
  await settle();

  expect(runsCall(get).pop()[1].params).toMatchObject({ q: 'run-2', offset: 0, count: true });
  expect(comp.pendingRunId).toBe('');
  expect(comp.expandedRuns).toEqual([]);
});

test('the automation filter lists every automation after All', async () => {
  await load();

  expect(comp.historyAutomationItems()).toEqual([
    { title: comp.i18n.all, value: '' },
    { title: 'Alert Triage', value: TRIAGE_ID },
  ]);
});

test('a run leaving the in-flight list reloads run history without recounting it, and not under a search', async () => {
  await load();
  let get = serve();

  comp.applyActivity(Object.assign(activity(), { runs: [] }));
  await settle();

  expect(runsCall(get).pop()[1].params.count).toBe(false);
  expect(comp.items).toEqual([]);

  comp.applyActivity(activity());
  comp.historySearch = 'mimikatz';
  get = serve();
  comp.applyActivity(Object.assign(activity(), { runs: [] }));
  await settle();

  expect(runsCall(get)).toEqual([]);
});

test('a load the user asked for reports failure; a background refresh only logs it', async () => {
  serve({ 'assistant/automations/activity': new Error('down') });

  await comp.loadActivity();
  expect(comp.$root.showError).toHaveBeenCalledTimes(1);

  await comp.loadActivity(true);
  expect(comp.$root.showError).toHaveBeenCalledTimes(1);
  expect(console.error).toHaveBeenCalled();
});

test('a refresh keeps what it had when it fails', async () => {
  await load();
  serve({ 'assistant/automations/activity': new Error('down') });

  await comp.loadActivity(true);

  expect(comp.items.length).toBe(4);
});

test('the scheduler stopping is reported', () => {
  comp.applyActivity(Object.assign(activity(), { schedulerRunning: false }));

  expect(comp.schedulerRunning).toBe(false);
});

test('only a session is a level; item detail expands in place', async () => {
  await load();
  expect(comp.level()).toBe(1);
  expect(comp.breadcrumbs()[0].to).toBeNull();

  comp.$route.params = { itemId: 'item-ps' };
  comp.applyRoute();
  expect(comp.level()).toBe(1);
  expect(comp.expandedItems).toEqual(['item-ps']);
  expect(comp.selectedItem().id).toBe('item-ps');

  comp.$route.params = { itemId: 'item-ps', sessionId: 's-ps' };
  comp.applyRoute();
  expect(comp.level()).toBe(2);
  expect(comp.watchedSessionId()).toBe('s-ps');
});

test('breadcrumbs name the item being watched', async () => {
  await load();
  comp.$route.params = { itemId: 'item-ps', sessionId: 's-ps' };
  comp.applyRoute();

  const crumbs = comp.breadcrumbs();
  expect(crumbs.length).toBe(2);
  expect(crumbs[0].title).toBe(comp.i18n.agentMonitor);
  expect(crumbs[0].to).not.toBeNull();
  expect(crumbs[1].to).toBeNull();
  expect(crumbs[1].title).toBe('Alert Triage — rule.name:Suspicious PowerShell');
  expect(crumbs[1].disabled).toBe(true);
});

test('watching a session loads its transcript as Onion AI would show it', async () => {
  await load();
  comp.$route.params = { itemId: 'item-ps', sessionId: 's-ps' };
  comp.applyRoute();
  await settle();

  const transcript = comp.watchedTranscript();
  expect(transcript.agent).toBe('Investigator');
  expect(comp.modelFor(transcript.agent)).toBe('claude-sonnet@soai');
  expect(transcript.subSessionIds).toEqual(['s-ps-child']);

  expect(transcript.messages.map(m => m.content)).toEqual(['Checking the host first.', 'Now the cases.']);
  const ran = transcript.messages[0].toolUses[0];
  expect(ran).toMatchObject({ name: 'query_events', status: 'completed', rawResult: { hits: 3 } });
  expect(transcript.messages[1].toolUses[0]).toMatchObject({ status: 'executing', approved: true });
  expect(comp.transcriptLoading).toBe(false);
  expect(comp.watchedIsLive()).toBe(true);
});

test('a session that is gone or not readable reaches the not-found view without an error', async () => {
  serve({ 'assistant/sessions/s-gone': httpError(404), 'assistant/sessions/s-private': httpError(403) });

  await comp.loadTranscript('s-gone');
  await comp.loadTranscript('s-private');

  comp.$route.params = { itemId: 'no-such-item', sessionId: 's-gone' };
  comp.selectedItemId = 'no-such-item';
  comp.selectedSessionId = 's-gone';
  expect(comp.level()).toBe(2, 'the level follows the link so the not-found view is reachable');
  expect(comp.selectedItem()).toBeNull();
  expect(comp.watchedTranscript()).toBeNull();
  expect(comp.watchedIsLive()).toBe(false);
  expect(comp.$root.showError).not.toHaveBeenCalled();
});

test('any other transcript failure is reported', async () => {
  serve({ 'assistant/sessions/s-x': new Error('boom') });

  await comp.loadTranscript('s-x');

  expect(comp.$root.showError).toHaveBeenCalled();
  expect(comp.transcriptLoading).toBe(false);
});

test('stream events for the watched session or its children refetch it, at most once per window', async () => {
  jest.useFakeTimers();
  try {
    comp.applyActivity(activity());
    comp.selectedSessionId = 's-travel-2';
    comp.transcripts['s-travel-2'] = { agent: 'Investigator', messages: [], subSessionIds: ['s-old-child'] };
    comp.loadTranscript = jest.fn();

    comp.onAgentStream({ sessionId: 'someone-else' });
    jest.advanceTimersByTime(2000);
    expect(comp.loadTranscript).not.toHaveBeenCalled();

    expect(comp.watchedSessionIds()).toEqual(['s-travel-2', 's-old-child', 's-travel-2', 's-travel-child']);
    comp.onAgentStream({ sessionId: 's-travel-child' });
    comp.onAgentStream({ sessionId: 's-travel-2' });
    comp.onAgentStream({ sessionId: 's-old-child' });
    jest.advanceTimersByTime(2000);
    expect(comp.loadTranscript).toHaveBeenCalledTimes(1);
    expect(comp.loadTranscript).toHaveBeenCalledWith('s-travel-2', true);

    comp.paused = true;
    comp.onAgentStream({ sessionId: 's-travel-2' });
    jest.advanceTimersByTime(2000);
    expect(comp.loadTranscript).toHaveBeenCalledTimes(1);
  } finally {
    jest.useRealTimers();
  }
});

test('nothing streams into a page that is not watching a session', () => {
  comp.selectedSessionId = '';

  expect(comp.watchedSessionIds()).toEqual([]);
  comp.onAgentStream({ sessionId: 's-ps' });
  expect(comp.transcriptRefreshTimer).toBeNull();
});

test('the transcript components are given the helpers they inject', () => {
  for (const helper of ['displayStatus', 'getToolStatusIcon', 'getToolStatusColor', 'getToolStatusTitle',
                        'pendingChildTools', 'delegateOwnCredits', 'delegateOwnOutputTokens',
                        'delegationHasCollapsedContent', 'formatCount', 'formatMarkdown', 'formatTimestamp',
                        'convertBackendMessagesToFrontend', 'reconstructChildSession', 'indexSubSessions']) {
    expect(typeof comp[helper]).toBe('function', helper + ' must be provided');
  }

  expect(comp.canChat).toBe(false);
  expect(() => { comp.approveTool({}); comp.rejectTool({}); }).not.toThrow();
});

// Catches a picked helper that depends on assistant page state before it breaks rendering.
test('every helper the transcript components call works against this page', async () => {
  comp.$root.formatMarkdown = jest.fn(text => '<p>' + text + '</p>');
  comp.$root.formatCount = jest.fn(n => String(n));
  comp.$root.formatTimestamp = jest.fn(t => t);
  await comp.loadTranscript('s-ps');
  const toolUse = comp.transcripts['s-ps'].messages[0].toolUses[0];

  expect(() => {
    comp.displayStatus(toolUse);
    comp.getToolStatusIcon(comp.displayStatus(toolUse));
    comp.getToolStatusColor(comp.displayStatus(toolUse));
    comp.getToolStatusTitle(comp.displayStatus(toolUse));
    comp.pendingChildTools(toolUse);
    comp.delegateOwnCredits(toolUse);
    comp.delegateOwnOutputTokens(toolUse);
    comp.delegationHasCollapsedContent(toolUse);
    comp.formatCount(1234);
    comp.formatTimestamp(new Date().toISOString());
  }).not.toThrow();

  expect(comp.formatMarkdown('pick one')).toBe('<p>pick one</p>');
  expect(comp.formatMarkdown('')).toBe('');
});

test('watch opens the newest session, and only a started item has one', async () => {
  await load();

  expect(comp.liveSessionOf(itemById('item-travel'))).toBe('s-travel-2');
  expect(comp.liveSessionOf(itemById('item-lsass'))).toBe('', 'nothing to watch before a session starts');

  comp.selectedItemId = 'item-travel';
  comp.selectedSessionId = 's-travel-1';
  expect(comp.watchedIsLive()).toBe(false, 'an earlier session of the same item is history');

  comp.selectedItemId = 'item-mimi';
  comp.selectedSessionId = 's-mimi';
  expect(comp.watchedIsLive()).toBe(false, 'a finished item has no live session');
});

test('sessions list newest first, with what the run details know about each', async () => {
  await load();

  const attempts = comp.attemptsFor(itemById('item-travel'));
  expect(attempts.map(a => a.attempt)).toEqual([2, 1]);
  expect(attempts[0].live).toBe(true);
  expect(attempts[1].state).toBe('failed', 'an earlier session ended so the item could be retried');
  expect(attempts[0].startTime).toBe('', 'an in-flight session has no known start yet');

  const done = comp.attemptsFor(itemById('item-mimi'));
  expect(done[0].live).toBe(false);
  expect(done[0].startTime).toBeTruthy();
  expect(done[0].startTime).toBe(comp.sessionStarts['s-mimi']);
  expect(done[0].watchable).toBe(true);

  expect(comp.attemptsFor(itemById('item-dns'))[0].watchable).toBe(false);
  expect(comp.attemptsFor(itemById('item-lsass'))).toEqual([]);
});

test('a claim that recorded no session is reported, since no row can show it', async () => {
  await load();

  expect(comp.attemptsWithoutSession(itemById('item-travel'))).toBe(1);
  expect(comp.attemptsWithoutSession(itemById('item-ps'))).toBe(0);
  expect(comp.attemptsWithoutSession({})).toBe(0);
});

test('the details tab lists the work item as key/value rows', async () => {
  await load();
  const item = itemById('item-ps');

  expect(comp.itemDetails(item).map(r => r.key)).toEqual([
    comp.i18n.agentMonitorItemId, comp.i18n.agentMonitorRunId, comp.i18n.agentMonitorAutomation,
    comp.i18n.agentMonitorGroup, comp.i18n.status, comp.i18n.attempt,
    comp.i18n.dateCreated, comp.i18n.agentMonitorLastChanged,
  ]);

  expect(comp.itemDetails(itemById('item-dns')).map(r => r.key)).toContain(comp.i18n.error);

  const rows = comp.itemDetails(Object.assign({}, item, { runId: '', groupKey: '' }));
  expect(rows.find(r => r.key === comp.i18n.agentMonitorRunId).value).toBe('—');
  expect(rows.find(r => r.key === comp.i18n.agentMonitorGroup).value).toBe('—');
});

test('for an admin, the automation row links to that automation in Agent Studio', async () => {
  await load();
  comp.$root.user = { id: 'admin-1', roles: ['superuser'] };

  for (const item of [itemById('item-ps'), itemById('item-mimi')]) {
    const row = comp.itemDetails(item).find(r => r.key === comp.i18n.agentMonitorAutomation);
    expect(row.link).toEqual({ name: 'agentstudio', query: { tab: 'automations', automation: TRIAGE_ID } });
  }
  expect(comp.automationConfigLink({})).toBeNull();

  // Agent Studio stays admin-only.
  comp.$root.user = { id: 'analyst-1', roles: ['analyst'] };
  expect(comp.automationConfigLink(itemById('item-ps'))).toBeNull();
});

test('anyone with automations/read sees the page; anyone else loads nothing', () => {
  for (const roles of [['analyst'], ['auditor'], ['superuser']]) {
    comp.$root.user = { id: 'u', roles };
    expect(comp.$root.canReadAutomations()).toBe(true, roles[0]);
  }

  comp.$root.user = { id: 'u', roles: ['limited-analyst'] };
  expect(comp.$root.canReadAutomations()).toBe(false);
  comp.loadData = jest.fn();
  comp.initAssistant(agenticParams());
  expect(comp.loadData).not.toHaveBeenCalled();
});

test('the key/value tabs follow the item, with result only once there is one', async () => {
  await load();
  const running = itemById('item-ps');
  const done = itemById('item-mimi');

  expect(comp.kvTabs(running)).toEqual(['details', 'payload']);
  expect(comp.kvTabs(done)).toEqual(['details', 'payload', 'result']);
  expect(comp.tabRows(running, 'payload').map(r => r.key)).toEqual(['groupFilter', 'count']);
  expect(comp.tabRows(done, 'result')).toEqual([{ key: 'sessionId', value: 's-mimi' }]);
});

test('payload and result render as key/value rows rather than raw JSON', () => {
  expect(comp.kvRows({ query: 'tags:alert', matched: 4, escalated: true })).toEqual([
    { key: 'query', value: 'tags:alert' },
    { key: 'matched', value: '4' },
    { key: 'escalated', value: 'true' },
  ]);
  expect(comp.kvRows({ caseId: null })[0].value).toBe('—');
  expect(comp.kvRows({ hosts: ['a', 'b'] })[0].value).toBe('["a","b"]');
  expect(comp.kvRows(null)).toEqual([]);
});

test('the state vocabulary matches the work item model', () => {
  expect(comp.stateLabel('pending')).toBe(comp.i18n.statePending);
  expect(comp.stateLabel('applying')).toBe(comp.i18n.stateApplying);
  expect(comp.stateLabel('done')).toBe(comp.i18n.stateDone);
  expect(comp.stateLabel('failed')).toBe(comp.i18n.stateFailed);
  expect(comp.stateLabel('wat')).toBe('wat', 'an unknown state shows itself rather than blank');

  expect(comp.isTerminal('done')).toBe(true);
  expect(comp.isTerminal('failed')).toBe(true);
  expect(comp.isTerminal('applying')).toBe(false);
  expect(comp.isTerminal('running')).toBe(false);
});

test('the activity line is what the item\'s sessions are doing now', async () => {
  await load();

  expect(comp.activityFor(itemById('item-ps'))).toBe(comp.i18n.agentMonitorWaitingOnModel);
  expect(comp.activityFor(itemById('item-travel'))).toBe(comp.i18n.agentMonitorInvoking + ' query_events');
  expect(comp.activityFor(itemById('item-kerb'))).toBe(comp.i18n.agentMonitorApplyingResults);
  expect(comp.activityFor(itemById('item-mimi'))).toBe('');

  expect(comp.activityFor({ state: 'running', phases: [] })).toBe(comp.i18n.agentMonitorPreparing);
  expect(comp.activityFor({ state: 'running', phases: [{ phase: 'invoking_tool:delegate_to_Hunter' }] }))
    .toBe(comp.i18n.agentMonitorDelegatingTo + ' Hunter');
  expect(comp.describePhase('something_new')).toBe('something_new', 'an unknown phase shows itself');
});

test('a waiting item says what it waits on', async () => {
  await load();

  expect(comp.blockedBy(itemById('item-lsass'))).toBe('Investigator');
  expect(comp.activityFor(itemById('item-lsass'))).toBe(comp.i18n.agentMonitorWaitingOnAgent + ' Investigator');

  comp.pool.agents[0].running = 1;
  expect(comp.activityFor(itemById('item-lsass'))).toBe('');
  expect(comp.activityFor({ state: 'pending', automationId: 'unknown' })).toBe('');
});

test('a claimed item waiting for a pool slot shows as queued, not running', async () => {
  await load();

  expect(comp.displayState(itemById('item-lsass'))).toBe('queued');
  expect(itemById('item-lsass').status).toBe('queued');
  expect(comp.itemHeaders.find(h => h.title === comp.i18n.status).value).toBe('status');
  expect(comp.stateLabel('queued')).toBe(comp.i18n.stateQueued);
  expect(comp.stateColor('queued')).toBe('warning');
  expect(comp.displayState(itemById('item-ps'))).toBe('running');
  expect(comp.displayState({ state: 'pending', queued: true })).toBe('pending');
});

test('an item can wait while the pool has a free slot, because its agent is full', async () => {
  await load();

  expect(comp.poolSaturated()).toBe(false);
  expect(comp.blockedBy(itemById('item-lsass'))).toBe('Investigator');
});

test('the agent column is the chain of agents working the item', async () => {
  await load();

  expect(comp.agentChain(itemById('item-travel'))).toEqual(['Investigator', 'Hunter']);
  expect(comp.agentChain(itemById('item-lsass'))).toEqual(['Investigator']);
  expect(comp.agentChain({ automationId: 'unknown' })).toEqual([]);
});

test('the pool is reported whole, chats included, and an unlimited one says so', async () => {
  await load();

  expect(comp.poolLabel()).toBe('3 / 4');
  expect(comp.queuedLabel()).toBe('1 / ' + comp.i18n.agentMonitorNoLimit);
  expect(comp.pool.busy).toBe(1);

  comp.pool.running = 4;
  expect(comp.poolSaturated()).toBe(true);
  comp.pool.queued = 0;
  expect(comp.poolSaturated()).toBe(false, 'at capacity but nothing waiting is not a problem');
  comp.pool.queued = 1;
  comp.pool.maxConcurrent = 0;
  expect(comp.poolLabel()).toBe('4 / ' + comp.i18n.agentMonitorNoLimit);
  expect(comp.poolSaturated()).toBe(false, 'an unlimited pool never saturates');
});

test('a partial pool fills in with zeros', () => {
  comp.applyActivity({ pool: { running: 2 } });

  expect(comp.pool).toMatchObject({ running: 2, queued: 0, busy: 0, agents: [] });
  expect(comp.items).toEqual([]);
});

test('time in state is reported separately from total age, and stops once terminal', async () => {
  await load();
  comp.now = Date.now();
  const item = itemById('item-ps');

  expect(comp.inStateMs(item)).toBeLessThan(comp.elapsedMs(item));
  expect(comp.inStateMs(item)).toBe(comp.now - new Date(item.updateTime).getTime());
  expect(comp.inStateMs(itemById('item-mimi'))).toBe(0, 'a finished item is not sitting in a state');
});

test('elapsed counts to now while in flight and freezes once terminal', async () => {
  await load();
  comp.now = Date.now();

  const running = itemById('item-ps');
  const before = comp.elapsedMs(running);
  comp.now += 5000;
  expect(comp.elapsedMs(running)).toBe(before + 5000);

  const finished = itemById('item-mimi');
  const frozen = comp.elapsedMs(finished);
  comp.now += 5000;
  expect(comp.elapsedMs(finished)).toBe(frozen);
});

test('elapsed formats as minutes and padded seconds', () => {
  expect(comp.formatElapsed(0)).toBe('0:00');
  expect(comp.formatElapsed(9000)).toBe('0:09');
  expect(comp.formatElapsed(64000)).toBe('1:04');
  expect(comp.formatElapsed(600000)).toBe('10:00');
});

const pushed = (generatedAt, items) => ({
  generatedAt, schedulerRunning: true, pool: {},
  runs: [{ id: 'run-1', automationId: TRIAGE_ID, displayName: 'Alert Triage', items }],
});

test('pushed activity is applied as it arrives, with no request, and the clock only ticks', () => {
  comp.$root.subscribe = jest.fn();
  comp.reload = jest.fn();
  comp.mounted();
  expect(comp.$root.subscribe).toHaveBeenCalledWith('assistant:automation', comp.onAutomationActivity);

  const get = serve();
  comp.onAutomationActivity(pushed('2026-10-02T12:00:00Z', [{ id: 'a', state: 'running' }]));
  expect(comp.items.map(i => i.id)).toEqual(['a']);
  expect(get).not.toHaveBeenCalled();

  comp.tick();
  expect(get).not.toHaveBeenCalled();
});

test('activity older than what is shown is dropped', () => {
  comp.applyActivity(pushed('2026-10-02T12:00:02Z', [{ id: 'a', state: 'running', payload: { groupFilter: 'x' } }]));

  comp.applyActivity(pushed('2026-10-02T12:00:01Z', []));
  expect(comp.items.map(i => i.id)).toEqual(['a'], 'a slow fetch does not undo a newer push');

  // A push carries the item whole, including its current payload.
  comp.applyActivity(pushed('2026-10-02T12:00:03Z', [{ id: 'a', state: 'running', payload: { groupFilter: 'x', latestAlertId: 'alert-9' } }]));
  expect(comp.items[0].payload).toEqual({ groupFilter: 'x', latestAlertId: 'alert-9' });
});

test('pausing stops the clock and ignores pushes; resuming fetches what was missed', () => {
  comp.loadActivity = jest.fn();
  comp.now = 0;
  comp.togglePaused();
  expect(comp.paused).toBe(true);

  comp.tick();
  comp.onAutomationActivity(pushed('2026-10-02T12:00:00Z', [{ id: 'a', state: 'running' }]));
  expect(comp.now).toBe(0);
  expect(comp.items).toEqual([]);

  comp.togglePaused();
  expect(comp.loadActivity).toHaveBeenCalledWith(true);
});

test('reconnecting reloads what was missed while disconnected', () => {
  const onConnected = routes.find(r => r.name === 'agentmonitor').component.watch['$root.connected'];
  comp.loadActivity = jest.fn();
  comp.agentic = true;

  onConnected.call(comp, false);
  expect(comp.loadActivity).not.toHaveBeenCalled();

  onConnected.call(comp, true);
  expect(comp.loadActivity).toHaveBeenCalledWith(true);
});

test('a refresh already in flight is not doubled', async () => {
  const get = serve();

  await Promise.all([comp.loadActivity(true), comp.loadActivity(true)]);

  expect(get.mock.calls.filter(call => call[0] === 'assistant/automations/activity').length).toBe(1);
});

test('the refresh button reloads everything, including the watched transcript', async () => {
  const get = serve();
  comp.selectedSessionId = 's-ps';

  await comp.loadData();

  const urls = get.mock.calls.map(call => call[0]);
  expect(urls).toContain('assistant/automations/activity');
  expect(urls).toContain('assistant/automations');
  expect(urls).toContain('assistant/sessions/s-ps');
});

test('the refresh button recounts run history once it has loaded', async () => {
  await load();
  const get = serve();

  await comp.loadData();

  expect(runsCall(get).pop()[1].params.count).toBe(true);
});

test('the tick timer is started on load and cleared on unmount', async () => {
  jest.useFakeTimers();
  try {
    comp.initAssistant(agenticParams());
    expect(comp.tickTimer).not.toBeNull();

    comp.stopTick();
    expect(comp.tickTimer).toBeNull();
  } finally {
    jest.useRealTimers();
  }
});

test('no timer runs when the page is unavailable', () => {
  comp.initAssistant({ enabled: true, agentic: false });

  expect(comp.tickTimer).toBeNull();
});

test('watching a session is a real URL, not page state', () => {
  expect(comp.buildSessionLink('item-ps', 'sess-9')).toEqual({
    name: 'agentmonitor', params: { itemId: 'item-ps', sessionId: 'sess-9' },
  });
});

test('sections collapse and the choice persists', () => {
  expect(comp.isExpandedSection('agentmonitor-history')).toBe(true);

  comp.toggleShowSection('agentmonitor-history');
  expect(comp.isExpandedSection('agentmonitor-history')).toBe(false);
  expect(comp.isExpandedSection('agentmonitor-inflight')).toBe(true, 'sections collapse independently');

  comp.collapsedSections = [];
  comp.loadLocalSettings();
  expect(comp.isExpandedSection('agentmonitor-history')).toBe(false);
});

test('table settings persist to local storage', () => {
  comp.sortBy = [{ key: 'automationName', order: 'desc' }];
  comp.itemsPerPage = 50;
  comp.saveLocalSettings();

  comp.sortBy = [{ key: 'createTime', order: 'asc' }];
  comp.itemsPerPage = 10;
  comp.loadLocalSettings();

  expect(comp.sortBy[0]).toEqual({ key: 'automationName', order: 'desc' });
  expect(comp.itemsPerPage).toBe(50);
});
