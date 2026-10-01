// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./alert-investigation.js');

let comp;

beforeEach(() => {
  resetPapi();
  comp = getComponent('alert-investigation');
  comp.summaries = {};
  comp.routeForQuery = (q) => ({ path: 'alerts', query: { q } });
  comp.$root.showError = jest.fn();
});

const history = [
  { message: { role: 'user', contentStr: 'Investigate' }, createTime: '2026-09-24T10:00:00Z' },
  {
    message: { role: 'assistant', contentBlocks: [
      { type: 'text', text: 'Notifying first.' },
      { type: 'tool_use', id: 't1', name: 'send_notification', input: { title: 'Heads up', summary: 'Ongoing' } },
    ] },
    createTime: '2026-09-24T10:01:00Z',
  },
  { tags: ['tool_result'], message: { role: 'user', contentBlocks: [] }, createTime: '2026-09-24T10:01:05Z' },
  { message: { role: 'assistant', contentStr: '## Report' }, createTime: '2026-09-24T10:02:00Z' },
];

test('summarizes a session into its report and any notification', () => {
  const s = comp.summarize({ session: { model: 'Orchestrator' }, history });

  expect(s.report).toBe('## Report');
  expect(s.notifications).toEqual([{ title: 'Heads up', summary: 'Ongoing', severity: 'info', failed: false, error: '' }]);
  expect(s.time).toBe('2026-09-24T10:02:00Z');
  expect(s.agent).toBe('Orchestrator');
});

test('every notification is listed in order, each with whether it went out', () => {
  const notify = (id, title, severity) => ({
    message: { role: 'assistant', contentBlocks: [{ type: 'tool_use', id: id, name: 'send_notification', input: { title: title, summary: 's', severity: severity } }] },
  });
  const result = (id, block) => ({ tags: ['tool_result'], message: { role: 'user', contentBlocks: [{ toolResult: Object.assign({ toolUseId: id }, block) }] } });

  const s = comp.summarize({ session: {}, history: [
    notify('n1', 'First', 'high'),
    result('n1', { status: 'success', content: [{ json: { sent: true } }] }),
    notify('n2', 'Second', 'critical'),
    result('n2', { status: 'error', isError: true, content: [{ text: 'Notifications are not enabled on this grid.' }] }),
    { message: { role: 'assistant', contentStr: '## Report' } },
  ] });

  expect(s.notifications.map(n => [n.title, n.severity, n.failed, n.error])).toEqual([
    ['First', 'high', false, ''],
    ['Second', 'critical', true, 'Notifications are not enabled on this grid.'],
  ]);
  expect(s.report).toBe('## Report');
  expect(comp.severityLabel('critical')).toBe('CRITICAL');
  expect(comp.severityLabel(undefined)).toBe('INFO');
});

test('a reply still being streamed is not taken as the report', () => {
  const streaming = history.concat([
    { tags: ['partial'], message: { role: 'assistant', contentStr: '## Half a rep' }, createTime: '2026-09-24T10:03:00Z' },
  ]);

  expect(comp.summarize({ session: {}, history: streaming }).report).toBe('## Report');
});

test('loads a real session through the API', async () => {
  const get = mockPapi('get', { data: { session: {}, history } });

  await comp.load('real_1');

  expect(get).toHaveBeenCalledWith('/assistant/sessions/real_1');
  expect(comp.summary('real_1').report).toBe('## Report');
  expect(comp.summary('unloaded').loading).toBe(true);
});

test('reads which investigations an alert has', () => {
  comp.alert = { 'event.so_alerttriage.session_id': 'triage_1' };
  expect(comp.automatedId()).toBe('triage_1');
  expect(comp.manualInvestigations()).toEqual([]);

  comp.alert = { 'event.so_alerttriage.failed_count': 3, 'event.acknowledged': 'true' };
  expect(comp.failedLabel()).toBe('Automated investigation failed after 3 attempts');
  expect(comp.acknowledged()).toBe(true);
});

test('manual investigations are read from the alert\'s entries, newest first', () => {
  comp.alert = {
    'event.so_investigations': [
      { session_id: 's1', user_id: 'u1', timestamp: '2026-09-28T10:00:00.000Z' },
      { session_id: 's2', user_id: 'u2' },
      { user_id: 'no-session' },
      'junk',
    ],
  };

  expect(comp.manualInvestigations()).toEqual([
    { sessionId: 's2', by: 'u2', time: '' },
    { sessionId: 's1', by: 'u1', time: '2026-09-28T10:00:00.000Z' },
  ]);
  expect(alertManualInvestigations(null)).toEqual([]);
});

test('an older alert\'s single values still count, before any entries and without duplicates', () => {
  expect(alertManualInvestigations({ 'event.investigation_session_id': 'only' })).toEqual([{ sessionId: 'only', by: '', time: '' }]);

  expect(alertManualInvestigations({
    'event.investigation_session_id': 'old', 'event.investigated_by': 'u0',
    'event.so_investigations': [{ session_id: 'old', user_id: 'u0' }, { session_id: 'new', user_id: 'u1' }],
  }).map(inv => inv.sessionId)).toEqual(['old', 'new']);
});

test('the start link is built once per alert, so re-renders keep one session id', () => {
  comp.newInvestigationLink = jest.fn(alert => ({ name: 'assistant', params: { sessionId: 'new-' + alert.soc_id } }));
  expect(comp.startLink()).toBeNull();

  comp.alert = { soc_id: 'a1' };
  expect(comp.startLink()).toEqual({ name: 'assistant', params: { sessionId: 'new-a1' } });
  comp.startLink();
  expect(comp.newInvestigationLink).toHaveBeenCalledTimes(1);

  comp.triagedAlert = { soc_id: 'older' };
  expect(comp.startLink().params.sessionId).toBe('new-older');
});

test('only other users\' sessions are checked, and only a definite no blocks', async () => {
  comp.$root.user = { id: 'me', roles: ['analyst'] };
  comp.alert = {
    'event.investigation_session_id': ['mine_1', 'shared_1', 'private_1', 'unknown_1'],
    'event.investigated_by': ['me', 'u2', 'u3', 'u4'],
  };
  const post = mockPapi('post', { data: { shared_1: true, private_1: false } });

  await comp.loadAccess();

  expect(post).toHaveBeenCalledWith('/assistant/sessions/access', { sessionIds: ['unknown_1', 'private_1', 'shared_1'] });
  const byId = Object.fromEntries(comp.manualInvestigations().map(inv => [inv.sessionId, inv]));
  expect(comp.isMine(byId.mine_1)).toBe(true);
  expect(comp.blocked(byId.mine_1)).toBe(false);
  expect(comp.blocked(byId.shared_1)).toBe(false);
  expect(comp.blocked(byId.private_1)).toBe(true);
  expect(comp.blocked(byId.unknown_1)).toBe(false);
  expect(comp.privateLabel(byId.private_1)).toBe('Private to u3. Ask them to share it.');
});

test('a failed access check blocks nothing, and all-mine skips the check', async () => {
  comp.$root.user = { id: 'me', roles: ['analyst'] };
  comp.alert = { 'event.investigation_session_id': ['private_1'], 'event.investigated_by': ['u3'] };
  mockPapi('post', null, new Error('down'));

  await comp.loadAccess();
  expect(comp.blocked(comp.manualInvestigations()[0])).toBe(false);

  resetPapi();
  const post = mockPapi('post', {});
  comp.alert = { 'event.investigation_session_id': ['mine_1'], 'event.investigated_by': ['me'] };
  await comp.loadAccess();
  expect(post).not.toHaveBeenCalled();
});

test('access is asked for at most 50 sessions at a time', async () => {
  const ids = Array.from({ length: 60 }, (_, i) => 's' + i);
  const post = mockPapi('post', { data: { s0: true } });

  expect(await fetchSessionAccess(comp.$root.papi, ids)).toEqual({ s0: true });
  expect(post.mock.calls[0][1].sessionIds).toEqual(ids.slice(0, 50));
});

test('investigators are shown by name once resolved, else by id', async () => {
  comp.$root.getUserById = jest.fn(async id => (id === 'u1' ? { id: 'u1', email: 'one@example.com' } : null));

  await comp.loadUserName('u1');
  await comp.loadUserName('ghost');

  expect(comp.userName('u1')).toBe('one@example.com');
  expect(comp.userName('ghost')).toBe('ghost');
});

test('a group describes its newest triaged alert when it has one', () => {
  comp.alert = { soc_id: 'newest', 'event.investigated': true, 'event.investigation_session_id': ['manual_newest'] };
  expect(comp.manualInvestigations().map(i => i.sessionId)).toEqual(['manual_newest']);
  expect(comp.groupNote()).toBe(comp.i18n.aiInvestigationGroupNewest);

  comp.triagedAlert = { soc_id: 'older', 'event.so_alerttriage.session_id': 'triage_1', 'event.investigated': true, 'event.investigation_session_id': ['copy_1'] };
  expect(comp.automatedId()).toBe('triage_1');
  expect(comp.manualInvestigations().map(i => i.sessionId)).toEqual(['copy_1']);
  expect(comp.groupNote()).toBe(comp.i18n.aiInvestigationGroupNewestTriaged);
  expect(comp.automatedLink()).toEqual({ name: 'assistant', params: { sessionId: 'triage_1' }, query: { alert: 'older' } });
  expect(comp.manualLink({ sessionId: 'copy_1' })).toEqual({ name: 'assistant', params: { sessionId: 'copy_1' }, query: { alert: 'older' } });
});

test('links the bucket to the alerts it covers', () => {
  comp.alert = { soc_id: 'x', 'event.so_alerttriage.session_id': 'triage_1' };

  expect(comp.bucketLink()).toEqual({ path: 'alerts', query: { q: 'event.so_alerttriage.session_id:"triage_1"' } });
  expect(comp.automatedLink().query).toEqual({ alert: 'x' });
});
