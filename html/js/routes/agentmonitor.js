// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-agentmonitor', 'pages/agentmonitor.html');

const MONITOR_TICK_MS = 1000;

// One details request per run, so this caps the cost of a load.
const MONITOR_RECENT_RUNS = 5;

// Matches the backend's agentStreamFlushIntervalMs; refetching faster finds nothing new.
const MONITOR_TRANSCRIPT_REFRESH_MS = 1000;

const MONITOR_PHASE_WAITING_LLM = 'waiting_llm';
const MONITOR_PHASE_INVOKING_TOOL = 'invoking_tool:';
const MONITOR_DELEGATE_TOOL = 'delegate_to_';

const emptyPool = () => ({
  queued: 0, running: 0, maxConcurrent: 0, maxQueueDepth: 0,
  peakQueued: 0, peakRunning: 0, rejected: 0, deduped: 0, busy: 0, agents: [],
});

// Assistant methods that tool-use-card, delegation-child and session conversion rely on.
const monitorDelegationCtx = () => Object.assign(
  {},
  pickMethods(globalThis.AssistantTools, ['displayStatus', 'hasPendingDescendantApproval', 'getToolStatusIcon', 'getToolStatusColor', 'getToolStatusTitle',
    'sessionTools', 'getSessionToolMap']),
  pickMethods(globalThis.AssistantStreaming, ['pendingChildTools', 'delegateOwnCredits', 'delegateOwnOutputTokens', 'delegationHasCollapsedContent',
    'ensureChildSession']),
  // Not formatMarkdown: the assistant's renders clickable choice buttons.
  pickMethods(globalThis.AssistantUtils, ['formatCount', 'formatTimestamp', 'dedupeToolUseBlocks', 'nbspRegexOp', 'calculateContextOfMessage']),
  pickMethods(globalThis.AssistantSessions, ['convertBackendMessagesToFrontend', 'processToolResultMessage', 'processOldFormatToolResult',
    'extractMessageContent', 'processToolUseBlocks', 'collectResolvedToolUseIds', 'isPartialMessage', 'isActiveToolTurn', 'indexSubSessions',
    'reconstructDelegateChildSessions', 'reconstructChildSession', 'finalizeResolvedDelegations', 'updateContextLength', 'calculateContextFromUsage']),
);

function pickMethods(module, names) {
  const picked = {};
  for (const name of names) {
    if (module && module[name]) picked[name] = module[name];
  }
  return picked;
}

routes.push({ path: '/agentmonitor/:itemId?/:sessionId?', name: 'agentmonitor', component: {
  template: '#page-agentmonitor',
  provide() { return { delegationCtx: this, agentMonitorCtx: this }; },
  data() { return {
    i18n: this.$root.i18n,
    paramsLoaded: false,
    assistantEnabled: false,
    agentic: false,
    agentMapping: {},

    schedulerRunning: true,
    pool: emptyPool(),
    items: [],
    recent: [],
    automations: [],
    sessionStarts: {},
    missingSessions: [],
    inFlightRunIds: [],
    // sessionId -> { agent, messages, subSessionIds }
    transcripts: {},
    transcriptLoading: false,
    transcriptRefreshTimer: null,
    activityLoading: false,
    // generatedAt of the activity shown, in ms; anything older is dropped.
    activityGeneratedAt: 0,

    // Written by the reused assistant conversion.
    sessionToolState: new Map(),
    delegationChildren: new Map(),
    contextLength: 0,
    contextStartMessageIndex: -1,
    currentChatId: '',

    selectedItemId: '',
    selectedSessionId: '',
    expandedItems: [],
    expandedRecent: [],
    itemTabs: {},

    collapsedSections: [],

    canChat: false,
    showModelThinking: true,
    paused: false,
    stopDialog: false,
    // { id, name } of the automation to stop; null stops them all.
    stopTarget: null,

    tickTimer: null,
    now: Date.now(),

    itemHeaders: [
      { title: '', value: 'expand', sortable: false, width: '48px' },
      { title: this.$root.i18n.agentMonitorAutomation, value: 'automationName' },
      { title: this.$root.i18n.agentMonitorGroup, value: 'groupKey', sortable: false },
      { title: this.$root.i18n.status, value: 'status', width: '120px' },
      { title: this.$root.i18n.agentMonitorDoing, value: 'activity', sortable: false },
      { title: this.$root.i18n.agentMonitorAgent, value: 'agentChain', sortable: false },
      { title: this.$root.i18n.attempt, value: 'attempts', width: '100px' },
      { title: this.$root.i18n.agentMonitorInState, value: 'updateTime', width: '110px' },
      { title: this.$root.i18n.agentMonitorElapsed, value: 'createTime', width: '110px' },
      { title: this.$root.i18n.actions, value: 'actions', sortable: false, width: '90px' },
    ],
    attemptHeaders: [
      { title: this.$root.i18n.attempt, value: 'attempt', sortable: false, width: '100px' },
      { title: this.$root.i18n.agentMonitorSession, value: 'sessionId', sortable: false },
      { title: this.$root.i18n.status, value: 'state', sortable: false, width: '120px' },
      { title: this.$root.i18n.agentMonitorStarted, value: 'startTime', sortable: false, width: '200px' },
      { title: this.$root.i18n.actions, value: 'actions', sortable: false, width: '90px' },
    ],
    expandedHeaders: [
      { title: 'key', value: 'key' },
      { title: 'value', value: 'value' },
    ],
    rightShiftedHeaders: ['attempts', 'createTime', 'updateTime', 'attempt', 'duration'],
    recentHeaders: [
      { title: '', value: 'expand', sortable: false, width: '48px' },
      { title: this.$root.i18n.agentMonitorAutomation, value: 'automationName' },
      { title: this.$root.i18n.agentMonitorGroup, value: 'groupKey', sortable: false },
      { title: this.$root.i18n.agentStudioAutomationOutcome, value: 'state', width: '120px' },
      { title: this.$root.i18n.error, value: 'error', sortable: false },
      { title: this.$root.i18n.attempt, value: 'attempts', width: '100px' },
      { title: this.$root.i18n.agentMonitorFinished, value: 'updateTime', width: '200px' },
      { title: this.$root.i18n.duration, value: 'duration', sortable: false, width: '110px' },
      { title: this.$root.i18n.actions, value: 'actions', sortable: false, width: '90px' },
    ],
    sortBy: [{ key: 'createTime', order: 'asc' }],
    itemsPerPage: 10,
    itemsPerPageOptions: [10, 50, 250, 1000],
  }},
  watch: {
    '$route': 'applyRoute',
    'sortBy': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
    // Changes pushed while disconnected were missed.
    '$root.connected'(connected) {
      if (connected && this.agentic && !this.paused) this.loadActivity(true);
    },
  },
  mounted() {
    this.reload();
    this.$root.subscribe('assistant:stream', this.onAgentStream);
    this.$root.subscribe('assistant:automation', this.onAutomationActivity);
  },
  beforeUnmount() {
    this.stopTick();
    this.$root.unsubscribe('assistant:stream', this.onAgentStream);
    this.$root.unsubscribe('assistant:automation', this.onAutomationActivity);
    clearTimeout(this.transcriptRefreshTimer);
  },
  methods: Object.assign({
    // Unreachable for a spectator, but the shared components reference them.
    approveTool() {},
    rejectTool() {},

    // Assistant formatMarkdown without the choice buttons.
    formatMarkdown(text) {
      if (!text) return '';
      const prepared = this.$root.performMermaidRegexes ? this.$root.performMermaidRegexes(text) : text;
      const html = this.$root.formatMarkdown(prepared, true);
      if (this.$root.renderMermaid) this.$nextTick(() => this.$root.renderMermaid());
      return html;
    },

    reload() {
      this.$root.startLoading();
      this.$root.loadParameters('assistant', this.initAssistant);
    },
    initAssistant(params) {
      params = params || {};
      this.assistantEnabled = params.enabled && this.$root.isLicensed('oai');
      this.agentic = params.agentic || false;
      this.agentMapping = params.agentMapping || {};
      this.paramsLoaded = true;
      if (this.assistantEnabled && this.agentic && this.$root.canReadAutomations()) {
        this.loadLocalSettings();
        this.applyRoute();
        this.loadData();
        this.startTick();
      }
      this.$root.stopLoading();
    },
    applyRoute() {
      const params = (this.$route || {}).params || {};
      this.selectedItemId = params.itemId || '';
      this.selectedSessionId = params.sessionId || '';
      if (this.selectedItemId && !this.selectedSessionId && !this.expandedItems.includes(this.selectedItemId)) {
        this.expandedItems = [this.selectedItemId];
      }
      if (this.selectedSessionId) this.loadTranscript(this.selectedSessionId);
    },
    saveLocalSettings() {
      localStorage['settings.agentmonitor.sortBy'] = this.sortBy[0].key;
      localStorage['settings.agentmonitor.sortDesc'] = this.sortBy[0].order;
      localStorage['settings.agentmonitor.itemsPerPage'] = this.itemsPerPage;
      localStorage['settings.agentmonitor.collapsedSections'] = JSON.stringify(this.collapsedSections);
    },
    loadLocalSettings() {
      if (localStorage['settings.agentmonitor.sortBy']) this.sortBy[0].key = localStorage['settings.agentmonitor.sortBy'];
      if (localStorage['settings.agentmonitor.sortDesc']) this.sortBy[0].order = localStorage['settings.agentmonitor.sortDesc'];
      if (localStorage['settings.agentmonitor.itemsPerPage']) this.itemsPerPage = parseInt(localStorage['settings.agentmonitor.itemsPerPage']);
      if (localStorage['settings.agentmonitor.collapsedSections']) this.collapsedSections = JSON.parse(localStorage['settings.agentmonitor.collapsedSections']);
    },
    toggleShowSection(item) {
      if (this.isExpandedSection(item)) {
        this.collapsedSections.push(item);
      } else {
        this.collapsedSections.splice(this.collapsedSections.indexOf(item), 1);
      }
      this.saveLocalSettings();
    },
    isExpandedSection(item) {
      return this.collapsedSections.indexOf(item) == -1;
    },

    // Background refreshes only log, so a transient failure doesn't pop an error.
    reportLoadError(error, background) {
      if (background) console.error('Failed to refresh Agent Monitor:', error);
      else this.$root.showError(error);
    },
    confirmStop(item) {
      this.stopTarget = item ? { id: item.automationId, name: item.automationName } : null;
      this.stopDialog = true;
    },
    cancelStop() {
      this.stopDialog = false;
      this.stopTarget = null;
    },
    async performStop() {
      const target = this.stopTarget;
      this.cancelStop();
      this.$root.startLoading();
      try {
        if (target) {
          await this.$root.papi.post('assistant/automations/' + encodeURIComponent(target.id) + '/stop');
          this.$root.showInfo(this.i18n.agentMonitorStopped.replace('{name}', target.name));
        } else {
          const response = await this.$root.papi.post('assistant/automations/stop');
          this.$root.showInfo(this.i18n.agentMonitorStoppedAll.replace('{count}', (response.data || {}).stopped || 0));
        }
        await this.loadData();
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.$root.stopLoading();
      }
    },
    async loadData(background = false) {
      this.now = Date.now();
      const loads = [this.loadActivity(background), this.loadRecent(background)];
      if (this.selectedSessionId) loads.push(this.loadTranscript(this.selectedSessionId, background));
      await Promise.all(loads);
    },
    async loadActivity(background = false) {
      if (this.activityLoading) return;
      this.activityLoading = true;
      try {
        const response = await this.$root.papi.get('assistant/automations/activity');
        this.applyActivity(response.data || {});
      } catch (error) {
        this.reportLoadError(error, background);
      } finally {
        this.activityLoading = false;
      }
    },
    onAutomationActivity(activity) {
      if (activity && !this.paused) this.applyActivity(activity);
    },
    applyActivity(activity) {
      // A slow fetch can land after a newer push.
      const generatedAt = Date.parse(activity.generatedAt) || 0;
      if (generatedAt && generatedAt < this.activityGeneratedAt) return;
      if (generatedAt) this.activityGeneratedAt = generatedAt;

      this.schedulerRunning = activity.schedulerRunning !== false;
      this.pool = Object.assign(emptyPool(), activity.pool || {});

      // Open items are listed per automation, so two runs of one repeat them.
      const items = [];
      const seen = new Set();
      for (const run of activity.runs || []) {
        for (const item of run.items || []) {
          if (seen.has(item.id)) continue;
          seen.add(item.id);
          const row = Object.assign({}, item, {
            automationName: run.displayName || item.automationId,
            phases: item.phases || [],
            queued: !!item.queued,
          });
          row.status = this.displayState(row);
          items.push(row);
        }
      }
      this.items = items;
      this.initItemTabs(items);

      const runIds = (activity.runs || []).map(run => run.id);
      const finished = this.inFlightRunIds.some(id => !runIds.includes(id));
      this.inFlightRunIds = runIds;
      if (finished) this.loadRecent(true);
    },
    async loadRecent(background = false) {
      try {
        const automations = (await this.$root.papi.get('assistant/automations')).data || [];
        this.automations = automations;

        const histories = await Promise.all(automations.map(a => this.$root.papi.get(
          'assistant/automations/' + encodeURIComponent(a.id) + '/runs', { params: { limit: MONITOR_RECENT_RUNS } })));
        const runs = histories
          .flatMap(response => (response.data || {}).runs || [])
          .filter(run => ['succeeded', 'failed'].includes(run.state) && this.runItemTotal(run) > 0)
          .sort((a, b) => new Date(b.startTime) - new Date(a.startTime))
          .slice(0, MONITOR_RECENT_RUNS);

        // Alerts aren't shown; 0 would fetch the server default of 500.
        const details = await Promise.all(runs.map(run => this.$root.papi.get(
          'assistant/automations/' + encodeURIComponent(run.automationId) + '/runs/' + encodeURIComponent(run.id),
          { params: { alertLimit: 1 } })));
        this.applyRecent(details.map(response => response.data || {}));
      } catch (error) {
        this.reportLoadError(error, background);
      }
    },
    runItemTotal(run) {
      const counts = run.itemCounts || {};
      return (counts.done || 0) + (counts.failed || 0);
    },
    applyRecent(detailsList) {
      const rows = [];
      const seen = new Set();
      const starts = {};
      const missing = [];
      for (const details of detailsList) {
        for (const session of details.sessions || []) {
          if (session.createTime) starts[session.sessionId] = session.createTime;
          if (session.missing) missing.push(session.sessionId);
        }
        // A retried item appears in both runs; the newer run comes first.
        for (const item of details.items || []) {
          if (!this.isTerminal(item.state) || seen.has(item.id)) continue;
          seen.add(item.id);
          rows.push(Object.assign({}, item, { automationName: details.displayName || details.automationId }));
        }
      }
      rows.sort((a, b) => new Date(b.updateTime) - new Date(a.updateTime));
      this.recent = rows;
      this.sessionStarts = starts;
      this.missingSessions = missing;
      this.initItemTabs(rows);
    },
    initItemTabs(rows) {
      rows.forEach(i => { if (!this.itemTabs[i.id]) this.itemTabs[i.id] = 'details'; });
    },

    async loadTranscript(sessionId, background = false) {
      if (!sessionId) return;
      if (!background) this.transcriptLoading = true;
      try {
        const response = await this.$root.papi.get('assistant/sessions/' + encodeURIComponent(sessionId));
        this.transcripts[sessionId] = this.buildTranscript(response.data || {});
      } catch (error) {
        const status = error.response && error.response.status;
        if (status === 403 || status === 404) delete this.transcripts[sessionId];
        else this.reportLoadError(error, background);
      } finally {
        this.transcriptLoading = false;
      }
    },
    buildTranscript(data) {
      const session = data.session || {};
      this.sessionToolState = new Map();
      this.delegationChildren = new Map();
      this.currentChatId = session.sessionId || '';
      this._loadSubSessions = this.indexSubSessions(data.subSessions);
      let messages;
      try {
        messages = this.convertBackendMessagesToFrontend(data.history || []);
      } finally {
        this._loadSubSessions = null;
      }
      // Drop the objective, which is stored as a user turn.
      messages = messages.filter(m => m.role === 'assistant');
      this.settleSpectatorTools(messages);
      return {
        agent: session.model || '',
        messages: messages,
        subSessionIds: (data.subSessions || []).map(s => (s.session || {}).sessionId).filter(Boolean),
      };
    },
    // Automated sessions have no approver; a tool without a result is still running.
    settleSpectatorTools(messages) {
      for (const message of messages || []) {
        for (const toolUse of message.toolUses || []) {
          if (toolUse.status === 'pending_approval') {
            toolUse.status = 'executing';
            toolUse.approved = true;
          }
          if (toolUse.childSession) this.settleSpectatorTools(toolUse.childSession.messages);
        }
      }
    },
    // Includes children from activity: a new delegation streams before it is stored.
    watchedSessionIds() {
      const root = this.selectedSessionId;
      if (!root) return [];
      const ids = [root].concat((this.transcripts[root] || {}).subSessionIds || []);
      for (const item of this.items) {
        for (const phase of item.phases || []) {
          if (phase.rootSessionId === root) ids.push(phase.sessionId);
        }
      }
      return ids;
    },
    // Refetch rather than merge, so live and stored transcripts are built the same way.
    onAgentStream(event) {
      if (this.paused || !event || !this.watchedSessionIds().includes(event.sessionId)) return;
      this.scheduleTranscriptRefresh();
    },
    scheduleTranscriptRefresh() {
      if (this.transcriptRefreshTimer) return;
      this.transcriptRefreshTimer = setTimeout(() => {
        this.transcriptRefreshTimer = null;
        this.loadTranscript(this.selectedSessionId, true);
      }, MONITOR_TRANSCRIPT_REFRESH_MS);
    },
    modelFor(agent) {
      return this.agentMapping[agent] || '';
    },

    // Keyed on the route, not a resolved row, so a stale link reaches the not-found view.
    level() {
      return this.selectedSessionId ? 2 : 1;
    },
    selectedItem() {
      if (!this.selectedItemId) return null;
      return this.items.concat(this.recent).find(i => i.id === this.selectedItemId) || null;
    },
    watchedSessionId() {
      return this.selectedSessionId;
    },
    watchedTranscript() {
      return this.transcripts[this.selectedSessionId] || null;
    },
    watchedIsLive() {
      const item = this.selectedItem();
      if (!item || this.isTerminal(item.state)) return false;
      const sessionIds = item.sessionIds || [];
      return sessionIds[sessionIds.length - 1] === this.selectedSessionId;
    },
    liveSessionOf(item) {
      const sessionIds = item.sessionIds || [];
      return sessionIds[sessionIds.length - 1] || '';
    },
    breadcrumbs() {
      // A disabled crumb with a `to` still renders as a clickable-looking anchor.
      const atRoot = this.level() === 1;
      const crumbs = [{ title: this.i18n.agentMonitor, to: atRoot ? null : { name: 'agentmonitor' }, disabled: atRoot }];
      if (this.level() === 2) {
        const item = this.selectedItem();
        const label = item
          ? item.automationName + (item.groupKey ? ' — ' + item.groupKey : '')
          : this.i18n.agentMonitorSession;
        crumbs.push({ title: label, to: null, disabled: true });
      }
      return crumbs;
    },

    buildSessionLink(itemId, sessionId) {
      return { name: 'agentmonitor', params: { itemId: itemId, sessionId: sessionId } };
    },
    // One row per recorded session, newest first. Not keyed to the attempts counter:
    // a claim that died before recording its session leaves no gap in session_ids.
    attemptsFor(item) {
      const sessionIds = item.sessionIds || [];
      return sessionIds.map((sessionId, index) => {
        const last = index === sessionIds.length - 1;
        return {
          attempt: index + 1,
          sessionId,
          live: last && !this.isTerminal(item.state),
          state: last ? item.state : 'failed',
          startTime: this.sessionStarts[sessionId] || '',
          watchable: !this.missingSessions.includes(sessionId),
        };
      }).reverse();
    },
    itemDetails(item) {
      const rows = [
        { key: this.i18n.agentMonitorItemId, value: item.id },
        { key: this.i18n.agentMonitorRunId, value: item.runId || '—', help: this.i18n.agentMonitorRunIdHelp },
        { key: this.i18n.agentMonitorAutomation, value: item.automationName, link: this.automationConfigLink(item) },
        { key: this.i18n.agentMonitorGroup, value: item.groupKey || '—' },
        { key: this.i18n.status, value: this.stateLabel(this.displayState(item)) },
        { key: this.i18n.attempt, value: item.attempts },
        { key: this.i18n.dateCreated, value: this.$root.formatDateTime(item.createTime) },
        { key: this.i18n.agentMonitorLastChanged, value: this.$root.formatDateTime(item.updateTime), help: this.i18n.agentMonitorInStateHelp },
      ];
      if (item.error) rows.push({ key: this.i18n.error, value: item.error });
      return rows;
    },
    // Agent Studio stays admin-only.
    automationConfigLink(item) {
      if (!item.automationId || !this.$root.isUserAdmin()) return null;
      return { name: 'agentstudio', query: { tab: 'automations', automation: item.automationId } };
    },
    kvRows(obj) {
      return Object.entries(obj || {}).map(([key, value]) => ({
        key,
        value: value === null || value === undefined ? '—'
          : typeof value === 'object' ? JSON.stringify(value) : String(value),
      }));
    },
    kvTabs(item) {
      return item.result ? ['details', 'payload', 'result'] : ['details', 'payload'];
    },
    tabRows(item, tab) {
      if (tab === 'payload') return this.kvRows(item.payload);
      if (tab === 'result') return this.kvRows(item.result);
      return this.itemDetails(item);
    },
    // Claims that died before their session was recorded.
    attemptsWithoutSession(item) {
      return Math.max(0, (item.attempts || 0) - (item.sessionIds || []).length);
    },

    isTerminal(state) {
      return state === 'done' || state === 'failed';
    },
    // A claimed item waiting for a pool slot is stored as running.
    displayState(item) {
      return item.state === 'running' && item.queued ? 'queued' : item.state;
    },
    stateLabel(state) {
      return ({
        pending: this.i18n.statePending,
        queued: this.i18n.stateQueued,
        running: this.i18n.stateRunning,
        applying: this.i18n.stateApplying,
        done: this.i18n.stateDone,
        failed: this.i18n.stateFailed,
      })[state] || state;
    },
    stateColor(state) {
      return ({ running: 'primary', applying: 'info', pending: 'warning', queued: 'warning', failed: 'error' })[state] || '';
    },

    agentOf(item) {
      return (this.automations.find(a => a.id === item.automationId) || {}).agent || '';
    },
    // An agent at its own limit holds work back even when the pool has a free slot.
    blockedBy(item) {
      const agent = this.agentOf(item);
      const load = (this.pool.agents || []).find(a => a.name === agent);
      return load && load.maxConcurrentInstances && load.running >= load.maxConcurrentInstances ? agent : '';
    },
    agentChain(item) {
      const agents = [];
      for (const phase of item.phases || []) {
        if (phase.agent && !agents.includes(phase.agent)) agents.push(phase.agent);
      }
      if (!agents.length && this.agentOf(item)) agents.push(this.agentOf(item));
      return agents;
    },
    activityFor(item) {
      if (this.isTerminal(item.state)) return '';
      if (item.state === 'applying') return this.i18n.agentMonitorApplyingResults;
      // Dispatch skips jobs whose agent is at its limit, so there is no queue position.
      if (item.state === 'pending' || item.queued) {
        const blocked = this.blockedBy(item);
        return blocked ? this.i18n.agentMonitorWaitingOnAgent + ' ' + blocked : '';
      }
      // A delegating session just waits on its child; report the one doing the work.
      const phases = item.phases || [];
      const working = phases.filter(p => !this.isDelegating(p.phase));
      const phase = working[working.length - 1] || phases[phases.length - 1];
      return phase ? this.describePhase(phase.phase) : this.i18n.agentMonitorPreparing;
    },
    isDelegating(phase) {
      return !!phase && phase.startsWith(MONITOR_PHASE_INVOKING_TOOL + MONITOR_DELEGATE_TOOL);
    },
    describePhase(phase) {
      if (phase === MONITOR_PHASE_WAITING_LLM) return this.i18n.agentMonitorWaitingOnModel;
      if (phase && phase.startsWith(MONITOR_PHASE_INVOKING_TOOL)) {
        const tool = phase.slice(MONITOR_PHASE_INVOKING_TOOL.length);
        if (tool.startsWith(MONITOR_DELEGATE_TOOL)) return this.i18n.agentMonitorDelegatingTo + ' ' + tool.slice(MONITOR_DELEGATE_TOOL.length);
        return this.i18n.agentMonitorInvoking + ' ' + tool;
      }
      return phase || '';
    },

    elapsedMs(item) {
      const start = new Date(item.createTime).getTime();
      const end = this.isTerminal(item.state) ? new Date(item.updateTime).getTime() : this.now;
      return Math.max(0, end - start);
    },
    inStateMs(item) {
      if (this.isTerminal(item.state)) return 0;
      return Math.max(0, this.now - new Date(item.updateTime).getTime());
    },
    formatElapsed(ms) {
      const total = Math.floor(ms / 1000);
      const mins = Math.floor(total / 60);
      const secs = total % 60;
      return mins + ':' + String(secs).padStart(2, '0');
    },
    withLimit(count, limit) {
      return count + ' / ' + (limit ? limit : this.i18n.agentMonitorNoLimit);
    },
    // Whole pool, chats included: they share the slots automations wait for.
    poolLabel() {
      return this.withLimit(this.pool.running, this.pool.maxConcurrent);
    },
    queuedLabel() {
      return this.withLimit(this.pool.queued, this.pool.maxQueueDepth);
    },
    poolSaturated() {
      return !!this.pool.maxConcurrent && this.pool.running >= this.pool.maxConcurrent && this.pool.queued > 0;
    },

    startTick() {
      this.stopTick();
      this.tickTimer = setInterval(this.tick, MONITOR_TICK_MS);
    },
    stopTick() {
      if (this.tickTimer) clearInterval(this.tickTimer);
      this.tickTimer = null;
    },
    // Resuming catches up on what was ignored while paused.
    togglePaused() {
      this.paused = !this.paused;
      if (!this.paused) this.loadActivity(true);
    },
    tick() {
      if (!this.paused) this.now = Date.now();
    },
  }, monitorDelegationCtx())
}});
