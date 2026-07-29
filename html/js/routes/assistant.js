// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-assistant', 'pages/assistant.html');

// Methods are split by concern across sibling files that load first (see index.html)
// and publish method objects on globalThis, merged into `methods` below.

routes.push({ path: '/assistant/:sessionId?', name: 'assistant', component: {
  template: '#page-assistant',
  // `tool-use-card` and recursive `delegation-child` are registered globally; provide
  // this instance as `delegationCtx` so every nested level reaches page state via `ctx`.
  provide() { return { delegationCtx: this }; },
  data() { return {
    i18n: this.$root.i18n,
    messages: [],
    newMessage: '',
    isTyping: false,
    chatHistory: [],
    chatHistoryById: {},
    currentChatId: null,
    creditsRemaining: 0,
    creditsLoaded: false,
    // Per-session tool-execution state (one record per session id); replaces five
    // parallel structures. Read/create a record with sessionTools(id).
    sessionToolState: new Map(), // Map<sessionId, {toolsById:Map, indexToId:Map, queue:[], busy:bool, floatingTool}>
    delegationChildren: new Map(), // Map<childSessionId, {parentToolUse, parentSessionId, parentToolUseId, agentName}>
    contextLength: 0,
    creditsUsed: 0,
    // creditsUsed split by producing agent (msg.model); buckets sum to creditsUsed.
    creditsByAgent: {}, // { "<agentName>": credits }
    increaseContextLimit: false,
    restoreLastActive: false,
    alwaysApproveReadRequests: false,
    // A tool POST 409s when another tool turn is already running (backend fails fast
    // rather than blocking); retry a bounded number of times before surfacing an error.
    toolBusyMaxRetries: 30,
    toolBusyRetryDelayMs: 1000,
    assistantEnabled: false,
    isStreaming: false,
    showChatHistory: true,
    investigationMsg: '',
    compressContextMsg: '',
    contextStartMessageIndex: -1,
    contextLimitSmall: 0,
    contextLimitLarge: 0,
    charsPerTokenEstimate: 0,
    thresholdColorRatioLow: 0.5,
    thresholdColorRatioMed: 0.75,
    thresholdColorRatioMax: 1,
    lowBalanceColorAlert: 0,
    agentic: false,
    availableAgents: [],
    agentMapping: {},
    availableModels: [],
    modelsMap: new Map(),
    availableAdapters: [],
    adaptersMap: new Map(),
    groupedModels: [],
    currentModel: '',
    activeStreamingSessionId: null,
    autoScrollOnNextRender: false, // gate for programmatic scrolls
    isPinnedToBottom: true, // user is at (or near) bottom?
    canChat: true,
    paramsLoaded: false,
    caseMenuVisible: false,
    mruCases: [],
    perMessageStatsEnabled: false,
    showModelThinking: false,
    showOptionsDialog: false,
  }},
  async created() {
    this.loadLocalSettings();
    this.loadNewChatScreen();
  },
  beforeUnmount() {
    // Backend automatically saves chats, just save current chat ID
    this.saveCurrentChatId();
  },
  mounted() {
    this.$root.loadParameters('assistant', this.initAssistant);
  },
  watch: {
    '$route'(to, from) {
      if (to.params.sessionId !== from.params.sessionId) {
        this.handleRouteSessionId();
      }
    },
    'increaseContextLimit': 'saveLocalSettings',
    'restoreLastActive': 'saveLocalSettings',
    'alwaysApproveReadRequests': 'saveLocalSettings',
    'showChatHistory': 'saveLocalSettings',
    'currentModel': 'saveLocalSettings',
    'showModelThinking': 'saveLocalSettings'
  },
  computed: {
    messageContextValues() {
      const msgs = this.messages || [];
      return msgs.map((_, i) => this.calculateContextOfMessage(msgs, i));
    },
    isMessageTooLong() {
      if (this.charsPerTokenEstimate <= 0 || !this.newMessage) return false;
      const contextLimit = this.increaseContextLimit ? this.contextLimitLarge : this.contextLimitSmall;
      const maxChars = contextLimit * this.charsPerTokenEstimate * 1.1;
      const usedChars = this.newMessage.length + (this.contextLength * this.charsPerTokenEstimate);
      return usedChars >= maxChars;
    },
    // Sub-agent tools awaiting approval, as {agentName, toolName} pairs. Skips closed
    // delegations (terminal delegate status) so the walk stays bounded to active ones.
    pendingSubAgentApprovals() {
      const pending = [];
      for (const m of (this.messages || [])) {
        const toolUses = m && m.toolUses;
        if (!Array.isArray(toolUses)) continue;
        for (const t of toolUses) {
          if (!t.childSession) continue;
          if (t.status === 'completed' || t.status === 'error') continue;
          const agentName = t.childSession.agentName || this.i18n.assistantDelegateAgent;
          for (const ct of this.pendingChildTools(t)) {
            pending.push({ agentName, toolName: ct.name });
          }
        }
      }
      return pending;
    },
    // Polite-live-region text for screen readers: summarizes any sub-agent tool
    // approvals currently awaiting the user, so it announces appearance, not tokens.
    subAgentApprovalAnnouncement() {
      return this.pendingSubAgentApprovals.map(({ agentName, toolName }) => {
        let msg = this.$root.replaceActionVar(this.i18n.assistantSubAgentApprovalRequest, 'name', agentName);
        return this.$root.replaceActionVar(msg, 'tool', toolName);
      }).join(' ');
    },
    // Rows for the Total Credits tooltip: {label, credits} per agent, highest first.
    creditBreakdown() {
      return Object.entries(this.creditsByAgent)
        .filter(([, credits]) => credits > 0)
        .map(([label, credits]) => ({ label, credits }))
        .sort((a, b) => b.credits - a.credits);
    },
  },
  methods: Object.assign({},
    AssistantSessions,
    AssistantStreaming,
    AssistantTools,
    AssistantUtils,
  ),
}});
