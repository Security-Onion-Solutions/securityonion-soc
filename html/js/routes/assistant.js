// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-assistant', 'pages/assistant.html');

// The bulk of this page's methods are split by concern across sibling files
// Each loads before this file (see index.html) and publishes a plain object of
// methods on globalThis; they are merged into the component's `methods` below,
// so the component is fully assembled when routes.push runs.

routes.push({ path: '/assistant/:sessionId?', name: 'assistant', component: {
  template: '#page-assistant',
  // `tool-use-card` and the recursive `delegation-child` (js/components/) are
  // registered globally; the page only provides its instance as `delegationCtx` so
  // those components (and every nested level) reach page state/helpers via `ctx`.
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
    // Per-session tool-execution state, one record per session id. Consolidates what
    // were five parallel structures: the tools-by-id map, the stream block-index ->
    // tool-id map, the approval queue, the runner-busy flag, and the floating
    // (pending-approval) tool shown above a collapsed delegate. Read/create a record
    // with sessionTools(id).
    sessionToolState: new Map(), // Map<sessionId, {toolsById:Map, indexToId:Map, queue:[], busy:bool, floatingTool}>
    delegationChildren: new Map(), // Map<childSessionId, {parentToolUse, parentSessionId, parentToolUseId, agentName}>
    contextLength: 0, // Track total context length
    creditsUsed: 0, // Track total accumulated credits used for a session
    increaseContextLimit: false, // Toggle for max context threshold
    restoreLastActive: false, // Toggle to restore last active chat
    alwaysApproveReadRequests: false,
    // A tool POST gets a 409 when another tool turn is already running for the session
    // (the backend fails fast rather than blocking). Retry a bounded number of times
    // with a short delay before surfacing an error.
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
    activeStreamingSessionId: null, // Track which session is actively streaming
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
      // Handle session ID changes from URL
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
    // Sub-agent tools currently awaiting the user's approval, as
    // {agentName, toolName} pairs. Re-evaluates when the message/tool structure
    // or a child tool's status changes; closed delegations (the delegate tool
    // reached a terminal status) are skipped so the walk stays bounded by the
    // active delegations rather than the whole transcript.
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
  },
  methods: Object.assign({},
    AssistantSessions,
    AssistantStreaming,
    AssistantTools,
    AssistantUtils,
  ),
}});
