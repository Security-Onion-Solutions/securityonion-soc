// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-assistant-chat', 'pages/assistant-chat.html');

// An assistant conversation rendered inside another page, so an investigation can run
// next to the thing being investigated instead of navigating away from it.
//
// The behaviour is the assistant's, not a reimplementation: the same method packs the
// /assistant page merges are merged here, so streaming, tool approval, delegated
// sub-agents and session persistence work identically. `embedded: true` is what those
// packs check to leave the URL and the disclaimer to the page that owns them.
//
// Sessions are saved server-side, so a conversation started here is the same session
// the full assistant page opens by id -- the host page can hand off mid-conversation.

components.push({
  name: "assistant-chat", component: {
    props: {
      // Alert fields the configured investigation prompt interpolates. Starts a new
      // investigation on mount when `sessionId` is not given.
      investigation: { type: Object, default: null },
      // An existing session to resume instead of starting one; takes precedence.
      sessionId: { type: String, default: null },
    },
    emits: ['session-started'],
    // `tool-use-card` and the recursive `delegation-child` reach chat state through
    // this, exactly as they do on the assistant page.
    provide() { return { delegationCtx: this }; },
    data() { return {
      i18n: this.$root.i18n,
      embedded: true,
      messages: [],
      newMessage: '',
      isTyping: false,
      chatHistory: [],
      chatHistoryById: {},
      currentChatId: null,
      creditsRemaining: 0,
      creditsLoaded: false,
      sessionToolState: new Map(),
      delegationChildren: new Map(),
      contextLength: 0,
      creditsUsed: 0,
      creditsByAgent: {},
      increaseContextLimit: false,
      restoreLastActive: false,
      alwaysApproveReadRequests: false,
      toolBusyMaxRetries: 30,
      toolBusyRetryDelayMs: 1000,
      assistantEnabled: false,
      isStreaming: false,
      showChatHistory: false,
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
      isPinnedToBottom: true,
      canChat: true,
      paramsLoaded: false,
      caseMenuVisible: false,
      mruCases: [],
      perMessageStatsEnabled: false,
      showModelThinking: false,
      // The alert this conversation is about, consumed by the first request so the
      // backend records the investigation against it (see callAIAPI).
      investigationSocId: null,
      starting: false,
      startErr: '',
    }},
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
      subAgentApprovalAnnouncement() {
        return this.pendingSubAgentApprovals.map(({ agentName, toolName }) => {
          let msg = this.$root.replaceActionVar(this.i18n.assistantSubAgentApprovalRequest, 'name', agentName);
          return this.$root.replaceActionVar(msg, 'tool', toolName);
        }).join(' ');
      },
    },
    async mounted() {
      await this.startEmbeddedChat();
    },
    beforeUnmount() {
      this.clearStreamingStates();
    },
    methods: Object.assign({},
      AssistantSessions,
      AssistantStreaming,
      AssistantTools,
      AssistantUtils,
      {
        // Parameters are read straight off $root rather than through loadParameters:
        // that call keeps a single pending callback, so registering a second one from
        // a component would silently discard whichever the host page registered. The
        // host only renders this component once the assistant parameters have landed.
        async startEmbeddedChat() {
          this.loadLocalSettings();

          const params = (this.$root.parameters || {})['assistant'];
          if (!params) {
            this.startErr = this.i18n.assistantNotAvailable;
            return;
          }

          this.applyAssistantParams(params);
          this.paramsLoaded = true;

          if (!this.assistantEnabled) {
            this.startErr = this.i18n.assistantNotAvailable;
            return;
          }

          // Sending an alert to the assistant is what the data privacy notice covers, so
          // nothing is requested until it has been accepted. The host raises the notice
          // rather than this component, because showing it unmounts the page underneath
          // it (index.html swaps the notice in for the router view) -- raising it from
          // here would destroy the panel mid-start. This is the backstop.
          if (localStorage.getItem(ONIONAI_DISCLAIMER_KEY) !== 'true') {
            this.startErr = this.i18n.assistantDisclaimerRequired;
            return;
          }

          this.starting = true;
          try {
            await this.loadStoredChats(false);
            await this.loadCredits();

            if (this.sessionId) {
              await this.resumeEmbeddedSession(this.sessionId);
            } else if (this.investigation) {
              await this.startEmbeddedInvestigation();
            } else {
              this.loadNewChatScreen();
            }
          } finally {
            this.starting = false;
          }
        },

        async resumeEmbeddedSession(sessionId) {
          this.currentChatId = sessionId;
          this.$emit('session-started', sessionId);
          try {
            await this.loadChatFromBackend(sessionId);
          } catch (error) {
            // A session that has since been deleted is not an error worth blocking on;
            // the user can simply start a new investigation.
            this.startErr = this.i18n.assistantUnableToLoadChat;
            this.loadNewChatScreen();
          }
        },

        // The page's startInvestigationSession defers the send behind a timer, because
        // there it races the router restoring a session into the same component. Here
        // the mount is the whole of the setup, so the prompt is sent as soon as it is
        // built and the panel is never silently idle.
        async startEmbeddedInvestigation() {
          if (!this.creditsLoaded) {
            this.startErr = this.i18n.assistantBalanceCheckUnhealthy;
            return;
          }

          this.currentChatId = this.generateChatId();
          this.investigationSocId = this.investigation.socId || null;
          this.$emit('session-started', this.currentChatId);

          this.messages = [];
          this.newMessage = this.generateInvestigationPrompt(this.investigation);

          await this.$nextTick();
          try {
            await this.sendMessage();
          } catch (error) {
            this.$root.showError(this.i18n.assistantUnableToInvestigate + ': ' + error.message);
          }
        },
      },
    ),
    template: '#component-assistant-chat',
  }
});
