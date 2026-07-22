// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Assistant page methods: scrolling, markdown/formatting helpers, context/model
// helpers, local settings persistence, and sharing/export/case-attach utilities.

globalThis.AssistantUtils = (function() {
  const SESTAG_SHARED = 'shared';
  const CHOICE_MARKER_REGEX = /\[\[CHOICE\]\]([\s\S]*?)\[\[\/CHOICE\]\]/g;

  return {
    isNearBottom(container, thresholdPx = 48) {
      return (container.scrollHeight - container.clientHeight - container.scrollTop) <= thresholdPx;
    },

    forceScrollBottom(container) {
      container.scrollTop = container.scrollHeight;
    },

    scrollToBottom() {
      this.$nextTick(() => {
        const messagesContainer = this.$el.querySelector('.chat-messages');
        if (messagesContainer) {
          messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
      });
    },

    async scrollToBottomSettled({ settleDelay = 180, maxWait = 3000 } = {}) {
      await this.$nextTick(); // wait for Vue's immediate DOM updates

      const container = this.$el && this.$el.querySelector
        ? this.$el.querySelector('.chat-messages')
        : null;
      if (!container) return;

      // Always do an initial snap
      this.forceScrollBottom(container);

      let resolved = false;
      let lastHeight = container.scrollHeight;
      let settleTimer = null;

      const cleanupFns = [];

      const scheduleSettle = () => {
        if (settleTimer) clearTimeout(settleTimer);
        settleTimer = setTimeout(() => {
          // If height hasn't changed for settleDelay, consider layout "settled"
          const sameHeight = container.scrollHeight === lastHeight;
          lastHeight = container.scrollHeight;
          if (sameHeight) {
            resolved = true;
            cleanup();
            // final snap (covers any last-millisecond growth)
            this.forceScrollBottom(container);
          } else {
            // height changed during debounce; snap again and wait again
            this.forceScrollBottom(container);
            scheduleSettle();
          }
        }, settleDelay);
      };

      const onMutateOrResize = () => {
        if (resolved) return;
        // When DOM mutates or sizes change, snap and restart settle timer
        this.forceScrollBottom(container);
        lastHeight = container.scrollHeight;
        scheduleSettle();
      };

      // Observe DOM changes under chat messages (mermaid renders, tool cards, etc.)
      const mo = new MutationObserver(onMutateOrResize);
      mo.observe(container, {
        childList: true,
        subtree: true,
        characterData: true,
      });
      cleanupFns.push(() => mo.disconnect());

      // Observe size changes (tables/images causing height growth)
      if ('ResizeObserver' in window) {
        const ro = new ResizeObserver(onMutateOrResize);
        ro.observe(container);
        cleanupFns.push(() => ro.disconnect());
      }

      // Listen for image loads inside container (images can change height after decode)
      const imgs = Array.from(container.querySelectorAll('img'));
      const pendingImgs = imgs.filter(img => !img.complete);
      const imgHandlers = [];
      pendingImgs.forEach(img => {
        const h = () => onMutateOrResize();
        img.addEventListener('load', h, { once: true });
        img.addEventListener('error', h, { once: true });
        imgHandlers.push(() => {
          img.removeEventListener('load', h);
          img.removeEventListener('error', h);
        });
      });
      cleanupFns.push(() => imgHandlers.forEach(fn => fn()));

      // Safety timeout so we don't hang forever if something keeps mutating
      const safetyTimer = setTimeout(() => {
        if (!resolved) {
          cleanup();
          this.forceScrollBottom(container);
        }
      }, maxWait);
      cleanupFns.push(() => clearTimeout(safetyTimer));

      const cleanup = () => {
        cleanupFns.forEach(fn => fn());
        if (settleTimer) clearTimeout(settleTimer);
      };

      // kick off the initial settle wait
      scheduleSettle();
    },

    onChatScroll(evt) {
      const c = evt.target;
      const atBottom = this.isNearBottom(c, 4);
      this.isPinnedToBottom = atBottom;
    },

    scrollIfPinned() {
      if (!this.isPinnedToBottom) return;
      this.scrollToBottom();
    },

    getAvatar(user) {
      return this.$root.getAvatar(user);
    },
    formatTimestamp(timestamp) {
      return this.$root.formatTimestamp(timestamp);
    },
    formatMarkdown(text) {
      text = this.applyChoiceButtons(text);
      text = this.$root.performMermaidRegexes(text);
      const md = this.$root.formatMarkdown(text, true);
      if (!this.isStreaming) {
        this.$nextTick(() => {
          this.$root.renderMermaid();
        });
      }
      return md;
    },
    renderInlineMarkdown(text) {
      if (!text) return '';
      return this.$root.formatMarkdown(text, false);
    },
    formatChatDate(timestamp) {
      return this.$root.formatDateTime(timestamp);
    },
    formatCount(count) {
      return this.$root.formatCount(count);
    },
    calculateContextOfMessage(allMessages, msgIndex) {
      // non-user messages tell us their context in output_tokens
      if (msgIndex >= 0 && msgIndex < allMessages.length && allMessages[msgIndex].role !== 'user') {
        // asking about an assistant message, return its output tokens
        return allMessages[msgIndex].usage ? allMessages[msgIndex].usage.output_tokens : 0;
      }

      // this is a user message, use nearby message to calculate how many tokens
      // are in this message
      let prev, next;
      if (msgIndex > 0) prev = allMessages[msgIndex - 1];
      if (msgIndex < allMessages.length - 1) next = allMessages[msgIndex + 1];

      let contextLength = 0;
      if (prev && prev.usage && next && next.usage) {
        // use the message before and after to calculate the tokens in this message
        contextLength = next.usage.input_tokens - (prev.usage.input_tokens + prev.usage.output_tokens);
      } else if (next && next.usage) {
        // use the next message's input_tokens as the length of this solitary message
        contextLength = next.usage.input_tokens;
      }
      return contextLength;
    },
    generateInvestigationPrompt(fields) {

      // Prepare the alert data for investigation
      const alertData = {
        socId: fields.socId,
        ruleUuid: fields.ruleUuid,
        ruleName: fields.ruleName,
        severity: fields.severity,
        timestamp: fields.timestamp,
        sourceIp: fields.sourceIp,
        destIp: fields.destIp,
        eventModule: fields.eventModule,
        eventDataset: fields.eventDataset,
        message: fields.message,
        alertRule: fields.alertRule
      };

      let investigationPrompt = this.investigationMsg;
      
      for (let alertKey in alertData) {
        investigationPrompt = this.$root.replaceActionVar(investigationPrompt, alertKey.toString(), alertData[alertKey] || 'Unknown');
      }

      return investigationPrompt;
    },

    getContextColor(value) {
      const maxContextLength = this.increaseContextLimit ? this.contextLimitLarge : this.contextLimitSmall;
      const threshold1 = maxContextLength * this.thresholdColorRatioLow;
      const threshold2 = maxContextLength * this.thresholdColorRatioMed;
      const threshold3 = maxContextLength * this.thresholdColorRatioMax;
      
      if (value < threshold1) return "text-success";
      if (value < threshold2) return "text-amber";
      if (value < threshold3) return "text-warning";
      return "text-error";
    },

    getCompressColor() {
      const maxContextLength = this.increaseContextLimit ? this.contextLimitLarge : this.contextLimitSmall;
      if (this.contextLength >= maxContextLength / 2) {
        return 'primary';
      }

      return 'theme-icon';
    },
    

    // Generic setting save method
    saveSetting(name, value, defaultValue = null) {
      var item = 'settings.assistant.' + name;
      if (defaultValue == null || value != defaultValue) {
        localStorage[item] = value;
      } else {
        localStorage.removeItem(item);
      }
    },

    // Save all local settings
    saveLocalSettings() {
      this.saveSetting('increaseContextLimit', this.increaseContextLimit, false);
      this.saveSetting('restoreLastActive', this.restoreLastActive, false);
      this.saveSetting('alwaysApproveReadRequests', this.alwaysApproveReadRequests, false);
      this.saveSetting('showChatHistory', this.showChatHistory, true);
      this.saveSetting('currentModel', this.currentModel, '');
      this.saveSetting('showModelThinking', this.showModelThinking, false);
    },

    // Load all local settings
    loadLocalSettings() {
      var prefix = 'settings.assistant';
      if (localStorage[prefix + '.increaseContextLimit']) this.increaseContextLimit = localStorage[prefix + '.increaseContextLimit'] == 'true';
      if (localStorage[prefix + '.restoreLastActive']) this.restoreLastActive = localStorage[prefix + '.restoreLastActive'] == 'true';
      if (localStorage[prefix + '.alwaysApproveReadRequests']) this.alwaysApproveReadRequests = localStorage[prefix + '.alwaysApproveReadRequests'] == 'true';
      if (localStorage[prefix + '.showChatHistory']) this.showChatHistory = localStorage[prefix + '.showChatHistory'] == 'true';
      if (localStorage[prefix + '.currentModel']) this.currentModel = localStorage[prefix + '.currentModel'];
      if (localStorage[prefix + '.perMessageStatsEnabled']) this.perMessageStatsEnabled = localStorage[prefix + '.perMessageStatsEnabled'] == 'true';
      if (localStorage[prefix + '.showModelThinking']) this.showModelThinking = localStorage[prefix + '.showModelThinking'] == 'true';

      if (localStorage['settings.case.mruCases']) this.mruCases = JSON.parse(localStorage['settings.case.mruCases']);
    },

    // Check if a tool should be auto-approved based on localStorage settings
    shouldAutoApproveTool(toolName) {
      return (
        this.alwaysApproveReadRequests &&
        (
          [
            'query_events',
            'get_playbooks',
            'query_cases',
            'query_detections',
          ].includes(toolName) ||
          /^delegate_to_.+$/.test(toolName)
        )
      );
    },

    clearStreamingStates() {
      this.activeStreamingSessionId = null;
      this.isTyping = false;
      this.isStreaming = false;
      // Drop delegated sub-agent linkage so stale child sessions from a previous
      // conversation can't mis-nest output after switching/loading/deleting chats.
      this.delegationChildren.clear();
    },
    
    checkIfDeleted(session) {
      if (session?.deleteTime) {
        this.canChat = false;
        this.$root.showWarning(this.i18n.assistantChatNoResume);
      } else {
        this.canChat = true;
      }
    },

    // Label for the "Current Model" info block. In agentic mode the picker
    // value is an agent name, so append the model it runs on (e.g.
    // "Orchestrator - Claude Sonnet"); otherwise it's just the model name.
    currentModelLabel() {
      const entry = this.modelsMap.get(this.currentModel);
      if (!entry) return '';
      if (this.agentic && entry.mappedModelName) {
        return `${entry.displayName} - ${entry.mappedModelName}`;
      }
      return entry.displayName;
    },

    // Whether the current selection ultimately runs on a credit-based cloud
    // model (protocol 'securityonion_ai_cloud'), which gates the credits pill.
    // In agentic mode the selector is an agent whose synthetic 'Agents' adapter
    // isn't a real backend adapter, so resolve through the mapped model's adapter.
    isCreditBasedModel() {
      const entry = this.modelsMap.get(this.currentModel);
      if (!entry) return false;
      const adapterName = this.agentic ? entry.mappedAdapter : entry.adapter;
      return this.adaptersMap.get(adapterName)?.protocol === 'securityonion_ai_cloud';
    },

    canSwitchModel() {
      return !this.$root.loading && !this.checkForActivity();
    },

    selectModel(key) {
      if (!key || key === this.currentModel) return;
      // Don't switch mid-turn.
      if (this.checkForActivity()) return;
      this.currentModel = key;
      this.updateModelParams();
      this.reloadCredits();
    },

    updateModelParams() {
      if (!this.currentModel || this.modelsMap.size == 0) return;
      const m = this.modelsMap.get(this.currentModel);
      if (!m) return;
      // Agent entries carry no context fields (they resolve to a model
      // server-side), so fall back to 0 until editable agents land.
      this.contextLimitSmall = m.contextLimitSmall || 0;
      this.contextLimitLarge = m.contextLimitLarge || 0;
      this.charsPerTokenEstimate = m.charsPerTokenEstimate || 0;
      this.lowBalanceColorAlert = m.lowBalanceColorAlert || 0;
    },

    // Legacy id@adapter selector, used as the model key only when a model has
    // no displayName and to migrate selectors saved before displayName became
    // the canonical identifier.
    buildModelIdentifier(model) {
      if (!model) return '';
      return `${model?.id||''}@${model?.adapter||''}`;
    },

    buildGroupedModels() {
      const groupedByAdapter = {};
      for (const model of this.modelsMap.values()) {
        const adapter = model.adapter || this.i18n.statusUnknown;
        if (!groupedByAdapter[adapter]) {
          groupedByAdapter[adapter] = [];
        }
        groupedByAdapter[adapter].push(model);
      }
      const result = [];
      const sortedAdapters = Object.keys(groupedByAdapter).sort();
      for (const adapter of sortedAdapters) {
        result.push({
          header: adapter
        });
        result.push(...groupedByAdapter[adapter]);
      }
      return result;
    },
    nbspRegexOp(text) {
      return text.replace(/^(&nbsp;?[\n]*)/, '');
    },
    messageClassesFromTags(tags) {
      return tags.map(tag => 'msgTag-' + tag);
    },
    async toggleSharedSession(chatId) {
      const session = this.chatHistoryById[chatId];
      if (!session || session.userId !== this.$root.user.id) return;
      
      const hasTag = (session.tags || []).includes(SESTAG_SHARED);
      const action = hasTag ? 'remove' : 'add';
      
      await this.updateSessionTag(chatId, action, SESTAG_SHARED);

      await this.loadStoredChats(false);
    },
    async updateSessionTag(sessionId, action, tag) {
      try {
        const payload = {
          action: action,
          tag: tag
        };
        await this.$root.papi.put(`/assistant/sessions/${sessionId}`, payload);

      } catch (error) {
        let msg = error.response.data;
        if (msg.startsWith('ERROR_SESSION_ATTACHED_TO_CASES')) { 
          const count = (msg.replaceAll('ERROR_SESSION_ATTACHED_TO_CASES', '') + '').trim();
          msg = this.$root.replaceActionVar(this.i18n.ERROR_SESSION_ATTACHED_TO_CASES, 'count', count);
        }

        this.$root.showError({ message: msg });
      }
    },
    focusChatInput() {
      this.$nextTick(() => {
        const input = this.$refs.chatInputField;
        if (!input) return;
        const el = input.$el.querySelector('textarea');
        if (el) {
          el.focus();
        }
      });
    },
    async exportSession() {
      this.$root.export({
        type: 'assistant_session',
        id: this.currentChatId,
      });
    },
    escapeHtml(str) {
      return String(str).replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[char]));
    },
    applyChoiceButtons(text) {
      if (!text || typeof text !== 'string') return text;

      return text.replace(CHOICE_MARKER_REGEX, (_fullMatch, rawLabel) => {
        const label = this.stripNewlines(rawLabel).trim();
        if (!label) return '';

        const cleanLabel = this.stripHtml(this.renderInlineMarkdown(label));
        const safeChoiceAttr = this.escapeHtml(label);

        return `<button type="button" class="assistant-choice-btn" data-choice="${safeChoiceAttr}">${cleanLabel}</button>`;
      });
    },
    onChatClick(event) {
      const btn = event.target?.closest?.('button[data-choice]');
      if (!btn) return;

      event.preventDefault();

      if (!this.canChat || this.checkForActivity() || !this.creditsLoaded) return;

      const choice = btn.getAttribute('data-choice') || '';
      if (!choice.trim()) return;

      this.newMessage = choice;
      this.$nextTick(() => {
        this.focusChatInput();
        this.sendMessage();
      });
    },
    stripHtml(str) {
      return str.replace(/<[^>]*>/g, '');
    },
    stripNewlines(text) {
      if (typeof text !== 'string') return text;
      return text.replace(/^\s*\n+/, '').replace(/\n+\s*$/, '');
    },
    async attachToCase(sessionId, caseId) {
      this.caseMenuVisible = false;

      const session = this.chatHistoryById[sessionId];
      if (!session) {
        this.$root.showError(this.i18n.assistantAttachNoSession);
        return;
      }

      if (!(session.tags || []).includes(SESTAG_SHARED)) {
        await this.toggleSharedSession(sessionId)
      }

      let caseTip = this.i18n.assistantAttachToCaseTipExisting;
      if (caseId === null) {
        caseId = await this.createCase(session.title);
        caseTip = this.i18n.assistantAttachToCaseTipNew;
      }

      const payload = {
        caseId: caseId,
        groupType: 'attachments',
        artifactType: 'assistant_chat',
        value: sessionId,
        description: session.title,
      };

      try {
        this.$root.papi.post('/case/artifacts', payload);
        this.$root.showTip(caseTip);
      } catch (err) { 
        this.$root.showError(this.i18n.assistantAttachToCaseFail);
      }
    },
    async createCase(title) {
      const response = await this.$root.papi.post('case/', {
        title: title,
        description: this.i18n.caseEscalatedDescription,
      });
      if (response && response.data) {
        return response.data.id;
      }

      return null;
    },
    formatCaseSummary(socCase) {
      return socCase?.title;
    },
    getLastThoughtTitle(text) {
      const titleRegex = /\*\*([^*]+)\*\*(?![\s\S]*\*\*)/;
      const match = text.match(titleRegex);
      return match ? match[1] : this.i18n.thinking;
    }
  };
})();
