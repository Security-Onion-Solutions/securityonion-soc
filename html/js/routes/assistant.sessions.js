// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Assistant page methods: init/params/credits, session and chat management, and
// reconstruction of chats (including delegated sub-agent sessions) loaded from the
// backend.

// Shared with assistant.streaming.js and assistant.tools.js, so it lives on
// globalThis (this file loads first).
globalThis.MSGTAG_CONTEXTCOMPRESSION = "context_compression";

globalThis.AssistantSessions = (function() {
  return {
    async initAssistant(params) {
      this.assistantEnabled = params["enabled"] && this.$root.isLicensed('oai');
      this.investigationMsg = params["investigationPrompt"];
      this.compressContextMsg = params["compressContextPrompt"];
      this.thresholdColorRatioLow = params["thresholdColorRatioLow"];
      this.thresholdColorRatioMed = params["thresholdColorRatioMed"];
      this.thresholdColorRatioMax = params["thresholdColorRatioMax"];
      this.toolBusyMaxRetries = params["toolBusyMaxRetries"];
      this.toolBusyRetryDelayMs = params["toolBusyRetryDelayMs"];
      this.agentic = params["agentic"] || false;
      this.availableAdapters = params["availableAdapters"];
      if (this.agentic) {
        // in agentic mode, use agent names rather than model names
        this.availableAgents = params["availableAgents"] || [];
        this.agentMapping = params["agentMapping"] || {};
        const allModels = params["availableModels"] || [];
        // Mirrors the backend's resolveModel: an agent's mapped model selector
        // is id@adapter or a bare id; prefer an enabled model, else first match.
        const resolveMappedModel = (selector) => {
          if (!selector) return null;
          let fallback = null;
          for (const m of allModels) {
            if (this.buildModelIdentifier(m) !== selector && m.id !== selector) continue;
            if (m.enabled) return m;
            if (!fallback) fallback = m;
          }
          return fallback;
        };
        this.availableModels = this.availableAgents.map(a => {
          const mapped = resolveMappedModel(this.agentMapping[a.name]);
          return {
            ...a,
            key: a.name,
            displayName: a.name,
            adapter: 'Agents',
            mappedModelName: mapped ? (mapped.displayName || this.buildModelIdentifier(mapped)) : '',
            mappedAdapter: mapped?.adapter || '',
            contextLimitSmall: mapped?.contextLimitSmall || 0,
            contextLimitLarge: mapped?.contextLimitLarge || 0,
            charsPerTokenEstimate: mapped?.charsPerTokenEstimate || 0,
            lowBalanceColorAlert: mapped?.lowBalanceColorAlert || 0,
          };
        });
        this.modelsMap = new Map(this.availableModels.map(a => [a.key, a]));
        // When the stored selector isn't a known agent (or none was stored),
        // default to the orchestrator the user talks to first, not just the
        // first agent in the list.
        if (!this.currentModel || !this.modelsMap.has(this.currentModel)) {
          const orchestrator = this.availableModels.find(a => a.isOrchestrator);
          this.currentModel = (orchestrator || this.availableModels[0])?.key || '';
        }
        this.groupedModels = this.buildGroupedModels();
      } else {
        this.availableModels = params["availableModels"];
        if (this.availableModels && this.availableModels.length > 0) {
          this.availableModels.forEach(m => {
            m.key = this.buildModelIdentifier(m);
            // displayName is optional, cosmetic-only; fall back to the selector
            if (!m.displayName) m.displayName = m.key;
          });
          this.modelsMap = new Map(
            this.availableModels.filter(m => m.enabled).map(m => [m.key, m])
          );
          for (let val of this.modelsMap.values()) {
            if (val.contextLimitLarge < val.contextLimitSmall) val.contextLimitLarge = val.contextLimitSmall;
          }
          if (!this.currentModel || !this.modelsMap.has(this.currentModel)) this.currentModel = this.availableModels[0].key;
          this.groupedModels = this.buildGroupedModels();
        }
      }
      if (this.availableAdapters && this.availableAdapters.length > 0) {
        this.adaptersMap = new Map(this.availableAdapters.map(a => [a.name, a]));
      }
      this.updateModelParams();

      this.$root.showDisclaimer(this.i18n.assistantDisclaimerMessage, this.i18n.assistantDisclaimerTitle, this.i18n.getStarted, 'settings.disclaimer.acknowledged.onionai');

      this.paramsLoaded = true;

      if (this.assistantEnabled) {
        if (!this.$root.disclaimer) {
          await this.loadStoredChats();
          await this.handleRouteSessionId();
          await this.loadCredits();
          this.focusChatInput();
        }
      } else {
        this.$root.disclaimer = false;
      }
    },
    
    // Ignore input tokens when on a context compression message.
    calculateContextFromUsage(usage, ignoreInputTokens) {
      if (!usage) return 0;
      const inputTokens = usage.input_tokens || 0;
      const outputTokens = usage.output_tokens || 0;
      
      return ignoreInputTokens ? outputTokens : inputTokens + outputTokens;
    },
    
    updateContextLength(usage, ignoreInputTokens = false) {
      if (usage) {
        const messageContext = this.calculateContextFromUsage(usage, ignoreInputTokens);
        this.contextLength = messageContext;
      }
    },

    // agentName is the producing agent: msg.model on reload, or the live selection /
    // delegate name while streaming (they match, since we send model: currentModel).
    accrueCredits(usage, agentName) {
      const credits = (usage && usage.credits) || 0;
      if (!credits) return;
      this.creditsUsed += credits;
      const key = agentName || this.i18n.assistantDelegateAgent;
      this.creditsByAgent[key] = (this.creditsByAgent[key] || 0) + credits;
    },

    // Rebuild credit totals from stored history (msg.model per turn) so attribution
    // can't drift with the model picker. `data` is the /assistant/sessions/{id} payload.
    recomputeCreditsFromHistory(data) {
      this.creditsUsed = 0;
      this.creditsByAgent = {};
      const addHistory = (history, fallbackAgent) => {
        for (const sm of (history || [])) {
          const usage = sm && sm.message && sm.message.usage;
          if (!usage || !usage.credits) continue;
          this.accrueCredits(usage, sm.model || fallbackAgent);
        }
      };
      // Fallbacks cover legacy messages saved before per-message model existed.
      addHistory(data && data.history, (data && data.session && data.session.model) || '');
      for (const sub of ((data && data.subSessions) || [])) {
        const subAgent = (sub && sub.session && (sub.session.delegateAgent || sub.session.model)) || '';
        addHistory(sub && sub.history, subAgent);
      }
    },

    checkContextLimitReached() {
      const maxContextLength = this.increaseContextLimit ? this.contextLimitLarge : this.contextLimitSmall;
      if (this.contextLength >= maxContextLength) {
        const formattedLimit = this.formatCount(maxContextLength);
        this.$root.showError(this.i18n.assistantContextLimitPt1 + ` (${formattedLimit}+ tokens). ` + this.i18n.assistantContextLimitPt2);
        return true;
      }
      return false;
    },

    async loadNewChatScreen() {
      try {
        this.messages = [
          {
            role: 'assistant',
            content: this.i18n.assistantWelcomeMessage,
            timestamp: new Date().toISOString()
          }
        ];
        this.contextLength = 0;
        this.creditsUsed = 0;
        this.creditsByAgent = {};
      } catch (error) {
        this.$root.showError(error);
      }
    },
    async loadStoredChats(showLoading = true) {
      if (showLoading) this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('/assistant/sessions');
        if (response.data && Array.isArray(response.data)) {
          this.chatHistoryById = {};
          this.chatHistory = response.data.map(session => {
            let s = {
              sessionId: session.sessionId,
              title: this.generateTitleFromMessage(session),
              messages: [], // Will be loaded when session is opened
              timestamp: session.createTime || new Date().toISOString(),
              lastUpdated: session.createTime || new Date().toISOString(),
              tags: session.tags || [],
              userId: session.userId,
            };
            this.chatHistoryById[session.sessionId] = s;

            return s;
          });
        } else {
          this.chatHistory = [];
        }
      } catch (error) {
        this.$root.showError(this.i18n.assistantUnableToLoadHistory + ': ' + error.message);

        this.chatHistory = [];
      } finally {
        if (showLoading) this.$root.stopLoading();
      }
    },
    saveCurrentChatId() {
      if (this.currentChatId) {
        localStorage.setItem('settings.assistant.currentChatId', this.currentChatId);
      } else {
        localStorage.removeItem('settings.assistant.currentChatId');
      }
    },
    loadCurrentChatId() {
      return localStorage.getItem('settings.assistant.currentChatId');
    },
    async handleRouteSessionId() {
      const urlSessionId = this.$route.params.sessionId;
      
      if (this.currentChatId !== urlSessionId) {
        this.clearStreamingStates();
      }

      if (!this.assistantEnabled) {
        return;
      }
      
      if (urlSessionId) {
        this.$root.startLoading();
        try {
          await this.loadChatFromBackend(urlSessionId);
        } catch (error) {
          const isInvestigation = this.$route.query.investigation === 'true';

          if (isInvestigation) {
            // Investigation sessions are allowed to create new sessions with the URL session ID
            this.currentChatId = urlSessionId;
            this.saveCurrentChatId();
            try {
              const investigationPrompt = this.generateInvestigationPrompt(this.$route.query);
              this.$nextTick(() => {
                this.startInvestigationSession(investigationPrompt);
              });
            } catch (error) {
              this.$root.showError(this.i18n.assistantUnableToParseInvestigation + ': ' + error.message);
            }
          } else if (urlSessionId !== this.currentChatId) {
            // Session ID doesn't exist, not an investigation, and not our own navigation — redirect to base assistant page
            await this.$router.replace({ name: 'assistant' });
            return;
          }
        } finally {
          this.$root.stopLoading();
        }
      } else {
        await this.restoreLastActiveChat();
      }
      await this.$nextTick();
      this.focusChatInput();
    },
    async restoreLastActiveChat() {
      if (!this.restoreLastActive) {
        this.startNewChat();
        return;
      }
      const lastChatId = this.loadCurrentChatId();
      if (lastChatId && this.chatHistory.some(c => c.sessionId === lastChatId)) {
        this.$root.startLoading();
        try {
          await this.updateUrlWithSessionId(lastChatId);
          return;
        } catch (error) {
          this.$root.showError(this.i18n.assistantUnableToRestoreLastActive + ': ' + error.message);
        } finally {
          this.$root.stopLoading();
        }
      }
      // If no valid last chat found, keep the default welcome message
    },
    reloadCredits() {
      this.creditsLoaded = false;
      this.loadCredits();
    },
    async loadCredits() {
      try {
        const response = await this.$root.papi.get('/assistant/balance/' + encodeURIComponent(this.currentModel));
        if (response.data) {
          if (response.data.health_status === 'healthy') {
            this.creditsRemaining = response.data.credit_balance || 0;
            this.creditsLoaded = true;
          } else {
            throw new Error(this.i18n.assistantBalanceCheckUnhealthy);
          }
        }
      } catch (error) {
        this.$root.showError(error);
        this.creditsLoaded = false;
      }
    },
    async saveCurrentChat() {
      if (this.messages.length <= 1) return; // Don't save if only welcome message
      
      // Backend auto-saves chats through the API calls; just track the current chat ID.
      if (!this.currentChatId) {
        this.currentChatId = this.generateChatId();
      }
      this.saveCurrentChatId();
      
      await this.loadStoredChats();
    },
    generateChatId() {
      return crypto.randomUUID();
    },
    async loadChat(chat) {
      await this.saveCurrentChat();
      this.clearStreamingStates();

      this.$root.startLoading();
      try {
        if (this.currentChatId === chat.sessionId) {
          await this.loadChatFromBackend(chat.sessionId);
        }
        await this.updateUrlWithSessionId(chat.sessionId);

      } catch (error) {
        this.$root.showError(this.i18n.assistantUnableToLoadChat + ': ' + error.message);
      } finally {
        this.$root.stopLoading();
      }
    },

    async deleteChat(chatId) {
      try {
        await this.$root.papi.delete(`/assistant/sessions/${chatId}`);
        
        this.chatHistory = this.chatHistory.filter(chat => chat.sessionId !== chatId);
        
        if (this.currentChatId === chatId) {
          this.currentChatId = null;
          this.saveCurrentChatId();
          this.loadNewChatScreen();
          this.$router.push({ name: 'assistant' });
        }
        
      } catch (error) {
        this.$root.showError(this.i18n.assistantUnableToDeleteChat + ': ' + (error.response?.data?.error || error.message));
      }
    },
    async startNewChat() {
      await this.saveCurrentChat();
      
      this.clearStreamingStates();
      
      this.currentChatId = null;
      this.saveCurrentChatId();
      this.loadNewChatScreen(); // also resets context length
      this.focusChatInput();
      this.canChat = true;
      this.$router.push({ name: 'assistant' });
    },
    async updateUrlWithSessionId(sessionId) {
      if (this.$route.params.sessionId !== sessionId) {
        await this.$router.replace({ name: 'assistant', params: { sessionId: sessionId } });
      }
    },
    async startInvestigationSession(investigationPrompt) {
      if (!this.creditsLoaded) {
        await this.loadCredits();
      }
      if (!this.creditsLoaded) {
        this.currentChatId = null;
        this.saveCurrentChatId();
        if (this.$route.params.sessionId) {
          await this.$router.replace({ name: 'assistant' });
        }
        return;
      }

      // Clear the welcome message for investigations.
      this.messages = [];

      // Set directly; no decoding needed.
      this.newMessage = investigationPrompt;

      await this.$nextTick();

      // Send the message after a delay to ensure everything is ready
      setTimeout(async () => {
        if (this.newMessage && this.newMessage.trim()) {
          try {
            await this.sendMessage();
          } catch (error) {
            this.$root.showError(this.i18n.assistantUnableToInvestigate + ': ' + error.message);
          }
        }
      }, 2000);
    },
    generateTitleFromMessage(session) {
      if (session && session.title) {
        let content = session.title;
        if (content) {
          let title = content.substring(0, 50);
          if (content.length > 50) {
            title += '...';
          }
          return title;
        }
      }
      return 'New Chat - ' + new Date().toLocaleDateString();
    },

    async loadChatFromBackend(sessionId) {
      try {
        const response = await this.$root.papi.get(`/assistant/sessions/${sessionId}`);
        if (response.data && Array.isArray(response.data.history) && response.data.history.length > 0) {
          this.currentChatId = sessionId;
          // Index delegated sub-sessions so delegate tool blocks can rebuild their
          // nested childSession from stored history (see reconstructChildSession).
          this._loadSubSessions = this.indexSubSessions(response.data.subSessions);
          try {
            this.messages = this.convertBackendMessagesToFrontend(response.data.history);
          } finally {
            this._loadSubSessions = null;
          }
          // Derive credits from stored history, independent of the render tree.
          this.recomputeCreditsFromHistory(response.data);
          this.saveCurrentChatId();

          await this.scrollToBottomSettled({ maxWait: 6000, settleDelay: 200 });

          // Blocks user from sending messages in deleted chats
          this.checkIfDeleted(response.data.session);

          this.chatHistoryById[sessionId] = response.data.session;
        } else {
          throw new Error(this.i18n.assistantNoHistoryFound + ' ' + sessionId);
        }
      } catch (error) {
        if (error.response && error.response.status === 404) {
          this.loadNewChatScreen();
          this.currentChatId = sessionId;
          this.saveCurrentChatId();

          await this.scrollToBottomSettled();
        } else {
          throw error;
        }
      }
    },
    
    // New-format (tagged) tool result messages.
    processToolResultMessage(msg, processedMessages) {
      let rawResult = null;
      let toolUseId = null;
      let toolError = null;
      let rejected = false;

      if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
        // proper tool use approach
        const toolResultBlock = msg.message.contentBlocks.find(block => block.toolResult);
        if (toolResultBlock && toolResultBlock.toolResult.content?.length) {
          const cb = toolResultBlock.toolResult.content[0];
          rejected = toolResultBlock.toolResult.status === 'rejected';
          if (toolResultBlock.toolResult.isError || toolResultBlock.toolResult.status === 'error' || rejected) {
            toolError = cb.text || this.i18n.assistantToolUnknownError;
            rawResult = '<nil>';
          } else {
            rawResult = cb?.json;
            toolError = '<nil>';
          }
          toolUseId = toolResultBlock.toolResult.toolUseId;
        } else {
          // legacy "ToolResult in Text Response" approach
          const textBlock = msg.message.contentBlocks.find(block => block.type === 'text');
          if (textBlock && textBlock.text) {
            // Parse the tool result format: "ToolUseId: tooluse_QdvZoVlXQNm0PBuqFuqRmA, Result: [actual_result_data]"
            const toolResultText = textBlock.text;
            const toolUseIdMatch = toolResultText.match(/ToolUseId:\s*([^,]+)/);
            const resultMatch = toolResultText.match(/Result:\s*(.+)$/s);
            const errorMatch = toolResultText.match(/Error:\s*([^,]+)/);
            
            if (toolUseIdMatch && resultMatch && errorMatch) {
              toolUseId = toolUseIdMatch[1].trim();
              rawResult = resultMatch[1].trim();
              toolError = errorMatch[1].trim();
            }
          }
        }
      }
      
      if (toolUseId && rawResult && toolError) {
        for (let j = processedMessages.length - 1; j >= 0; j--) {
          const processedMsg = processedMessages[j];
          if (processedMsg.role === 'assistant' && processedMsg.toolUses) {
            const toolUses = processedMsg.toolUses;
            const matchingToolUse = toolUses.find(tool => tool.id === toolUseId);
            if (matchingToolUse) {
              matchingToolUse.rawResult = rawResult;
              matchingToolUse.completedAt = msg.createTime;
              if (toolError != "<nil>") {
                matchingToolUse.error = toolError;
                matchingToolUse.status = rejected ? "rejected" : "error";
              }
              break;
            }
          }
        }
      }
    },
    
    processOldFormatToolResult(msg, processedMessages) {
      const prevMessage = processedMessages[processedMessages.length - 1];
      if (prevMessage && prevMessage.role === 'assistant' && prevMessage.toolUses) {
        const toolUses = prevMessage.toolUses;
        if (toolUses.length > 0) {
          const lastToolUse = toolUses[toolUses.length - 1];
          lastToolUse.rawResult = msg.message.contentStr;
        }
      }
    },
    
    extractMessageContent(msg, frontendMsg) {
      if (msg.message.contentStr) {
        frontendMsg.content = msg.message.contentStr;
      } else if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
        const textBlocks = msg.message.contentBlocks.filter(block => block.type === 'text');
        if (textBlocks.length > 0) {
          frontendMsg.content = textBlocks.map(block => this.nbspRegexOp(block.text)).join('\n');
        } else {
          frontendMsg.content = '';
        }
      } else {
        frontendMsg.content = 'Empty message';
      }
    },
    
    processToolUseBlocks(msg, frontendMsg, backendMessages, i) {
      const toolBlocks = msg.message.contentBlocks.filter(block => block.type === 'tool_use');
      if (toolBlocks.length === 0) return;

      // Status is decided per tool: one turn can request parallel tools saved as separate
      // tool_results, so it may mix resolved/pending/skipped (a declined tool is a rejected result).
      const resolvedIds = this.collectResolvedToolUseIds(backendMessages);

      // An unresolved tool awaits approval only while this turn is the active tail (only
      // tool_results follow it); once another message follows, it was abandoned (skipped).
      const active = this.isActiveToolTurn(backendMessages, i);

      frontendMsg.toolUses = toolBlocks.map(block => {
        const base = {
          id: block.id || 'unknown',
          name: block.name || 'unknown',
          input: block.input || {},
          result: null,
          error: null,
          rawResult: null, // Populated by the matching tool_result message, if any
          timestamp: msg.createTime || new Date().toISOString(),
        };

        // Resolved: a tool_result exists. Status/result are refined by processToolResultMessage.
        if (resolvedIds.has(base.id)) {
          return { ...base, status: 'completed', approved: true };
        }
        // Unresolved but still at the active tail: awaiting approval. A delegate that
        // already spawned a sub-session is running, not pending -- re-prompting would
        // spawn a duplicate sub-session.
        if (active) {
          const inFlightDelegation = !!(this._loadSubSessions && this._loadSubSessions.byParentToolUseId.has(base.id));
          const toolUse = {
            ...base,
            status: inFlightDelegation ? 'executing' : 'pending_approval',
            approved: inFlightDelegation ? true : null,
            sessionId: this.currentChatId,
          };
          this.getSessionToolMap(this.currentChatId).set(toolUse.id, toolUse);
          if (!inFlightDelegation && !this.sessionTools(this.currentChatId).floatingTool) {
            this.sessionTools(this.currentChatId).floatingTool = toolUse;
          }
          return toolUse;
        }
        // Unanswered and the conversation moved on without it.
        return { ...base, status: 'skipped', approved: false };
      });

      // Rebuild nested sub-agent activity for any delegate tool blocks.
      if (frontendMsg.toolUses) {
        this.reconstructDelegateChildSessions(frontendMsg.toolUses);
      }
    },

    // Collect every tool_use id that has a persisted tool_result, so a reloaded turn can
    // tell which of its (possibly parallel) tools are resolved vs still pending.
    collectResolvedToolUseIds(backendMessages) {
      const ids = new Set();
      for (const m of backendMessages) {
        if (!m || !m.tags || !m.tags.includes('tool_result')) continue;
        const blocks = m.message && m.message.contentBlocks;
        if (!Array.isArray(blocks)) continue;
        for (const b of blocks) {
          if (b.toolResult && b.toolResult.toolUseId) {
            ids.add(b.toolResult.toolUseId);
          } else if (b.type === 'text' && b.text) {
            // Legacy "ToolUseId: <id>, Result: ..." text-encoded tool_result.
            const match = b.text.match(/ToolUseId:\s*([^,]+)/);
            if (match) ids.add(match[1].trim());
          }
        }
      }
      return ids;
    },

    // True while every message after turn i is a tool_result answering it; once another
    // message follows, any unanswered tool from the turn was abandoned, not pending.
    isActiveToolTurn(backendMessages, i) {
      for (let j = i + 1; j < backendMessages.length; j++) {
        const m = backendMessages[j];
        if (!m || !m.tags || !m.tags.includes('tool_result')) return false;
      }
      return true;
    },

    // Build a lookup of delegated sub-sessions returned with a loaded conversation,
    // keyed by the parent tool_use id that spawned each (and by sessionId for recursion).
    indexSubSessions(subSessions) {
      const index = { byParentToolUseId: new Map(), bySessionId: new Map() };
      if (Array.isArray(subSessions)) {
        for (const sub of subSessions) {
          if (!sub || !sub.session) continue;
          index.bySessionId.set(sub.session.sessionId, sub);
          if (sub.session.parentToolUseId) {
            index.byParentToolUseId.set(sub.session.parentToolUseId, sub);
          }
        }
      }
      return index;
    },

    // For each delegate tool block, rebuild its nested childSession from the loaded
    // sub-session histories so reopening a conversation matches the live view.
    reconstructDelegateChildSessions(toolUses) {
      const index = this._loadSubSessions;
      if (!index || !Array.isArray(toolUses)) return;
      for (const toolUse of toolUses) {
        if (!toolUse.name || !toolUse.name.startsWith('delegate_to_')) continue;
        const sub = index.byParentToolUseId.get(toolUse.id);
        if (sub) this.reconstructChildSession(toolUse, sub, index, this.currentChatId);
      }
    },

    // Populate a delegate tool's childSession from a stored sub-session's history:
    // the sub-agent's prose becomes a collapsed thought, its tool calls become nested
    // tool cards (with raw results), recursing into deeper delegations.
    reconstructChildSession(delegateToolUse, sub, index, ownerSessionId) {
      const agentName = (sub.session && sub.session.delegateAgent) || '';
      const childSessionId = sub.session && sub.session.sessionId;
      const cs = this.ensureChildSession(delegateToolUse, agentName);

      // The backend marks which tool_use in this sub-session awaits approval.
      const pendingToolUseId = sub.pendingApproval && sub.pendingApproval.toolUseId;

      const history = Array.isArray(sub.history) ? sub.history : [];
      const toolUseById = new Map();
      const delegateChildTools = []; // grandchild delegations, recursed after statuses are set
      const childMessages = [];

      for (const sm of history) {
        const m = sm && sm.message;
        if (!m) continue;

        // tool_result message: attach the raw result to its matching child tool card
        if (sm.tags && sm.tags.includes('tool_result')) {
          const block = (m.contentBlocks || []).find(b => b.toolResult);
          if (block && block.toolResult) {
            const t = toolUseById.get(block.toolResult.toolUseId);
            if (t) {
              const cb = block.toolResult.content && block.toolResult.content[0];
              if (block.toolResult.status === 'rejected') {
                t.error = (cb && cb.text) || this.i18n.assistantToolUseReject;
                t.status = 'rejected';
              } else if (block.toolResult.isError || block.toolResult.status === 'error') {
                t.error = (cb && cb.text) || this.i18n.assistantToolUnknownError;
                t.status = 'error';
              } else {
                t.rawResult = cb && cb.json;
                t.status = 'completed';
              }
              t.completedAt = sm.createTime;
            }
          }
          continue;
        }

        // Only the sub-agent's assistant turns render nested; skip the objective/user msgs.
        if (m.role !== 'assistant') continue;

        const childMsg = { role: 'assistant', thoughts: '', content: '', toolUses: [], timestamp: sm.createTime };

        // Split the turn like the live stream: prose -> content, reasoning -> thoughts.
        // Folding prose into thoughts would hide the sub-agent's answer after reload
        // (thoughts only show when "show thinking" is on).
        let contentText = '';
        const thoughtText = m.thoughts || '';
        for (const b of (m.contentBlocks || [])) {
          if (b.type === 'text' && b.text) {
            contentText += b.text;
          } else if (b.type === 'tool_use') {
            const childTool = {
              id: b.id || 'unknown',
              name: b.name || 'unknown',
              input: b.input || {},
              // Default 'skipped' for a tool_use with no result; finalized below to
              // completed/error/executing/pending_approval. Must NOT default to
              // 'completed' -- that would show a false checkmark for a tool that never ran.
              status: 'skipped',
              result: null,
              error: null,
              rawResult: null,
              timestamp: sm.createTime || new Date().toISOString(),
              approved: true,
              sessionId: childSessionId,
            };
            childMsg.toolUses.push(childTool);
            toolUseById.set(childTool.id, childTool);

            // Defer grandchild recursion until this tool's status is finalized below.
            if (childTool.name.startsWith('delegate_to_')) {
              const gchild = index.byParentToolUseId.get(childTool.id);
              if (gchild) delegateChildTools.push({ childTool, gchild });
            }
          }
        }
        childMsg.thoughts = thoughtText;
        childMsg.content = contentText;
        // Usage drives the delegate card's per-invocation credit chip.
        if (m.usage) childMsg.usage = m.usage;
        childMessages.push(childMsg);
      }

      // The backend flags one pending tool_use, but its turn may hold parallel siblings
      // equally awaiting approval. Treat the whole flagged turn as active; unresolved
      // tools in earlier turns were genuinely abandoned.
      let activeTurnToolIds = null;
      if (pendingToolUseId) {
        const activeMsg = childMessages.find(m => m.toolUses.some(t => t.id === pendingToolUseId));
        if (activeMsg) activeTurnToolIds = new Set(activeMsg.toolUses.map(t => t.id));
      }

      // Finalize tools with no tool_result: a delegate that spawned a sub-session is
      // running; tools in the active (flagged) turn await approval; anything else stays.
      for (const t of toolUseById.values()) {
        if (t.rawResult != null || t.status === 'error') continue; // resolved
        if (index.byParentToolUseId.has(t.id)) {
          t.status = 'executing';
          t.approved = true;
        } else if (activeTurnToolIds && activeTurnToolIds.has(t.id)) {
          t.status = 'pending_approval';
          t.approved = null;
          // Register so the queue runner can resolve and fire it, like the live path.
          this.getSessionToolMap(childSessionId).set(t.id, t);
        }
      }

      cs.messages = childMessages;

      // While the delegation is running, re-register it as a live delegation child so
      // the approval's response streams nested and resolves back into its parent.
      if (delegateToolUse.status === 'executing' && childSessionId) {
        this.delegationChildren.set(childSessionId, {
          parentToolUse: delegateToolUse,
          parentSessionId: ownerSessionId || this.currentChatId,
          parentToolUseId: delegateToolUse.id,
          agentName,
        });
      }

      // Recurse into grandchild delegations now that statuses are finalized.
      for (const { childTool, gchild } of delegateChildTools) {
        this.reconstructChildSession(childTool, gchild, index, childSessionId);
      }
    },

    // Post-pass after the whole conversation is rebuilt: reconstructChildSession runs
    // before a delegate's own tool_result, so it can't know the outcome. Here a settled
    // delegation's leftover executing/pending sub-agent tools are marked skipped and
    // unregistered so they're not actionable. Settlement propagates to all descendants.
    finalizeResolvedDelegations(messages) {
      const visit = (toolUses, ancestorSettled) => {
        if (!Array.isArray(toolUses)) return;
        for (const t of toolUses) {
          const cs = t.childSession;
          if (!cs || !Array.isArray(cs.messages)) continue;

          const childTools = cs.messages.flatMap(m => (Array.isArray(m.toolUses) ? m.toolUses : []));
          // Terminal delegate states (no longer running): a result folded in, or an
          // error/rejected/skipped outcome. A live-rejected delegate carries no
          // rawResult, so its status must be checked explicitly.
          const settled = ancestorSettled || t.rawResult != null
            || t.status === 'error' || t.status === 'rejected' || t.status === 'skipped';

          if (settled) {
            for (const ct of childTools) {
              if (ct.status === 'pending_approval' || ct.status === 'executing') {
                ct.status = 'skipped';
                ct.approved = false;
                if (ct.sessionId) this.getSessionToolMap(ct.sessionId).delete(ct.id);
              }
              // Drop the live-delegation linkage so nothing tries to resume this child session.
              if (ct.sessionId) this.delegationChildren.delete(ct.sessionId);
            }
          }

          visit(childTools, settled);
        }
      };
      visit(messages.flatMap(m => (Array.isArray(m.toolUses) ? m.toolUses : [])), false);
    },

    convertBackendMessagesToFrontend(backendMessages) {
      const processedMessages = [];
      // Reset context length when loading from backend (credits handled separately).
      this.contextLength = 0;
      this.contextStartMessageIndex = -1;
      let justResetContext = false;

      for (let i = 0; i < backendMessages.length; i++) {
        const msg = backendMessages[i];
        
        if (msg.tags && msg.tags.includes('tool_result')) {
          this.processToolResultMessage(msg, processedMessages);
          continue;
        }
        
        // old-format tool result (user role with contentStr, no blocks)
        if (msg.message.role === 'user' && msg.message.contentStr && !msg.message.contentBlocks) {
          this.processOldFormatToolResult(msg, processedMessages);
          continue;
        }
        
        const frontendMsg = {
          role: msg.message.role,
          timestamp: msg.createTime || new Date().toISOString(),
          tags: msg.tags || [],
        };

        if (msg.message.thoughts) {
          frontendMsg.thoughts = msg.message.thoughts;
        }

        this.extractMessageContent(msg, frontendMsg);
        
        if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
          this.processToolUseBlocks(msg, frontendMsg, backendMessages, i);
        }

        if (msg.message.usage) {
          frontendMsg.usage = msg.message.usage;
          this.updateContextLength(msg.message.usage, justResetContext);
        }

        processedMessages.push(frontendMsg);

        if (msg.tags && msg.tags.includes(MSGTAG_CONTEXTCOMPRESSION)) {
          // reset context; messages before this are no longer sent to the AI
          if (i >= 0 && i < backendMessages.length - 1) {
            this.contextLength = this.calculateContextOfMessage(backendMessages.map(m => m.message), i);
          } else {
            // this context compression is the latest message, can't determine
            // context size until assistant responds
            this.contextLength = 0;
          }
          this.contextStartMessageIndex = processedMessages.length - 1;
          justResetContext = true;
        } else {
          justResetContext = false;
        }
      }

      // Now that every delegate tool's resolution is known, settle finished
      // delegations so their sub-agent tools aren't left executing/actionable.
      this.finalizeResolvedDelegations(processedMessages);

      return processedMessages;
    },
  };
})();
