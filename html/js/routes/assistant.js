// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-assistant', 'pages/assistant.html');

const MSGTAG_CONTEXTCOMPRESSION = "context_compression";

const SESTAG_SHARED = 'shared';

const CHOICE_MARKER_REGEX = /\[\[CHOICE\]\]([\s\S]*?)\[\[\/CHOICE\]\]/g;

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
  methods: {

    async initAssistant(params) {
      this.assistantEnabled = params["enabled"] && this.$root.isLicensed('oai');
      this.investigationMsg = params["investigationPrompt"];
      this.compressContextMsg = params["compressContextPrompt"];
      this.thresholdColorRatioLow = params["thresholdColorRatioLow"];
      this.thresholdColorRatioMed = params["thresholdColorRatioMed"];
      this.thresholdColorRatioMax = params["thresholdColorRatioMax"];
      this.agentic = params["agentic"] || false;
      this.availableAdapters = params["availableAdapters"];
      if (this.agentic) {
        // in agentic mode, use agent names rather than model names
        this.availableAgents = params["availableAgents"] || [];
        this.agentMapping = params["agentMapping"] || {};
        const modelsByName = new Map((params["availableModels"] || []).map(m => [m.displayName, m]));
        this.availableModels = this.availableAgents.map(a => {
          const mapped = modelsByName.get(this.agentMapping[a.name]);
          return {
            ...a,
            key: a.name,
            displayName: a.name,
            adapter: 'Agents',
            mappedModelName: mapped?.displayName || '',
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
          this.availableModels.forEach(m => m.key = m.displayName || this.buildModelIdentifier(m));
          this.modelsMap = new Map(
            this.availableModels.filter(m => m.enabled).map(m => [m.key, m])
          );
          for (let val of this.modelsMap.values()) {
            if (val.contextLimitLarge < val.contextLimitSmall) val.contextLimitLarge = val.contextLimitSmall;
          }
          // Selectors restored from localStorage may still be in the legacy
          // id@adapter form; silently migrate them to the model's current key.
          let legacyModelKeys = new Map(
            this.availableModels.filter(m => m.enabled).map(m => [this.buildModelIdentifier(m), m.key])
          );
          if (this.currentModel && !this.modelsMap.has(this.currentModel) && legacyModelKeys.has(this.currentModel)) {
            this.currentModel = legacyModelKeys.get(this.currentModel);
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
    
    // Calculate context length from usage data (input_tokens + output_tokens),
    // ignore input tokens if on a context compression message
    calculateContextFromUsage(usage, ignoreInputTokens) {
      if (!usage) return 0;
      const inputTokens = usage.input_tokens || 0;
      const outputTokens = usage.output_tokens || 0;
      
      return ignoreInputTokens ? outputTokens : inputTokens + outputTokens;
    },
    
    // Update the total context length
    updateContextLength(usage, ignoreInputTokens = false) {
      if (usage) {
        const messageContext = this.calculateContextFromUsage(usage, ignoreInputTokens);
        this.contextLength = messageContext;
      }
    },

    updateCreditsUsed(usage) {
      if (usage) {
        const messageCredits = usage.credits || 0;
        this.creditsUsed += messageCredits;
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
        // Initialize with a welcome message from the AI Assistant
        this.messages = [
          {
            role: 'assistant',
            content: this.i18n.assistantWelcomeMessage,
            timestamp: new Date().toISOString()
          }
        ];
        // Reset context length for new chat
        this.contextLength = 0;
        this.creditsUsed = 0;
      } catch (error) {
        this.$root.showError(error);
      }
    },
    async loadStoredChats(showLoading = true) {
      if (showLoading) this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('/assistant/sessions');
        if (response.data && Array.isArray(response.data)) {
          // Convert backend format to frontend format
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

        // Fallback to empty array if backend is unavailable
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
      
      // Clear active streaming session and UI state when route changes to different session
      if (this.currentChatId !== urlSessionId) {
        this.clearStreamingStates();
      }

      if (!this.assistantEnabled) {
        return;
      }
      
      if (urlSessionId) {
        // Try to load chat from backend first
        this.$root.startLoading();
        try {
          await this.loadChatFromBackend(urlSessionId);
        } catch (error) {
          // Check if this is an investigation session
          const isInvestigation = this.$route.query.investigation === 'true';

          if (isInvestigation) {
            // Investigation sessions are allowed to create new sessions with the URL session ID
            this.currentChatId = urlSessionId;
            this.saveCurrentChatId();
            try {
              const investigationPrompt = this.generateInvestigationPrompt(this.$route.query);
              // This is a new investigation session, start with investigation prompt
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
        // No session ID in URL, restore last active chat
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
          // Update URL to reflect the current session
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
      
      // Backend automatically saves chats through the API calls
      // Just update the current chat ID
      if (!this.currentChatId) {
        this.currentChatId = this.generateChatId();
      }
      this.saveCurrentChatId();
      
      // Refresh the chat history to reflect any changes
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
        // Call the backend DELETE endpoint to remove the session
        await this.$root.papi.delete(`/assistant/sessions/${chatId}`);
        
        // Remove from local history after successful backend deletion
        this.chatHistory = this.chatHistory.filter(chat => chat.sessionId !== chatId);
        
        // If we deleted the current chat, start a new one
        if (this.currentChatId === chatId) {
          this.currentChatId = null;
          this.saveCurrentChatId(); // Clear the saved current chat ID
          this.loadNewChatScreen(); // Reset to welcome message
          // Navigate to chat without session ID
          this.$router.push({ name: 'assistant' });
        }
        
      } catch (error) {
        this.$root.showError(this.i18n.assistantUnableToDeleteChat + ': ' + (error.response?.data?.error || error.message));
      }
    },
    async startNewChat() {
      await this.saveCurrentChat(); // Save current chat before starting new one
      
      // Clear active streaming session and UI state when starting new chat
      this.clearStreamingStates();
      
      this.currentChatId = null;
      this.saveCurrentChatId(); // Clear the saved current chat ID
      this.loadNewChatScreen(); // Reset to welcome message (also resets context length)
      this.focusChatInput();
      this.canChat = true;
      // Navigate to chat without session ID
      this.$router.push({ name: 'assistant' });
    },
    async updateUrlWithSessionId(sessionId) {
      // Only update URL if it's different from current
      if (this.$route.params.sessionId !== sessionId) {
        await this.$router.replace({ name: 'assistant', params: { sessionId: sessionId } });
      }
    },
    async sendMessage(tags) {
      if (!this.newMessage.trim()) return;

      if (!this.canChat) return;
      
      if (!this.assistantEnabled) {
        this.$root.showError(this.i18n.assistantNotAvailable);
        return;
      }

      const isCompressing = tags && tags.includes(MSGTAG_CONTEXTCOMPRESSION);
      // Check if message + context exceeds estimated token limit
      if (!isCompressing && this.isMessageTooLong) return;
      // Check if context length has reached the limit
      if (!isCompressing && this.checkContextLimitReached()) return;
      
      // Bail out if the model wasn't reachable when credits were last fetched
      if (!this.creditsLoaded) {
        this.$root.showError(this.i18n.assistantBalanceCheckUnhealthy);
        return;
      }

      // Check if user has credits
      if (this.creditsRemaining <= 0) {
        this.$root.showError(this.i18n.assistantOutOfCredits);
        return;
      }
      
      // Generate session ID and update URL BEFORE starting the API call
      // This prevents the URL update from interrupting ongoing tool execution
      if (!this.currentChatId) {
        this.currentChatId = this.generateChatId();
        this.saveCurrentChatId();
      }
      
      // Update URL with session ID if not already set - do this BEFORE the API call
      if (this.currentChatId && !this.$route.params.sessionId) {
        await this.updateUrlWithSessionId(this.currentChatId);
        // Wait for the route change to complete before proceeding
        await this.$nextTick();
      }
      
      const userMessage = {
        role: 'user',
        content: this.newMessage.trim(),
        timestamp: new Date().toISOString()
      };
      
      if (this.messages.length == 1) {
        this.messages = [];
      }

      const floatingState = this.sessionToolState.get(this.currentChatId);
      if (this.messages.length > 1 && floatingState && floatingState.floatingTool) {
        floatingState.floatingTool.status = 'skipped';
        floatingState.floatingTool = null;
      }

      // Add user message to chat
      this.messages.push(userMessage);
      const messageText = this.newMessage.trim();
      this.newMessage = '';
      this.scrollToBottom();
      
      // Show typing indicator
      this.isTyping = true;
      
      // Call the actual AI API - session ID is already set
      await this.callAIAPI(messageText, tags);

      // Refresh chat history to show the latest session
      await this.loadStoredChats(false);
    },
    
    // Helper method to parse JSON chunks and handle concatenated/partial JSON
    parseJsonChunk(chunk) {
      try {
        return { success: true, data: JSON.parse(chunk), isPartial: null };
      } catch {
        // Handle partial JSON or multiple concatenated JSON objects
        const splitChunks = [];
        let currentChunk = '';
        let braceCount = 0;
        let inString = false;
        let escaped = false;
        
        for (let j = 0; j < chunk.length; j++) {
          const char = chunk[j];
          currentChunk += char;
          
          if (escaped) {
            escaped = false;
            continue;
          }
          
          if (char === '\\') {
            escaped = true;
            continue;
          }
          
          if (char === '"') {
            inString = !inString;
            continue;
          }
          
          if (!inString) {
            if (char === '{') {
              braceCount++;
            } else if (char === '}') {
              braceCount--;
              if (braceCount === 0) {
                // Complete JSON object found
                splitChunks.push(currentChunk);
                currentChunk = '';
              }
            }
          }
        }
        
        // If we found complete JSON objects, return them for processing
        if (splitChunks.length > 0) {
          return {
            success: true,
            data: splitChunks,
            isPartial: currentChunk.trim() ? currentChunk : null
          };
        } else if (currentChunk.trim()) {
          // No complete JSON found, treat entire chunk as partial
          return { success: false, data: null, isPartial: currentChunk };
        } else {
          // Fallback: treat as partial
          return { success: false, data: null, isPartial: chunk };
        }
      }
    },
    
    // Helper method to process streaming chunks and handle partial data
    processStreamingChunks(value, chunks, partial) {
      // Cleanup the data, split messages apart, remove SSE label, filter out empty lines
      const newChunks = value.split('\n\n').filter(d => d.trim()).map(d => (d.startsWith("data: ") ? d.slice(6) : d));
      
      // If the last read had partial data, prepend it to the new data and process it again
      if (partial) {
        newChunks[0] = chunks[0] + newChunks[0];
        partial = false;
      }
      
      return { chunks: newChunks, partial };
    },
    
    // Helper method to handle message_start event
    handleMessageStart(c, assistantMessage) {
      this.isTyping = false;

      const msg = {
        role: 'assistant',
        thoughts: '',
        content: '',
        timestamp: new Date().toISOString(),
        usage: null,
        toolUses: [] // Track tool uses in this message
      };

      // Sometimes usage comes in message_start
      let messageUsage = null;
      if (c.message && c.message.usage) {
        messageUsage = c.message.usage;
      }

      this.messages.push(msg);
      // Mutate the reactive instance now living in this.messages so streaming
      // updates (content/thoughts/toolUses) notify the template.
      assistantMessage = this.messages[this.messages.length - 1];
      this.scrollIfPinned();

      return { assistantMessage, messageUsage };
    },
    
    // --- Unified content-block stream handlers ---
    // A streamed content block (a tool_use, or a text/thought/input delta) is applied
    // the same way in all three streaming contexts -- the orchestrator's own turn, a
    // chained tool-result turn, and a delegated sub-agent's turn. The only differences
    // are captured in `target`:
    //   message   - the message to append content/thoughts/toolUses to (null = don't render)
    //   sessionId - the session whose tool maps own this block
    //   visible   - whether that session is on screen (drives scroll-if-pinned)
    // The handle*ContentBlock* methods are thin adapters that build `target` for their
    // context; these apply* methods hold the one real implementation.
    applyBlockStart(c, target) {
      if (!(c.content_block && c.content_block.type === 'tool_use')) return;
      const toolUse = {
        id: c.content_block.id,
        name: c.content_block.name,
        input: c.content_block.input || {},
        inputJson: '', // Accumulate input JSON from deltas
        status: 'preparing', // Start as preparing, not executing
        result: null,
        error: null,
        rawResult: null, // Will store the raw tool result
        timestamp: new Date().toISOString(),
        blockIndex: c.index, // Store the block index for tracking
        approved: null, // null = pending, true = approved, false = rejected
        sessionId: target.sessionId, // Track which session this belongs to
      };

      // Push into the reactive message first, then track that reactive instance in the
      // session map so later mutations (status, input, childSession) notify the view.
      let tracked = toolUse;
      if (target.message) {
        target.message.toolUses.push(toolUse);
        tracked = target.message.toolUses[target.message.toolUses.length - 1];
        if (target.visible) this.scrollIfPinned();
      }
      this.getSessionToolMap(target.sessionId).set(toolUse.id, tracked);
      this.getIndexMap(target.sessionId).set(c.index, toolUse.id);
    },
    applyBlockDelta(c, target) {
      if (c.delta.type === 'text_delta') {
        if (target.message) {
          target.message.content = this.nbspRegexOp(target.message.content + c.delta.text);
          if (target.visible) this.scrollIfPinned();
        }
      } else if (c.delta.type === 'input_json_delta') {
        const toolId = this.getIndexMap(target.sessionId).get(c.index);
        const toolUse = this.getSessionToolMap(target.sessionId).get(toolId);
        if (toolUse) {
          toolUse.inputJson += c.delta.partial_json;
          toolUse.status = 'preparing';
          if (target.visible) this.scrollIfPinned();
        }
      } else if (c.delta.type === 'thought_delta') {
        if (target.message) {
          target.message.thoughts += this.nbspRegexOp(c.delta.text);
          if (target.visible) this.scrollIfPinned();
        }
      }
    },
    applyBlockStop(c, target) {
      let messageUsage = null;
      const toolId = this.getIndexMap(target.sessionId).get(c.index);
      const toolUse = this.getSessionToolMap(target.sessionId).get(toolId);
      if (toolUse && toolUse.status === 'preparing') {
        try {
          // Parse the accumulated JSON input
          if (toolUse.inputJson) {
            toolUse.input = JSON.parse(toolUse.inputJson);
          }
          // Read-only tools honor the auto-approval setting; everything else prompts.
          if (this.shouldAutoApproveTool(toolUse.name)) {
            if (this.checkContextLimitReached()) return messageUsage;
            toolUse.approved = true;
            this.queueTool(target.sessionId, toolUse.id);
          } else {
            toolUse.status = 'pending_approval';
            toolUse.approved = null;
            this.sessionTools(target.sessionId).floatingTool = toolUse;
          }
        } catch (error) {
          toolUse.status = 'error';
          toolUse.error = this.i18n.assistantToolParseInputError + ': ' + error.message;
        }
        if (target.visible) this.scrollIfPinned();
      }
      // Usage sometimes rides the content_block_stop event.
      if (c.usage) {
        messageUsage = c.usage;
      }
      return messageUsage;
    },

    // Adapter: the orchestrator's own turn renders into the current session's message.
    handleContentBlockStart(c, assistantMessage, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      this.applyBlockStart(c, { message: assistantMessage, sessionId: sid, visible: sid === this.currentChatId });
    },
    handleContentBlockDelta(c, assistantMessage, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      this.applyBlockDelta(c, { message: assistantMessage, sessionId: sid, visible: sid === this.currentChatId });
    },
    handleContentBlockStop(c, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      return this.applyBlockStop(c, { sessionId: sid, visible: sid === this.currentChatId });
    },
    
    // Helper method to handle message_stop event
    handleMessageStop(assistantMessage, messageUsage) {
      // Store usage information with the message if available
      if (assistantMessage && messageUsage) {
        assistantMessage.usage = messageUsage;
        // Update context length
        this.updateContextLength(messageUsage);
        this.updateCreditsUsed(messageUsage);
        this.$forceUpdate();
      }
      
      return { assistantMessage: null, messageUsage: null };
    },
    
    async callAIAPI(userMessage, tags = null) {
      // Capture the session ID at the start of the API call
      const streamingSessionId = this.currentChatId;
      this.activeStreamingSessionId = streamingSessionId;
      let reader = null;

      try {
        // Build the URL with entityType and entityId query parameters if present
        let url = '/assistant/chat';
        const socId = this.$route.query.socId;
        if (socId) {
          url += `?entityType=alert_investigation&entityId=${encodeURIComponent(socId)}`;
          // Clear the investigation query params after first use to prevent
          // marking the alert as investigated on every subsequent message
          this.$nextTick(() => {
            const query = { ...this.$route.query };
            delete query.investigation;
            delete query.socId;
            this.$router.replace({
              name: 'assistant',
              params: this.$route.params,
              query: query
            });
          });
        }
        
        const response = await this.$root.papi.post(url, {
          msg: userMessage,
          sessionId: streamingSessionId,
          model: this.currentModel,
          tags: tags,
        },
        {
          headers: {
            'Accept': 'text/event-stream'
          },
          responseType: 'stream',
          adapter: 'fetch',
        });

        const stream = response.data;
        reader = stream.pipeThrough(new TextDecoderStream()).getReader();

        this.isStreaming = true;
        let output = 0;
        let assistantMessage = null;
        let chunks = [];
        let partial = false;
        let messageUsage = null;

        while (true) {
          // read in more messages
          const { done, value } = await reader.read();
          if (done) break;
          
          // Check if we're still in the same session for UI updates
          const isCurrentSession = this.activeStreamingSessionId === streamingSessionId && this.currentChatId === streamingSessionId;
          
          // Process streaming chunks using helper method
          const chunkResult = this.processStreamingChunks(value, chunks, partial);
          chunks = chunkResult.chunks;
          partial = chunkResult.partial;
          
          // process each chunk
          for (let i = 0; i < chunks.length; i++) {
            if (chunks[i] === '[DONE]') {
              assistantMessage = null;
              continue;
            }

            // Parse JSON chunk using helper method
            const parseResult = this.parseJsonChunk(chunks[i]);
            
            if (!parseResult.success) {
              // Handle partial JSON
              if (parseResult.isPartial) {
                partial = true;
                chunks = [parseResult.isPartial];
                break;
              }
              continue;
            }
            
            // Handle multiple JSON objects in one chunk
            if (Array.isArray(parseResult.data)) {
              chunks.splice(i, 1, ...parseResult.data);
              i--; // Reprocess from current position
              
              // If there's remaining partial content, save it for next read
              if (parseResult.isPartial) {
                partial = true;
                chunks.push(parseResult.isPartial);
              }
              continue;
            }

            const c = parseResult.data;

            // Always process chunks for tool execution logic, but only update UI if current session
            switch (c.type) {
              case 'message_start':
                if (isCurrentSession) {
                  const startResult = this.handleMessageStart(c, assistantMessage);
                  assistantMessage = startResult.assistantMessage;
                  if (startResult.messageUsage) {
                    messageUsage = startResult.messageUsage;
                  }
                }
                break;
                
              case 'content_block_start':
                this.handleContentBlockStart(c, isCurrentSession ? assistantMessage : null, streamingSessionId);
                break;
                
              case 'content_block_delta':
                this.handleContentBlockDelta(c, isCurrentSession ? assistantMessage : null, streamingSessionId);
                break;
                
              case 'content_block_stop':
                const stopUsage = this.handleContentBlockStop(c, streamingSessionId);
                if (stopUsage && isCurrentSession) {
                  messageUsage = stopUsage;
                }
                break;
                
              case 'message_stop':
                if (isCurrentSession) {
                  const stopResult = this.handleMessageStop(assistantMessage, messageUsage);
                  assistantMessage = stopResult.assistantMessage;
                  messageUsage = stopResult.messageUsage;
                }
                break;
                
              case 'message_delta':
                // Handle usage information if present
                if (c.usage && isCurrentSession) {
                  messageUsage = c.usage;
                }
                break;
                
              default:
                // Log any unhandled event types that might contain usage
                if (c.usage && isCurrentSession) {
                  messageUsage = c.usage;
                }
                break;
            }
          }

          // done processing received chunks, update UI only if still current session
          if (isCurrentSession) {
            await this.$nextTick();
          }
          output++;
        }
        
        // Only update UI state if we're still in the same session
        if (this.activeStreamingSessionId === streamingSessionId && this.currentChatId === streamingSessionId) {
          this.isStreaming = false;
          // Update credits from API after successful response
          await this.loadCredits();
        }
        
        // Clear the active streaming session if this was the active one
        if (this.activeStreamingSessionId === streamingSessionId) {
          this.activeStreamingSessionId = null;
        }
        
      } catch (error) {
        // Only update UI state if we're still in the same session
        if (this.activeStreamingSessionId === streamingSessionId && this.currentChatId === streamingSessionId) {
          this.isTyping = false;
          this.isStreaming = false;
          
          // Show user-friendly error message
          const errorMessage = {
            role: 'assistant',
            content: this.i18n.assistantErrorMessage,
            timestamp: new Date().toISOString()
          };
          this.messages.push(errorMessage);
          this.scrollIfPinned();

          // Read streamed error
          if (error && error.response && error.response.data) {
            const stream = error.response.data;
            const errorReader = stream.pipeThrough(new TextDecoderStream()).getReader();
            const { done, value } = await errorReader.read();
            error = value;
          }

          // Show error to user
          this.$root.showError(error);
        }
        
        // Clear the active streaming session if this was the active one
        if (this.activeStreamingSessionId === streamingSessionId) {
          this.activeStreamingSessionId = null;
        }
      } finally {
        // Release the stream reader so an interrupted turn (mid-stream error or
        // session switch) can't leak the underlying connection.
        if (reader) {
          try {
            await reader.cancel();
          } catch (e) {
            // already closed; nothing to release
          }
        }
      }
    },

    // Helper method to handle message_start event for tool execution
    handleToolExecutionMessageStart(c, assistantMessage, toolUse) {
      const msg = {
        role: 'assistant',
        thoughts: '',
        content: '',
        timestamp: new Date().toISOString(),
        usage: null,
        toolUses: [], // Track tool uses in this response too
        isToolResult: true,
        toolName: toolUse.name,
        toolId: toolUse.id
      };

      let messageUsage = null;
      if (c.message && c.message.usage) {
        messageUsage = c.message.usage;
      }

      this.messages.push(msg);
      // Mutate the reactive instance from this.messages so streaming notifies.
      assistantMessage = this.messages[this.messages.length - 1];
      this.scrollIfPinned();

      return { assistantMessage, messageUsage };
    },
    
    // Adapter: a chained tool-result turn renders the same way as the orchestrator's
    // own turn, so it reuses the unified content-block handlers verbatim.
    handleToolExecutionContentBlockStart(c, assistantMessage, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      this.applyBlockStart(c, { message: assistantMessage, sessionId: sid, visible: sid === this.currentChatId });
    },
    handleToolExecutionContentBlockDelta(c, assistantMessage, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      this.applyBlockDelta(c, { message: assistantMessage, sessionId: sid, visible: sid === this.currentChatId });
    },
    handleToolExecutionContentBlockStop(c, sessionId = null) {
      const sid = sessionId || this.currentChatId;
      return this.applyBlockStop(c, { sessionId: sid, visible: sid === this.currentChatId });
    },

    // --- Delegation (sub-agent) streaming helpers ---
    // A delegated sub-agent runs as its own session, but its turns are rendered
    // nested under the parent's delegate tool block (toolUse.childSession). Its
    // tool requests are surfaced for approval just like top-level tools (always
    // prompting), routed by the child session id.

    // Lazily create the nested render container on a delegate tool block. The
    // delegateToolUse must be the reactive instance from this.messages so that
    // attaching childSession (and everything under it) notifies the template.
    ensureChildSession(delegateToolUse, agentName) {
      if (!delegateToolUse.childSession) {
        delegateToolUse.childSession = {
          agentName: agentName || '',
          messages: [],
        };
      } else if (agentName) {
        delegateToolUse.childSession.agentName = agentName;
      }
      return delegateToolUse.childSession;
    },

    // Child tools currently awaiting the user's approval. These are surfaced OUTSIDE
    // the collapsed sub-agent region so they stay visible/actionable; once the user
    // responds they leave this list and fold into the collapsed transcript.
    pendingChildTools(delegateToolUse) {
      const cs = delegateToolUse && delegateToolUse.childSession;
      if (!cs || !Array.isArray(cs.messages)) return [];
      const pending = [];
      for (const m of cs.messages) {
        const tools = m && m.toolUses;
        if (!Array.isArray(tools)) continue;
        for (const t of tools) {
          if (t.status === 'pending_approval') pending.push(t);
        }
      }
      return pending;
    },

    // Whether the collapsed sub-agent region has anything worth showing (a thought or
    // an already-resolved tool) — avoids rendering an empty expandable when the only
    // activity so far is a still-pending tool shown outside.
    delegationHasCollapsedContent(delegateToolUse) {
      const cs = delegateToolUse && delegateToolUse.childSession;
      if (!cs || !Array.isArray(cs.messages)) return false;
      for (const m of cs.messages) {
        if (m && m.content) return true;
        if (m && m.thoughts) return true;
        const tools = m && m.toolUses;
        if (Array.isArray(tools) && tools.some(t => t.status !== 'pending_approval')) return true;
      }
      return false;
    },

    // message_start within a delegated sub-agent's stream: begin a new nested message.
    handleDelegationMessageStart(delegateToolUse) {
      const childMsg = {
        role: 'assistant',
        thoughts: '',
        content: '',
        toolUses: [],
        timestamp: new Date().toISOString(),
      };
      delegateToolUse.childSession.messages.push(childMsg);
      this.scrollIfPinned();
      // Return the reactive instance now in childSession.messages so streaming
      // updates to this nested message notify the template.
      return delegateToolUse.childSession.messages[delegateToolUse.childSession.messages.length - 1];
    },

    // Adapter: a delegated sub-agent's turn renders into its nested childMsg. Its
    // transcript is always on screen (collapsed under the parent's agent panel), so
    // visible is always true; tool approvals route back to the child session id.
    handleDelegationContentBlockStart(c, childSessionId, childMsg) {
      this.applyBlockStart(c, { message: childMsg, sessionId: childSessionId, visible: true });
    },
    handleDelegationContentBlockDelta(c, childSessionId, childMsg) {
      this.applyBlockDelta(c, { message: childMsg, sessionId: childSessionId, visible: true });
    },
    handleDelegationContentBlockStop(c, childSessionId) {
      this.applyBlockStop(c, { sessionId: childSessionId, visible: true });
    },

    // Capture the raw tool result the backend persists shortly after a tool runs,
    // by re-reading the session's history. By default the newest tool_result in
    // the currently viewed session is assumed to be ours; for tools inside a
    // delegated sub-agent, pass the child sessionId and matchById so the result
    // is matched explicitly on the tool's use id.
    // applyStreamedToolResult attaches a tool's result to its card and advances its
    // status to completed/error. The result is delivered inline by the backend's
    // synthetic tool_result SSE event (see executeTool), so no session re-fetch is
    // needed. Empty content still advances status, otherwise the card spins forever.
    applyStreamedToolResult(toolUse, toolResult) {
      toolUse.completedAt = new Date().toISOString();
      // A declined tool reports a 'rejected' result; keep the rejected card (not error).
      if (toolResult.status === 'rejected') {
        toolUse.status = 'rejected';
        toolUse.error = toolResult.content?.[0]?.text || this.i18n.assistantToolUseReject;
        return;
      }
      if (toolResult.isError || toolResult.status === 'error') {
        toolUse.rawResult = null;
        toolUse.error = toolResult.content?.[0]?.text || this.i18n.assistantToolUnknownError;
        toolUse.status = 'error';
      } else {
        toolUse.rawResult = toolResult.content?.[0]?.json ?? null;
        toolUse.status = 'completed';
      }
    },

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
    async executeTool(toolUse) {
      // Use the tool's session ID if available, otherwise use current session
      let toolStreamingSessionId = toolUse.sessionId || this.currentChatId;

      let childMsg = null;
      let reader = null;

      try {
        // Create ToolRequest object with history and params. A rejected tool is not
        // executed: the backend records an error tool_result so the turn resolves.
        const rejected = toolUse.approved === false;
        const toolRequest = {
          sessionId: toolStreamingSessionId,
          toolUseId: toolUse.id,
          params: toolUse.input,
          model: this.currentModel,
          rejected,
        };

        if (!rejected) this.applyToolSpecificChanges(toolUse, toolRequest);

        // Use streaming for tool results
        const response = await this.$root.papi.post(`/assistant/tool/${toolUse.name}`, toolRequest, {
          headers: {
            'Accept': 'text/event-stream'
          },
          responseType: 'stream',
          adapter: 'fetch',
        });

        // Update tool status to executing only if visible in the current session. A
        // rejected tool was never executing; keep its 'rejected' status.
        if (!rejected && this.currentChatId === toolStreamingSessionId) {
          toolUse.status = 'executing';
        }

        // Stream the AI's response to the tool result
        const stream = response.data;
        reader = stream.pipeThrough(new TextDecoderStream()).getReader();

        if (this.currentChatId === toolStreamingSessionId || this.delegationChildren.has(toolStreamingSessionId)) {
          this.isStreaming = true;
        }
        let assistantMessage = null;
        let chunks = [];
        let partial = false;
        let messageUsage = null;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          // Process streaming chunks using helper method
          const chunkResult = this.processStreamingChunks(value, chunks, partial);
          chunks = chunkResult.chunks;
          partial = chunkResult.partial;

          for (let i = 0; i < chunks.length; i++) {
            if (chunks[i] === '[DONE]') {
              assistantMessage = null;
              continue;
            }

            // Parse JSON chunk using helper method
            const parseResult = this.parseJsonChunk(chunks[i]);

            if (!parseResult.success) {
              // Handle partial JSON
              if (parseResult.isPartial) {
                partial = true;
                chunks = [parseResult.isPartial];
                break;
              }
              continue;
            }

            // Handle multiple JSON objects in one chunk
            if (Array.isArray(parseResult.data)) {
              chunks.splice(i, 1, ...parseResult.data);
              i--; // Reprocess from current position

              // If there's remaining partial content, save it for next read
              if (parseResult.isPartial) {
                partial = true;
                chunks.push(parseResult.isPartial);
              }
              continue;
            }

            const c = parseResult.data;
            const isCurrentSession = this.currentChatId === toolStreamingSessionId;

            // The executed tool's result arrives inline as a synthetic tool_result
            // event; attach it to the tool card here rather than re-fetching the
            // session. Only direct execution emits it (delegations resolve via the
            // markers below), and it always targets this stream's tool.
            if (c.type === 'tool_result') {
              if (c.toolResult && c.toolResult.toolUseId === toolUse.id) {
                this.applyStreamedToolResult(toolUse, c.toolResult);
              }
              continue;
            }

            // Delegation markers retarget the stream between the sub-agent's nested
            // session and the parent thread (the backend chains both onto one response).
            if (c.type === 'delegation_start') {
              // A delegation_start is only ever emitted in the stream executing that
              // delegate tool, so the owner is this stream's tool.
              const owner = toolUse;
              this.delegationChildren.set(c.childSessionId, {
                parentToolUse: owner,
                parentSessionId: owner.sessionId,
                parentToolUseId: c.parentToolUseId,
                agentName: c.agentName,
              });
              this.ensureChildSession(owner, c.agentName);
              toolStreamingSessionId = c.childSessionId;
              childMsg = null;
              continue;
            }
            if (c.type === 'delegation_resolved') {
              // Close the boundary: mark the delegate tool done and forget the child
              // session so nothing that streams afterward (the resumed parent turn)
              // can be misattributed back under this delegate.
              const resolvedChild = this.delegationChildren.get(toolStreamingSessionId);
              const owner = resolvedChild && resolvedChild.parentToolUse;
              if (owner) {
                owner.status = 'completed';
                owner.completedAt = new Date().toISOString();
              }
              if (this.delegationChildren.has(toolStreamingSessionId)) {
                this.delegationChildren.delete(toolStreamingSessionId);
                this.sessionToolState.delete(toolStreamingSessionId);
              }
              childMsg = null;
              assistantMessage = null;
              toolStreamingSessionId = c.parentSessionId;
              continue;
            }

            // Decide nesting purely from the delegationChildren map. A chunk renders
            // nested under the delegate tool only while its session id is still a live
            // child entry. delegation_resolved (above) deletes that entry, so the
            // parent's resumed turn falls through to top-level rendering automatically.
            const activeChild = this.delegationChildren.get(toolStreamingSessionId);
            if (activeChild) {
              const owner = activeChild.parentToolUse;
              switch (c.type) {
                case 'error':
                  this.$root.showError(this.i18n.assistantToolUseFail + ': ' + c.error.message);
                  break;
                case 'message_start':
                  childMsg = this.handleDelegationMessageStart(owner);
                  break;
                case 'content_block_start':
                  this.handleDelegationContentBlockStart(c, toolStreamingSessionId, childMsg);
                  break;
                case 'content_block_delta':
                  this.handleDelegationContentBlockDelta(c, toolStreamingSessionId, childMsg);
                  break;
                case 'content_block_stop':
                  this.handleDelegationContentBlockStop(c, toolStreamingSessionId);
                  break;
                default:
                  break;
              }
              continue;
            }

            // Normal (parent / top-level) tool result rendering.
            switch (c.type) {
              case 'error':
                this.$root.showError(this.i18n.assistantToolUseFail + ': ' + c.error.message);
                break;
              case 'message_start':
                if (isCurrentSession) {
                  const startResult = this.handleToolExecutionMessageStart(c, assistantMessage, toolUse);
                  assistantMessage = startResult.assistantMessage;
                  if (startResult.messageUsage) {
                    messageUsage = startResult.messageUsage;
                  }
                }
                break;

              case 'content_block_start':
                this.handleToolExecutionContentBlockStart(c, isCurrentSession ? assistantMessage : null, toolStreamingSessionId);
                break;

              case 'content_block_delta':
                this.handleToolExecutionContentBlockDelta(c, isCurrentSession ? assistantMessage : null, toolStreamingSessionId);
                break;

              case 'content_block_stop':
                const stopUsage = this.handleToolExecutionContentBlockStop(c, toolStreamingSessionId);
                if (stopUsage && isCurrentSession) {
                  messageUsage = stopUsage;
                }
                break;

              case 'message_stop':
                if (isCurrentSession) {
                  const stopResult = this.handleMessageStop(assistantMessage, messageUsage);
                  assistantMessage = stopResult.assistantMessage;
                  messageUsage = stopResult.messageUsage;
                }
                break;

              case 'message_delta':
                if (c.usage && isCurrentSession) {
                  messageUsage = c.usage;
                }
                break;

              default:
                if (c.usage && isCurrentSession) {
                  messageUsage = c.usage;
                }
                break;
            }
          }

          await this.$nextTick();
        }

        this.isStreaming = false;
        // Update credits if the turn that finished is the one in view
        if (this.currentChatId === toolStreamingSessionId) {
          await this.loadCredits();
        }
      } catch (error) {
        // Always update tool status with error, but only update UI if current session
        toolUse.status = 'error';
        toolUse.error = error.message;
        this.isStreaming = false;

        // If a delegation was still in flight (its session has a live child entry),
        // the delegate card and child session are still open. Close them here so a
        // dropped/aborted stream can't leave the delegate tool spinning forever (the
        // backend may not have emitted a delegation_resolved marker). Derived from
        // the map before the cleanup below deletes the entry.
        const activeDelegate = this.delegationChildren.get(toolStreamingSessionId)?.parentToolUse;
        if (activeDelegate) {
          activeDelegate.status = 'error';
          activeDelegate.error = error.message;
          activeDelegate.completedAt = new Date().toISOString();
        }
        if (this.delegationChildren.has(toolStreamingSessionId)) {
          this.delegationChildren.delete(toolStreamingSessionId);
          this.sessionToolState.delete(toolStreamingSessionId);
        }

        const isCurrentSession = this.currentChatId === (toolUse.sessionId || this.currentChatId);

        if (isCurrentSession && !activeDelegate) {
          // Add error message to chat
          const errorMessage = {
            role: 'assistant',
            content: `Error executing tool "${toolUse.name}": ${error.message}`,
            timestamp: new Date().toISOString(),
            isToolResult: true,
            toolName: toolUse.name,
            toolId: toolUse.id
          };

          this.messages.push(errorMessage);
          this.scrollIfPinned();
        }
      } finally {
        // Release the stream reader so an interrupted turn (mid-stream error or
        // session switch) can't leak the underlying connection.
        if (reader) {
          try {
            await reader.cancel();
          } catch (e) {
            // already closed; nothing to release
          }
        }
      }
    },
    // displayStatus is the status to render for a tool, which can differ from its raw
    // status. A delegate stays 'executing' while its sub-agent is parked on a tool
    // awaiting the user's approval (it must remain non-approvable so re-prompting can't
    // spawn a duplicate sub-session), but it isn't actually working -- surface
    // 'action_needed' so the card shows a "needs you" indicator, not a busy spinner.
    displayStatus(toolUse) {
      if (toolUse.status === 'executing' && this.hasPendingDescendantApproval(toolUse)) {
        return 'action_needed';
      }
      return toolUse.status;
    },
    // Whether any tool nested under this delegate (at any depth) is awaiting approval.
    hasPendingDescendantApproval(toolUse) {
      const cs = toolUse && toolUse.childSession;
      if (!cs || !Array.isArray(cs.messages)) return false;
      for (const m of cs.messages) {
        if (!m || !Array.isArray(m.toolUses)) continue;
        for (const t of m.toolUses) {
          if (t.status === 'pending_approval') return true;
          if (this.hasPendingDescendantApproval(t)) return true;
        }
      }
      return false;
    },
    getToolStatusIcon(status) {
      switch (status) {
        case 'preparing': return 'fa-cog';
        case 'queued': return 'fa-cog';
        case 'skipped': return 'fa-circle-info';
        case 'pending_approval': return 'fa-question-circle';
        case 'action_needed': return 'fa-user-clock';
        case 'executing': return 'fa-hourglass-half';
        case 'completed': return 'fa-check-circle';
        case 'error': return 'fa-exclamation-triangle';
        case 'rejected': return 'fa-times-circle';
        default: return 'fa-question-circle';
      }
    },
    getToolStatusColor(status) {
      switch (status) {
        case 'preparing': return 'info';
        case 'queued': return 'info';
        case 'skipped': return 'info';
        case 'pending_approval': return 'warning';
        case 'action_needed': return 'warning';
        case 'executing': return 'warning';
        case 'completed': return 'success';
        case 'error': return 'error';
        case 'rejected': return 'error';
        default: return 'info';
      }
    },
    getToolStatusTitle(status) {
      switch (status) {
        case 'preparing': return this.i18n.preparing;
        case 'queued': return this.i18n.preparing;
        case 'skipped': return this.i18n.skipped;
        case 'pending_approval': return this.i18n.pendingApproval;
        case 'action_needed': return this.i18n.actionNeeded;
        case 'executing': return this.i18n.executing;
        case 'completed': return this.i18n.completed;
        case 'error': return this.i18n.error;
        case 'rejected': return this.i18n.rejected;
        default: return this.i18n.statusUnknown;
      }
    },
    // A tool is top-level when it belongs to the viewed conversation rather than a
    // nested sub-agent session; only those should drive the main view's scroll.
    isTopLevelTool(toolUse) {
      return !toolUse.sessionId || toolUse.sessionId === this.currentChatId;
    },
    async approveTool(toolUse) {
      try {
        if (this.checkContextLimitReached()) return;
        toolUse.approved = true;
        toolUse.status = 'preparing';
        this.clearFloatingTool(toolUse.sessionId || this.currentChatId);
        this.queueTool(toolUse.sessionId || this.currentChatId, toolUse.id);
      } catch (error) {
        toolUse.status = 'error';
        toolUse.error = this.i18n.assistantToolUseFail + ': ' + error.message;
      }
      if (this.isTopLevelTool(toolUse)) this.scrollToBottom();
    },
    async rejectTool(toolUse) {
      if (this.checkContextLimitReached()) return;
      toolUse.approved = false;
      toolUse.status = 'rejected';
      toolUse.error = this.i18n.assistantToolUseReject;
      this.clearFloatingTool(toolUse.sessionId || this.currentChatId);

      // Submit the rejection as a tool_result (the backend records an error result and
      // resumes the turn). Routing it through the same queue as approvals keeps a
      // parallel turn's tools serialized, so its coalescing resolves correctly.
      this.queueTool(toolUse.sessionId || this.currentChatId, toolUse.id);
      if (this.isTopLevelTool(toolUse)) this.scrollToBottom();
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

      // Clear the welcome message for investigations (similar to normal chats)
      this.messages = [];

      // Set the investigation prompt directly (no decoding needed)
      this.newMessage = investigationPrompt;

      // Wait for the UI to update again
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
    // Helper method to generate title from a session/message
    generateTitleFromMessage(session) {
      if (session && session.title) {
        // Handle different message formats
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

    // Helper method to load a specific chat from backend
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
    
    // Helper method to process tool result messages (new format with tags)
    processToolResultMessage(msg, processedMessages) {
      // This is a tool result message - extract the result data
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
      
      // Find the assistant message with the matching tool use and add the raw result
      if (toolUseId && rawResult && toolError) {
        // Look backwards through processed messages to find the tool use
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
    
    // Helper method to process old format tool result messages
    processOldFormatToolResult(msg, processedMessages) {
      // This is a tool result - find the previous assistant message with tool uses
      const prevMessage = processedMessages[processedMessages.length - 1];
      if (prevMessage && prevMessage.role === 'assistant' && prevMessage.toolUses) {
        // Add the raw result to the last tool use in the previous message
        const toolUses = prevMessage.toolUses;
        if (toolUses.length > 0) {
          const lastToolUse = toolUses[toolUses.length - 1];
          lastToolUse.rawResult = msg.message.contentStr;
        }
      }
    },
    
    // Helper method to extract content from message blocks
    extractMessageContent(msg, frontendMsg) {
      if (msg.message.contentStr) {
        frontendMsg.content = msg.message.contentStr;
      } else if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
        // Extract text from content blocks
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
    
    // Helper method to process tool use blocks
    processToolUseBlocks(msg, frontendMsg, backendMessages, i) {
      const toolBlocks = msg.message.contentBlocks.filter(block => block.type === 'tool_use');
      if (toolBlocks.length === 0) return;

      // Status is decided PER TOOL, mirroring the sub-agent reload (reconstructChildSession):
      // a single assistant turn can request several tools in parallel whose results are
      // persisted as separate tool_result messages, so one turn may hold a mix of
      // resolved, pending, and skipped tools. A declined tool is just a resolved
      // tool_result (status 'rejected'): it lands in the resolved branch below and is
      // refined to 'rejected' by processToolResultMessage.
      const resolvedIds = this.collectResolvedToolUseIds(backendMessages);

      // An unresolved tool is still awaiting approval only while this turn is the
      // conversation's active tail (everything after it is a tool_result answering it --
      // the model has not continued and the user has not moved on). Once a non-tool_result
      // message follows, an unanswered tool was abandoned (skipped). This is the top-level
      // analogue of the sub-agent path's "turn holding the backend-flagged pending tool".
      const active = this.isActiveToolTurn(backendMessages, i);

      frontendMsg.toolUses = toolBlocks.map(block => {
        const base = {
          id: block.id || 'unknown',
          name: block.name || 'unknown',
          input: block.input || {}, // Ensure input is always an object, never null/undefined
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

    // Whether the assistant turn at index i is still the conversation's active tool turn:
    // every message after it is a tool_result (answering this turn's tools), so the model
    // has not continued and the user has not moved on. Once a non-tool_result message
    // follows, any unanswered tool from the turn was abandoned, not pending.
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

        // Split the sub-agent's turn the same way the live stream and the top-level
        // reload do: response prose renders as content, reasoning as thoughts. Folding
        // prose into thoughts here would hide the sub-agent's answer after a reload
        // (thoughts only show when "show thinking" is on), unlike the live view.
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
              // Default for a tool_use with no result: it was requested but never
              // produced a result (the sub-agent stopped/errored). Finalized below to
              // completed/error when a result exists, or executing/pending_approval
              // when it's a live delegation or the backend-flagged pending tool. Must
              // NOT default to 'completed' -- that would show a false checkmark for a
              // tool that never ran (mirrors the top-level reload guard).
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
        childMessages.push(childMsg);
      }

      // The backend flags a single pending tool_use, but that tool's turn may have
      // requested several in parallel -- all of its unresolved siblings are equally
      // awaiting approval, not skipped. Treat the whole turn holding the flagged tool
      // as active; unresolved tools in earlier turns were genuinely abandoned.
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

    // A delegation that has settled -- its delegate tool carries a result, errored, was
    // rejected, or was skipped -- must not present its sub-agent as live.
    // reconstructChildSession runs while the delegate tool_use message is processed --
    // BEFORE the delegate's own tool_result is processed -- so it can't know the outcome
    // and may leave child tools executing/pending. This post-pass, run once the whole
    // conversation is rebuilt, makes a settled delegation inert: any leftover
    // executing/pending sub-agent tool is marked skipped and unregistered (from the
    // session tool map and the live delegation linkage), so it is never actionable.
    // Settlement propagates downward -- a settled ancestor settles every descendant.
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

    // Helper method to convert backend message format to frontend format
    convertBackendMessagesToFrontend(backendMessages) {
      const processedMessages = [];
      // Reset context length when loading from backend
      this.creditsUsed = 0;
      this.contextLength = 0;
      this.contextStartMessageIndex = -1;
      let justResetContext = false;

      for (let i = 0; i < backendMessages.length; i++) {
        const msg = backendMessages[i];
        
        // Check if this is a tool result message (new format with tags)
        if (msg.tags && msg.tags.includes('tool_result')) {
          this.processToolResultMessage(msg, processedMessages);
          // Skip adding this message to the processed messages (filter it out)
          continue;
        }
        
        // Check if this is a tool result message (old format - user role with contentStr)
        if (msg.message.role === 'user' && msg.message.contentStr && !msg.message.contentBlocks) {
          this.processOldFormatToolResult(msg, processedMessages);
          // Skip adding this message to the processed messages (filter it out)
          continue;
        }
        
        const frontendMsg = {
          role: msg.message.role,
          timestamp: msg.createTime || new Date().toISOString(),
          tags: msg.tags || [],
        };

        // Extract thoughts if present
        if (msg.message.thoughts) {
          frontendMsg.thoughts = msg.message.thoughts;
        }

        // Extract message content using helper method
        this.extractMessageContent(msg, frontendMsg);
        
        // Process tool use blocks if present
        if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
          this.processToolUseBlocks(msg, frontendMsg, backendMessages, i);
        }

        // Handle usage information if present
        if (msg.message.usage) {
          frontendMsg.usage = msg.message.usage;
          // Update context length for loaded messages
          this.updateContextLength(msg.message.usage, justResetContext);
          this.updateCreditsUsed(msg.message.usage);
        }

        processedMessages.push(frontendMsg);

        if (msg.tags && msg.tags.includes(MSGTAG_CONTEXTCOMPRESSION)) {
          // reset context, messages prior to this message are no longer
          // sent to the AI
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
      
      if (value < threshold1) return "text-green";
      if (value < threshold2) return "text-yellow";
      if (value < threshold3) return "text-amber darken-1";
      return "text-red darken-1";
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

    applyToolSpecificChanges(toolUse, toolRequest) {
      if (toolUse.name === 'query_cases') {
        const rawMRU = localStorage.getItem('settings.case.mruCases');
        if (rawMRU) {
          const cases = JSON.parse(rawMRU);
          toolRequest.auxData = cases;
        }
      }
    },
    // sessionTools returns the per-session tool-execution state, creating it on first
    // use. One record consolidates the tools-by-id map, the stream block-index ->
    // tool-id map, the approval queue, the runner-busy flag, and the floating
    // (pending-approval) tool shown above a collapsed delegate.
    sessionTools(sessionId) {
      let s = this.sessionToolState.get(sessionId);
      if (!s) {
        s = { toolsById: new Map(), indexToId: new Map(), queue: [], busy: false, floatingTool: null };
        this.sessionToolState.set(sessionId, s);
      }
      return s;
    },
    getSessionToolMap(sessionId) {
      return this.sessionTools(sessionId).toolsById;
    },
    getIndexMap(sessionId) {
      return this.sessionTools(sessionId).indexToId;
    },
    // clearFloatingTool drops the pending-approval tool a session was surfacing above
    // its collapsed delegate, without disturbing the rest of that session's state.
    clearFloatingTool(sessionId) {
      const s = this.sessionToolState.get(sessionId);
      if (s) s.floatingTool = null;
    },
    queueTool(sessionId, toolUseId) {
      this.sessionTools(sessionId).queue.push(toolUseId);
      this.runToolQueue(sessionId);
    },
    async runToolQueue(sessionId) {
      const s = this.sessionTools(sessionId);
      if (s.busy) return;
      s.busy = true;
      try {
        // Re-read the record each iteration: a session's state can be torn down
        // mid-run (e.g. a resolved delegation), which ends the loop just as the old
        // per-session map deletes did.
        while (true) {
          const cur = this.sessionToolState.get(sessionId);
          if (!cur || cur.queue.length === 0) break;
          const toolUseId = cur.queue[0];
          const toolUse = cur.toolsById.get(toolUseId);
          // A rejected tool (approved === false) still needs its declination submitted
          // to the backend, so it bypasses the resolved skip-list; everything else that
          // is already terminal is dropped.
          const isReject = toolUse && toolUse.approved === false;
          if (!toolUse || (!isReject && ['completed','error','rejected'].includes(toolUse.status))) {
            cur.queue.shift();
            continue;
          }
          // executeTool keeps a reject's 'rejected' status; only an approved tool runs.
          if (!isReject) toolUse.status = 'executing';
          await this.executeTool(toolUse);
          cur.queue.shift();
        }
      } finally {
        const cur = this.sessionToolState.get(sessionId);
        if (cur) cur.busy = false;
      }
    },
    checkForActivity() {
      if (this.isStreaming || this.isTyping) return true;
      // Tool queues are per session: a delegation runs its sub-agent's tools under the
      // child session, not the current one. Count queued work in the current session or
      // any live delegation child (tracked in delegationChildren) as activity, so the
      // send/export controls stay disabled while a sub-agent's tools are still running.
      const queued = (sessionId) => {
        const s = this.sessionToolState.get(sessionId);
        return !!(s && s.queue.length > 0);
      };
      if (queued(this.currentChatId)) return true;
      for (const childSessionId of this.delegationChildren.keys()) {
        if (queued(childSessionId)) return true;
      }
      return false;
    },
    async compressCurrentSession() {
      const oldMsg = this.newMessage;
      this.newMessage = this.compressContextMsg;

      this.contextLength = 0;
      
      await this.sendMessage([MSGTAG_CONTEXTCOMPRESSION]);
      this.loadChatFromBackend(this.currentChatId);
      
      if (oldMsg) this.newMessage = oldMsg;
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
  }
}});
