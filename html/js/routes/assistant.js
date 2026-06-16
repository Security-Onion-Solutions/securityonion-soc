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
    executingToolsBySession: new Map(), // Map<sessionId, Map<toolUseId, toolUse>>
    toolIndexToIdBySession: new Map(), // Map<sessionId, Map<index, toolUseId>>
    toolQueues: new Map(), // Map<sessionId, Array<toolUseId>>
    toolRunnerBusy: new Set(), // Set<sessionId>
    mostRecentFloatingTool: new Map(), // Map<sessionId, toolUse>
    delegationChildren: new Map(), // Map<childSessionId, {parentToolUse, parentSessionId, parentToolUseId, agentName}>
    pendingResultTimers: new Set(), // Set<timeoutId> for deferred raw-result captures, cleared on session switch
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
      this.availableModels = params["availableModels"];
      this.availableAdapters = params["availableAdapters"];
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

      if (this.messages.length > 1 && this.mostRecentFloatingTool.get(this.currentChatId)) {
        let floatingTool = this.mostRecentFloatingTool.get(this.currentChatId);
        floatingTool.status = 'skipped';
        this.mostRecentFloatingTool.delete(this.currentChatId);
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
    
    // Helper method to handle content_block_start event
    handleContentBlockStart(c, assistantMessage, sessionId = null) {
      // Handle tool use blocks
      if (c.content_block && c.content_block.type === 'tool_use') {
        const targetSessionId = sessionId || this.currentChatId;
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
          sessionId: targetSessionId // Track which session this belongs to
        };

        // Push into the reactive message first, then track the reactive instance in
        // the session map so later mutations (status, input, childSession) notify.
        let tracked = toolUse;
        if (assistantMessage && targetSessionId === this.currentChatId) {
          assistantMessage.toolUses.push(toolUse);
          tracked = assistantMessage.toolUses[assistantMessage.toolUses.length - 1];
          this.scrollIfPinned();
        }
        this.getSessionToolMap(targetSessionId).set(toolUse.id, tracked);
        this.getIndexMap(targetSessionId).set(c.index, toolUse.id);
      }
    },

    // Helper method to handle content_block_delta event
    handleContentBlockDelta(c, assistantMessage, sessionId = null) {
      const targetSessionId = sessionId || this.currentChatId;
      
      if (assistantMessage && c.delta.type === 'text_delta' && targetSessionId === this.currentChatId) {
        // Only update UI if this is for the current session
        assistantMessage.content = this.nbspRegexOp(assistantMessage.content + c.delta.text);
        this.scrollIfPinned();
      } else if (c.delta.type === 'input_json_delta') {
        const idMap = this.getIndexMap(targetSessionId);
        const toolId = idMap.get(c.index);
        const toolUse = this.getSessionToolMap(targetSessionId).get(toolId);
        if (toolUse) {
          toolUse.inputJson += c.delta.partial_json;
          toolUse.status = 'preparing';
          // Only update UI if this is for the current session
          if (targetSessionId === this.currentChatId) {
            this.scrollIfPinned();
          }
        }
      } else if (c.delta.type === 'thought_delta') {
        if (assistantMessage && targetSessionId === this.currentChatId) {
          assistantMessage.thoughts += this.nbspRegexOp(c.delta.text);
          this.scrollIfPinned();
        }
      }
    },

    // Helper method to handle content_block_stop event
    handleContentBlockStop(c, sessionId = null) {
      let messageUsage = null;
      const targetSessionId = sessionId || this.currentChatId;
      
      const idMap = this.getIndexMap(targetSessionId);
      const toolId = idMap.get(c.index);
      const toolUse = this.getSessionToolMap(targetSessionId).get(toolId);
      if (toolUse && toolUse.status === 'preparing') {
        try {
          // Parse the accumulated JSON input
          if (toolUse.inputJson) {
            toolUse.input = JSON.parse(toolUse.inputJson);
          }
          // Check if this tool should be auto-approved
          if (this.shouldAutoApproveTool(toolUse.name)) {
            if (this.checkContextLimitReached()) return;
            // Auto-approve the tool
            toolUse.approved = true;
            this.queueTool(targetSessionId, toolUse.id);
          } else {
            // Set status to pending approval instead of executing
            toolUse.status = 'pending_approval';
            toolUse.approved = null;
            this.mostRecentFloatingTool.set(targetSessionId, toolUse);
          }
        } catch (error) {
          toolUse.status = 'error';
          toolUse.error = this.i18n.assistantToolParseInputError + ': ' + error.message;
        }
        
        // Only update UI if this is for the current session
        if (targetSessionId === this.currentChatId) {
          this.scrollIfPinned();
        }
      }
      
      // Sometimes usage comes here
      if (c.usage) {
        messageUsage = c.usage;
      }
      
      return messageUsage;
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
    
    // Helper method to handle content_block_start event for tool execution (chained tools)
    handleToolExecutionContentBlockStart(c, assistantMessage, sessionId = null) {
      // Handle tool use blocks in the response after tool execution
      if (c.content_block && c.content_block.type === 'tool_use') {
        const targetSessionId = sessionId || this.currentChatId;
        const newToolUse = {
          id: c.content_block.id,
          name: c.content_block.name,
          input: c.content_block.input || {},
          inputJson: '', // Accumulate input JSON from deltas
          status: 'preparing',
          result: null,
          error: null,
          rawResult: null, // Will store the raw tool result
          timestamp: new Date().toISOString(),
          blockIndex: c.index,
          approved: null,
          sessionId: targetSessionId // Track which session this belongs to
        };

        // Push into the reactive message first, then track the reactive instance.
        let tracked = newToolUse;
        if (assistantMessage && targetSessionId === this.currentChatId) {
          assistantMessage.toolUses.push(newToolUse);
          tracked = assistantMessage.toolUses[assistantMessage.toolUses.length - 1];
          this.scrollIfPinned();
        }
        this.getSessionToolMap(targetSessionId).set(newToolUse.id, tracked);
        this.getIndexMap(targetSessionId).set(c.index, newToolUse.id);
      }
    },
    
    // Helper method to handle content_block_delta event for tool execution
    handleToolExecutionContentBlockDelta(c, assistantMessage, sessionId = null) {
      const targetSessionId = sessionId || this.currentChatId;
      
      if (assistantMessage && c.delta.type === 'text_delta' && targetSessionId === this.currentChatId) {
        // Only update UI if this is for the current session
        assistantMessage.content = this.nbspRegexOp(assistantMessage.content + c.delta.text);
        this.scrollIfPinned();
      } else if (c.delta.type === 'input_json_delta') {
        const idMap = this.getIndexMap(targetSessionId);
        const toolId = idMap.get(c.index);
        const chainedToolUse = this.getSessionToolMap(targetSessionId).get(toolId);
        if (chainedToolUse) {
          chainedToolUse.inputJson += c.delta.partial_json;
          chainedToolUse.status = 'preparing';
          // Only update UI if this is for the current session
          if (targetSessionId === this.currentChatId) {
            this.scrollIfPinned();
          }
        }
      } else if (c.delta.type === 'thought_delta') {
        if (assistantMessage && targetSessionId === this.currentChatId) {
          assistantMessage.thoughts += this.nbspRegexOp(c.delta.text);
          this.scrollIfPinned();
        }
      }
    },

    // Helper method to handle content_block_stop event for tool execution (chained tools)
    handleToolExecutionContentBlockStop(c, sessionId = null) {
      let messageUsage = null;
      const targetSessionId = sessionId || this.currentChatId;
      
      // Handle tool input completion for chained tools
      const idMap = this.getIndexMap(targetSessionId);
      const toolId = idMap.get(c.index);
      const chainedToolUse = this.getSessionToolMap(targetSessionId).get(toolId);
      if (chainedToolUse && chainedToolUse.status === 'preparing') {
        try {
          // Parse the accumulated JSON input
          if (chainedToolUse.inputJson) {
            chainedToolUse.input = JSON.parse(chainedToolUse.inputJson);
          }
          
          // Check if this chained tool should be auto-approved
          if (this.shouldAutoApproveTool(chainedToolUse.name)) {
            if (this.checkContextLimitReached()) return;
            chainedToolUse.approved = true;
            this.queueTool(targetSessionId, chainedToolUse.id);
          } else {
            // Set status to pending approval
            chainedToolUse.status = 'pending_approval';
            chainedToolUse.approved = null;
            this.mostRecentFloatingTool.set(targetSessionId, chainedToolUse);
          }
        } catch (error) {
          chainedToolUse.status = 'error';
          chainedToolUse.error = this.i18n.assistantToolParseInputError + ': ' + error.message;
        }
        
        // Only update UI if this is for the current session
        if (targetSessionId === this.currentChatId) {
          this.scrollIfPinned();
        }
      }
      
      // Sometimes usage comes here
      if (c.usage) {
        messageUsage = c.usage;
      }
      
      return messageUsage;
    },
    
    // Helper method to handle message_stop event for tool execution
    handleToolExecutionMessageStop(assistantMessage, messageUsage) {
      if (assistantMessage && messageUsage) {
        assistantMessage.usage = messageUsage;
        // Update context length for tool result messages too
        this.updateContextLength(messageUsage);
        this.updateCreditsUsed(messageUsage);
        this.$forceUpdate();
      }
      return { assistantMessage: null, messageUsage: null };
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

    handleDelegationContentBlockStart(c, childSessionId, childMsg) {
      if (c.content_block && c.content_block.type === 'tool_use') {
        const toolUse = {
          id: c.content_block.id,
          name: c.content_block.name,
          input: c.content_block.input || {},
          inputJson: '',
          status: 'preparing',
          result: null,
          error: null,
          rawResult: null,
          timestamp: new Date().toISOString(),
          blockIndex: c.index,
          approved: null,
          sessionId: childSessionId, // approvals route back to the child session
        };
        // Push into the reactive nested message first, then track the reactive
        // instance so its status -> pending_approval transition surfaces the
        // approval card live.
        let tracked = toolUse;
        if (childMsg) {
          childMsg.toolUses.push(toolUse);
          tracked = childMsg.toolUses[childMsg.toolUses.length - 1];
          this.scrollIfPinned();
        }
        this.getSessionToolMap(childSessionId).set(toolUse.id, tracked);
        this.getIndexMap(childSessionId).set(c.index, toolUse.id);
      }
    },

    handleDelegationContentBlockDelta(c, childSessionId, childMsg) {
      if (c.delta.type === 'text_delta') {
        // Sub-agent response text is real prose, not a thought. The whole sub-agent
        // transcript is already collapsed under the parent's agent panel, so render
        // response text directly as content (reasoning still routes to thoughts below).
        if (childMsg) {
          childMsg.content += this.nbspRegexOp(c.delta.text);
          this.scrollIfPinned();
        }
      } else if (c.delta.type === 'input_json_delta') {
        const toolId = this.getIndexMap(childSessionId).get(c.index);
        const toolUse = this.getSessionToolMap(childSessionId).get(toolId);
        if (toolUse) {
          toolUse.inputJson += c.delta.partial_json;
          toolUse.status = 'preparing';
        }
      } else if (c.delta.type === 'thought_delta') {
        if (childMsg) {
          childMsg.thoughts += this.nbspRegexOp(c.delta.text);
          this.scrollIfPinned();
        }
      }
    },

    // Sub-agent read-only tools honor the same auto-approval setting as the
    // main orchestrator; everything else still prompts for approval.
    handleDelegationContentBlockStop(c, childSessionId) {
      const toolId = this.getIndexMap(childSessionId).get(c.index);
      const toolUse = this.getSessionToolMap(childSessionId).get(toolId);
      if (toolUse && toolUse.status === 'preparing') {
        try {
          if (toolUse.inputJson) {
            toolUse.input = JSON.parse(toolUse.inputJson);
          }
          // Check if this tool should be auto-approved
          if (this.shouldAutoApproveTool(toolUse.name)) {
            if (this.checkContextLimitReached()) return;
            // Auto-approve the tool, routing execution to the child session
            toolUse.approved = true;
            this.queueTool(childSessionId, toolUse.id);
          } else {
            toolUse.status = 'pending_approval';
            toolUse.approved = null;
            this.mostRecentFloatingTool.set(childSessionId, toolUse);
          }
        } catch (error) {
          toolUse.status = 'error';
          toolUse.error = this.i18n.assistantToolParseInputError + ': ' + error.message;
        }
        this.scrollIfPinned();
      }
    },

    // Capture the raw tool result the backend persists shortly after a tool runs,
    // by re-reading the session's history. By default the newest tool_result in
    // the currently viewed session is assumed to be ours; for tools inside a
    // delegated sub-agent, pass the child sessionId and matchById so the result
    // is matched explicitly on the tool's use id.
    captureToolResult(toolUse, { sessionId = this.currentChatId, matchById = false } = {}) {
      const timer = setTimeout(async () => {
        this.pendingResultTimers.delete(timer);
        try {
          const response = await this.$root.papi.get(`/assistant/sessions/${sessionId}`);
          if (response.data && response.data.history) {
            // Find the most recent matching tool result message for this tool.
            const messages = response.data.history;
            for (let i = messages.length - 1; i >= 0; i--) {
              const msg = messages[i];
              if (!(msg.tags && msg.tags.includes('tool_result'))) continue;
              const resultBlock = msg.message.contentBlocks.find(block => block.toolResult);
              if (matchById && resultBlock?.toolResult?.toolUseId !== toolUse.id) continue;

              let rawResult = null;
              let toolError = '<nil>';
              // Always advance status when a matching tool_result exists, even when
              // its content is empty; otherwise the tool card spins forever.
              if (resultBlock?.toolResult?.isError || resultBlock?.toolResult?.status === 'error') {
                toolError = resultBlock.toolResult.content?.[0]?.text || this.i18n.assistantToolUnknownError;
              } else {
                rawResult = resultBlock?.toolResult?.content?.[0]?.json ?? null;
              }
              toolUse.rawResult = rawResult;
              toolUse.completedAt = msg.createTime;
              if (toolError != '<nil>') {
                toolUse.error = toolError;
                toolUse.status = 'error';
              } else {
                toolUse.status = 'completed';
              }
              break;
            }
          }
        } catch (error) {
          this.$root.showError(this.i18n.assistantNoRawToolResult + ': ' + error.message);
        }
      }, 1000); // Wait 1 second for the backend to save the result
      this.pendingResultTimers.add(timer);
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

      // When this tool's session is a live child entry at entry time, this call is
      // executing an embedded sub-agent tool; capture its raw result for the
      // collapsed dropdown. The delegationChildren map is the single source of
      // truth for delegation ownership — always derived, never copied to a local.
      const isChildToolCall = this.delegationChildren.has(toolStreamingSessionId);
      let childResultCaptured = false;
      // Tracks whether this stream involved a delegation (a child tool call, or a
      // kickoff that emitted delegation_start). When it did, the normal-path raw
      // result capture must be skipped: the parent's resumed turn would otherwise
      // attach the delegation tool_result to the wrong tool card.
      let sawDelegation = isChildToolCall;
      let childMsg = null;
      let reader = null;

      try {
        // Create ToolRequest object with history and params
        const toolRequest = {
          sessionId: toolStreamingSessionId,
          toolUseId: toolUse.id,
          params: toolUse.input,
          model: this.currentModel,
        };

        this.applyToolSpecificChanges(toolUse, toolRequest);

        // Use streaming for tool results
        const response = await this.$root.papi.post(`/assistant/tool/${toolUse.name}`, toolRequest, {
          headers: {
            'Accept': 'text/event-stream'
          },
          responseType: 'stream',
          adapter: 'fetch',
        });

        // Update tool status to executing only if visible in the current session
        if (this.currentChatId === toolStreamingSessionId) {
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

            // Delegation markers retarget the stream between the sub-agent's nested
            // session and the parent thread (the backend chains both onto one response).
            if (c.type === 'delegation_start') {
              sawDelegation = true;
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
                this.executingToolsBySession.delete(toolStreamingSessionId);
                this.toolIndexToIdBySession.delete(toolStreamingSessionId);
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
                  // The embedded tool's result is now saved in the child session;
                  // capture it once for the collapsed raw-result dropdown.
                  if (isChildToolCall && !childResultCaptured) {
                    this.captureToolResult(toolUse, { sessionId: toolUse.sessionId, matchById: true });
                    childResultCaptured = true;
                  }
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
                  // Capture raw tool result using helper method. Skip when this
                  // stream involved a delegation: the resumed parent turn must not
                  // attach the delegation tool_result to the (child) tool card.
                  if (!sawDelegation) {
                    this.captureToolResult(toolUse);
                  }

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
                  const stopResult = this.handleToolExecutionMessageStop(assistantMessage, messageUsage);
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
          this.executingToolsBySession.delete(toolStreamingSessionId);
          this.toolIndexToIdBySession.delete(toolStreamingSessionId);
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
    getToolStatusIcon(status) {
      switch (status) {
        case 'preparing': return 'fa-cog';
        case 'queued': return 'fa-cog';
        case 'skipped': return 'fa-circle-info';
        case 'pending_approval': return 'fa-question-circle';
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
        case 'executing': return this.i18n.executing;
        case 'completed': return this.i18n.completed;
        case 'error': return this.i18n.error;
        case 'rejected': return this.i18n.rejected;
        default: return this.i18n.statusUnknown;
      }
    },
    async approveTool(toolUse) {
      try {
        if (this.checkContextLimitReached()) return;
        toolUse.approved = true;
        toolUse.status = 'preparing';
        this.mostRecentFloatingTool.delete(toolUse.sessionId || this.currentChatId);
        this.queueTool(toolUse.sessionId || this.currentChatId, toolUse.id);
      } catch (error) {
        toolUse.status = 'error';
        toolUse.error = this.i18n.assistantToolUseFail + ': ' + error.message;
      }
      this.scrollToBottom();
    },
    async rejectTool(toolUse) {
      if (this.checkContextLimitReached()) return;
      toolUse.approved = false;
      toolUse.status = 'rejected';
      this.mostRecentFloatingTool.delete(toolUse.sessionId || this.currentChatId);
      toolUse.error = this.i18n.assistantToolUseReject;
      
      // Add a message indicating the tool was rejected
      const rejectionMessage = this.$root.localizeMessage(this.i18n.assistantToolUseRejectMessage, {toolName: toolUse.name});
      await this.callAIAPI(rejectionMessage);

      this.scrollToBottom();
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
      
      if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
        // proper tool use approach
        const toolResultBlock = msg.message.contentBlocks.find(block => block.toolResult);
        if (toolResultBlock && toolResultBlock.toolResult.content?.length) {
          const cb = toolResultBlock.toolResult.content[0];
          if (toolResultBlock.toolResult.isError || toolResultBlock.toolResult.status === 'error') {
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
                matchingToolUse.status = "error";
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
      let skip_next = false;
      
      if (toolBlocks.length > 0) {
        if (i < backendMessages.length - 1 && (!backendMessages[i + 1].tags || !backendMessages[i + 1].tags.includes('tool_result'))) {
          const nextMessage = backendMessages[i + 1];
          if (nextMessage.message.contentBlocks[0].text && nextMessage.message.contentBlocks[0].text.includes('rejected by the user')) {
            frontendMsg.toolUses = toolBlocks.map(block => ({
              id: block.id || 'unknown',
              name: block.name || 'unknown',
              input: block.input || {}, // Ensure input is always an object, never null/undefined
              status: 'rejected',
              result: null,
              error: this.i18n.assistantToolUseReject,
              rawResult: null,
              timestamp: msg.createTime || new Date().toISOString(),
              approved: false
            }));
            skip_next = true;
          } else if (nextMessage.message.role === 'user') {
            frontendMsg.toolUses = toolBlocks.map(block => ({
              id: block.id || 'unknown',
              name: block.name || 'unknown',
              input: block.input || {}, // Ensure input is always an object, never null/undefined
              status: 'skipped',
              result: null,
              error: null,
              timestamp: msg.createTime || new Date().toISOString(),
              approved: false
            }));
          }
        // Using "else if" instead of "else" prevents tool uses that haven't been interacted with from appearing as completed after refreshing
        } else if (i < backendMessages.length - 1) {
          frontendMsg.toolUses = toolBlocks.map(block => ({
            id: block.id || 'unknown',
            name: block.name || 'unknown',
            input: block.input || {}, // Ensure input is always an object, never null/undefined
            status: 'completed', // Assume completed since it's from history
            result: null,
            error: null,
            rawResult: null, // Will be populated by subsequent tool result message
            timestamp: msg.createTime || new Date().toISOString(),
            approved: true
          }));
        // Allows tool use blocks at the end of a session to persist even when the user clicks away
        } else {
          frontendMsg.toolUses = toolBlocks.map(block => {
            // A delegate that spawned a sub-session is running, not awaiting approval:
            // re-prompting would spawn a duplicate sub-session.
            const inFlightDelegation = !!(this._loadSubSessions && this._loadSubSessions.byParentToolUseId.has(block.id));
            const toolUse = {
              id: block.id || 'unknown',
              name: block.name || 'unknown',
              input: block.input || {}, // Ensure input is always an object, never null/undefined
              status: inFlightDelegation ? 'executing' : 'pending_approval',
              result: null,
              error: null,
              rawResult: null, // Will be populated by subsequent tool result message
              timestamp: msg.createTime || new Date().toISOString(),
              approved: inFlightDelegation ? true : null,
              sessionId: this.currentChatId
            };
            this.getSessionToolMap(this.currentChatId).set(toolUse.id, toolUse);
            if (!inFlightDelegation) {
              this.mostRecentFloatingTool.set(this.currentChatId, toolUse);
            }
            return toolUse;
          });
        }
      }

      // Rebuild nested sub-agent activity for any delegate tool blocks.
      if (frontendMsg.toolUses) {
        this.reconstructDelegateChildSessions(frontendMsg.toolUses);
      }

      return skip_next;
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
              if (block.toolResult.isError || block.toolResult.status === 'error') {
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

        const childMsg = { thoughts: '', toolUses: [] };

        // Fold the sub-agent's response text and reasoning into a single collapsed thought.
        let thoughtText = m.thoughts || '';
        for (const b of (m.contentBlocks || [])) {
          if (b.type === 'text' && b.text) {
            thoughtText += b.text;
          } else if (b.type === 'tool_use') {
            const childTool = {
              id: b.id || 'unknown',
              name: b.name || 'unknown',
              input: b.input || {},
              status: 'completed', // provisional; finalized below
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
        childMessages.push(childMsg);
      }

      // Finalize tools with no tool_result: a delegate that spawned a sub-session is
      // running; the backend-flagged tool_use awaits approval; anything else stays.
      for (const t of toolUseById.values()) {
        if (t.rawResult != null || t.status === 'error') continue; // resolved
        if (index.byParentToolUseId.has(t.id)) {
          t.status = 'executing';
          t.approved = true;
        } else if (t.id === pendingToolUseId) {
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

    // Helper method to convert backend message format to frontend format
    convertBackendMessagesToFrontend(backendMessages) {
      const processedMessages = [];
      // Reset context length when loading from backend
      this.creditsUsed = 0;
      this.contextLength = 0;
      this.contextStartMessageIndex = -1;
      let justResetContext = false;
      
      let skip_next = false;

      for (let i = 0; i < backendMessages.length; i++) {
        
        if (skip_next) {
          skip_next = false;
          continue
        }
        
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
          const toolSkipNext = this.processToolUseBlocks(msg, frontendMsg, backendMessages, i);
          if (toolSkipNext) {
            skip_next = true;
          }
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
      return ['query_events', 'get_playbooks', 'query_cases', 'query_detections'].includes(toolName) && this.alwaysApproveReadRequests;
    },

    clearStreamingStates() {
      this.activeStreamingSessionId = null;
      this.isTyping = false;
      this.isStreaming = false;
      // Drop delegated sub-agent linkage so stale child sessions from a previous
      // conversation can't mis-nest output after switching/loading/deleting chats.
      this.delegationChildren.clear();
      // Cancel any deferred raw-result captures so they can't fire (and surface a
      // late error toast) against a conversation the user has navigated away from.
      this.pendingResultTimers.forEach(clearTimeout);
      this.pendingResultTimers.clear();
    },
    
    checkIfDeleted(session) {
      if (session?.deleteTime) {
        this.canChat = false;
        this.$root.showWarning(this.i18n.assistantChatNoResume);
      } else {
        this.canChat = true;
      }
    },

    updateModelParams() {
      if (!this.currentModel || this.modelsMap.size == 0) return;
      this.contextLimitSmall = this.modelsMap.get(this.currentModel).contextLimitSmall;
      this.contextLimitLarge = this.modelsMap.get(this.currentModel).contextLimitLarge;
      this.charsPerTokenEstimate = this.modelsMap.get(this.currentModel).charsPerTokenEstimate;
      this.lowBalanceColorAlert = this.modelsMap.get(this.currentModel).lowBalanceColorAlert;
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
    getSessionToolMap(sessionId) {
      let m = this.executingToolsBySession.get(sessionId);
      if (!m) {
        m = new Map();
        this.executingToolsBySession.set(sessionId, m);
      }
      return m;
    },
    getIndexMap(sessionId) {
      let m = this.toolIndexToIdBySession.get(sessionId);
      if (!m) {
        m = new Map();
        this.toolIndexToIdBySession.set(sessionId, m);
      }
      return m;
    },
    queueTool(sessionId, toolUseId) {
      const q = this.toolQueues.get(sessionId) || [];
      q.push(toolUseId);
      this.toolQueues.set(sessionId, q);
      this.runToolQueue(sessionId);
    },
    async runToolQueue(sessionId) {
      if (this.toolRunnerBusy.has(sessionId)) return;
      this.toolRunnerBusy.add(sessionId);
      try {
        let q = this.toolQueues.get(sessionId) || [];
        const toolMap = this.getSessionToolMap(sessionId);
        while (q.length) {
          const toolUseId = q[0];
          const toolUse = toolMap.get(toolUseId);
          if (!toolUse || ['completed','error','rejected'].includes(toolUse.status)) {
            q.shift();
            continue;
          }
          toolUse.status = 'executing';
          await this.executeTool(toolUse);
          q.shift();
          q = this.toolQueues.get(sessionId) || [];
        }
      } finally {
        this.toolRunnerBusy.delete(sessionId);
      }
    },
    checkForActivity() {
      const tQ = this.toolQueues.get(this.currentChatId) || [];
      return this.isStreaming || this.isTyping || tQ.length > 0;
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
