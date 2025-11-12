// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-assistant', 'pages/assistant.html');

routes.push({ path: '/assistant/:sessionId?', name: 'assistant', component: {
  template: '#page-assistant',
  data() { return {
    i18n: this.$root.i18n,
    messages: [],
    newMessage: '',
    isTyping: false,
    chatHistory: [],
    currentChatId: null,
    creditsRemaining: 0,
    executingToolsBySession: new Map(), // Map<sessionId, Map<toolUseId, toolUse>>
    toolIndexToIdBySession: new Map(), // Map<sessionId, Map<index, toolUseId>>
    toolQueues: new Map(), // Map<sessionId, Array<toolUseId>>
    toolRunnerBusy: new Set(), // Set<sessionId>
    mostRecentFloatingTool: new Map(), // Map<sessionId, toolUse>
    contextLength: 0, // Track total context length
    increaseContextLimit: false, // Toggle for max context threshold
    restoreLastActive: false, // Toggle to restore last active chat
    alwaysApproveReadRequests: false,
    assistantEnabled: false,
    isStreaming: false,
    showChatHistory: true,
    investigationMsg: '',
    compressContextMsg: '',
    contextLimitSmall: 0,
    contextLimitLarge: 0,
    thresholdColorRatioLow: 0.5,
    thresholdColorRatioMed: 0.75,
    thresholdColorRatioMax: 1,
    lowBalanceColorAlert: 0,
    availableModels: [],
    modelsMap: new Map(),
    currentModel: '',
    activeStreamingSessionId: null, // Track which session is actively streaming
    autoScrollOnNextRender: false, // gate for programmatic scrolls
    isPinnedToBottom: true, // user is at (or near) bottom?
    canChat: true,
    paramsLoaded: false,
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
    'currentModel': 'saveLocalSettings'
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
      if (this.availableModels.length > 0) {
        this.modelsMap = new Map(
          this.availableModels.filter(m => m.enabled).map(m => [m.id, m])
        );
        for (let val of this.modelsMap.values()) {
          if (val.contextLimitLarge < val.contextLimitSmall) val.contextLimitLarge = val.contextLimitSmall;
        }
        if (!this.currentModel || !this.modelsMap.has(this.currentModel)) this.currentModel = this.availableModels[0].id;
      }
      this.updateModelParams();

      this.$root.showDisclaimer(this.i18n.assistantDisclaimerMessage, this.i18n.assistantDisclaimerTitle, this.i18n.getStarted, 'settings.disclaimer.acknowledged.onionai');

      this.paramsLoaded = true;
      
      if (this.assistantEnabled) {
        if (!this.$root.disclaimer) {
          await this.loadStoredChats();
          await this.handleRouteSessionId();
          await this.loadCredits();
        }
      } else {
        this.$root.disclaimer = false;
      }
    },
    
    // Calculate context length from usage data (input_tokens + output_tokens)
    calculateContextFromUsage(usage) {
      if (!usage) return 0;
      const inputTokens = usage.input_tokens || 0;
      const outputTokens = usage.output_tokens || 0;
      return inputTokens + outputTokens;
    },
    
    // Update the total context length
    updateContextLength(usage) {
      if (usage) {
        const messageContext = this.calculateContextFromUsage(usage);
        this.contextLength += messageContext;
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
      } catch (error) {
        this.$root.showError(error);
      }
    },
    async loadStoredChats() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('/assistant/sessions');
        if (response.data && Array.isArray(response.data)) {
          // Convert backend format to frontend format
          this.chatHistory = response.data.map(session => ({
            sessionId: session.sessionId,
            title: this.generateTitleFromMessage(session),
            messages: [], // Will be loaded when session is opened
            timestamp: session.createTime || new Date().toISOString(),
            lastUpdated: session.createTime || new Date().toISOString()
          }));
        } else {
          this.chatHistory = [];
        }
      } catch (error) {
        this.$root.showError(this.i18n.assistantUnableToLoadHistory + ': ' + error.message);

        // Fallback to empty array if backend is unavailable
        this.chatHistory = [];
      } finally {
        this.$root.stopLoading();
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
          // Session ID in URL doesn't exist, start new chat with this ID
          this.currentChatId = urlSessionId;
          this.saveCurrentChatId();
          
          // Check if this is an investigation session
          const isInvestigation = this.$route.query.investigation === 'true';
          
          if (isInvestigation) {
            try {
              const investigationPrompt = this.generateInvestigationPrompt(this.$route.query);
              // This is a new investigation session, start with investigation prompt
              this.$nextTick(() => {
                this.startInvestigationSession(investigationPrompt);
              });
            } catch (error) {
              this.$root.showError(this.i18n.assistantUnableToParseInvestigation + ': ' + error.message);
            }
            
          } else if (this.messages.length > 1) {
            this.loadNewChatScreen();
          }
        } finally {
          this.$root.stopLoading();
        }
      } else {
        // No session ID in URL, restore last active chat
        await this.restoreLastActiveChat();
      }
    },
    async restoreLastActiveChat() {
      if (!this.restoreLastActive) {
        this.startNewChat();
        return;
      }
      const lastChatId = this.loadCurrentChatId();
      if (lastChatId && this.chatHistory.length > 0) {
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
    async loadCredits() {
      try {
        const response = await this.$root.papi.get('/assistant/balance');
        if (response.data) {
          if (response.data.health_status === 'healthy') {
            this.creditsRemaining = response.data.credit_balance || 0;
          } else {
            throw new Error(this.i18n.assistantBalanceCheckUnhealthy);
          }
        }
      } catch (error) {
        this.$root.showError(this.i18n.assistantUnableToLoadCredits + ': ' + error.message);
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
      return 'chat_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
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

      // Check if context length has reached the limit
      if (this.checkContextLimitReached()) return;
      
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
      
      try {
        // Call the actual AI API - session ID is already set
        await this.callAIAPI(messageText, tags);

        // Refresh chat history to show the latest session
        await this.loadStoredChats();
      } catch (error) {
        this.$root.showError(this.i18n.assistantNoResponse + ': ' + error.message);
        this.isTyping = false;
      }
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

      assistantMessage = {
        role: 'assistant',
        content: Vue.ref(''), // MUST be ref
        timestamp: new Date().toISOString(),
        usage: Vue.ref(null),
        toolUses: Vue.ref([]) // Track tool uses in this message
      };

      // Sometimes usage comes in message_start
      let messageUsage = null;
      if (c.message && c.message.usage) {
        messageUsage = c.message.usage;
      }

      this.messages.push(assistantMessage);
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
        
        this.getSessionToolMap(targetSessionId).set(toolUse.id, toolUse);
        this.getIndexMap(targetSessionId).set(c.index, toolUse.id);
        
        // Only update UI if this is for the current session and we have an assistant message
        if (assistantMessage && targetSessionId === this.currentChatId) {
          assistantMessage.toolUses.value.push(toolUse);
          this.scrollIfPinned();
        }
      }
    },
    
    // Helper method to handle content_block_delta event
    handleContentBlockDelta(c, assistantMessage, sessionId = null) {
      const targetSessionId = sessionId || this.currentChatId;
      
      if (assistantMessage && c.delta.type === 'text_delta' && targetSessionId === this.currentChatId) {
        // Only update UI if this is for the current session
        assistantMessage.content.value += c.delta.text;
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
        // Set the ref's value
        assistantMessage.usage.value = messageUsage;
        // Update context length
        this.updateContextLength(messageUsage);
        this.$forceUpdate();
      }
      
      return { assistantMessage: null, messageUsage: null };
    },
    
    async callAIAPI(userMessage, tags = null) {
      // Capture the session ID at the start of the API call
      const streamingSessionId = this.currentChatId;
      this.activeStreamingSessionId = streamingSessionId;
      
      try {
        const response = await this.$root.papi.post('/assistant/chat', {
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
        const reader = stream.pipeThrough(new TextDecoderStream()).getReader();

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
          
          // Show error to user
          this.$root.showError(this.i18n.assistantNoResponse + ': ' + (error.response?.data?.error || error.message));
        }
        
        // Clear the active streaming session if this was the active one
        if (this.activeStreamingSessionId === streamingSessionId) {
          this.activeStreamingSessionId = null;
        }
      }
    },
    
    // Helper method to handle message_start event for tool execution
    handleToolExecutionMessageStart(c, assistantMessage, toolUse) {
      assistantMessage = {
        role: 'assistant',
        content: Vue.ref(''),
        timestamp: new Date().toISOString(),
        usage: Vue.ref(null),
        toolUses: Vue.ref([]), // Track tool uses in this response too
        isToolResult: true,
        toolName: toolUse.name,
        toolId: toolUse.id
      };

      let messageUsage = null;
      if (c.message && c.message.usage) {
        messageUsage = c.message.usage;
      }

      this.messages.push(assistantMessage);
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
        
        this.getSessionToolMap(targetSessionId).set(newToolUse.id, newToolUse);
        this.getIndexMap(targetSessionId).set(c.index, newToolUse.id);
        
        // Only update UI if this is for the current session and we have an assistant message
        if (assistantMessage && targetSessionId === this.currentChatId) {
          assistantMessage.toolUses.value.push(newToolUse);
          this.scrollIfPinned();
        }
      }
    },
    
    // Helper method to handle content_block_delta event for tool execution
    handleToolExecutionContentBlockDelta(c, assistantMessage, sessionId = null) {
      const targetSessionId = sessionId || this.currentChatId;
      
      if (assistantMessage && c.delta.type === 'text_delta' && targetSessionId === this.currentChatId) {
        // Only update UI if this is for the current session
        assistantMessage.content.value += c.delta.text;
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
        assistantMessage.usage.value = messageUsage;
        // Update context length for tool result messages too
        this.updateContextLength(messageUsage);
        this.$forceUpdate();
      }
      return { assistantMessage: null, messageUsage: null };
    },
    
    // Helper method to capture raw tool result from backend
    async captureRawToolResult(toolUse) {
      setTimeout(async () => {
        try {
          // Reload the chat history to get the raw result that was just saved
          const response = await this.$root.papi.get(`/assistant/sessions/${this.currentChatId}`);
          if (response.data && Array.isArray(response.data)) {
            // Find the last tool result message for this tool
            for (let i = response.data.length - 1; i >= 0; i--) {
              const msg = response.data[i];
              if (msg.tags && msg.tags.includes('tool_result')) {
                let rawResult = null;
                let toolError = null;
                const textBlock = msg.message.contentBlocks.find(block => block.type === 'text');
                if (textBlock && textBlock.text) {
                  // Parse the tool result format: "ToolUseId: tooluse_QdvZoVlXQNm0PBuqFuqRmA, Result: [actual_result_data]"
                  const toolResultText = textBlock.text;
                  const toolUseIdMatch = toolResultText.match(/ToolUseId:\s*([^,]+)/);
                  const resultMatch = toolResultText.match(/Result:\s*(.+)$/s);
                  const errorMatch = toolResultText.match(/Error:\s*([^,]+)/);
                  
                  if (toolUseIdMatch && resultMatch && errorMatch) {
                    rawResult = resultMatch[1].trim();
                    toolError = errorMatch[1].trim();
                  }
                }
                // This is a tool result - associate it with our tool use
                toolUse.rawResult = rawResult;
                toolUse.completedAt = msg.createTime;
                if (toolError != "<nil>") {
                  toolUse.error = toolError;
                  toolUse.status = "error";
                } else {
                  toolUse.status = "completed";
                }
                break;
              }
            }
          }
        } catch (error) {
          this.$root.showError(this.i18n.assistantNoRawToolResult + ': ' + error.message);
        }
      }, 1000); // Wait 1 second for the backend to save the result
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
      text = this.$root.performMermaidRegexes(text);
      md = this.$root.formatMarkdown(text, true);
      if (!this.isStreaming) {
        this.$nextTick(() => {
          this.$root.renderMermaid();
        });
      }
      return md;
    },
    formatChatDate(timestamp) {
      return this.$root.formatDateTime(timestamp);
    },
    formatCount(count) {
      return this.$root.formatCount(count);
    },
    async executeTool(toolUse) {
      // Use the tool's session ID if available, otherwise use current session
      const toolStreamingSessionId = toolUse.sessionId || this.currentChatId;
      
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

        // Check if we should update UI (current session)
        const isCurrentSession = this.currentChatId === toolStreamingSessionId;

        // Update tool status to executing only if still in same session
        if (isCurrentSession) {
          toolUse.status = 'executing';
        }

        // Stream the AI's response to the tool result
        const stream = response.data;
        const reader = stream.pipeThrough(new TextDecoderStream()).getReader();

        if (isCurrentSession) {
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

            // Always process chunks for tool execution logic, but only update UI if current session
            switch (c.type) {
              case 'message_start':
                if (isCurrentSession) {
                  // Capture raw tool result using helper method
                  this.captureRawToolResult(toolUse);
                  
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

          // Only update UI if still in same session
          if (isCurrentSession) {
            await this.$nextTick();
          }
        }
        
        // Only update UI state if we're still in the same session
        if (isCurrentSession) {
          this.isStreaming = false;
          // Update credits after tool execution
          await this.loadCredits();
        }
        
      } catch (error) {
        // Always update tool status with error, but only update UI if current session
        toolUse.status = 'error';
        toolUse.error = error.message;

        const isCurrentSession = this.currentChatId === toolStreamingSessionId;
        
        if (isCurrentSession) {
          this.isStreaming = false;
          
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
        if (response.data && Array.isArray(response.data) && response.data.length > 0) {
          this.currentChatId = sessionId;
          this.messages = this.convertBackendMessagesToFrontend(response.data);
          this.saveCurrentChatId();

          await this.scrollToBottomSettled({ maxWait: 6000, settleDelay: 200 });

          // Blocks user from sending messages in deleted chats
          this.checkIfDeleted(sessionId);

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
      
      // Find the assistant message with the matching tool use and add the raw result
      if (toolUseId && rawResult && toolError) {
        // Look backwards through processed messages to find the tool use
        for (let j = processedMessages.length - 1; j >= 0; j--) {
          const processedMsg = processedMessages[j];
          if (processedMsg.role === 'assistant' && processedMsg.toolUses) {
            const toolUses = processedMsg.toolUses.value;
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
        const toolUses = prevMessage.toolUses.value;
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
          frontendMsg.content = textBlocks.map(block => block.text).join('\n');
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
            frontendMsg.toolUses = Vue.ref(toolBlocks.map(block => ({
              id: block.id || 'unknown',
              name: block.name || 'unknown',
              input: block.input || {}, // Ensure input is always an object, never null/undefined
              status: 'rejected',
              result: null,
              error: this.i18n.assistantToolUseReject,
              rawResult: null,
              timestamp: msg.createTime || new Date().toISOString(),
              approved: false
            })));
            skip_next = true;
          } else if (nextMessage.message.role === 'user') {
            frontendMsg.toolUses = Vue.ref(toolBlocks.map(block => ({
              id: block.id || 'unknown',
              name: block.name || 'unknown',
              input: block.input || {}, // Ensure input is always an object, never null/undefined
              status: 'skipped',
              result: null,
              error: null,
              timestamp: msg.createTime || new Date().toISOString(),
              approved: false
            })));
          }
        // Using "else if" instead of "else" prevents tool uses that haven't been interacted with from appearing as completed after refreshing
        } else if (i < backendMessages.length - 1) {
          frontendMsg.toolUses = Vue.ref(toolBlocks.map(block => ({
            id: block.id || 'unknown',
            name: block.name || 'unknown',
            input: block.input || {}, // Ensure input is always an object, never null/undefined
            status: 'completed', // Assume completed since it's from history
            result: null,
            error: null,
            rawResult: null, // Will be populated by subsequent tool result message
            timestamp: msg.createTime || new Date().toISOString(),
            approved: true
          })));
        // Allows tool use blocks at the end of a session to persist even when the user clicks away
        } else {
          frontendMsg.toolUses = Vue.ref(toolBlocks.map(block => {
            const toolUse = {
              id: block.id || 'unknown',
              name: block.name || 'unknown',
              input: block.input || {}, // Ensure input is always an object, never null/undefined
              status: 'pending_approval',
              result: null,
              error: null,
              rawResult: null, // Will be populated by subsequent tool result message
              timestamp: msg.createTime || new Date().toISOString(),
              approved: null,
              sessionId: this.currentChatId
            };
            this.getSessionToolMap(this.currentChatId).set(toolUse.id, toolUse);
            this.mostRecentFloatingTool.set(this.currentChatId, toolUse);
            return toolUse;
          }));
        }
      }
      
      return skip_next;
    },

    // Helper method to convert backend message format to frontend format
    convertBackendMessagesToFrontend(backendMessages) {
      const processedMessages = [];
      // Reset context length when loading from backend
      this.contextLength = 0;
      
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

        // Extract message content using helper method
        this.extractMessageContent(msg, frontendMsg);
        
        // Process tool use blocks if present
        if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
          const toolSkipNext = this.processToolUseBlocks(msg, frontendMsg, backendMessages, i);
          if (toolSkipNext) {
            skip_next = true;
          }
        }

        if (msg.tags && msg.tags.includes('context_compression')) {
          // reset context, messages prior to this message are no longer
          // sent to the AI
          this.contextLength = 0;
        }

        // Handle usage information if present
        if (msg.message.usage) {
          frontendMsg.usage = Vue.ref(msg.message.usage);
          // Update context length for loaded messages
          this.updateContextLength(msg.message.usage);
        }

        processedMessages.push(frontendMsg);
      }
      
      return processedMessages;
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
      const maxContextLength = this.increaseMaxContextThreshold ? this.contextLimitLarge : this.contextLimitSmall;
      if (this.contextLength >= maxContextLength / 2) {
        return 'primary';
      }

      return 'secondary';
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
    },

    // Load all local settings
    loadLocalSettings() {
      var prefix = 'settings.assistant';
      if (localStorage[prefix + '.increaseContextLimit']) this.increaseContextLimit = localStorage[prefix + '.increaseContextLimit'] == 'true';
      if (localStorage[prefix + '.restoreLastActive']) this.restoreLastActive = localStorage[prefix + '.restoreLastActive'] == 'true';
      if (localStorage[prefix + '.alwaysApproveReadRequests']) this.alwaysApproveReadRequests = localStorage[prefix + '.alwaysApproveReadRequests'] == 'true';
      if (localStorage[prefix + '.showChatHistory']) this.showChatHistory = localStorage[prefix + '.showChatHistory'] == 'true';
      if (localStorage[prefix + '.currentModel']) this.currentModel = localStorage[prefix + '.currentModel'];
    },

    // Check if a tool should be auto-approved based on localStorage settings
    shouldAutoApproveTool(toolName) {
      return ['query_events', 'get_playbooks', 'query_cases'].includes(toolName) && this.alwaysApproveReadRequests;
    },

    // Open the options menu programmatically
    openOptionsMenu() {
      this.$nextTick(() => {
        // Find the options expansion panel and open it
        const optionsPanel = this.$el.querySelector('[data-aid="assistant_options"]');
        if (optionsPanel) {
          // Trigger click on the expansion panel title to open it
          const panelTitle = optionsPanel.querySelector('.v-expansion-panel-title');
          if (panelTitle) {
            panelTitle.click();
          }
        }
        
        // Scroll to the options panel
        const optionsHeader = this.$el.querySelector('#chatOptionsHeader');
        if (optionsHeader) {
          optionsHeader.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      });
    },

    clearStreamingStates() {
      this.activeStreamingSessionId = null;
      this.isTyping = false;
      this.isStreaming = false;
    },
    
    checkIfDeleted(sessionId) {
      const sessionInHistory = this.chatHistory.some(session => session.sessionId === sessionId);
      if (!sessionInHistory) {
        this.canChat = false;
        this.$root.showWarning(this.i18n.assistantChatIsDeleted);
      } else {
        this.canChat = true;
      }
    },

    updateModelParams() {
      if (!this.currentModel || this.modelsMap.size == 0) return;
      this.contextLimitSmall = this.modelsMap.get(this.currentModel).contextLimitSmall;
      this.contextLimitLarge = this.modelsMap.get(this.currentModel).contextLimitLarge;
      this.lowBalanceColorAlert = this.modelsMap.get(this.currentModel).lowBalanceColorAlert;
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
      
      await this.sendMessage(['context_compression']);
      this.loadChatFromBackend(this.currentChatId);
      
      if (oldMsg) this.newMessage = oldMsg;
    },

    messageClassesFromTags(tags) {
      return tags.map(tag => 'msgTag-' + tag);
    },
  }
}});