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
    executingTools: new Map(), // Track tool executions by ID
    contextLength: 0, // Track total context length
    increaseMaxContextThreshold: false, // Toggle for max context threshold
    restoreLastActive: false, // Toggle to restore last active chat
    alwaysApproveReadRequests: false,
    assistantEnabled: false,
    isStreaming: false,
    investigationMsg: '',
    contextLimitSmall: 200000,
    contextLimitLarge: 1000000,
    thresholdColorRatioLow: 0.5,
    thresholdColorRatioMed: 0.75,
    thresholdColorRatioMax: 1,
    lowBalanceColorAlert: 500000,
  }},
  async created() {
    // this.$root.showDisclaimer(this.i18n.assistantDisclaimerMessage, this.i18n.assistantDisclaimerTitle, this.i18n.acknowledge, 'so-data-retention-disclaimer');
    this.loadContextThresholdSetting();
    this.loadLastActiveSetting();
    this.loadReadApprovalSetting();
    this.loadChatHistory();
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
    'increaseMaxContextThreshold'() {
      this.saveContextThresholdSetting();
    },
    'restoreLastActive' () {
      this.saveLastActiveSetting();
    },
    'alwaysApproveReadRequests'() {
      this.saveReadApprovalSetting();
    }
  },
  methods: {

    async initAssistant(params) {
      this.assistantEnabled = params["enabled"] && this.$root.isLicensed('oai');
      this.investigationMsg = params["investigationPrompt"];
      this.contextLimitSmall = params["contextLimitSmall"];
      this.contextLimitLarge = params["contextLimitLarge"];
      this.thresholdColorRatioLow = params["thresholdColorRatioLow"];
      this.thresholdColorRatioMed = params["thresholdColorRatioMed"];
      this.thresholdColorRatioMax = params["thresholdColorRatioMax"];
      this.lowBalanceColorAlert = params["lowBalanceColorAlert"];

      this.$root.showDisclaimer(this.i18n.assistantDisclaimerMessage, this.i18n.assistantDisclaimerTitle, this.i18n.getStarted, 'so-data-retention-disclaimer');
      
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
    
    async loadChatHistory() {
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
        localStorage.setItem('so-current-chat-id', this.currentChatId);
      } else {
        localStorage.removeItem('so-current-chat-id');
      }
    },
    loadCurrentChatId() {
      return localStorage.getItem('so-current-chat-id');
    },
    async handleRouteSessionId() {
      const urlSessionId = this.$route.params.sessionId;
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
            this.loadChatHistory();
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
        return;
      }
      const lastChatId = this.loadCurrentChatId();
      if (lastChatId && this.chatHistory.length > 0) {
        this.$root.startLoading();
        try {
          // Update URL to reflect the current session
          this.updateUrlWithSessionId(lastChatId);
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
          this.creditsRemaining = response.data.credit_balance || 0;
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
      await this.saveCurrentChat(); // Save current chat before switching
      this.$root.startLoading();
      try {
        if (this.currentChatId === chat.sessionId) {
          await this.loadChatFromBackend(chat.sessionId);
        }
        this.updateUrlWithSessionId(chat.sessionId);
        this.scrollToBottom();
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
          this.loadChatHistory(); // Reset to welcome message
          // Navigate to chat without session ID
          this.$router.push({ name: 'assistant' });
        }
        
      } catch (error) {
        this.$root.showError(this.i18n.assistantUnableToDeleteChat + ': ' + (error.response?.data?.error || error.message));
      }
    },
    async startNewChat() {
      await this.saveCurrentChat(); // Save current chat before starting new one
      this.currentChatId = null;
      this.saveCurrentChatId(); // Clear the saved current chat ID
      this.loadChatHistory(); // Reset to welcome message (also resets context length)
      // Navigate to chat without session ID
      this.$router.push({ name: 'assistant' });
    },
    updateUrlWithSessionId(sessionId) {
      // Only update URL if it's different from current
      if (this.$route.params.sessionId !== sessionId) {
        this.$router.replace({ name: 'assistant', params: { sessionId: sessionId } });
      }
    },
    async sendMessage() {
      if (!this.newMessage.trim()) return;
      
      if (!this.assistantEnabled) {
        this.$root.showError(this.i18n.assistantNotAvailable);
        return;
      }

      // Check if context length has reached the limit
      const maxContextLength = this.increaseMaxContextThreshold ? this.contextLimitLarge : this.contextLimitSmall;
      if (this.contextLength >= maxContextLength) {
        const formattedLimit = this.formatCount(maxContextLength);
        this.$root.showError(`Context length limit reached (${formattedLimit}+ tokens). Please start a new chat to continue.`);
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
        this.updateUrlWithSessionId(this.currentChatId);
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

      // Add user message to chat
      this.messages.push(userMessage);
      const messageText = this.newMessage.trim();
      this.newMessage = '';
      this.scrollToBottom();
      
      // Show typing indicator
      this.isTyping = true;
      
      try {
        // Call the actual AI API - session ID is already set
        await this.callAIAPI(messageText);
        
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
      this.scrollToBottom();
      
      return { assistantMessage, messageUsage };
    },
    
    // Helper method to handle content_block_start event
    handleContentBlockStart(c, assistantMessage) {
      // Handle tool use blocks
      if (c.content_block && c.content_block.type === 'tool_use') {
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
          approved: null // null = pending, true = approved, false = rejected
        };
        
        if (assistantMessage) {
          assistantMessage.toolUses.value.push(toolUse);
          this.executingTools.set(toolUse.id, toolUse);
          // Also track by block index for delta updates
          this.executingTools.set(`block_${c.index}`, toolUse);
          this.scrollToBottom();
        }
      }
    },
    
    // Helper method to handle content_block_delta event
    handleContentBlockDelta(c, assistantMessage) {
      if (assistantMessage && c.delta.type === 'text_delta') {
        // update the ref's value
        assistantMessage.content.value += c.delta.text;
        this.scrollToBottom();
      } else if (c.delta.type === 'input_json_delta') {
        // Handle tool input updates - accumulate the JSON
        const toolUse = this.executingTools.get(`block_${c.index}`);
        if (toolUse) {
          toolUse.inputJson += c.delta.partial_json;
          toolUse.status = 'preparing';
          this.scrollToBottom();
        }
      }
    },
    
    // Helper method to handle content_block_stop event
    handleContentBlockStop(c) {
      let messageUsage = null;
      
      // Handle tool input completion - wait for user approval
      const toolUse = this.executingTools.get(`block_${c.index}`);
      if (toolUse && toolUse.status === 'preparing') {
        try {
          // Parse the accumulated JSON input
          if (toolUse.inputJson) {
            toolUse.input = JSON.parse(toolUse.inputJson);
          }
          
          // Check if this tool should be auto-approved
          if (this.shouldAutoApproveTool(toolUse.name)) {
            // Auto-approve the tool
            toolUse.status = 'executing';
            toolUse.approved = true;
            // Execute the tool immediately
            this.$nextTick(() => {
              this.executeTool(toolUse);
            });
          } else {
            // Set status to pending approval instead of executing
            toolUse.status = 'pending_approval';
            toolUse.approved = null;
          }
        } catch (error) {
          toolUse.status = 'error';
          toolUse.error = this.i18n.assistantToolParseInputError + ': ' + error.message;
        }
        this.scrollToBottom();
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
    
    async callAIAPI(userMessage) {
      try {
        const response = await this.$root.papi.post('/assistant/chat', {
          msg: userMessage,
          sessionId: this.currentChatId,
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

            // handle chunk by type using helper methods
            switch (c.type) {
              case 'message_start':
                const startResult = this.handleMessageStart(c, assistantMessage);
                assistantMessage = startResult.assistantMessage;
                if (startResult.messageUsage) {
                  messageUsage = startResult.messageUsage;
                }
                break;
                
              case 'content_block_start':
                this.handleContentBlockStart(c, assistantMessage);
                break;
                
              case 'content_block_delta':
                this.handleContentBlockDelta(c, assistantMessage);
                break;
                
              case 'content_block_stop':
                const stopUsage = this.handleContentBlockStop(c);
                if (stopUsage) {
                  messageUsage = stopUsage;
                }
                break;
                
              case 'message_stop':
                const stopResult = this.handleMessageStop(assistantMessage, messageUsage);
                assistantMessage = stopResult.assistantMessage;
                messageUsage = stopResult.messageUsage;
                break;
                
              case 'message_delta':
                // Handle usage information if present
                if (c.usage) {
                  messageUsage = c.usage;
                }
                break;
                
              default:
                // Log any unhandled event types that might contain usage
                if (c.usage) {
                  messageUsage = c.usage;
                }
                break;
            }
          }

          // done processing received chunks, update UI then read more
          await this.$nextTick();
          output++;
        }
        
        this.isStreaming = false;

        // Update credits from API after successful response
        await this.loadCredits();
      } catch (error) {
        this.isTyping = false;
        this.isStreaming = false;
        
        // Show user-friendly error message
        const errorMessage = {
          role: 'assistant',
          content: this.i18n.assistantErrorMessage,
          timestamp: new Date().toISOString()
        };
        this.messages.push(errorMessage);
        this.scrollToBottom();
        
        // Show error to user
        this.$root.showError(this.i18n.assistantNoResponse + ': ' + (error.response?.data?.error || error.message));
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
      this.scrollToBottom();
      
      return { assistantMessage, messageUsage };
    },
    
    // Helper method to handle content_block_start event for tool execution (chained tools)
    handleToolExecutionContentBlockStart(c, assistantMessage) {
      // Handle tool use blocks in the response after tool execution
      if (c.content_block && c.content_block.type === 'tool_use') {
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
          approved: null
        };
        
        if (assistantMessage) {
          assistantMessage.toolUses.value.push(newToolUse);
          this.executingTools.set(newToolUse.id, newToolUse);
          this.executingTools.set(`block_${c.index}`, newToolUse);
          this.scrollToBottom();
        }
      }
    },
    
    // Helper method to handle content_block_delta event for tool execution
    handleToolExecutionContentBlockDelta(c, assistantMessage) {
      if (assistantMessage && c.delta.type === 'text_delta') {
        assistantMessage.content.value += c.delta.text;
        this.scrollToBottom();
      } else if (c.delta.type === 'input_json_delta') {
        // Handle tool input updates for chained tools
        const chainedToolUse = this.executingTools.get(`block_${c.index}`);
        if (chainedToolUse) {
          chainedToolUse.inputJson += c.delta.partial_json;
          chainedToolUse.status = 'preparing';
          this.scrollToBottom();
        }
      }
    },
    
    // Helper method to handle content_block_stop event for tool execution (chained tools)
    handleToolExecutionContentBlockStop(c) {
      let messageUsage = null;
      
      // Handle tool input completion for chained tools
      const chainedToolUse = this.executingTools.get(`block_${c.index}`);
      if (chainedToolUse && chainedToolUse.status === 'preparing') {
        try {
          // Parse the accumulated JSON input
          if (chainedToolUse.inputJson) {
            chainedToolUse.input = JSON.parse(chainedToolUse.inputJson);
          }
          
          // Check if this chained tool should be auto-approved
          if (this.shouldAutoApproveTool(chainedToolUse.name)) {
            // Auto-approve the chained tool
            chainedToolUse.status = 'executing';
            chainedToolUse.approved = true;
            // Execute the tool immediately
            this.$nextTick(() => {
              this.executeTool(chainedToolUse);
            });
          } else {
            // Set status to pending approval
            chainedToolUse.status = 'pending_approval';
            chainedToolUse.approved = null;
          }
        } catch (error) {
          chainedToolUse.status = 'error';
          chainedToolUse.error = this.i18n.assistantToolParseInputError + ': ' + error.message;
        }
        this.scrollToBottom();
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
    
    scrollToBottom() {
      this.$nextTick(() => {
        const messagesContainer = this.$el.querySelector('.chat-messages');
        if (messagesContainer) {
          messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
      });
    },
    getAvatar(user) {
      return this.$root.getAvatar(user);
    },
    formatTimestamp(timestamp) {
      return this.$root.formatTimestamp(timestamp);
    },
    formatMarkdown(text) {
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
      try {
        // Create ToolRequest object with history and params
        // Session ID should already be set by sendMessage()
        const toolRequest = {
          sessionId: this.currentChatId,
          toolUseId: toolUse.id,
          params: toolUse.input
        };
        
        // Use streaming for tool results
        const response = await this.$root.papi.post(`/assistant/tool/${toolUse.name}`, toolRequest, {
          headers: {
            'Accept': 'text/event-stream'
          },
          responseType: 'stream',
          adapter: 'fetch',
        });

        // Update tool status to executing
        toolUse.status = 'executing';

        // Stream the AI's response to the tool result
        const stream = response.data;
        const reader = stream.pipeThrough(new TextDecoderStream()).getReader();

        this.isStreaming = true;
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

            // Handle streaming chunks for tool result response using helper methods
            switch (c.type) {
              case 'message_start':
                const startResult = this.handleToolExecutionMessageStart(c, assistantMessage, toolUse);
                assistantMessage = startResult.assistantMessage;
                if (startResult.messageUsage) {
                  messageUsage = startResult.messageUsage;
                }
                break;

              case 'content_block_start':
                this.handleToolExecutionContentBlockStart(c, assistantMessage);
                break;

              case 'content_block_delta':
                this.handleToolExecutionContentBlockDelta(c, assistantMessage);
                break;

              case 'content_block_stop':
                const stopUsage = this.handleToolExecutionContentBlockStop(c);
                if (stopUsage) {
                  messageUsage = stopUsage;
                }
                break;

              case 'message_stop':
                const stopResult = this.handleToolExecutionMessageStop(assistantMessage, messageUsage);
                assistantMessage = stopResult.assistantMessage;
                messageUsage = stopResult.messageUsage;
                break;

              case 'message_delta':
                if (c.usage) {
                  messageUsage = c.usage;
                }
                break;

              default:
                if (c.usage) {
                  messageUsage = c.usage;
                }
                break;
            }
          }

          await this.$nextTick();
        }
        
        this.isStreaming = false;

        // Capture raw tool result using helper method
        this.captureRawToolResult(toolUse);
        
        // Update credits after tool execution
        await this.loadCredits();
        
      } catch (error) {
        this.isStreaming = false;

        // Update tool use status with error
        toolUse.status = 'error';
        toolUse.error = error.message;
        
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
        this.scrollToBottom();
      }
    },
    getToolStatusIcon(status) {
      switch (status) {
        case 'preparing': return 'fa-cog';
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
        case 'pending_approval': return 'warning';
        case 'executing': return 'warning';
        case 'completed': return 'success';
        case 'error': return 'error';
        case 'rejected': return 'error';
        default: return 'info';
      }
    },
    async approveTool(toolUse) {
      try {
        toolUse.approved = true;
        toolUse.status = 'executing';
        await this.executeTool(toolUse);
      } catch (error) {
        toolUse.status = 'error';
        toolUse.error = this.i18n.assistantToolUseFail + ': ' + error.message;
      }
      this.scrollToBottom();
    },
    async rejectTool(toolUse) {
      toolUse.approved = false;
      toolUse.status = 'rejected';
      toolUse.error = this.i18n.assistantToolUseReject;
      
      // Add a message indicating the tool was rejected
      const rejectionMessage = this.$root.replaceActionVar(this.i18n.assistantToolUseRejectMessage, 'toolName', toolUse.name);
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
          // Convert backend messages to frontend format
          this.messages = this.convertBackendMessagesToFrontend(response.data);
          this.currentChatId = sessionId;
          this.saveCurrentChatId();
        } else {
          throw new Error(this.i18n.assistantNoHistoryFound + ' ' + sessionId);
        }
      } catch (error) {
        // If session doesn't exist, start with welcome message
        if (error.response && error.response.status === 404) {
          this.loadChatHistory(); // Reset to welcome message
          this.currentChatId = sessionId;
          this.saveCurrentChatId();
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
          if (nextMessage.message.contentBlocks[0].text.includes('rejected by the user')) {
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
          timestamp: msg.createTime || new Date().toISOString()
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
      const maxContextLength = this.increaseMaxContextThreshold ? this.contextLimitLarge : this.contextLimitSmall;
      const threshold1 = maxContextLength * this.thresholdColorRatioLow;
      const threshold2 = maxContextLength * this.thresholdColorRatioMed;
      const threshold3 = maxContextLength * this.thresholdColorRatioMax;
      
      if (value < threshold1) return "text-green";
      if (value < threshold2) return "text-yellow";
      if (value < threshold3) return "text-amber darken-1";
      return "text-red darken-1";
    },
    
    // Save and load settings for the context threshold toggle
    saveContextThresholdSetting() {
      try {
        localStorage.setItem('so-chat-increase-max-context-threshold', this.increaseMaxContextThreshold.toString());
      } catch (error) {
        this.$root.showError(this.i18n.assistantSaveContextError + ': ' + error.message);
      }
    },
    
    loadContextThresholdSetting() {
      try {
        const saved = localStorage.getItem('so-chat-increase-max-context-threshold');
        if (saved !== null) {
          this.increaseMaxContextThreshold = saved === 'true';
        }
      } catch (error) {
        this.$root.showError(this.i18n.assistantLoadContextError + ': ' + error.message);
      }
    },

    // Save and load settings for the context threshold toggle
    saveLastActiveSetting() {
      try {
        localStorage.setItem('so-chat-restore-last-active', this.restoreLastActive.toString());
      } catch (error) {
        this.$root.showError(this.i18n.assistantSaveRecentError + ': ' + error.message);
      }
    },
    
    loadLastActiveSetting() {
      try {
        const saved = localStorage.getItem('so-chat-restore-last-active');
        if (saved !== null) {
          this.restoreLastActive = saved === 'true';
        }
      } catch (error) {
        this.$root.showError(this.i18n.assistantLoadRecentError + ': ' + error.message);
      }
    },

    saveReadApprovalSetting() {
      try {
        localStorage.setItem('so-chat-always-approve-read-requests', this.alwaysApproveReadRequests.toString());
      } catch (error) {
        this.$root.showError(this.i18n.assistantSaveReadApprovalError + ': ' + error.message);
      }
    },
    
    loadReadApprovalSetting() {
      try {
        const saved = localStorage.getItem('so-chat-always-approve-read-requests');
        if (saved !== null) {
          this.alwaysApproveReadRequests = saved === 'true';
        }
      } catch (error) {
        this.$root.showError(this.i18n.assistantLoadReadApprovalError + ': ' + error.message);
      }
    },

    // Check if a tool should be auto-approved based on localStorage settings
    shouldAutoApproveTool(toolName) {
      return ['query_events', 'get_playbook_questions'].includes(toolName) && this.alwaysApproveReadRequests;
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
  }
}});