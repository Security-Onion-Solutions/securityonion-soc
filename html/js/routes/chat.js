// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-chat', 'pages/chat.html');

routes.push({ path: '/chat/:sessionId?', name: 'chat', component: {
  template: '#page-chat',
  data() { return {
    i18n: this.$root.i18n,
    messages: [],
    newMessage: '',
    username: this.$root.username || 'User',
    isTyping: false,
    chatHistory: [],
    currentChatId: null,
    showHistoryDialog: false,
    creditsRemaining: 0,
    executingTools: new Map(), // Track tool executions by ID
    pendingToolResults: new Map(), // Store tool results waiting to be sent back
    contextLength: 0, // Track total context length
  }},
  async created() {
    this.loadChatHistory();
    await this.loadStoredChats();
    await this.handleRouteSessionId();
    await this.loadCredits();
  },
  beforeUnmount() {
    // Backend automatically saves chats, just save current chat ID
    this.saveCurrentChatId();
  },
  watch: {
    '$route'(to, from) {
      // Handle session ID changes from URL
      if (to.params.sessionId !== from.params.sessionId) {
        this.handleRouteSessionId();
      }
    }
  },
  methods: {
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
        console.log('Updated context length:', this.contextLength, 'Added:', messageContext);
      }
    },
    
    // Reset context length (for new chats)
    resetContextLength() {
      this.contextLength = 0;
    },
    
    async loadChatHistory() {
      try {
        // Initialize with a welcome message from the AI Assistant
        this.messages = [
          {
            role: 'assistant',
            content: 'Hello! I\'m your AI Assistant for Security Onion. How can I help you today?',
            timestamp: new Date().toISOString()
          }
        ];
        // Reset context length for new chat
        this.resetContextLength();
      } catch (error) {
        this.$root.showError(error);
      }
    },
    async loadStoredChats() {
      try {
        const response = await this.$root.papi.get('/assistant/sessions');
        if (response.data && Array.isArray(response.data)) {
          // Convert backend format to frontend format
          this.chatHistory = response.data.map(session => ({
            id: session.sessionId,
            title: this.generateTitleFromMessage(session),
            messages: [], // Will be loaded when session is opened
            timestamp: session.createTime || new Date().toISOString(),
            lastUpdated: session.createTime || new Date().toISOString()
          }));
        } else {
          this.chatHistory = [];
        }
      } catch (error) {
        console.log('Failed to load chat history from backend:', error);
        // Fallback to empty array if backend is unavailable
        this.chatHistory = [];
      }
    },
    // No longer needed - backend handles persistence
    saveStoredChats() {
      // Backend automatically saves chats, no action needed
    },
    saveCurrentChatId() {
      try {
        if (this.currentChatId) {
          localStorage.setItem('so-current-chat-id', this.currentChatId);
        } else {
          localStorage.removeItem('so-current-chat-id');
        }
      } catch (error) {
        console.log('Failed to save current chat ID:', error);
      }
    },
    loadCurrentChatId() {
      try {
        return localStorage.getItem('so-current-chat-id');
      } catch (error) {
        console.log('Failed to load current chat ID:', error);
        return null;
      }
    },
    async handleRouteSessionId() {
      const urlSessionId = this.$route.params.sessionId;
      if (urlSessionId) {
        // Try to load chat from backend first
        try {
          await this.loadChatFromBackend(urlSessionId);
        } catch (error) {
          console.log('Session not found in backend, starting new session:', urlSessionId);
          // Session ID in URL doesn't exist, start new chat with this ID
          this.currentChatId = urlSessionId;
          this.saveCurrentChatId();
          
          // Check if this is an investigation session
          const isInvestigation = this.$route.query.investigation === 'true';
          const socId = this.$route.query.socId;
          
          if (isInvestigation && socId) {
            // Try to get investigation data from localStorage
            const investigationKey = `investigation_${urlSessionId}`;
            const investigationDataStr = localStorage.getItem(investigationKey);
            
            if (investigationDataStr) {
              try {
                const investigationData = JSON.parse(investigationDataStr);
                console.log('Found investigation data for session:', urlSessionId);
                // This is a new investigation session, start with investigation prompt
                this.$nextTick(() => {
                  this.startInvestigationSession(investigationData.socId, investigationData.prompt);
                });
                // Clean up the localStorage after use
                localStorage.removeItem(investigationKey);
              } catch (error) {
                console.error('Failed to parse investigation data:', error);
              }
            } else {
              console.warn('Investigation session detected but no data found in localStorage for key:', investigationKey);
              // List all localStorage keys for debugging
              console.log('Available localStorage keys:', Object.keys(localStorage));
            }
          } else {
            // Keep the default welcome message
          }
        }
      } else {
        // No session ID in URL, restore last active chat
        await this.restoreLastActiveChat();
      }
    },
    async restoreLastActiveChat() {
      const lastChatId = this.loadCurrentChatId();
      if (lastChatId && this.chatHistory.length > 0) {
        try {
          await this.loadChatFromBackend(lastChatId);
          // Update URL to reflect the current session
          this.updateUrlWithSessionId(lastChatId);
          return;
        } catch (error) {
          console.log('Failed to restore last active chat:', error);
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
        console.error('Error loading credits from API:', error);
        // Fallback to localStorage if API fails
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
    generateChatTitle() {
      // Generate title from first user message
      const firstUserMessage = this.messages.find(m => m.role === 'user');
      if (firstUserMessage) {
        let title = firstUserMessage.content.substring(0, 50);
        if (firstUserMessage.content.length > 50) {
          title += '...';
        }
        return title;
      }
      return 'New Chat - ' + new Date().toLocaleDateString();
    },
    async loadChat(chat) {
      await this.saveCurrentChat(); // Save current chat before switching
      try {
        await this.loadChatFromBackend(chat.id);
        this.updateUrlWithSessionId(chat.id);
        this.scrollToBottom();
      } catch (error) {
        console.error('Failed to load chat:', error);
        this.$root.showError('Failed to load chat: ' + error.message);
      }
    },
    async deleteChat(chatId) {
      try {
        // Call the backend DELETE endpoint to remove the session
        await this.$root.papi.delete(`/assistant/sessions/${chatId}`);
        
        // Remove from local history after successful backend deletion
        this.chatHistory = this.chatHistory.filter(chat => chat.id !== chatId);
        
        // If we deleted the current chat, start a new one
        if (this.currentChatId === chatId) {
          this.currentChatId = null;
          this.saveCurrentChatId(); // Clear the saved current chat ID
          this.loadChatHistory(); // Reset to welcome message
          // Navigate to chat without session ID
          this.$router.push({ name: 'chat' });
        }
        
        console.log('Chat deleted successfully:', chatId);
      } catch (error) {
        console.error('Failed to delete chat:', error);
        this.$root.showError('Failed to delete chat: ' + (error.response?.data?.error || error.message));
      }
    },
    async startNewChat() {
      await this.saveCurrentChat(); // Save current chat before starting new one
      this.currentChatId = null;
      this.saveCurrentChatId(); // Clear the saved current chat ID
      this.loadChatHistory(); // Reset to welcome message (also resets context length)
      // Navigate to chat without session ID
      this.$router.push({ name: 'chat' });
    },
    updateUrlWithSessionId(sessionId) {
      // Only update URL if it's different from current
      if (this.$route.params.sessionId !== sessionId) {
        this.$router.replace({ name: 'chat', params: { sessionId: sessionId } });
      }
    },
    async sendMessage() {
      if (!this.newMessage.trim()) return;
      
      // Check if user has credits
      if (this.creditsRemaining <= 0) {
        this.$root.showError('Insufficient credits. Please contact your administrator to purchase more credits.');
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
        this.$root.showError('Failed to get AI response: ' + error.message);
        this.isTyping = false;
      }
    },
    async callAIAPI(userMessage) {
      try {
        let response = await fetch('/api/assistant/chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Srv-Token': this.$root.papi.defaults.headers.common['X-Srv-Token'],
            'Accept': 'text/event-stream'
          },
          body: JSON.stringify({
            msg: userMessage,
            sessionId: this.currentChatId
          })
        });

        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');

        console.log("reading messages...");
        let output = 0;
        let assistantMessage = null;
        let chunks = [];
        let partial = false;
        let messageUsage = null;

        while (true) {
          // read in more messages
          const { done, value } = await reader.read();
          if (done) break;

          // parse the text, watch for bytes that span updates
          let data = decoder.decode(value, { stream: true });
          
          // cleanup the data, split messages apart, remove SSE label, filter out empty lines
          const newChunks = data.split('\n\n').filter(d => d && d.startsWith('data:')).map(d => (d.startsWith("data: ") ? d.slice(6) : d));
          
          // if the last read had partial data, prepend it to the new data and process it again
          if (partial) {
            newChunks[0] = chunks[0] + newChunks[0]
            partial = false;
          }

          chunks = newChunks;
          console.log(chunks);
          
          // process each chunk
          for (let i = 0; i < chunks.length; i++) {
            if (chunks[i] === '[DONE]') {
              // DONE done
              assistantMessage = null;
              continue;
            }

            // attempt to parse chunk
            let c;
            try {
              c = JSON.parse(chunks[i]);
            } catch {
              // Handle partial JSON or multiple concatenated JSON objects
              const chunk = chunks[i];
              
              // Try to split concatenated JSON objects by finding complete JSON boundaries
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
              
              // If we found complete JSON objects, process them first
              if (splitChunks.length > 0) {
                // We successfully split concatenated JSON objects, reprocess them
                chunks.splice(i, 1, ...splitChunks);
                i--; // Reprocess from current position
                
                // If there's remaining partial content, save it for next read
                if (currentChunk.trim()) {
                  partial = true;
                  chunks.push(currentChunk);
                  console.log('partial found');
                }
                continue;
              } else if (currentChunk.trim()) {
                // No complete JSON found, treat entire chunk as partial
                partial = true;
                chunks = [currentChunk];
                console.log('partial found');
                break;
              } else {
                // Fallback: treat as partial
                partial = true;
                chunks = [chunk];
                console.log('partial found');
                break;
              }
            }

            // handle chunk by type
            switch (c.type) {
              case 'message_start':
                this.isTyping = false;

                assistantMessage = {
                  role: 'assistant',
                  content: Vue.ref(''), // MUST be ref
                  timestamp: new Date().toISOString(),
                  usage: Vue.ref(null),
                  toolUses: Vue.ref([]) // Track tool uses in this message
                };

                // Sometimes usage comes in message_start
                if (c.message && c.message.usage) {
                  messageUsage = c.message.usage;
                  console.log('Usage found in message_start:', messageUsage);
                }

                this.messages.push(assistantMessage);
                this.scrollToBottom();
                
                break;
              case 'content_block_start':
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
                    console.log('Tool use started:', toolUse);
                    this.scrollToBottom();
                  }
                }
                break;
              case 'content_block_delta':
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
                    console.log('Tool input delta accumulated:', toolUse.inputJson);
                    this.scrollToBottom();
                  }
                }

                break;
              case 'message_stop':
                // Store usage information with the message if available
                if (assistantMessage && messageUsage) {
                  console.log('Setting usage on message:', messageUsage);
                  // Set the ref's value
                  assistantMessage.usage.value = messageUsage;
                  // Update context length
                  this.updateContextLength(messageUsage);
                  console.log('Message after setting usage:', assistantMessage);
                  this.$forceUpdate();
                } else {
                  console.log('No usage to set - assistantMessage:', !!assistantMessage, 'messageUsage:', messageUsage);
                }
                assistantMessage = null;
                messageUsage = null;
                break;
              case 'message_delta':
                // Handle usage information if present
                if (c.usage) {
                  messageUsage = c.usage;
                  console.log('Usage found in message_delta:', messageUsage);
                }
                break;
              case 'content_block_stop':
                // Handle tool input completion - wait for user approval
                const toolUse = this.executingTools.get(`block_${c.index}`);
                if (toolUse && toolUse.status === 'preparing') {
                  try {
                    // Parse the accumulated JSON input
                    if (toolUse.inputJson) {
                      toolUse.input = JSON.parse(toolUse.inputJson);
                      console.log('Tool input complete:', toolUse.input);
                    }
                    
                    // Set status to pending approval instead of executing
                    toolUse.status = 'pending_approval';
                    toolUse.approved = null;
                  } catch (error) {
                    console.error('Failed to parse tool input JSON:', error, toolUse.inputJson);
                    toolUse.status = 'error';
                    toolUse.error = 'Failed to parse tool input: ' + error.message;
                  }
                  this.scrollToBottom();
                }
                
                // Sometimes usage comes here
                if (c.usage) {
                  messageUsage = c.usage;
                  console.log('Usage found in content_block_stop:', messageUsage);
                }
                break;
              default:
                // Log any unhandled event types that might contain usage
                if (c.usage) {
                  messageUsage = c.usage;
                  console.log('Usage found in unhandled event type:', c.type, messageUsage);
                }
                console.log('Unhandled event type:', c.type, c);
                break;
            }
          }

          // done processing received chunks, update UI then read more
          await this.$nextTick();
          output++;
        }
        
        // Update credits from API after successful response
        await this.loadCredits();
      } catch (error) {
        this.isTyping = false;
        console.error('AI API Error:', error);
        
        // Show user-friendly error message
        const errorMessage = {
          role: 'assistant',
          content: 'I apologize, but I\'m having trouble connecting to the AI service right now. Please try again in a moment.',
          timestamp: new Date().toISOString()
        };
        this.messages.push(errorMessage);
        this.scrollToBottom();
        
        // Show error to user
        this.$root.showError('Failed to get AI response: ' + (error.response?.data?.error || error.message));
      }
    },
    handleAIResponse(response) {
      // Handle real AI responses when implemented
      this.isTyping = false;
      this.messages.push({
        role: 'assistant',
        content: response.content,
        timestamp: new Date().toISOString()
      });
      this.scrollToBottom();
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
      return this.$root.formatMarkdown(text);
    },
    formatChatDate(timestamp) {
      return this.$root.formatDateTime(timestamp);
    },
    formatCount(count) {
      return this.$root.formatCount(count);
    },
    async executeTool(toolUse) {
      try {
        console.log('Executing tool:', toolUse.name, 'with params:', toolUse.input);
        
        // Create ToolRequest object with history and params
        // Session ID should already be set by sendMessage()
        const toolRequest = {
          sessionId: this.currentChatId,
          toolUseId: toolUse.id,
          params: toolUse.input
        };
        
        // Use streaming for tool results
        const response = await fetch(`/api/assistant/tool/${toolUse.name}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Srv-Token': this.$root.papi.defaults.headers.common['X-Srv-Token'],
            'Accept': 'text/event-stream'
          },
          body: JSON.stringify(toolRequest)
        });

        if (!response.ok) {
          throw new Error(`Tool execution failed: ${response.statusText}`);
        }

        // Update tool status to completed (tool execution itself is done)
        toolUse.status = 'completed';

        // Stream the AI's response to the tool result
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');

        console.log("Streaming tool result response...");
        let assistantMessage = null;
        let chunks = [];
        let partial = false;
        let messageUsage = null;
        let capturedRawResult = null; // Capture the raw tool result

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          let data = decoder.decode(value, { stream: true });
          
          const newChunks = data.split('\n\n').filter(d => d && d.startsWith('data:')).map(d => (d.startsWith("data: ") ? d.slice(6) : d));
          
          if (partial) {
            newChunks[0] = chunks[0] + newChunks[0]
            partial = false;
          }

          chunks = newChunks;
          console.log('Tool result chunks:', chunks);
          
          for (let i = 0; i < chunks.length; i++) {
            if (chunks[i] === '[DONE]') {
              assistantMessage = null;
              continue;
            }

            let c;
            try {
              c = JSON.parse(chunks[i]);
            } catch {
              // Handle partial JSON similar to callAIAPI
              const chunk = chunks[i];
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
                      splitChunks.push(currentChunk);
                      currentChunk = '';
                    }
                  }
                }
              }
              
              if (splitChunks.length > 0) {
                chunks.splice(i, 1, ...splitChunks);
                i--;
                
                if (currentChunk.trim()) {
                  partial = true;
                  chunks.push(currentChunk);
                }
                continue;
              } else if (currentChunk.trim()) {
                partial = true;
                chunks = [currentChunk];
                break;
              } else {
                partial = true;
                chunks = [chunk];
                break;
              }
            }

            // Handle streaming chunks for tool result response
            switch (c.type) {
              case 'message_start':
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

                if (c.message && c.message.usage) {
                  messageUsage = c.message.usage;
                }

                this.messages.push(assistantMessage);
                this.scrollToBottom();
                break;

              case 'content_block_start':
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
                    console.log('Chained tool use started:', newToolUse);
                    this.scrollToBottom();
                  }
                }
                break;

              case 'content_block_delta':
                if (assistantMessage && c.delta.type === 'text_delta') {
                  assistantMessage.content.value += c.delta.text;
                  this.scrollToBottom();
                } else if (c.delta.type === 'input_json_delta') {
                  // Handle tool input updates for chained tools
                  const chainedToolUse = this.executingTools.get(`block_${c.index}`);
                  if (chainedToolUse) {
                    chainedToolUse.inputJson += c.delta.partial_json;
                    chainedToolUse.status = 'preparing';
                    console.log('Chained tool input delta accumulated:', chainedToolUse.inputJson);
                    this.scrollToBottom();
                  }
                }
                break;

              case 'content_block_stop':
                // Handle tool input completion for chained tools
                const chainedToolUse = this.executingTools.get(`block_${c.index}`);
                if (chainedToolUse && chainedToolUse.status === 'preparing') {
                  try {
                    // Parse the accumulated JSON input
                    if (chainedToolUse.inputJson) {
                      chainedToolUse.input = JSON.parse(chainedToolUse.inputJson);
                      console.log('Chained tool input complete:', chainedToolUse.input);
                    }
                    
                    // Set status to pending approval
                    chainedToolUse.status = 'pending_approval';
                    chainedToolUse.approved = null;
                  } catch (error) {
                    console.error('Failed to parse chained tool input JSON:', error, chainedToolUse.inputJson);
                    chainedToolUse.status = 'error';
                    chainedToolUse.error = 'Failed to parse tool input: ' + error.message;
                  }
                  this.scrollToBottom();
                }
                
                // Sometimes usage comes here
                if (c.usage) {
                  messageUsage = c.usage;
                  console.log('Usage found in content_block_stop:', messageUsage);
                }
                break;

              case 'message_stop':
                if (assistantMessage && messageUsage) {
                  assistantMessage.usage.value = messageUsage;
                  // Update context length for tool result messages too
                  this.updateContextLength(messageUsage);
                  this.$forceUpdate();
                }
                assistantMessage = null;
                messageUsage = null;
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
        
        // After streaming is complete, check if we need to capture the raw result
        // The raw result will be in the next message that gets saved to backend
        // We'll capture it by monitoring the messages array for new tool result messages
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
                  const textBlock = msg.message.contentBlocks.find(block => block.type === 'text');
                  if (textBlock && textBlock.text) {
                    // Parse the tool result format: "ToolUseId: tooluse_QdvZoVlXQNm0PBuqFuqRmA, Result: [actual_result_data]"
                    const toolResultText = textBlock.text;
                    const toolUseIdMatch = toolResultText.match(/ToolUseId:\s*([^,]+)/);
                    const resultMatch = toolResultText.match(/Result:\s*(.+)$/s);
                    
                    if (toolUseIdMatch && resultMatch) {
                      rawResult = resultMatch[1].trim();
                    }
                  }
                  // This is a tool result - associate it with our tool use
                  toolUse.rawResult = rawResult;
                  toolUse.completedAt = msg.createTime;
                  console.log('Captured raw tool result:', toolUse.rawResult);
                  break;
                }
              }
            }
          } catch (error) {
            console.log('Could not capture raw tool result:', error);
          }
        }, 1000); // Wait 1 second for the backend to save the result
        
        // Update credits after tool execution
        await this.loadCredits();
        
      } catch (error) {
        console.error('Tool execution error:', error);
        
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
        console.log('Tool approved by user:', toolUse.name);
        await this.executeTool(toolUse);
      } catch (error) {
        console.error('Error approving tool:', error);
        toolUse.status = 'error';
        toolUse.error = 'Failed to execute approved tool: ' + error.message;
      }
      this.scrollToBottom();
    },
    async rejectTool(toolUse) {
      toolUse.approved = false;
      toolUse.status = 'rejected';
      toolUse.error = 'Tool execution rejected by user';
      console.log('Tool rejected by user:', toolUse.name);
      
      // Add a message indicating the tool was rejected
      const rejectionMessage = `Tool execution for "${toolUse.name}" was rejected by the user.`;
      await this.callAIAPI(rejectionMessage);

      this.scrollToBottom();
    },
    async startInvestigationSession(socId, investigationPrompt) {
      console.log('Starting investigation session for SOC ID:', socId);
      console.log('Investigation prompt length:', investigationPrompt.length);
      
      // Replace the welcome message with an investigation-specific welcome
      this.messages = [
        {
          role: 'assistant',
          content: `Hello! I'm starting an AI investigation for SOC ID: ${socId}. I'll analyze this alert systematically and ask for your approval before using any tools. Let me begin the investigation now.`,
          timestamp: new Date().toISOString(),
          isInvestigationStart: true,
          socId: socId
        }
      ];
      
      // Wait for the UI to update
      await this.$nextTick();
      
      // Set the investigation prompt directly (no decoding needed)
      this.newMessage = investigationPrompt;
      
      // Wait for the UI to update again
      await this.$nextTick();
      
      // Send the message after a delay to ensure everything is ready
      setTimeout(async () => {
        console.log('About to send message, length:', this.newMessage.length);
        if (this.newMessage && this.newMessage.trim()) {
          try {
            await this.sendMessage();
            console.log('Investigation message sent successfully');
          } catch (error) {
            console.error('Failed to send investigation message:', error);
          }
        } else {
          console.error('No message to send');
        }
      }, 2000);
    },
    updateInvestigationStatus(alertId, status, assessment = null, confidence = null) {
      // Update the investigation status in localStorage so hunt page can reflect changes
      try {
        const aiInvestigations = JSON.parse(localStorage.getItem('aiInvestigations') || '{}');
        if (aiInvestigations[alertId]) {
          aiInvestigations[alertId].status = status;
          if (assessment) aiInvestigations[alertId].assessment = assessment;
          if (confidence) aiInvestigations[alertId].confidence = confidence;
          aiInvestigations[alertId].lastUpdated = new Date().toISOString();
          localStorage.setItem('aiInvestigations', JSON.stringify(aiInvestigations));
        }
      } catch (error) {
        console.error('Failed to update investigation status:', error);
      }
    },
    // Helper method to generate title from a session/message
    generateTitleFromMessage(session) {
      if (session && session.message) {
        // Handle different message formats
        let content = '';
        if (session.message.contentStr) {
          content = session.message.contentStr;
        } else if (session.message.contentBlocks && session.message.contentBlocks.length > 0) {
          const textBlock = session.message.contentBlocks.find(block => block.type === 'text');
          if (textBlock) {
            content = textBlock.text;
          }
        }
        
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
          throw new Error('No chat history found for session');
        }
      } catch (error) {
        console.error('Failed to load chat from backend:', error);
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

    // Helper method to convert backend message format to frontend format
    convertBackendMessagesToFrontend(backendMessages) {
      const processedMessages = [];
      // Reset context length when loading from backend
      this.resetContextLength();
      
      let skip_next = false;

      for (let i = 0; i < backendMessages.length; i++) {
        
        if (skip_next) {
          skip_next = false;
          continue
        }
        
        const msg = backendMessages[i];
        
        // Check if this is a tool result message (new format with tags)
        if (msg.tags && msg.tags.includes('tool_result')) {
          // This is a tool result message - extract the result data
          let rawResult = null;
          let toolUseId = null;
          
          if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
            const textBlock = msg.message.contentBlocks.find(block => block.type === 'text');
            if (textBlock && textBlock.text) {
              // Parse the tool result format: "ToolUseId: tooluse_QdvZoVlXQNm0PBuqFuqRmA, Result: [actual_result_data]"
              const toolResultText = textBlock.text;
              const toolUseIdMatch = toolResultText.match(/ToolUseId:\s*([^,]+)/);
              const resultMatch = toolResultText.match(/Result:\s*(.+)$/s);
              
              if (toolUseIdMatch && resultMatch) {
                toolUseId = toolUseIdMatch[1].trim();
                rawResult = resultMatch[1].trim();
              }
            }
          }
          
          // Find the assistant message with the matching tool use and add the raw result
          if (toolUseId && rawResult) {
            // Look backwards through processed messages to find the tool use
            for (let j = processedMessages.length - 1; j >= 0; j--) {
              const processedMsg = processedMessages[j];
              if (processedMsg.role === 'assistant' && processedMsg.toolUses) {
                const toolUses = processedMsg.toolUses.value;
                const matchingToolUse = toolUses.find(tool => tool.id === toolUseId);
                if (matchingToolUse) {
                  matchingToolUse.rawResult = rawResult;
                  matchingToolUse.completedAt = msg.createTime;
                  console.log('Associated raw tool result with tool use:', toolUseId);
                  break;
                }
              }
            }
          }
          
          // Skip adding this message to the processed messages (filter it out)
          continue;
        }
        
        // Check if this is a tool result message (old format - user role with contentStr)
        if (msg.message.role === 'user' && msg.message.contentStr && !msg.message.contentBlocks) {
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
          // Skip adding this message to the processed messages (filter it out)
          continue;
        }
        
        const frontendMsg = {
          role: msg.message.role,
          timestamp: msg.createTime || new Date().toISOString()
        };

        // Handle different content formats
        if (msg.message.contentStr) {
          frontendMsg.content = msg.message.contentStr;
        } else if (msg.message.contentBlocks && msg.message.contentBlocks.length > 0) {
          // For now, just extract text from content blocks
          if (frontendMsg.role === 'user') {
            const textBlocks = msg.message.contentBlocks.filter(block => block.type === 'text');
            if (textBlocks.length > 0) {
              frontendMsg.content = textBlocks.map(block => block.text).join('\n');
            } else {
              frontendMsg.content = 'Complex message with tools/attachments';
            }
          } else if (frontendMsg.role === 'assistant') {
            const textBlocks = msg.message.contentBlocks.filter(block => block.type === 'text');
            if (textBlocks.length > 0) {
              frontendMsg.content = textBlocks.map(block => block.text).join('\n');
            } else {
              frontendMsg.content = 'Complex message with tools/attachments';
            }
          }
            
          // Handle tool uses if present
          const toolBlocks = msg.message.contentBlocks.filter(block => block.type === 'tool_use');
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
                  error: 'Tool execution rejected by user',
                  rawResult: null,
                  timestamp: msg.createTime || new Date().toISOString(),
                  approved: false
                })));
                skip_next = true;
              }
            } else {

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
        } else {
          frontendMsg.content = 'Empty message';
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

    getContextColor(value) {
      if (value < 100000) return "text-green";
      if (value < 150000) return "text-yellow";
      if (value < 200000) return "text-amber darken-1";
      return "text-red darken-1";
    }
  }
}});