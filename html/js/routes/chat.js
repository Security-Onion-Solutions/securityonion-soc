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
  }},
  async created() {
    this.loadChatHistory();
    this.loadStoredChats();
    this.handleRouteSessionId();
    await this.loadCredits();
  },
  beforeUnmount() {
    // Save current chat state when navigating away from the chat page
    this.saveCurrentChat();
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
      } catch (error) {
        this.$root.showError(error);
      }
    },
    loadStoredChats() {
      try {
        const stored = localStorage.getItem('so-chat-history');
        if (stored) {
          this.chatHistory = JSON.parse(stored);
        }
      } catch (error) {
        console.log('Failed to load chat history:', error);
        this.chatHistory = [];
      }
    },
    saveStoredChats() {
      try {
        localStorage.setItem('so-chat-history', JSON.stringify(this.chatHistory));
      } catch (error) {
        console.log('Failed to save chat history:', error);
      }
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
    handleRouteSessionId() {
      const urlSessionId = this.$route.params.sessionId;
      
      if (urlSessionId) {
        // Load chat from URL session ID
        const chat = this.chatHistory.find(chat => chat.id === urlSessionId);
        if (chat) {
          this.messages = [...chat.messages];
          this.currentChatId = chat.id;
          this.saveCurrentChatId();
        } else {
          // Session ID in URL doesn't exist, start new chat with this ID
          this.currentChatId = urlSessionId;
          this.saveCurrentChatId();
          // Keep the default welcome message
        }
      } else {
        // No session ID in URL, restore last active chat
        this.restoreLastActiveChat();
      }
    },
    restoreLastActiveChat() {
      const lastChatId = this.loadCurrentChatId();
      if (lastChatId && this.chatHistory.length > 0) {
        const lastChat = this.chatHistory.find(chat => chat.id === lastChatId);
        if (lastChat) {
          this.messages = [...lastChat.messages];
          this.currentChatId = lastChat.id;
          // Update URL to reflect the current session
          this.updateUrlWithSessionId(lastChat.id);
          return;
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
    saveCurrentChat() {
      if (this.messages.length <= 1) return; // Don't save if only welcome message
      
      const chatTitle = this.generateChatTitle();
      const chatData = {
        id: this.currentChatId || this.generateChatId(),
        title: chatTitle,
        messages: [...this.messages],
        timestamp: new Date().toISOString(),
        lastUpdated: new Date().toISOString()
      };
      
      const existingIndex = this.chatHistory.findIndex(chat => chat.id === chatData.id);
      if (existingIndex >= 0) {
        this.chatHistory[existingIndex] = chatData;
      } else {
        this.chatHistory.unshift(chatData);
      }
      
      // Keep only the last 5 chats
      if (this.chatHistory.length > 5) {
        this.chatHistory = this.chatHistory.slice(0, 5);
      }
      
      this.currentChatId = chatData.id;
      this.saveStoredChats();
      this.saveCurrentChatId();
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
    loadChat(chat) {
      this.saveCurrentChat(); // Save current chat before switching
      this.messages = [...chat.messages];
      this.currentChatId = chat.id;
      this.saveCurrentChatId();
      this.updateUrlWithSessionId(chat.id);
      this.scrollToBottom();
    },
    deleteChat(chatId) {
      this.chatHistory = this.chatHistory.filter(chat => chat.id !== chatId);
      this.saveStoredChats();
      
      // If we deleted the current chat, start a new one
      if (this.currentChatId === chatId) {
        this.startNewChat();
      }
    },
    startNewChat() {
      this.saveCurrentChat(); // Save current chat before starting new one
      this.currentChatId = null;
      this.saveCurrentChatId(); // Clear the saved current chat ID
      this.loadChatHistory(); // Reset to welcome message
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
        // Call the actual AI API
        await this.callAIAPI(messageText);
        
        // Auto-save chat after each exchange
        this.saveCurrentChat();
        
        // Update URL with session ID if not already set
        if (this.currentChatId && !this.$route.params.sessionId) {
          this.updateUrlWithSessionId(this.currentChatId);
        }
      } catch (error) {
        this.$root.showError('Failed to get AI response: ' + error.message);
        this.isTyping = false;
      }
    },
    async callAIAPI(userMessage) {
      try {
        // Prepare message history (exclude the current user message that was just added)
        const messageHistory = this.messages.slice(0, -1).map(msg => {
          const contentText = typeof msg.content === 'object' && msg.content.value !== undefined ? msg.content.value : msg.content;
          return {
            role: msg.role,
            content: [
              {
                type: "text",
                text: contentText
              }
            ]
          };
        });

        let response = await fetch('/api/assistant/chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Srv-Token': this.$root.papi.defaults.headers.common['X-Srv-Token'],
            'Accept': 'text/event-stream'
          },
          body: JSON.stringify({
            msg: userMessage,
            messages: messageHistory,
            sessionId: this.currentChatId || this.generateChatId()
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
        
        // Prepare message history for the tool request
        const messageHistory = this.messages.map(msg => {
          const contentText = typeof msg.content === 'object' && msg.content.value !== undefined ? msg.content.value : msg.content;
          return {
            role: msg.role,
            content: [
              {
                type: "text",
                text: contentText
              }
            ]
          };
        });
        
        // Create ToolRequest object with history and params
        const toolRequest = {
          history: messageHistory,
          sessionId: this.currentChatId || this.generateChatId(),
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
        toolUse.completedAt = new Date().toISOString();

        // Stream the AI's response to the tool result
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');

        console.log("Streaming tool result response...");
        let assistantMessage = null;
        let chunks = [];
        let partial = false;
        let messageUsage = null;

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
        
        // Update credits after tool execution
        await this.loadCredits();
        
      } catch (error) {
        console.error('Tool execution error:', error);
        
        // Update tool use status with error
        toolUse.status = 'error';
        toolUse.error = error.message;
        toolUse.completedAt = new Date().toISOString();
        
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
    rejectTool(toolUse) {
      toolUse.approved = false;
      toolUse.status = 'rejected';
      toolUse.error = 'Tool execution rejected by user';
      console.log('Tool rejected by user:', toolUse.name);
      
      // Add a message indicating the tool was rejected
      const rejectionMessage = {
        role: 'assistant',
        content: `Tool execution for "${toolUse.name}" was rejected by the user.`,
        timestamp: new Date().toISOString(),
        isToolResult: true,
        toolName: toolUse.name,
        toolId: toolUse.id
      };
      
      this.messages.push(rejectionMessage);
      this.scrollToBottom();
    }
  }
}});
