// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-chat', 'pages/chat.html');

routes.push({ path: '/chat', name: 'chat', component: {
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
  }},
  async created() {
    this.loadChatHistory();
    this.loadStoredChats();
    this.restoreLastActiveChat();
    await this.loadCredits();
  },
  beforeUnmount() {
    // Save current chat state when navigating away from the chat page
    this.saveCurrentChat();
  },
  watch: {
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
    restoreLastActiveChat() {
      const lastChatId = this.loadCurrentChatId();
      if (lastChatId && this.chatHistory.length > 0) {
        const lastChat = this.chatHistory.find(chat => chat.id === lastChatId);
        if (lastChat) {
          this.messages = [...lastChat.messages];
          this.currentChatId = lastChat.id;
          return;
        }
      }
      // If no valid last chat found, keep the default welcome message
    },
    async loadCredits() {
      try {
        const response = await this.$root.papi.get('/assistant/balance');
        if (response.data) {
          this.creditsRemaining = response.data.balance || 0;
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
      this.showHistoryDialog = false;
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
      this.showHistoryDialog = false;
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
      } catch (error) {
        this.$root.showError('Failed to get AI response: ' + error.message);
        this.isTyping = false;
      }
    },
    async callAIAPI(userMessage) {
      try {
        // Prepare message history (exclude the current user message that was just added)
        const messageHistory = this.messages.slice(0, -1).map(msg => ({
          role: msg.role,
          content: msg.content
        }));

        let response = await fetch('/api/assistant/chat', {
          method: 'POST',
          headers: {
            'X-Srv-Token': this.$root.papi.defaults.headers.common['X-Srv-Token'],
            'Accept': 'text/event-stream'
          },
          body: JSON.stringify({
            msg: userMessage,
            messages: messageHistory,
          })
        });

        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8');

        console.log("reading messages...");
        let output = 0;
        let assistantMessage = null;
        let chunks = [];
        let partial = false;

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
                  timestamp: new Date().toISOString()
                };

                this.messages.push(assistantMessage);
                this.scrollToBottom();
                
                break;
              case 'content_block_delta':
                if (assistantMessage && c.delta.type === 'text_delta') {
                  // update the ref's value
                  assistantMessage.content.value += c.delta.text;
                  this.scrollToBottom();
                }

                break;
              case 'message_stop':
                assistantMessage = null;
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
    }
  }
}});
