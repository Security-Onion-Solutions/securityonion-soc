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
    connected: false,
    isTyping: false,
    chatHistory: [],
    currentChatId: null,
    showHistoryDialog: false,
    creditsRemaining: 0,
  }},
  async created() {
    this.loadChatHistory();
    this.loadStoredChats();
    await this.loadCredits();
    this.connectToChat();
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

        const response = await this.$root.papi.post('/assistant/chat', {
          msg: userMessage,
          messages: messageHistory,
        });
        
        if (response.data) {
          const assistantMessage = {
            role: 'assistant',
            content: response.data.Content[0].text,
            timestamp: new Date().toISOString()
          };
          
          this.isTyping = false;
          this.messages.push(assistantMessage);
          this.scrollToBottom();
          
          // Update credits from API after successful response
          await this.loadCredits();
        } else {
          throw new Error('Invalid response format from AI API');
        }
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