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
    creditsRemaining: 45000000,
  }},
  created() {
    this.loadChatHistory();
    this.loadStoredChats();
    this.loadCredits();
    this.connectToChat();
  },
  beforeUnmount() {
    this.disconnectFromChat();
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
    loadCredits() {
      try {
        const stored = localStorage.getItem('so-chat-credits');
        if (stored) {
          const credits = JSON.parse(stored);
          this.creditsRemaining = credits.remaining || 100;
        }
      } catch (error) {
        console.log('Failed to load credits:', error);
        this.creditsRemaining = 100;
      }
    },
    saveCredits() {
      try {
        const credits = {
          remaining: this.creditsRemaining,
        };
        localStorage.setItem('so-chat-credits', JSON.stringify(credits));
      } catch (error) {
        console.log('Failed to save credits:', error);
      }
    },
    deductCredit() {
      if (this.creditsRemaining > 0) {
        this.creditsRemaining -= 1000;
        this.saveCredits();
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
    connectToChat() {
      // In a real implementation, this would establish a connection to the AI service
      this.connected = true;
      this.$root.subscribe('ai-response', this.handleAIResponse);
    },
    disconnectFromChat() {
      this.connected = false;
      this.$root.unsubscribe('ai-response', this.handleAIResponse);
    },
    async sendMessage() {
      if (!this.newMessage.trim()) return;
      
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
        // In a real implementation, this would send the message to an AI service
        // For now, we'll simulate an AI response
        await this.simulateAIResponse(messageText);
        
        // Auto-save chat after each exchange
        this.saveCurrentChat();
      } catch (error) {
        this.$root.showError('Failed to get AI response: ' + error.message);
        this.isTyping = false;
      }
    },
    async simulateAIResponse(userMessage) {
      // Simulate AI processing time
      await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
      
      let aiResponse = '';
      
      // Simple response logic based on user input
      const lowerMessage = userMessage.toLowerCase();
      
      if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
        aiResponse = 'Hello! I\'m here to help you with Security Onion. What would you like to know?';
      } else if (lowerMessage.includes('alert') || lowerMessage.includes('detection')) {
        aiResponse = 'I can help you with alerts and detections in Security Onion. You can view alerts in the Alerts section, create custom detections, or tune existing ones. What specific aspect would you like to explore?';
      } else if (lowerMessage.includes('hunt') || lowerMessage.includes('search')) {
        aiResponse = 'The Hunt interface allows you to search through your security data using OQL (Onion Query Language). You can filter by time ranges, specific fields, and create complex queries. Would you like help with a specific hunt query?';
      } else if (lowerMessage.includes('case') || lowerMessage.includes('incident')) {
        aiResponse = 'Cases in Security Onion help you manage security incidents. You can escalate alerts to cases, add observables, comments, and track investigation progress. Do you need help with case management?';
      } else if (lowerMessage.includes('dashboard') || lowerMessage.includes('metric')) {
        aiResponse = 'Dashboards provide visual insights into your security data. You can view pre-built dashboards or create custom ones. The metrics show system health, alert trends, and network activity. What metrics are you interested in?';
      } else if (lowerMessage.includes('help') || lowerMessage.includes('how')) {
        aiResponse = 'I can assist you with various Security Onion features including:\n\n• **Alerts & Detections** - Managing and tuning security alerts\n• **Hunt** - Searching and analyzing security data\n• **Cases** - Incident response and case management\n• **Dashboards** - Monitoring and metrics\n• **Grid Management** - System administration\n\nWhat would you like to learn more about?';
      } else {
        aiResponse = 'I understand you\'re asking about: "' + userMessage + '"\n\nI\'m here to help with Security Onion questions. Could you provide more specific details about what you\'d like to know? I can assist with alerts, hunting, cases, dashboards, and system administration.';
      }
      
      const assistantMessage = {
        role: 'assistant',
        content: aiResponse,
        timestamp: new Date().toISOString()
      };
      
      this.isTyping = false;
      this.messages.push(assistantMessage);
      this.deductCredit(); // Deduct credit for successful AI response
      this.scrollToBottom();
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