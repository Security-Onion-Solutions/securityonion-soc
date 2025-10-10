// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-aimetrics', 'pages/aimetrics.html');

routes.push({ path: '/aimetrics/:userId?/:sessionId?', name: 'aimetrics', component: {
  template: '#page-aimetrics',
  data() { return {
    i18n: this.$root.i18n,
    aimetrics: [],
    headers: [
      [
        { title: this.$root.i18n.email, value: 'userId' },
        { title: this.$root.i18n.totalInputTokens, value: 'totalInputTokens' },
        { title: this.$root.i18n.totalOutputTokens, value: 'totalOutputTokens' },
        { title: this.$root.i18n.totalCredits, value: 'totalCredits' },
        { title: this.$root.i18n.totalSessions, value: 'totalSessions' },
        { title: this.$root.i18n.totalMessages, value: 'totalMessages' },
      ],
      [
        { value: 'expand' },
        { title: this.$root.i18n.title, value: 'title' },
        { title: this.$root.i18n.createTime, value: 'createTime' },
        { title: this.$root.i18n.sessionId, value: 'sessionId' },
      ],
      [
        { value: 'expand' },
        { title: this.$root.i18n.id, value: 'id' },
        { title: this.$root.i18n.createTime, value: 'createTime' },
      ],
    ],
    expandedFields: {
      1: {
        'id': this.$root.i18n.id,
        'userId': this.$root.i18n.userId,
        'kind': this.$root.i18n.kind,
        'tags': this.$root.i18n.tags,
        'usage': this.$root.i18n.usage,
      },
      2: {
        'userId': this.$root.i18n.userId,
        'kind': this.$root.i18n.kind,
        'sessionId': this.$root.i18n.sessionId,
        'message': this.$root.i18n.message,
      },
    },
    sortBy0: [{ key: 'totalCredits', order: 'desc' }],
    sortBy1: [{ key: 'createTime', order: 'desc' }],
    sortBy2: [{ key: 'createTime', order: 'desc' }],
    itemsPerPage: 10,
    itemsPerPageOptions: [10,50,250,1000],
    tableSetting: 0, // 0: users 1: sessions 2: messages
    expanded: [],
    expandedHeaders: [
      { title: "key", value: "key" },
      { title: "value", value: "value" }
    ],
    creditsRemaining: 0,
  }},
  created() {
    this.loadData();
  },
  watch: {
    '$route': 'loadData',
    'sortBy0': 'saveLocalSettings',
    'sortBy1': 'saveLocalSettings',
    'sortBy2': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    async loadData() {
      const currUserId = this.$route.params.userId;
      const currSessionId = this.$route.params.sessionId;

      this.$root.startLoading();
      try {
        if (currSessionId && currUserId) {
          this.tableSetting = 2;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get(`/assistant/admin/${currUserId}/sessions/${currSessionId}/history`, {
            params: {
              format: '2006/01/02 3:04:05 PM',
              range: '2000/01/01 00:00:00 AM - 2050/01/01 00:00:00 AM',
            }
          });
          this.aimetrics = response.data;
        } else if (currUserId) {
          this.tableSetting = 1;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get(`/assistant/admin/${currUserId}/sessions`, {
            params: {
              format: '2006/01/02 3:04:05 PM',
              range: '2000/01/01 00:00:00 AM - 2050/01/01 00:00:00 AM',
            }
          });
          this.aimetrics = response.data;
        } else {
          this.tableSetting = 0;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get('/assistant/admin/stats', {
            params: {
              format: '2006/01/02 3:04:05 PM',
              range: '2000/01/01 00:00:00 AM - 2050/01/01 00:00:00 AM',
            }
          });
          this.aimetrics = response.data;
        }
        this.loadLocalSettings();
      } catch (error) {
        this.$root.showError(error);
        this.aimetrics = [];
      }
      this.$root.stopLoading();
      await this.loadCredits();
    },
    saveLocalSettings() {
      localStorage['settings.aimetrics.sortBy0'] = JSON.stringify(this.sortBy0);
      localStorage['settings.aimetrics.sortBy1'] = JSON.stringify(this.sortBy1);
      localStorage['settings.aimetrics.sortBy2'] = JSON.stringify(this.sortBy2);
      localStorage['settings.aimetrics.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.aimetrics.sortBy0']) {
        this.sortBy = JSON.parse(localStorage['settings.aimetrics.sortBy0']);  
      }
      if (localStorage['settings.aimetrics.sortBy1']) {
        this.sortBy = JSON.parse(localStorage['settings.aimetrics.sortBy1']);  
      }
      if (localStorage['settings.aimetrics.sortBy2']) {
        this.sortBy = JSON.parse(localStorage['settings.aimetrics.sortBy2']);  
      }
      if (localStorage['settings.aimetrics.itemsPerPage']) {
        this.itemsPerPage = parseInt(localStorage['settings.aimetrics.itemsPerPage']);
      }
    },
    buildUserLink(userId) {
      return { name: 'aimetrics', params: { userId: userId } };
    },
    buildSessionLink(sessionId) {
      return { name: 'aimetrics', params: { userId: this.$route.params.userId, sessionId: sessionId }}
    },
    getExpandedData(data) {
      const currFields = this.expandedFields[this.tableSetting];
      if (!currFields) {
        return [];
      }
      var records = [];
      for (let key in data) {
        if (Object.keys(currFields).includes(key)) {
          records.push({
            key: key,
            value: data[key],
            title: currFields[key],
          });
        }
      }
      return records;
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
    lookupSocId(data) {
      if (data && data.length == 36 && data.indexOf("-") == 8) {
        const user = this.$root.getUserByIdViaCache(data);
        if (user && user.email) {
          data = user.email;
        }
      }
      return data;
    },
  }
}});
