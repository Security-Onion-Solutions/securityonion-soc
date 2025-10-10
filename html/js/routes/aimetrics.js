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
        { title: this.$root.i18n.email, value: 'email' },
        { title: this.$root.i18n.totalInputTokens, value: 'totalInputTokens' },
        { title: this.$root.i18n.totalOutputTokens, value: 'totalOutputTokens' },
        { title: this.$root.i18n.totalCredits, value: 'totalCredits' },
        { title: this.$root.i18n.totalSessions, value: 'totalSessions' },
        { title: this.$root.i18n.totalMessages, value: 'totalMessages' },
        { title: this.$root.i18n.actions },
      ],
      [
        { title: this.$root.i18n.title, value: 'title' },
        { title: this.$root.i18n.createTime, value: 'createTime' },
        { title: this.$root.i18n.totalInputTokens, value: 'totalInputTokens' },
        { title: this.$root.i18n.totalOutputTokens, value: 'totalOutputTokens' },
        { title: this.$root.i18n.totalCredits, value: 'totalCredits' },
        { title: this.$root.i18n.totalMessages, value: 'totalMessages' },
        { title: this.$root.i18n.actions },
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
    searchFilter: '',
    
    // Date range filter properties
    dateRange: '',
    relativeTimeEnabled: true,
    relativeTimeValue: 24,
    relativeTimeUnit: RELATIVE_TIME_HOURS,
    relativeTimeUnits: [],
    zone: '',
    autoRefreshInterval: 0,
    autoRefreshIntervals: [],
    autoRefreshTimer: null,
  }},
  created() {
    this.relativeTimeUnits = [
      { title: this.$root.i18n.seconds, value: RELATIVE_TIME_SECONDS },
      { title: this.$root.i18n.minutes, value: RELATIVE_TIME_MINUTES },
      { title: this.$root.i18n.hours, value: RELATIVE_TIME_HOURS },
      { title: this.$root.i18n.days, value: RELATIVE_TIME_DAYS },
      { title: this.$root.i18n.weeks, value: RELATIVE_TIME_WEEKS },
      { title: this.$root.i18n.months, value: RELATIVE_TIME_MONTHS }
    ];
    this.autoRefreshIntervals = [
      { title: this.$root.i18n.interval0s, value: 0 },
      { title: this.$root.i18n.interval5s, value: 5 },
      { title: this.$root.i18n.interval10s, value: 10 },
      { title: this.$root.i18n.interval15s, value: 15 },
      { title: this.$root.i18n.interval30s, value: 30 },
      { title: this.$root.i18n.interval1m, value: 60 },
      { title: this.$root.i18n.interval2m, value: 120 },
      { title: this.$root.i18n.interval5m, value: 300 },
      { title: this.$root.i18n.interval10m, value: 600 },
      { title: this.$root.i18n.interval15m, value: 900 },
      { title: this.$root.i18n.interval30m, value: 1800 },
      { title: this.$root.i18n.interval1h, value: 3600 },
      { title: this.$root.i18n.interval2h, value: 7200 },
      { title: this.$root.i18n.interval5h, value: 18000 },
      { title: this.$root.i18n.interval10h, value: 36000 },
      { title: this.$root.i18n.interval24h, value: 86400 },
    ];
    this.zone = moment.tz.guess();
    this.loadData();
  },
  beforeUnmount() {
    this.stopRefreshTimer();
  },
  watch: {
    '$route': 'loadData',
    'sortBy0': 'saveLocalSettings',
    'sortBy1': 'saveLocalSettings',
    'sortBy2': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
    'autoRefreshInterval': 'resetRefreshTimer',
  },
  methods: {
    autoRefreshIntervalChanged() {
      this.saveSetting('autoRefreshInterval', this.autoRefreshInterval, 0);
    },
    stopRefreshTimer() {
      if (this.autoRefreshTimer) {
        clearTimeout(this.autoRefreshTimer);
      }
    },
    resetRefreshTimer() {
      var route = this;
      this.stopRefreshTimer();
      if (this.autoRefreshInterval > 0) {
        this.autoRefreshTimer = setTimeout(function () { route.loadData(); }, this.autoRefreshInterval * 1000);
      }
    },
    saveSetting(name, value, defaultValue = null) {
      var item = 'settings.aimetrics.' + name;
      if (defaultValue == null || value != defaultValue) {
        localStorage[item] = value;
      } else {
        localStorage.removeItem(item);
      }
    },
    async loadData() {
      const currUserId = this.$route.params.userId;
      const currSessionId = this.$route.params.sessionId;
      
      this.loadLocalSettings();
      //debugger;
      // Calculate date range
      let range = this.dateRange;
      if (this.relativeTimeEnabled || range === '') {
        this.dateRange = '';
        range = this.getStartDate().format(this.$root.i18n.timePickerFormat) + " - " + this.getEndDate().format(this.$root.i18n.timePickerFormat);
        this.dateRange = range;
      }

      this.$root.startLoading();
      try {
        if (currSessionId && currUserId) {
          this.tableSetting = 2;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get(`/assistant/admin/${currUserId}/sessions/${currSessionId}/history`, {
            params: {
              format: this.$root.i18n.timePickerSample,
              range: range,
              timezone: this.zone,
            }
          });
          this.aimetrics = response.data;
        } else if (currUserId) {
          this.tableSetting = 1;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get(`/assistant/admin/${currUserId}/sessions`, {
            params: {
              format: this.$root.i18n.timePickerSample,
              range: range,
              timezone: this.zone,
            }
          });
          this.aimetrics = response.data;
          this.aimetrics.forEach(item => {
            item.totalInputTokens = item.usage.totalInputTokens;
            item.totalOutputTokens = item.usage.totalOutputTokens;
            item.totalCredits = item.usage.totalCredits;
            item.totalMessages = item.usage.totalMessages;
          });
        } else {
          this.tableSetting = 0;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get('/assistant/admin/stats', {
            params: {
              format: this.$root.i18n.timePickerSample,
              range: range,
              timezone: this.zone,
            }
          });
          this.aimetrics = response.data;
          this.aimetrics.forEach(async item => {
            item.email = await this.lookupSocId(item.userId);
          });
        }
      } catch (error) {
        this.$root.showError(error);
        this.aimetrics = [];
      }
      this.$root.stopLoading();
      await this.loadCredits();
      this.resetRefreshTimer();
    },
    saveLocalSettings() {
      this.saveSetting('sortBy0', JSON.stringify(this.sortBy0), '[]');
      this.saveSetting('sortBy1', JSON.stringify(this.sortBy1), '[]');
      this.saveSetting('sortBy2', JSON.stringify(this.sortBy2), '[]');
      this.saveSetting('itemsPerPage', this.itemsPerPage, 10);
      this.saveSetting('relativeTimeValue', this.relativeTimeValue, 24);
      this.saveSetting('relativeTimeUnit', this.relativeTimeUnit, RELATIVE_TIME_HOURS);
      this.saveSetting('autoRefreshInterval', this.autoRefreshInterval, 0);
      localStorage['timezone'] = this.zone;
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
      if (localStorage['settings.aimetrics.relativeTimeValue']) {
        this.relativeTimeValue = parseInt(localStorage['settings.aimetrics.relativeTimeValue']);
      }
      if (localStorage['settings.aimetrics.relativeTimeUnit']) {
        this.relativeTimeUnit = parseInt(localStorage['settings.aimetrics.relativeTimeUnit']);
      }
      if (localStorage['timezone']) {
        this.zone = localStorage['timezone'];
      }
      if (localStorage['settings.aimetrics.autoRefreshInterval']) {
        this.autoRefreshInterval = parseInt(localStorage['settings.aimetrics.autoRefreshInterval']);
      }
    },
    buildUserLink(userId) {
      return { name: 'aimetrics', params: { userId: userId } };
    },
    buildSessionLink(sessionId) {
      return { name: 'aimetrics', params: { userId: this.$route.params.userId, sessionId: sessionId } }
    },
    buildAssistantLink(sessionId) {
      return { name: 'assistant', params: {sessionId: sessionId } };
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
    async lookupSocId(data) {
      if (data && data.length == 36 && data.indexOf("-") == 8) {
        const user = await this.$root.getUserById(data);
        if (user && user.email) {
          data = user.email;
        }
      }
      return data;
    },
    // Date range methods
    getEndDate() {
      if (this.dateRange != '') {
        var pieces = this.dateRange.split(" - ");
        if (pieces.length == 2) {
          return moment(pieces[1], this.$root.i18n.timePickerFormat);
        }
      }
      return moment();
    },
    getStartDate() {
      if (this.dateRange != '') {
        var pieces = this.dateRange.split(" - ");
        if (pieces.length == 2) {
          return moment(pieces[0], this.$root.i18n.timePickerFormat);
        }
      }
      var unit = "hour";
      switch (this.relativeTimeUnit) {
        case RELATIVE_TIME_SECONDS: unit = "seconds"; break;
        case RELATIVE_TIME_MINUTES: unit = "minutes"; break;
        case RELATIVE_TIME_HOURS: unit = "hours"; break;
        case RELATIVE_TIME_DAYS: unit = "days"; break;
        case RELATIVE_TIME_WEEKS: unit = "weeks"; break;
        case RELATIVE_TIME_MONTHS: unit = "months"; break;
      }
      return moment().subtract(this.relativeTimeValue, unit);
    },
    setupDateRangePicker() {
      if (this.relativeTimeEnabled) return;

      $('#aimetricsdaterange').daterangepicker({
        ranges: this.$root.generateDatePickerPreselects(),
        timePicker: true,
        timePickerSeconds: true,
        endDate: this.getEndDate(),
        startDate: this.getStartDate(),
        locale: {
          format: this.$root.i18n.timePickerFormat
        }
      });
      var route = this;
      if (route.dateRange == '') {
        route.dateRange = $('#aimetricsdaterange')[0].value;
      }
      $('#aimetricsdaterange').on('hide.daterangepicker', function (ev, picker) {
        route.hideDateRangePicker();
      });
    },
    showDateRangePicker() {
      if (this.relativeTimeEnabled) return;
      $('#aimetricsdaterange').click();
    },
    hideDateRangePicker() {
      if (this.relativeTimeEnabled) return;
      this.dateRange = $('#aimetricsdaterange')[0].value;
      this.loadData();
    },
    showAbsoluteTime() {
      this.relativeTimeEnabled = false;
      setTimeout(this.setupDateRangePicker, 10);
    },
    showRelativeTime() {
      this.relativeTimeEnabled = true;
    },
    notifyInputsChanged() {
      this.saveLocalSettings();
      this.loadData();
    },
    trimTitle(title) {
      let trimmed = '';
      if (title) {
        trimmed = title.substring(0, 41)
        if (title.length > 41) trimmed += '...';
      }
      return trimmed;
    }
  }
}});
