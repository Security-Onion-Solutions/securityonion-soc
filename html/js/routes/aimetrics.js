// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-aimetrics', 'pages/aimetrics.html');

routes.push({ path: '/aimetrics/:userId?/:sessionId?', name: 'aimetrics', component: {
  template: '#page-aimetrics',
  data() { return {
    i18n: this.$root.i18n,
    TABLE_SETTING_USERS: 0,
    TABLE_SETTING_SESSIONS: 1,
    TABLE_SETTING_MESSAGES: 2,
    showOptionsDialog: false,
    aimetrics: [],
    headers: [
      [
        { title: this.$root.i18n.email, value: 'email' },
        { title: this.$root.i18n.totalInputTokens, value: 'totalInputTokens' },
        { title: this.$root.i18n.totalOutputTokens, value: 'totalOutputTokens' },
        { title: this.$root.i18n.totalCredits, value: 'totalCredits' },
        { title: this.$root.i18n.creditPercentage, value: 'creditPercentage' },
        { title: this.$root.i18n.totalSessions, value: 'totalSessions' },
        { title: this.$root.i18n.totalMessages, value: 'totalMessages' },
        { title: this.$root.i18n.actions, value: 'actions' },
      ],
      [
        { title: this.$root.i18n.title, value: 'title' },
        { title: this.$root.i18n.createTime, value: 'createTime' },
        { title: this.$root.i18n.duration, value: 'durationMs' },
        { title: this.$root.i18n.totalInputTokens, value: 'totalInputTokens' },
        { title: this.$root.i18n.totalOutputTokens, value: 'totalOutputTokens' },
        { title: this.$root.i18n.totalCredits, value: 'totalCredits' },
        { title: this.$root.i18n.creditsPerMinute, value: 'creditsPerMinute' },
        { title: this.$root.i18n.totalMessages, value: 'totalMessages' },
        { title: this.$root.i18n.actions, value: 'actions' },
      ],
      [
        { value: 'expand' },
        { title: this.$root.i18n.message, value: 'expandMessage' },
        { title: this.$root.i18n.createTime, value: 'createTime' },
        { title: this.$root.i18n.role, value: 'role' },
        { title: this.$root.i18n.inputTokens, value: 'inputTokens' },
        { title: this.$root.i18n.outputTokens, value: 'outputTokens' },
        { title: this.$root.i18n.credits, value: 'credits' },
        { title: this.$root.i18n.model, value: 'model' },
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
    },
    rightShiftedHeaders: [
      ['totalInputTokens', 'totalOutputTokens', 'totalCredits', 'creditPercentage', 'totalSessions', 'totalMessages'],
      ['durationMs', 'totalInputTokens', 'totalOutputTokens', 'totalCredits', 'creditsPerMinute', 'totalMessages'],
      ['inputTokens', 'outputTokens', 'credits'],
    ],
    sortByUsers: [{ key: 'totalCredits', order: 'desc' }],
    sortBySessions: [{ key: 'createTime', order: 'desc' }],
    sortByMessages: [{ key: 'createTime', order: 'desc' }],
    itemsPerPage: 10,
    itemsPerPageOptions: [10,50,250,1000],
    tableSetting: 0, // 0: users 1: sessions 2: messages
    expanded: [],
    expandedHeaders: [
      { title: "key", value: "key" },
      { title: "value", value: "value" }
    ],
    searchFilter: '',
    
    dateRange: '',
    relativeTimeEnabled: true,
    relativeTimeValue: 24,
    relativeTimeUnit: RELATIVE_TIME_HOURS,
    relativeTimeUnits: [],
    zone: '',
    autoRefreshInterval: 0,
    autoRefreshIntervals: [],
    autoRefreshTimer: null,
    assistantEnabled: false,
    breadcrumbs: [],
    paramsLoaded: false,
    collapsedSections: [],
    chartHeight: 200,
    
    graphUsersCreditsOptions: {},
    graphUsersCreditsData: {},
    graphUsersSessionsOptions: {},
    graphUsersSessionsData: {},
    graphUsersMessagesOptions: {},
    graphUsersMessagesData: {},
    graphSessionsCreditsOptions: {},
    graphSessionsCreditsData: {},
    graphSessionsMessagesOptions: {},
    graphSessionsMessagesData: {},
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
    this.$root.initializeCharts();
  },
  beforeUnmount() {
    this.stopRefreshTimer();
  },
  mounted() {
    this.$root.loadParameters('assistant', this.initAssistant);
    this.setupCharts();
  },
  watch: {
    '$route': 'loadData',
    'sortByUsers': 'saveLocalSettings',
    'sortBySessions': 'saveLocalSettings',
    'sortByMessages': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
    'autoRefreshInterval': 'resetRefreshTimer',
  },
  methods: {
    async initAssistant(params) {
      this.assistantEnabled = params["enabled"] && this.$root.isLicensed('oai');
      this.paramsLoaded = true;
      if (this.assistantEnabled) {
        this.loadData();
      }
    },
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

      if (!this.assistantEnabled) {
        return;
      }
      // Calculate date range
      let range = this.dateRange;
      if (this.relativeTimeEnabled || range === '') {
        this.dateRange = '';
        range = this.getStartDate().format(this.$root.i18n.timePickerFormat) + " - " + this.getEndDate().format(this.$root.i18n.timePickerFormat);
        this.dateRange = range;
      }

      this.$root.startLoading();
      this.updateBreadcrumbs(currUserId, currSessionId);
      try {
        if (currSessionId && currUserId) {
          this.tableSetting = this.TABLE_SETTING_MESSAGES;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get(`/assistant/admin/${currUserId}/sessions/${currSessionId}/history`, {
            params: {
              format: this.$root.i18n.timePickerSample,
              range: range,
              zone: this.zone,
            }
          });
          this.aimetrics = response.data;
          this.aimetrics.forEach(item => {
            item.role = item.message.role;
            if (item.role === 'assistant' && item.message.usage) {
              item.inputTokens = item.message.usage.input_tokens;
              item.outputTokens = item.message.usage.output_tokens;
              item.credits = item.message.usage.credits;
            } else {
              item.inputTokens = 0;
              item.outputTokens = 0;
              item.credits = 0;
            }
            item.expandMessage = this.formatExpandMessage(item);
          });
        } else if (currUserId) {
          this.tableSetting = this.TABLE_SETTING_SESSIONS;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get(`/assistant/admin/${currUserId}/sessions`, {
            params: {
              format: this.$root.i18n.timePickerSample,
              range: range,
              zone: this.zone,
            }
          });
          this.aimetrics = response.data;
          this.aimetrics.forEach(item => {
            item.totalInputTokens = item.usage.totalInputTokens;
            item.totalOutputTokens = item.usage.totalOutputTokens;
            item.totalCredits = item.usage.totalCredits;
            item.totalMessages = item.usage.totalMessages;
            const startMs = new Date(item.createTime);
            const endMs = new Date(item.updateTime);
            item.durationMs = endMs - startMs;
            item.duration = this.$root.formatLongDuration(item.durationMs);
            item.creditsPerMinute = this.getCPM(item.durationMs, item.totalCredits);
          });
          this.populateSessionsCharts();
        } else {
          this.tableSetting = this.TABLE_SETTING_USERS;
          this.$root.adjustSubgridColVisibility(this.headers[this.tableSetting]);
          const response = await this.$root.papi.get('/assistant/admin/stats', {
            params: {
              format: this.$root.i18n.timePickerSample,
              range: range,
              zone: this.zone,
            }
          });
          this.aimetrics = response.data;
          let currTotal = 0;
          this.aimetrics.forEach(item => {
            currTotal += item.totalCredits;
          });
          await Promise.all(this.aimetrics.map(async item => {
            item.creditPercentage = this.calculateCreditPercentage(item.totalCredits, currTotal);
            item.email = await this.lookupSocId(item.userId);
          }));
          this.populateUsersCharts();
        }
      } catch (error) {
        this.$root.showError(error);
        this.aimetrics = [];
      }
      this.$root.stopLoading();
      this.resetRefreshTimer();
    },
    saveLocalSettings() {
      this.saveSetting('sortByUsers', this.sortByUsers[0].key, 'totalCredits');
      this.saveSetting('sortDescUsers', this.sortByUsers[0].order, 'desc')
      this.saveSetting('sortBySessions', this.sortBySessions[0].key, 'createTime');
      this.saveSetting('sortDescSessions', this.sortBySessions[0].order, 'desc')
      this.saveSetting('sortByMessages', this.sortByMessages[0].key, 'createTime');
      this.saveSetting('sortDescMessages', this.sortByMessages[0].order, 'desc')
      this.saveSetting('itemsPerPage', this.itemsPerPage, 10);
      this.saveSetting('relativeTimeValue', this.relativeTimeValue, 24);
      this.saveSetting('relativeTimeUnit', this.relativeTimeUnit, RELATIVE_TIME_HOURS);
      this.saveSetting('autoRefreshInterval', this.autoRefreshInterval, 0);
      localStorage['timezone'] = this.zone;
    },
    loadLocalSettings() {
      if (localStorage['settings.aimetrics.sortByUsers']) this.sortByUsers[0].key = localStorage['settings.aimetrics.sortByUsers'];
      if (localStorage['settings.aimetrics.sortDescUsers']) this.sortByUsers[0].order = localStorage['settings.aimetrics.sortDescUsers'];
      
      if (localStorage['settings.aimetrics.sortBySessions']) this.sortBySessions[0].key = localStorage['settings.aimetrics.sortBySessions'];
      if (localStorage['settings.aimetrics.sortDescSessions']) this.sortBySessions[0].order = localStorage['settings.aimetrics.sortDescSessions'];
      
      if (localStorage['settings.aimetrics.sortByMessages']) this.sortByMessages[0].key = localStorage['settings.aimetrics.sortByMessages'];
      if (localStorage['settings.aimetrics.sortDescMessages']) this.sortByMessages[0].order = localStorage['settings.aimetrics.sortDescMessages'];
      
      if (localStorage['settings.aimetrics.itemsPerPage']) this.itemsPerPage = parseInt(localStorage['settings.aimetrics.itemsPerPage']);
      if (localStorage['settings.aimetrics.relativeTimeValue']) this.relativeTimeValue = parseInt(localStorage['settings.aimetrics.relativeTimeValue']);
      if (localStorage['settings.aimetrics.relativeTimeUnit']) this.relativeTimeUnit = parseInt(localStorage['settings.aimetrics.relativeTimeUnit']);
      if (localStorage['timezone']) this.zone = localStorage['timezone'];
      if (localStorage['settings.aimetrics.autoRefreshInterval']) this.autoRefreshInterval = parseInt(localStorage['settings.aimetrics.autoRefreshInterval']);
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
    },
    formatExpandMessage(data) {
      let expandMessage = '';
      if (!data.message || !data.message.contentBlocks) return expandMessage;
      
      let blocks = data.message.contentBlocks;
      
      for (let i = 0; i < blocks.length; i++) {
        let block = blocks[i];
        if (block.type === 'text') {
          if (data.message.role === 'assistant') {
            if (i > 0 && this.nbspRegexOp(blocks[i - 1].text) != '') {
              expandMessage += `\n\n<hr>\n\n<br>`;
            }
            expandMessage += this.formatMarkdownMermaid(this.nbspRegexOp(block.text));
          } else {
            expandMessage += block.text;
          }
        } else if (block.type === 'tool_use') {
          if (i > 0 && this.nbspRegexOp(blocks[i - 1].text) != '') {
            expandMessage += `\n\n<hr>\n\n<br>`;
          }
          let toolMessage = `**Tool:** ${block.name}`;
          if (block.input) {
            toolMessage += `\n**Parameters:**`;
            for (let toolKey in block.input) {
              if (toolKey === 'limit') {
                toolMessage += `\n- ${toolKey}: ${block.input[toolKey]}`;
              } else {
                toolMessage += `\n- ${toolKey}: "${block.input[toolKey]}"`;
              }
            }
          }
          expandMessage += this.$root.formatMarkdown(toolMessage);
        } else if (block.toolResult) {
          let resultMessage = `**Tool Result:**\n`;
          if (block.toolResult.content) {
            for (let j = 0; j < block.toolResult.content.length; j++) {
              if (j > 0) {
                expandMessage += `\n\n<hr>\n\n<br>`;
              }
              let contentBlock = block.toolResult.content[j];
              if (contentBlock.text) {
                if (block.toolResult.isError) {
                  resultMessage += `\n**Error:** ${contentBlock.text}\n`;
                } else {
                  resultMessage += `\n${contentBlock.text}\n`;
                }
              } else if (contentBlock.json) {
                resultMessage += `\n\`\`\`json\n${JSON.stringify(contentBlock.json, null, 2)}\n\`\`\`\n`;
              }
            }
          }
          expandMessage += this.$root.formatMarkdown(resultMessage);
        }
      }
      return expandMessage;
    },
    stripHtml(str) {
      return str.replace(/<[^>]*>/g, '');
    },
    formatMarkdownMermaid(text) {
      text = this.$root.performMermaidRegexes(text);
      md = this.$root.formatMarkdown(text, true);
      this.$nextTick(() => {
        this.$root.renderMermaid();
      });
      return md;
    },
    updateBreadcrumbs(currUserId, currSessionId) {
      if (currUserId && currSessionId) {
        this.breadcrumbs = [
          {
            title: 'Users',
            disabled: false,
            to: { name: 'aimetrics' },
          },
          {
            title: 'Sessions',
            disabled: false,
            to: { name: 'aimetrics', params: { userId: currUserId } },
          },
          {
            title: 'Messages',
            disabled: true,
            to: null,
          },
        ];
      } else if (currUserId) {
        this.breadcrumbs = [
          {
            title: 'Users',
            disabled: false,
            to: { name: 'aimetrics' },
          },
          {
            title: 'Sessions',
            disabled: true,
            to: null,
          },
        ];
      } else {
        this.breadcrumbs = [
          {
            title: 'Users',
            disabled: true,
            to: null,
          },
        ];
      }
    },
    calculateCreditPercentage(credits, total) {
      let percentage = (credits / total) * 100;
      return `${percentage.toFixed(1)}%`;
    },
    getCPM(durationMs, totalCredits) {
      let minutes = durationMs / 60000;
      if (minutes < 1) minutes = 1;
      const rawCPM = totalCredits / minutes;
      return Math.round(rawCPM);
    },
    nbspRegexOp(text) {
      return text.replace(/^(&nbsp;?[\n]*)/, '');
    },
    toggleShowSection(item) {
      if (this.isExpandedSection(item)) {
        this.collapsedSections.push(item);
      } else {
        this.collapsedSections.splice(this.collapsedSections.indexOf(item), 1);
      }
    },
    isExpandedSection(item) {
      return (this.collapsedSections.indexOf(item) == -1);
    },
    setupCharts() {
      this.setupPieChart(this.graphUsersCreditsOptions, this.graphUsersCreditsData, this.i18n.totalCredits);
      this.setupPieChart(this.graphUsersSessionsOptions, this.graphUsersSessionsData, this.i18n.totalSessions);
      this.setupPieChart(this.graphUsersMessagesOptions, this.graphUsersMessagesData, this.i18n.totalMessages);
      this.graphUsersCreditsData.key = 0;
      this.graphUsersSessionsData.key = 0;
      this.graphUsersMessagesData.key = 0;

      this.setupTimelineChart(this.graphSessionsCreditsOptions, this.graphSessionsCreditsData, this.i18n.totalCredits);
      this.setupPieChart(this.graphSessionsMessagesOptions, this.graphSessionsMessagesData, this.i18n.totalMessages);
      this.graphSessionsCreditsData.key = 0;
      this.graphSessionsMessagesData.key = 0;
    },
    populateUsersCharts() {
      this.populateChart(this.graphUsersCreditsData, this.aimetrics, 'totalCredits');
      this.populateChart(this.graphUsersSessionsData, this.aimetrics, 'totalSessions');
      this.populateModelsChart(this.graphUsersMessagesData, this.aimetrics);
    },
    populateSessionsCharts() {
      this.populateChart(this.graphSessionsCreditsData, this.aimetrics, 'totalCredits', 'createTime');
      this.populateModelsChart(this.graphSessionsMessagesData, this.aimetrics);
    },
    populateModelsChart(chart, data) {
      chart.key++;
      chart.labels = [];
      chart.datasets[0].data = [];
      
      if (!data || data.length === 0) return;
      
      const modelMessageCounts = {};
      
      data.forEach(item => {
        const modelUsage = item.usage?.modelUsage || item.modelUsage;
        
        if (modelUsage) {
          for (const [modelKey, modelData] of Object.entries(modelUsage)) {
            if (!modelMessageCounts[modelKey]) {
              modelMessageCounts[modelKey] = 0;
            }
            modelMessageCounts[modelKey] += modelData.modelMessages || 0;
          }
        }
      });
      
      for (const [modelKey, messageCount] of Object.entries(modelMessageCounts)) {
        chart.labels.push(modelKey);
        chart.datasets[0].data.push(messageCount);
      }
    },
    populateChart(chart, data, field, timefield=null) {
      chart.key++;
      chart.labels = [];
      chart.datasets[0].data = [];
      
      if (!data || data.length === 0) return;
      
      const route = this;
      if (timefield != null) {
        data.forEach(function (item, index) {
          chart.datasets[0].data.push({
            x: new Date(item[timefield]),
            y: item[field] || 0
          });
        });
      } else {
        data.forEach(function (item, index) {
          const label = item.email || item.userId || route.i18n.unknown;
          chart.labels.push(route.$root.truncate(label, 30));
          chart.datasets[0].data.push(item[field] || 0);
        });
      }
    },
    setupBarChart(options, data, title) {
      var fontColor = this.$root.getColor("#888888", -40);
      var dataColor = this.$root.getColor("primary");
      var gridColor = this.$root.getColor("#888888", 65);
      options.responsive = true;
      options.maintainAspectRatio = false;
      options.plugins = {
        legend: {
          display: false,
        },
        title: {
          display: true,
          text: title,
        }
      };
      options.scales = {
        y: {
          grid: {
            color: gridColor,
          },
          ticks: {
            beginAtZero: true,
            fontColor: fontColor,
            precision: 0,
          }
        },
        x: {
          gridLines: {
            color: gridColor,
          },
          ticks: {
            fontColor: fontColor,
          }
        },
      };

      data.labels = [];
      data.datasets = [{
        backgroundColor: dataColor,
        borderColor: dataColor,
        pointRadius: 3,
        fill: false,
        data: [],
        label: this.i18n.field_count,
      }];
    },
    setupTimelineChart(options, data, title) {
      this.setupBarChart(options, data, title);
      options.onClick = null;
      options.scales.x.type = 'timeseries';
    },
    setupPieChart(options, data, title) {
      options.responsive = true;
      options.maintainAspectRatio = false;
      options.plugins = {
        legend: {
          display: true,
          position: 'left',
        },
        title: {
          display: true,
          text: title,
        }
      };
      data.labels = [];
      data.datasets = [{
        backgroundColor: [
          'rgba(77, 201, 246, 1)',
          'rgba(246, 112, 25, 1)',
          'rgba(245, 55, 148, 1)',
          'rgba(83, 123, 196, 1)',
          'rgba(172, 194, 54, 1)',
          'rgba(22, 106, 143, 1)',
          'rgba(0, 169, 80, 1)',
          'rgba(88, 89, 91, 1)',
          'rgba(133, 73, 186, 1)',
          'rgba(235, 204, 52, 1)',
          'rgba(127, 127, 127, 1)',
        ],
        borderColor: 'rgba(255, 255, 255, 0.5)',
        data: [],
        label: this.i18n.field_count,
      }];
    },
    buildModelIdentifier(model) {
      if (!model) return '';
      return `${model?.id||''}@${model?.adapter||''}`;
    }
  }
}});
