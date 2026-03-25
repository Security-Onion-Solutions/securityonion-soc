// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const RELATIVE_TIME_SECONDS = 10;
const RELATIVE_TIME_MINUTES = 20;
const RELATIVE_TIME_HOURS = 30;
const RELATIVE_TIME_DAYS = 40;
const RELATIVE_TIME_WEEKS = 50;
const RELATIVE_TIME_MONTHS = 60;
const FILTER_INCLUDE = 'INCLUDE';
const FILTER_EXCLUDE = 'EXCLUDE';
const FILTER_EXACT = 'EXACT';
const FILTER_DRILLDOWN = 'DRILLDOWN';

loadPageTemplate('page-hunt', 'pages/hunt.html');

const huntComponent = {
  template: '#page-hunt',
  data() {
    return {
      i18n: this.$root.i18n,
      params: null,
      category: '',
      advanced: false,
      queryAltered: false,
      query: '',
      querySearch: '',
      queryRemainder: '',
      queries: [],
      queryBaseFilter: "",
      queryName: '',
      queryFilters: [],
      queryGroupBys: [],
      queryGroupByOptions: [],
      querySortBys: [],
      queryTableFields: [],
      queryTableOptions: [],
      eventFields: {},
      dateRange: '',
      relativeTimeEnabled: true,
      relativeTimeValue: 24,
      relativeTimeUnit: RELATIVE_TIME_HOURS,
      relativeTimeUnits: [],
      autoRefreshInterval: 0,
      autoRefreshIntervals: [],
      autoRefreshTimer: null,
      loaded: false,
      chartHeight: 200,
      zone: '',
      huntPending: false,
      ackEnabled: false,
      escalateEnabled: false,
      assistantEnabled: false,
      investigateEnabled: false,
      investigationMsg: '',
      viewEnabled: false,
      createLink: '',
      collapsedSections: [],

      filterToggles: [],

      timelineChartOptions: {},
      timelineChartData: {},

      metricsEnabled: false,
      eventsEnabled: true,
      topChartOptions: {},
      topChartData: {},
      bottomChartOptions: {},
      bottomChartData: {},
      groupBys: [],
      groupByLimitOptions: [10, 25, 50, 100, 200, 500],
      groupByLimit: 10,
      groupByFilter: '',
      groupByItemsPerPage: 10,
      groupByFooters: [10, 25, 50, 100, 200, 500],
      groupByPage: 1,
      groupBySortBy: 'count',
      groupBySortDesc: true,
      chartLabelMaxLength: 30,
      chartLabelOtherLimit: 10,
      chartLabelFieldSeparator: ', ',

      eventLimitOptions: [10, 25, 50, 100, 200, 500, 1000, 2000, 5000],
      eventLimit: 100,
      eventData: [],
      eventFilter: '',
      eventHeaders: [],
      eventPage: 1,
      sortBy: [{ key: 'soc_timestamp', order: 'desc' }],
      sortDesc: true,
      itemsPerPage: 10,
      itemsPerPageOptions: [10, 25, 50, 100, 200, 500, 1000],

      expandedHeaders: [
        { title: "key", value: "key" },
        { title: "value", value: "value" }
      ],

      totalEvents: 0,
      fetchTimeSecs: 0,
      roundTripTimeSecs: 0,
      mruQueries: [],
      mruCases: [],

      autohunt: true,
      showFullQuery: true,
      showOptionsDialog: false,

      filterRouteInclude: "",
      filterRouteExclude: "",
      filterRouteExact: "",
      filterRouteDrilldown: "",
      filterRouteLessThan: "",
      filterRouteLessThanEqual: "",
      filterRouteGreaterThan: "",
      filterRouteGreaterThanEqual: "",
      groupByRoute: "",
      groupByNewRoute: "",
      quickActionVisible: false,
      quickActionTarget: null,
      quickActionEvent: null,
      quickActionField: "",
      quickActionValue: "",
      quickActionIsNumeric: false,
      escalationMenuVisible: false,
      escalationMenuTarget: null,
      escalationItem: null,
      escalationGroupIdx: -1,
      escalateRelatedEventsEnabled: false,
      aggregationActionsEnabled: false,
      actions: [],
      safeStringMaxLength: Number.MAX_SAFE_INTEGER,
      betweenDialogVisible: false,
      betweenStart: '',
      betweenStartEquals: false,
      betweenEnd: '',
      betweenEndEquals: false,
      betweenError: '',
      equalityOperators: [
        { title: '<', value: false },
        { title: '≤', value: true }
      ],
      addToCaseDialogVisible: false,
      mruCases: [],
      selectedMruCase: null,
      disableRouteLoad: false,
      selectAllState: false,
      selectAllIndeterminate: false,
      selectedCount: 0,
      selectedAction: 'enable',
      bulkActions: [
        { title: this.$root.i18n.enable, value: 'enable' },
        { title: this.$root.i18n.disable, value: 'disable' },
        { title: this.$root.i18n.delete, value: 'delete' },
      ],
      quickActionDetId: null,
      presets: {},
      manualSyncTargetEngine: null,
      showBulkDeleteConfirmDialog: false,
      tuneDetectionTabTarget: null,
      eventCurrentItems: [],
      detectionEngineStatusQueries: {},
      highlightedDetection: null,
      highlightedAlertInfo: null,
      showDetailsPanel: true,
      openPanel: [0],
      quickActionsOpen: [],
      escalatingDetectionEvents: false,
      showAckManyDialog: false,
      ackManyArgs: [],
      ackManyVerb: '',
      fieldValueDialogVisible: false,
      fieldValueDialogKey: '',
      fieldValueDialogValue: '',
      menuScrollPos: 0,
      maxEscalate: 100,
      chartResizeTracker: {},
      gridId: null,
      activeTabs: {},
      gridLayoutExpansions: true,
      showGuidedAnalysisFirst: true,
      expandedEvents: [],
      eventColumnWidth: 0,
      expandedPlaybookQuestions: {},
    }
  },
  created() {
    this.$root.initializeCharts();
    this.relativeTimeUnits = [
      { title: this.i18n.seconds, value: RELATIVE_TIME_SECONDS },
      { title: this.i18n.minutes, value: RELATIVE_TIME_MINUTES },
      { title: this.i18n.hours, value: RELATIVE_TIME_HOURS },
      { title: this.i18n.days, value: RELATIVE_TIME_DAYS },
      { title: this.i18n.weeks, value: RELATIVE_TIME_WEEKS },
      { title: this.i18n.months, value: RELATIVE_TIME_MONTHS }
    ];
    this.autoRefreshIntervals = [
      { title: this.i18n.interval0s, value: 0 },
      { title: this.i18n.interval5s, value: 5 },
      { title: this.i18n.interval10s, value: 10 },
      { title: this.i18n.interval15s, value: 15 },
      { title: this.i18n.interval30s, value: 30 },
      { title: this.i18n.interval1m, value: 60 },
      { title: this.i18n.interval2m, value: 120 },
      { title: this.i18n.interval5m, value: 300 },
      { title: this.i18n.interval10m, value: 600 },
      { title: this.i18n.interval15m, value: 900 },
      { title: this.i18n.interval30m, value: 1800 },
      { title: this.i18n.interval1h, value: 3600 },
      { title: this.i18n.interval2h, value: 7200 },
      { title: this.i18n.interval5h, value: 18000 },
      { title: this.i18n.interval10h, value: 36000 },
      { title: this.i18n.interval24h, value: 86400 },
    ];
  },
  beforeUnmount() {
    this.$root.setSubtitle("");
    this.stopRefreshTimer();
    this.$root.unsubscribe('detections:bulkUpdate', this.bulkUpdateReport);
    this.$root.unsubscribe('related:bulkCreate', this.bulkUpdateReport);

    if (this.isCategory('alerts')) {
      window.removeEventListener('resize', this.calculateEventColumnWidth);
    }

    window.removeEventListener('resize', this.checkAllFieldTruncation);
  },
  mounted() {
    window.addEventListener('resize', this.checkAllFieldTruncation);

    this.$root.startLoading();
    this.category = this.$route.path.replace("/", "");
    this.$root.loadParameters(this.category, this.initHunt);

    if (this.isCategory('detections')) {
      this.$root.subscribe('detections:bulkUpdate', this.bulkUpdateReport);
    }

    if (this.isCategory('alerts') || this.isCategory('hunt')) {
      this.$root.subscribe('related:bulkCreate', this.bulkUpdateReport);
    }

    if (this.isCategory('alerts')) {
      window.addEventListener('resize', this.calculateEventColumnWidth);
    }
  },
  watch: {
    expandedEvents() {
      this.$nextTick(() => this.checkAllFieldTruncation());
    },
    gridLayoutExpansions() {
      this.$nextTick(() => this.checkAllFieldTruncation());
    },
    '$route': 'loadData',
    'groupBySortBy': 'saveLocalSettings',
    'groupBySortDesc': 'saveLocalSettings',
    'groupByItemsPerPage': 'groupByItemsPerPageChanged',
    'groupByLimit': 'groupByLimitChanged',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
    'itemsPerPage': 'itemsPerPageChanged',
    'eventLimit': 'eventLimitChanged',
    'relativeTimeValue': 'saveLocalSettings',
    'relativeTimeUnit': 'saveLocalSettings',
    'autohunt': 'saveLocalSettings',
    'autoRefreshInterval': 'resetRefreshTimer',
    'showDetailsPanel': 'toggleShowDetailsPanel',
    'advanced': 'saveLocalSettings',
    'gridLayoutExpansions': 'saveLocalSettings',
    'showGuidedAnalysisFirst': 'saveLocalSettings',
  },
  computed: {
    alertGroupCount() {
      return this.groupBys.length > 0 && this.groupBys[0].data ? this.groupBys[0].data.length : 0;
    },
    criticalHighCount() {
      return this.eventData.filter(e => {
        var sev = (e['event.severity_label'] || e['so_case.severity'] || '').toLowerCase();
        return sev === 'critical' || sev === 'high';
      }).length;
    },
    alertStatus() {
      const ackBool = this.isFilterToggleEnabled('acknowledged');
      const escBool = this.isFilterToggleEnabled('escalated');
      const invBool = this.isFilterToggleEnabled('investigated');
      let retStr = "";
      if (ackBool && escBool) {
        retStr = this.i18n.escalated;
      } else if (escBool) {
        retStr = this.i18n.escalated + ", " + this.i18n.unacknowledged;
      } else if (ackBool) {
        retStr = this.i18n.acknowledged;
      } else {
        retStr = this.i18n.unacknowledged;
      }
      if (invBool) {
        retStr += ", " + this.i18n.aiInvestigated;
      }
      return retStr;
    },
    excludeStatus() {
      const excludeCase = this.isFilterToggleEnabled('caseExcludeToggle');
      const excludeDet = this.isFilterToggleEnabled('detectionsExcludeToggle');
      const excludeSoc = this.isFilterToggleEnabled('socExcludeToggle');
      const excludeAI = this.isFilterToggleEnabled('onionaiExcludeToggle');
      let retStr = "";
      if (excludeCase) {
        retStr = this.i18n.caseData;
      }
      if (excludeDet) {
        retStr = retStr ? retStr + ', ' + this.i18n.detectionsData : this.i18n.detectionsData;
      }
      if (excludeSoc) {
        retStr = retStr ? retStr + ', ' + this.i18n.socLogs : this.i18n.socLogs;
      }
      if (excludeAI) {
        retStr = retStr ? retStr + ', ' + this.i18n.onionaiData : this.i18n.onionaiData;
      }
      if (!retStr) {
        retStr = this.i18n.none;
      }
      return retStr;
    },
  },
  methods: {
    moment: moment,
    isAdvanced() {
      return this.advanced;
    },
    shouldAutohunt() {
      return this.autohunt || !this.isAdvanced();
    },
    isCategory(testCategory) {
      return testCategory == this.category;
    },
    loading() {
      return this.$root.loading;
    },
    initAssistant(params) {
      this.assistantEnabled = params["enabled"];
      this.investigationMsg = params["investigationPrompt"];
    },
    async initHunt(params) {
      this.params = params;
      this.groupByItemsPerPage = params["groupItemsPerPage"];
      this.groupByLimit = params["groupFetchLimit"];
      this.itemsPerPage = params["eventItemsPerPage"];
      this.eventLimit = params["eventFetchLimit"];
      this.relativeTimeValue = params["relativeTimeValue"];
      this.relativeTimeUnit = params["relativeTimeUnit"];
      this.mruQueryLimit = params["mostRecentlyUsedLimit"];
      this.safeStringMaxLength = params["safeStringMaxLength"];
      this.queryBaseFilter = params["queryBaseFilter"];
      this.queries = this.applyQuerySubstitutions(params["queries"]);
      this.filterToggles = params["queryToggleFilters"];
      this.eventFields = params["eventFields"];
      this.advanced = params["advanced"];
      this.ackEnabled = params["ackEnabled"];
      this.escalateEnabled = params["escalateEnabled"];
      this.escalateRelatedEventsEnabled = params["escalateRelatedEventsEnabled"];
      this.aggregationActionsEnabled = params["aggregationActionsEnabled"];
      this.viewEnabled = params["viewEnabled"];
      this.createLink = params["createLink"];
      this.chartLabelMaxLength = params["chartLabelMaxLength"]
      this.chartLabelOtherLimit = params["chartLabelOtherLimit"]
      this.chartLabelFieldSeparator = params["chartLabelFieldSeparator"]
      this.presets = params["presets"];
      this.manualSyncTargetEngine = this.getPresets("manualSync")[0];
      this.maxEscalate = params["maxBulkEscalateEvents"];
      if (params["detectionEngineStatusQueries"]) {
        try {
          this.detectionEngineStatusQueries = jsyaml.load(params["detectionEngineStatusQueries"], { schema: jsyaml.FAILSAFE_SCHEMA })
        } catch {
          this.detectionEngineStatusQueries = {};
        }
      }
      if (this.queries != null && this.queries.length > 0) {
        this.query = this.queries[0].query;
      }
      this.actions = params["actions"] || [];
      this.zone = moment.tz.guess();

      this.loadLocalSettings();
      
      if (this.isCategory('alerts')) {
        this.$nextTick().then(() => {
          this.$root.loadParameters('assistant', this.initAssistant);
          this.investigateEnabled = this.$root.isLicensed('oai') && this.assistantEnabled;
        });
      }
      
      if (this.mruQueries.length > 0 && this.isAdvanced()) {
        this.query = this.mruQueries[0];
      }

      if (!this.isCategory('alerts')) {
        this.showDetailsPanel = false;
      }

      if (this.$route.query.t) {
        // This page was either refreshed, or opened from an existing hunt hyperlink,
        // so switch to absolute time since the URL has the absolute time defined.
        this.relativeTimeEnabled = false;
        this.dateRange = this.$route.query.t;
      }

      this.setupCharts();

      this.$root.stopLoading();

      if (!this.parseUrlParameters()) return;

      if (this.$route.query.q || (this.shouldAutohunt() && this.query)) {
        this.hunt(true);
      }
    },
    applyQuerySubstitutions(queries) {
      if (Array.isArray(queries)) {
        queries.forEach(query => {
          query.query = query.query.replace(/\{myId\}/g, this.$root.user.id);
        });

        return queries;
      } else {
        return [];
      }
    },
    reconstructQuery() {
      if (this.isAdvanced() && !this.showFullQuery) {
        this.query = this.querySearch + " " + this.queryRemainder;
      }
    },
    submitQuery() {
      this.reconstructQuery();
      this.hunt();
    },
    queryModified() {
      this.reconstructQuery();
      return this.notifyInputsChanged();
    },
    notifyInputsChanged(replaceHistory = false) {
      var hunted = false;
      this.toggleQuickAction();
      if (!this.loading()) {
        if (this.shouldAutohunt()) {
          this.hunt(replaceHistory);
          hunted = true;
        } else {
          this.$root.drawAttention('#hunt');
          this.huntPending = true;
        }
      }
      return hunted;
    },
    addMRUQuery(query) {
      if (query && query.length > 1 && this.isAdvanced()) {
        var existingIndex = this.mruQueries.indexOf(query);
        if (existingIndex >= 0) {
          this.mruQueries.splice(existingIndex, 1);
        }
        this.mruQueries.unshift(query);
        while (this.mruQueries.length > this.mruQueryLimit) {
          this.mruQueries.pop();
        }
        this.saveLocalSettings();
      }
    },
    hunt(replaceHistory = false) {
      this.huntPending = false;
      this.selectAllState = false;
      this.selectAllIndeterminate = false;
      this.selectedCount = 0;
      this.expandedPlaybookQuestions = {};

      var onSuccess = () => { };
      var onFail = () => {
        // When navigating to the same URL, simply refresh data
        this.loadData();
      };
      if (this.isCategory('detections')) {
        this.dateRange = moment(0).format(this.i18n.timePickerFormat) + " - " + moment().format(this.i18n.timePickerFormat);
      } else if (this.relativeTimeEnabled) {
        this.dateRange = '';
        this.dateRange = this.getStartDate().format(this.i18n.timePickerFormat) + " - " + this.getEndDate().format(this.i18n.timePickerFormat);
      }

      const targetRoute = this.$router.resolve(this.buildCurrentRoute());
      const currentRoute = this.$router.resolve(this.$router.currentRoute.value);

      if (currentRoute.fullPath === targetRoute.fullPath) {
        this.loadData();
      } else {
        if (replaceHistory === true) {
          this.$router.replace(targetRoute, onSuccess, onFail);
        } else {
          this.$router.push(targetRoute);
        }
      }

      this.resetRefreshTimer();

      this.selectAllState = false;
      this.selectedCount = 0;
    },
    autoRefreshIntervalChanged() {
      // This cannot occur with the other settings due to risk of query params overwriting the saved settings
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
        this.autoRefreshTimer = setTimeout(function () { route.hunt(true); }, this.autoRefreshInterval * 1000);
      }
    },
    huntQuery(query) {
      this.query = query;
      this.hunt();
    },
    async getQuery() {
      var q = "";
      if (this.queryBaseFilter.length > 0) {
        q = this.queryBaseFilter;
      }

      if (Array.isArray(this.filterToggles)) {
        for (var i = 0; i < this.filterToggles.length; i++) {
          filter = this.filterToggles[i];

          if (filter.enabled) {
            if (q.length > 0) {
              q = q + " AND ";
            }
            q = q + filter.filter;
          } else if (filter.exclusive) {
            if (q.length > 0) {
              q = q + " AND ";
            }
            q = q + "NOT " + filter.filter;
          }
        }
      }

      if (q.length > 0) {
        const response = await this.$root.papi.get('query/filtered', {
          params: {
            query: this.query,
            field: "",
            value: q,
            scalar: true,
            mode: FILTER_INCLUDE,
            condense: true,
          }
        });

        return response.data;
      }
      return this.query;
    },
    parseUrlParameters() {
      this.category = this.$route.path.replace("/", "");

      if (this.$route.query.q) {
        this.query = this.$route.query.q;
      }

      if (this.$route.query.rt) {
        this.relativeTimeEnabled = true;
        this.relativeTimeValue = parseInt(this.$route.query.rt);
      }
      if (this.$route.query.rtu) {
        this.relativeTimeEnabled = true;
        this.setRelativeTimeUnits(this.$route.query.rtu);
      }
      if (this.$route.query.t) {
        this.relativeTimeEnabled = false;
        setTimeout(this.setupDateRangePicker, 10);

        this.dateRange = this.$route.query.t;
      }
      if (this.$route.query.z) {
        this.zone = this.$route.query.z;
      }
      if (this.$route.query.el) {
        this.eventLimit = parseInt(this.$route.query.el);
      }
      if (this.$route.query.gl) {
        this.groupByLimit = parseInt(this.$route.query.gl);
      }
      if (this.$route.query.ar) {
        let found = false;
        this.autoRefreshIntervals.forEach(inter => {
          if (inter.value === parseInt(this.$route.query.ar)) {
            found = true;
            return false;
          }
        });

        this.autoRefreshInterval = found ? parseInt(this.$route.query.ar) : 0;
      }
      if (this.$route.query.tab) {
        this.activeTabs[0] = this.$route.query.tab;
      }
      if (this.$route.query.expand) {
        const items = this.$route.query.expand.split('|');
        for (let item of items) {
          this.expandedEvents.push(item);
        }
      }
      if (Array.isArray(this.filterToggles)) {
        for (const q in this.$route.query) {
          this.filterToggles.forEach(toggle => {
            if (toggle.name === q) {
              let enabled = this.$route.query[q];
              if (typeof enabled === 'string') {
                enabled = enabled.toLowerCase() === 'true';
              }
              toggle.enabled = enabled;
            }
          });
        }
      }

      this.gridId = this.$route.query.gridId;

      // Check for special params that force a re-route. This is needed when async functions will handle the hunt themselves.
      // So setting reroute=true tells the current thread not to perform the hunt, because the async thread will be doing it momentarily.
      var reRoute = false;
      if (this.$route.query.filterValue) {
        this.filterQuery(this.$route.query.filterField, this.$route.query.filterValue, this.$route.query.filterMode, undefined, this.$route.query.scalar === 'true');
        reRoute = true;
      }
      if (this.$route.query.groupByField) {
        this.groupQuery(this.$route.query.groupByField, this.$route.query.groupByGroup);
        reRoute = true;
      }
      if (reRoute) return false;

      return true;
    },
    async loadData() {
      if (this.disableRouteLoad) return;

      if (!this.parseUrlParameters()) return;

      const abortController = new AbortController();
      this.$root.startLoading(() => {
        abortController.abort();
        this.$root.stopLoading();
      });
      try {
        this.obtainQueryDetails();

        // This must occur before the following await, so that Vue flushes the old groupby DOM renders
        this.groupBys.splice(0);

        let range = this.dateRange;
        const params = {
          query: await this.getQuery(),
          range: range,
          format: this.i18n.timePickerSample,
          zone: this.zone,
          metricLimit: this.groupByLimit,
          eventLimit: this.eventLimit,
        };

        if (this.gridId && this.gridId.length > 0) {
          params.gridId = this.gridId;
        }

        if (this.loaded) {
          this.activeTabs = {};
          this.expandedEvents = [];
        }

        let response = await this.$root.papi.get('events/', { params: params, signal: abortController.signal });

        this.eventPage = 1;
        this.groupByPage = 1;
        this.totalEvents = response.data.totalEvents;
        this.fetchTimeSecs = response.data.elapsedMs / 1000;
        this.roundTripTimeSecs = Math.abs(moment(response.data.completeTime) - moment(response.data.createTime)) / 1000;
        this.populateChart(this.timelineChartData, response.data.metrics["timeline"]);
        this.populateEventTable(response.data.events);

        this.metricsEnabled = false;
        if (response.data.metrics["bottom"] != undefined) {
          this.metricsEnabled = true;
          this.populateGroupByTables(response.data.metrics);
          this.populateChart(this.topChartData, response.data.metrics[this.lookupTopMetricKey(response.data.metrics)]);
          this.populateChart(this.bottomChartData, response.data.metrics["bottom"]);
        }
        this.loaded = true;
        this.addMRUQuery(this.query);

        if (this.activeTabs[0] === 'playbook') {
          // this should only happen when the user is opening a
          // playbook for a specific alert from another page
          for (let item of this.eventData) {
            this.loadPlaybook(item);
          }
        }

        var subtitle = this.isAdvanced() ? this.query : this.queryName;
        this.$root.setSubtitle(this.i18n[this.category] + " - " + subtitle);
      } catch (error) {
        this.$root.showError(error);
      }

      this.$root.stopLoading();

      if (this.isCategory('alerts')) {
        this.$nextTick(() => {
          this.calculateEventColumnWidth();
        });
      }
    },
    async exportMetrics(group, groupIdx) {
      this.$root.export({
          type: 'tabular',
          query: await this.getQuery(),
          group: group.key,
          groupIdx: groupIdx,
          timezone: this.zone,
        }, this.getStartDate().format(), this.getEndDate().format());
    },
    async exportEvents() {
      this.$root.export({
          type: 'tabular',
          query: await this.getQuery(),
          timezone: this.zone,
        }, this.getStartDate().format(), this.getEndDate().format());
    },
    getPresets(kind) {
      if (this.presets && this.presets[kind]) {
        return this.presets[kind].labels;
      }

      return [];
    },
    async filterQuery(field, value, filterMode, notify = true, scalar = false) {
      try {
        const valueType = typeof value;
        if (valueType == "boolean" || valueType == "number" || valueType == "bigint") {
          scalar = true;
        }
        const response = await this.$root.papi.get('query/filtered', {
          params: {
            query: this.query,
            field: filterMode == FILTER_EXACT ? "" : field,
            value: value,
            scalar: scalar,
            mode: filterMode,
          }
        });
        this.query = response.data;
        if (notify) {
          this.notifyInputsChanged(true);
        }
      } catch (error) {
        this.$root.showError(error);
      }
    },
    async groupQuery(field, group, notify = true) {
      try {
        const response = await this.$root.papi.get('query/grouped', {
          params: {
            query: this.query,
            field: field,
            group: group,
          }
        });
        this.query = response.data;
        if (notify) {
          this.notifyInputsChanged(true);
        }
      } catch (error) {
        this.$root.showError(error);
      }
    },
    buildCase(item) {
      var title = 'rule.name' in item && item['rule.name'] ? '' + item['rule.name'] : null;
      if (!title) {
        title = this.i18n.eventCaseTitle;
        if (item['event.module'] || item['event.dataset']) {
          title = title + ": ";
          if (item['event.module']) {
            title = title + item['event.module'];
            if (item['event.dataset']) {
              title = title + " - ";
            }
          }
          if (item['event.dataset']) {
            title = title + item['event.dataset'];
          }
        }
      }

      var description = this.i18n.caseEscalatedDescription;
      if (!this.escalateRelatedEventsEnabled) {
        var description = item['message'];
        if (!description) {
          description = JSON.stringify(item);
        }
      }

      var severity = 'event.severity' in item && item['event.severity'] ? '' + item['event.severity'] : '';
      var template = 'rule.case_template' in item && item['rule.case_template'] ? '' + item['rule.case_template'] : '';

      return {
        title: this.formatSafeString(title),
        description: description,
        severity: severity,
        template: template,
      };
    },
    panelAck(args) {
      args[1] = !this.isFilterToggleEnabled('acknowledged');
      this.ack(...args);
    },
    async ack(item, acknowledge, escalate, caseId, groupIdx, detectionRelated = false, skipDialog = false) {
      if (detectionRelated && !skipDialog) {
        if (escalate) {
          this.ackManyVerb = this.i18n.escalate.toLowerCase();
        } else {
          this.ackManyVerb = acknowledge ? this.i18n.acknowledge : this.i18n.acknowledgeUndo;
        }

        this.ackManyArgs = [item, acknowledge, escalate, caseId, groupIdx, detectionRelated, true];
        this.showAckManyDialog = true;

        return;
      } else {
        this.closeAckManyDialog();
      }

      this.$root.startLoading();
      try {
        var docEvent = {};
        if (item["soc_id"]) {
          // only send necessary fields
          docEvent["soc_id"] = item["soc_id"];
        } else {
          for (let field of Object.keys(item)) {
            if (field !== 'newest' && !field.startsWith('_')) docEvent[field] = item[field]
          }
        }
        var isAlert = ('rule.name' in item || 'event.severity_label' in item);
        if (escalate) {
          if (!caseId || !this.escalateRelatedEventsEnabled) {
            // Add to new case
            const response = await this.$root.papi.post('case/', this.buildCase(item));
            if (response && response.data) {
              caseId = response.data.id;
            }
          }

          // Attach the event to the case
          if (caseId && this.escalateRelatedEventsEnabled) {
            let payload = {
              fields: docEvent,
              caseId: caseId,
              acknowledged: this.isFilterToggleEnabled('acknowledged'),
              escalated: this.isFilterToggleEnabled('escalated'),
              dateRange: this.dateRange,
              dateRangeFormat: this.i18n.timePickerSample,
              timezone: this.zone,
            };

            if (detectionRelated) {
              payload.fields = {
                'rule.uuid': item["rule.uuid"],
              };
            }

            await this.$root.papi.post('case/events', payload);
          }
        }
        if (isAlert) {
          let searchFilter;
          let eventFilter;

          if (!detectionRelated) {
            for (let prop in docEvent) {
              docEvent[prop] = this.subMissing(docEvent[prop]);
            }

            eventFilter = docEvent;
            searchFilter = await this.getQuery();
          } else {
            searchFilter = (acknowledge ? 'NOT ' : '') + 'event.acknowledged:true AND tags:alert';
            eventFilter = {
              'rule.uuid': item["rule.uuid"],
            };
          }

          const response = await this.$root.papi.post('events/ack', {
            searchFilter: searchFilter,
            eventFilter: eventFilter,
            dateRange: this.dateRange,
            dateRangeFormat: this.i18n.timePickerSample,
            timezone: this.zone,
            escalate: escalate,
            acknowledge: acknowledge,
          });
          if (response.data && response.data.errors && response.data.errors.length > 0) {
            this.$root.showWarning(this.i18n.ackPartialSuccess);
          }
        }
        if (this.isCategory('alerts')) {
          if ((item["count"] && item["count"] > 1) || detectionRelated) {
            this.$root.showTip(escalate ? this.i18n.escalatedMultipleTip : (acknowledge ? this.i18n.ackMultipleTip : this.i18n.ackUndoMultipleTip));
          } else {
            this.$root.showTip(escalate ? this.i18n.escalatedSingleTip : (acknowledge ? this.i18n.ackSingleTip : this.i18n.ackUndoSingleTip));
          }

          var data;
          if (item["count"] && groupIdx >= 0 && this.groupBys?.[groupIdx]?.data) {
            data = this.groupBys[groupIdx].data;
          } else {
            data = this.eventData;
          }

          this.removeDataItemFromView(data, item, detectionRelated);
        } else if (escalate) {
          this.$root.showTip(this.i18n.escalatedEventTip);
          item['event.escalated'] = true;
        }


        if (this.highlightedAlertInfo) {
          const inGroup = this.highlightedAlertInfo.groupIndex === -1

          if ((!inGroup && item === this.highlightedAlertInfo.item) ||
            (inGroup && this.highlightedDetection.publicId === item["rule.uuid"])) {
            this.highlightedDetection = null;
            this.highlightedAlertInfo = null;
          }
        }
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    removeDataItemFromView(data, item, detectionRelated) {
      for (var j = 0; j < data.length; j++) {
        if (data[j] == item || (detectionRelated && data[j]["rule.uuid"] === item["rule.uuid"])) {
          data.splice(j, 1);
          if (item["count"]) {
            this.totalEvents -= item["count"];
          } else {
            this.totalEvents--;
          }
          if (this.totalEvents < 0) {
            this.totalEvents = 0;
          }
          if (!detectionRelated) {
            break;
          }
          j--;
        }
      }
    },
    getFilterToggle(name) {
      for (var i = 0; i < this.filterToggles.length; i++) {
        var filter = this.filterToggles[i];
        if (filter.name == name) {
          return filter;
        }
      }
      return null;
    },
    isFilterToggleEnabled(name) {
      var toggle = this.getFilterToggle(name);
      if (toggle) {
        return toggle.enabled;
      }
      return false;
    },
    filterToggled(event, filterToggle) {
      if (filterToggle.enabled && filterToggle.enablesToggles) {
        filterToggle.enablesToggles.forEach((name) => {
          var toggle = this.getFilterToggle(name)
          if (toggle) {
            toggle.enabled = true;
          }
        });
      } else if (!filterToggle.enabled && filterToggle.disablesToggles) {
        filterToggle.disablesToggles.forEach((name) => {
          var toggle = this.getFilterToggle(name)
          if (toggle) {
            toggle.enabled = false;
          }
        });
      }
    },
    formatSafeString(item) {
      if (item.length > this.safeStringMaxLength) {
        return item.substring(0, this.safeStringMaxLength - 3) + "...";
      }
      return item;
    },
    getDisplayedQueryVar() {
      if (this.isAdvanced()) {
        if (this.showFullQuery) {
          return 'query'
        } else {
          return 'querySearch'
        }
      }
      return 'queryName'
    },
    isComplexQuery(query) {
      // Test for a query containing opening parenthesis outside of a double quoted value string.
      var quoting = false;
      var escaping = false;
      for (var idx = 0; idx < query.length; idx++) {
        var ch = query[idx];
        if (ch == '"' && !escaping) {
          quoting = !quoting;
        } else if (ch == '(' && !quoting) {
          return true;
        }

        if (ch == '\\') {
          escaping = !escaping;
        } else {
          escaping = false;
        }
      }
      return false;
    },
    obtainQueryDetails() {
      this.queryAltered = false;
      this.queryName = "";
      this.querySearch = "";
      this.queryRemainder = "";
      this.queryFilters = [];
      this.queryGroupBys = [];
      this.queryGroupByOptions = [];
      this.queryTableFields = [];
      this.queryTableOptions = [];
      this.querySortBys = [];
      var route = this;
      if (this.query) {
        this.query = this.query.trim();

        // find first segment
        var insideQuote = false;
        var escaping = false;
        var segmentDelimIdx = -1;
        for (var i = 0; i < this.query.length; i++) {
          if (this.query[i] == "|" && !insideQuote && !escaping) {
            segmentDelimIdx = i;
            break;
          } else if (this.query[i] == "\"" && !escaping) {
            insideQuote = !insideQuote;
          } else if (this.query[i] == "\\" && !escaping) {
            escaping = true;
          } else {
            escaping = false;
          }
        }

        var segments = [];

        if (segmentDelimIdx > -1 && this.query.length > segmentDelimIdx + 1) {
          // Filter/group/sort/etc segments cannot have | in them.
          segments = this.query.substring(segmentDelimIdx + 1).split("|");
          segments.unshift(this.query.substring(0, segmentDelimIdx));
        } else {
          segments = [this.query];
        }

        if (segments.length > 0) {
          this.querySearch = segments[0].trim();
          if (segments.length > 1) {
            // Used for reconstructing full query from simplified filter-only view
            this.queryRemainder = this.query.substring(segmentDelimIdx);
          }
          var matchingQueryName = this.i18n.custom;
          for (var i = 0; i < this.queries.length; i++) {
            if (this.query == this.queries[i].query) {
              matchingQueryName = this.queries[i].name;
            }
          }
          this.queryName = matchingQueryName;
          if (!route.isComplexQuery(this.querySearch)) {
            this.querySearch.split(" AND ").forEach(function (item, index) {
              item = item.trim();
              if (item.length > 0 && item != "*") {
                route.queryFilters.push(item);
              }
            });
          }
        }

        if (segments.length > 1) {
          for (var segmentIdx = 1; segmentIdx < segments.length; segmentIdx++) {
            var segment = segments[segmentIdx].trim().replace(/,/g, ' ');
            if (segment.indexOf("groupby") == 0) {
              var fields = [];
              var options = [];
              segment.split(" ").forEach(function (item, index) {
                // Skip empty fields and segment options (they start with a hyphen)
                if (item[0] == "-") {
                  options.push(item.substring(1));
                } else if (index > 0 && item.trim().length > 0) {
                  if (item.split("\"").length % 2 == 1) {
                    // Will currently skip quoted items with spaces.
                    fields.push(item);
                  }
                }
              });
              route.queryGroupBys.push(fields);
              route.queryGroupByOptions.push(options);
            }
            if (segment.indexOf("table") == 0) {
              var fields = [];
              var options = [];
              segment.split(" ").forEach(function (item, index) {
                // Skip empty fields and segment options (they start with a hyphen)
                if (item[0] == "-") {
                  options.push(item.substring(1));
                } else if (index > 0 && item.trim().length > 0) {
                  if (item.split("\"").length % 2 == 1) {
                    // Will currently skip quoted items with spaces.
                    fields.push(item);
                  }
                }
              });
              route.queryTableFields = fields;
              route.queryTableOptions = options;
            }
            if (segment.indexOf("sortby") == 0) {
              segment.split(" ").forEach(function (item, index) {
                if (index > 0 && item.trim().length > 0) {
                  if (item.split("\"").length % 2 == 1) {
                    // Will currently skip quoted items with spaces.
                    route.querySortBys.push(item);
                  }
                }
              });
            }
          }
        }
      }
    },
    removeFilter(filter) {
      var newQuery = this.query.replace(" AND " + filter, "");
      if (newQuery == this.query) {
        newQuery = this.query.replace(filter + " AND ", "");
        if (newQuery == this.query) {
          newQuery = this.query.replace(filter, "");
        }
      }
      if (newQuery.trim().indexOf("|") == 0) {
        newQuery = "* " + newQuery.trim()
      }
      if (newQuery.trim().length == 0) {
        newQuery = "*";
      }
      this.query = newQuery;
      if (!this.notifyInputsChanged()) {
        this.obtainQueryDetails();
      }
    },
    removeGroupBy(groupIdx, fieldIdx) {
      if (groupIdx < 0 || groupIdx >= this.queryGroupBys.length) {
        return;
      }
      var group = this.queryGroupBys[groupIdx];
      if (fieldIdx >= group.length) {
        return;
      }
      var field = null;
      if (fieldIdx >= 0) {
        field = group[fieldIdx];
      }

      var segments = this.query.split("|");
      var newQuery = segments[0];
      var currentGroupIdx = 0;
      for (var i = 1; i < segments.length; i++) {
        if (segments[i].trim().indexOf("groupby") == 0) {
          if (currentGroupIdx++ == groupIdx) {
            segments[i].replace(/,/g, ' ');
            segments[i] = segments[i].replace(" " + field, "");

            // Assume groupby's of a single field no longer have anything to group by
            if (group.length == 1 || !field) {
              segments[i] = "";
            }
          }
        }
        if (segments[i].length > 0) {
          newQuery = newQuery.trim() + " | " + segments[i].trim();
        }
      }
      this.query = newQuery.trim();
      if (!this.notifyInputsChanged()) {
        this.obtainQueryDetails();
      }
    },
    removeSortBy(sortBy) {
      var segments = this.query.split("|");
      var newQuery = segments[0];
      for (var i = 1; i < segments.length; i++) {
        if (segments[i].trim().indexOf("sortby") == 0) {
          segments[i].replace(/,/g, ' ');
          segments[i] = segments[i].replace(" " + sortBy, "");
          if (segments[i].trim() == "sortby") {
            segments[i] = "";
          }
        }
        if (segments[i].length > 0) {
          newQuery = newQuery.trim() + " | " + segments[i].trim();
        }
      }
      this.query = newQuery.trim();
      if (!this.notifyInputsChanged()) {
        this.obtainQueryDetails();
      }
    },
    buildCurrentRoute() {
      let queryObj = { q: this.query, z: this.zone, el: this.eventLimit, gl: this.groupByLimit };

      if (this.relativeTimeEnabled) {
        queryObj.rt = this.relativeTimeValue;
        queryObj.rtu = this.getRelativeTimeUnits();
      } else {
        queryObj.t = this.dateRange;
      }

      if (this.autoRefreshInterval > 0) {
        queryObj.ar = this.autoRefreshInterval;
      }

      if (this.gridId) {
        queryObj.gridId = this.gridId;
      }

      return { path: this.category, query: queryObj };
    },
    buildFilterRoute(filterField, filterValue, filterMode, scalar) {
      route = this.buildCurrentRoute()

      route.query.filterField = filterField;
      route.query.filterValue = this.subMissing(filterValue);
      route.query.filterMode = filterMode;

      if (arguments.length > 3) {
        route.query.scalar = scalar ? 'true' : 'false';
      }

      return route;
    },
    buildGroupByRoute(field) {
      route = this.buildCurrentRoute()
      route.query.groupByField = field;

      const groups = (this.query || '').replaceAll(/\s/g, '').match(/\|groupby/gi);
      if (groups) {
        route.query.groupByGroup = groups.length - 1;
      } else {
        route.query.groupByGroup = 1;
      }

      return route;
    },
    buildGroupByNewRoute(field) {
      route = this.buildCurrentRoute()
      route.query.groupByField = field;
      route.query.groupByGroup = -1;
      return route;
    },
    buildGroupOptionRoute(groupIdx, removals, addition) {
      var segments = this.query.split("|");
      var newQuery = segments[0];
      var currentGroupIdx = 0;
      for (var i = 1; i < segments.length; i++) {
        if (segments[i].trim().indexOf("groupby") == 0) {
          if (currentGroupIdx++ == groupIdx) {
            segments[i].replace(/,/g, ' ');
            removals.forEach(function (removal, index) {
              segments[i] = segments[i].replace(" -" + removal + " ", " ");
            });
            if (addition) {
              segments[i] = "groupby -" + addition + " " + segments[i].substring("groupby ".length + 1);
            }
          }
        }
        newQuery = newQuery.trim() + " | " + segments[i].trim();
      }
      var route = this.buildCurrentRoute();
      route.query.q = newQuery;
      return route;
    },
    buildToggleLegendRoute(group, groupIdx) {
      var addition = group.chart_options && group.chart_options.plugins.legend.display ? "nolegend" : "legend";
      var removal = group.chart_options && group.chart_options.plugins.legend.display ? "legend" : "nolegend";
      return this.buildGroupOptionRoute(groupIdx, [removal], addition);
    },
    buildMaximizeRoute(group, groupIdx) {
      return this.buildGroupOptionRoute(groupIdx, [], "maximize");
    },
    buildNonMaximizedRoute(group, groupIdx) {
      return this.buildGroupOptionRoute(groupIdx, ["maximize"], '');
    },
    buildGroupWithoutOptionsRoute(groupIdx) {
      const removals = ["pie", "bar", "legend", "nolegend", "sankey", "maximize"];
      return this.buildGroupOptionRoute(groupIdx, removals, '');
    },
    countDrilldown(event) {
      const keys = Object.keys(event).filter(field => field != 'newest' && !field.startsWith('_'));
      if ((keys.length == 2 && keys[0] == "count") || (keys.length == 5 && keys[0] == "count" && keys[1] == "rule.name" && keys[2] == "event.module" && keys[3] == "event.severity_label" && keys[4] == "rule.uuid")) {
        this.filterRouteDrilldown = this.buildFilterRoute(keys[1], event[keys[1]], FILTER_DRILLDOWN);
        this.$router.push(this.filterRouteDrilldown);
      }
    },
    toggleEscalationMenu(domEvent, event, groupIdx, detectionRelated = false) {
      if (!this.escalateRelatedEventsEnabled) {
        this.ack(event, true, true, null, groupIdx);
        return;
      }

      if (!domEvent || this.quickActionVisible || this.escalationMenuVisible) {
        this.quickActionVisible = false;
        this.escalationMenuVisible = false;
        this.escalatingDetectionEvents = false;
        return;
      }
      this.escalationMenuTarget = domEvent.target;
      this.escalationItem = event;
      this.escalationGroupIdx = groupIdx;
      this.$nextTick(() => {
        this.escalatingDetectionEvents = detectionRelated;
        this.escalationMenuVisible = true;
      });
    },
    async toggleQuickAction(domEvent, event, groupIdx, field, value) {
      if (!domEvent || this.quickActionVisible || this.escalationMenuVisible || window?.getSelection()?.type === 'Range') {
        this.quickActionVisible = false;
        this.escalationMenuVisible = false;
        return;
      }

      if (this.isCategory('alerts')) {
        const id = event["rule.uuid"];
        this.quickActionDetId = null;
        this.tuneDetectionTabTarget = null;

        const getData = (response) => {
          const det = response?.data || this.highlightedDetection;

          this.quickActionDetId = det.id;
          this.tuneDetectionTabTarget = 'tuning';
          if (det.engine === 'strelka') {
            this.tuneDetectionTabTarget = 'source';
          }
        };

        if (id && !this.highlightedDetection) {
          this.highlightDetection(id, event, groupIdx).then(getData);
        } else {
          this.$root.papi.get(`detection/public/${id}`).then(getData);
        }
      }

      this.quickActionIsNumeric = this.isNumeric(value);
      if (this.quickActionIsNumeric) {
        this.filterRouteLessThan = this.buildFilterRoute(field, "<" + value, FILTER_INCLUDE, true);
        this.filterRouteLessThanEqual = this.buildFilterRoute(field, "<=" + value, FILTER_INCLUDE, true);
        this.filterRouteGreaterThan = this.buildFilterRoute(field, ">" + value, FILTER_INCLUDE, true);
        this.filterRouteGreaterThanEqual = this.buildFilterRoute(field, ">=" + value, FILTER_INCLUDE, true);
        this.betweenStart = '';
        this.betweenEnd = '';
        this.betweenStartEquals = false;
        this.betweenEndEquals = false;
      }



      if (value != null && this.canQuery(field)) {
        this.filterRouteInclude = this.buildFilterRoute(field, value, FILTER_INCLUDE);
        this.filterRouteExclude = this.buildFilterRoute(field, value, FILTER_EXCLUDE);
        this.filterRouteExact = this.buildFilterRoute(field, value, FILTER_EXACT);
        this.filterRouteDrilldown = this.buildFilterRoute(field, value, FILTER_DRILLDOWN);
        this.groupByRoute = this.buildGroupByRoute(field);
        this.groupByNewRoute = this.buildGroupByNewRoute(field);

        var route = this;
        this.actions.forEach(function (action, index) {
          action.enabled = true;

          if (action.categories && action.categories.indexOf(route.category) == -1) {
            action.enabled = false;
          }

          if (action.enabled && action.fields) {
            action.enabled = false;
            for (var x = 0; x < action.fields.length; x++) {
              if (action.fields[x] == field) {
                action.enabled = true;
                break;
              }
            }
          }

          if (action.enabled && !action.jsCall) {
            var link = route.$root.findEligibleActionLinkForEvent(action, event);
            if (link) {
              action.linkFormatted = route.$root.formatActionContent(link, event, field, value, true);
              action.bodyFormatted = route.$root.formatActionContent(action.body, event, field, value, action.encodeBody);
              action.backgroundSuccessLinkFormatted = route.$root.formatActionContent(action.backgroundSuccessLink, event, field, value, true);
              action.backgroundFailureLinkFormatted = route.$root.formatActionContent(action.backgroundFailureLink, event, field, value, true);
            } else {
              action.enabled = false;
            }
          }
        });
        this.quickActionEvent = event;
        this.quickActionField = field;
        this.quickActionValue = value;
        if (domEvent.type === 'keydown') {
          const rect = domEvent.currentTarget.getBoundingClientRect();
          this.quickActionTarget = [rect.left, rect.top];
        } else {
          this.quickActionTarget = [domEvent.clientX, domEvent.clientY];
        }
        this.$nextTick(async () => {
          this.quickActionVisible = true;

          // When opening a menu, the router is involved so any groups with :to that
          // match the current route will be opened as "you're on this page."
          // We don't want that so we will carry forward all known open groups,
          // BUT we can't set it on nextTick as that'll start rendering the menu
          // with the router-chosen groups open, we need to overwrite the array
          // before the browser paints, so requestAnimationFrame
          const openCache = [...this.quickActionsOpen];
          requestAnimationFrame(() => {
            this.quickActionsOpen = openCache;
          });
        });
      }
    },
    filterVisibleFields(eventModule, eventDataset, fields) {
      let relatedFields = '';
      for (const field of fields) {
        const match = field.match(/so_[^.]*\.fields./);
        if (match) {
          relatedFields = match[0];
          break;
        }
      }
      if (this.eventFields) {
        var filteredFields = null;
        if (eventDataset) {
          if (eventDataset.indexOf('.') !== -1) {
            eventDataset = eventDataset.substring(eventDataset.indexOf('.') + 1);
          }
        }
        if (eventModule && eventDataset) {
          filteredFields = this.eventFields[":" + eventModule + ":" + eventDataset];
        }
        if (!filteredFields && eventDataset) {
          filteredFields = this.eventFields["::" + eventDataset];
        }
        if (!filteredFields && eventModule) {
          filteredFields = this.eventFields[":" + eventModule + ":"];
        }
        if (!filteredFields) {
          filteredFields = this.eventFields["default"];
        }
        if (filteredFields && filteredFields.length > 0) {
          fields = filteredFields;
          if (relatedFields) {
            fields = fields.map(f => relatedFields + f);
          }
        }
      }
      return fields;
    },
    localizeValue(value) {
      if (value && value.startsWith && value.startsWith("__")) {
        value = this.$root.localizeMessage(value);
      }
      return value;
    },
    constructHeaders(fields) {
      var headers = [];

      const customSorts = {
        'event.severity_label': this.sortBySeverity,
      };

      if (fields && fields.length > 0) {
        var i18n = this.i18n;
        fields.forEach((item) => {
          var i18nKey = "field_" + item;
          var header = {
            title: i18n[i18nKey] ? i18n[i18nKey] : item,
            value: item,
          };

          const sort = customSorts[item];
          if (sort) {
            header.sort = sort;
          }

          headers.push(header);
        });
      }
      return headers;
    },
    sortBySeverity(a, b) {
      // normalize
      const na = (typeof a === 'string' ? a : String(a)).toLowerCase();
      const nb = (typeof b === 'string' ? b : String(b)).toLowerCase();

      // map
      const levels = ['unknown', 'informational', 'low', 'medium', 'high', 'critical'];
      const sevA = levels.findIndex(x => x === na);
      const sevB = levels.findIndex(x => x === nb);

      // compare
      return sevA - sevB;
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
    lookupSocIds(record) {
      for (const key in record) {
        if (key.endsWith("case.assigneeId") || key.endsWith("case.userId")) {
          record[key] = this.lookupSocId(record[key]);
        }
      }
    },
    constructGroupByRows(fields, data) {
      const records = [];
      const route = this;
      let batch = [];
      data.forEach(function (row, index) {
        var record = {
          count: row.value,
          _row_idx_: index,
        };
        fields.forEach(function (field, index) {
          record[field] = route.localizeValue(row.keys[index]);
          batch.push(record[field]);
        });
        route.lookupSocIds(record);
        records.push(record);
      });
      this.$root.batchLookup(batch, this);
      return records;
    },
    constructChartMetrics(data) {
      const records = [];
      const route = this;
      var other = 0;
      data.forEach(function (row, index) {
        var record = {
          value: row.value,
          keys: [row.keys.join(route.chartLabelFieldSeparator)],
        };
        if (records.length >= route.chartLabelOtherLimit) {
          other += row.value;
        } else {
          records.push(record);
        }
      });
      if (other > 0) {
        records.push({ value: other, keys: [this.i18n.other] });
      }
      return records;
    },
    populateGroupByTables(metrics) {
      var idx = 0;
      this.groupBys = [];
      while (this.populateGroupByTable(metrics, idx++)) { };
    },
    populateGroupByTable(metrics, groupIdx) {
      const route = this;
      var key = this.lookupGroupByMetricKey(metrics, groupIdx, true);
      if (key) {
        var fields = key.split("|");
        if (fields.length > 1 && fields[0] == "groupby_" + groupIdx) {
          fields.shift();

          // Group objects have the following attributes:
          // key:           Unique key for the group, such as "groupby_0|field1|field2|field3"
          // title:         Chart title
          // fields:        Array of field names in the group, starting with an empty string (for the action
          //                buttons column, and then the 'count', followed by the actual field names.
          // data:          The rows of tabular data in the format:
          //                { count: <count>, keys: [fieldValue0, fieldValue1, fieldValueN] }
          // headers:       Array of header objects for the table view, in the format:
          //                { text: 'Human Friendly', value: 'field_name0' }
          // chart_metrics: Alternative data format for chart rendering, in the
          //                format: { value: <count>, keys: ["fieldValue0, fieldValue1, fieldValueN"] }
          //                Note that the keys array is always of length one, containing the concatenated
          //                 string of field values.
          // chart_type:    ChartJS type, such as pie, bar, sankey, etc.
          // chart_options: ChartJS options. See setupBarChart, etc.
          // chart_data:    ChartJS labels and datasets. See setupBarChart and populateBarChart.
          // is_incomplete: True if only partial data is rendered to avoid complete render failure.
          // sortBy:        Optional name of a field to sort by.
          // sortDesc:      True if the optional sort should be in descending order.
          // maximized:     True if this group view has been maximized.
          var group = {};
          group.key = key;
          group.title = fields.join(this.chartLabelFieldSeparator);
          group.fields = [...fields];
          group.data = this.constructGroupByRows(fields, metrics[key])
          fields.unshift("count");
          if (this.aggregationActionsEnabled) {
            fields.unshift(""); // Leave empty header column for optional action buttons/icons
          }
          group.headers = this.constructHeaders(fields);
          group.chart_metrics = this.constructChartMetrics(metrics[key]);

          // Preserve group-by sort settings only for first group. Useful for non-advanced views.
          group.sortBy = [{ key: 'count', order: 'desc' }];
          if (this.groupBys.length == 0 && this.groupBySortBy) {
            group.sortBy = [{ key: this.groupBySortBy, order: this.groupBySortDesc ? 'desc' : 'asc' }];
          }

          this.groupBys.push(group);

          var options = this.queryGroupByOptions[groupIdx];
          if (options.indexOf("pie") != -1) {
            this.displayPieChart(group, groupIdx);
          } else if (options.indexOf("bar") != -1) {
            this.displayBarChart(group, groupIdx);
          } else if (options.indexOf("sankey") != -1) {
            this.displaySankeyChart(group, groupIdx);
          }
          group.maximized = options.indexOf("maximize") != -1;
          if (group.maximized) {
            const unmaximizeFn = function () {
              const newRoute = route.buildNonMaximizedRoute(group, groupIdx);
              route.$router.push(newRoute, function () { }, function () { });
            };
            this.$nextTick(() => {
              route.$root.maximizeById("group-" + groupIdx, unmaximizeFn);
            });
          }
        }

        return true;
      }
      return false;
    },
    debounceChartResize(chart, size) {
      const MAX_RESIZE_METRIC_COUNT = 20;
      const MAX_RESIZE_METRIC_AGE = 1000; // milliseconds
      const MAX_RESIZE_METRIC_FLAPS = 1;

      if (!chart.options.responsive) return;

      const now = Date.now();

      // Get this chart's resize metric history, or create a new history
      var data = this.chartResizeTracker[chart];
      if (!data) {
        data = [];
        this.chartResizeTracker[chart] = data;
      }

      // Determine how many metrics are expired
      var pruneCount = 0;
      for (var idx = 0; idx < data.length; idx++) {
        var metric = data[idx];
        if (metric.time < now - MAX_RESIZE_METRIC_AGE) {
          pruneCount = idx + 1;
        } else {
          break
        }
      }

      // Remove expired metrics
      for (var idx = 0; idx < pruneCount; idx++) {
        data.shift();
      }

      var newResizeMetric = {
        size: size,
        time: now,
      }

      data.push(newResizeMetric);

      // Limit the number of metrics in history
      if (data.length > MAX_RESIZE_METRIC_COUNT) {
        data.shift();
      }

      // Review the metric history and determine if the chart size is flapping
      var flapCount = 0;
      var prevDirection = 0;
      for (var idx = 0; idx < data.length; idx++) {
        var prev = data[idx];
        if (idx < data.length - 1) {
          var next = data[idx + 1];
          var nextDirection = 0;
          if (next.size.width > prev.size.width) {
            nextDirection = 1;
          } else if (next.size.width < prev.size.width) {
            nextDirection = -1;
          }

          if (prevDirection != 0 && nextDirection != 0) {
            if (nextDirection != prevDirection) {
              flapCount++;
            }
          }
          if (nextDirection != 0) {
            prevDirection = nextDirection;
          }
        }
      }
      if (flapCount > MAX_RESIZE_METRIC_FLAPS) {
        chart.options.responsive = false;
        // for (var idx = 0; idx < data.length; idx++) {
        //   console.log(idx + " -> " + data[idx].size.width)
        // }
        // console.log("Excessive chart flapping detected; disabled chart resizing")
      }
    },
    updateGroupBySort(i) {
      if (this.groupBys.length > 0 && i === 0 && this.groupBys[0].sortBy[0]) {
        this.groupBySortBy = this.groupBys[0].sortBy[0].key;
        this.groupBySortDesc = this.groupBys[0].sortBy[0].order === 'desc';
      }
    },
    populateEventTable(events) {
      var records = [];
      var fields = [];
      var eventModule;
      var eventDataset;
      var route = this;
      if (events != null && events.length > 0) {
        let batch = [];

        const multiSelect = this.isMultiSelect();
        events.forEach((event, index) => {
          var record = route.extractSocValues(event);
          route.lookupSocIds(record);

          if (multiSelect) {
            record._isSelected = false;
          }

          record._row_idx_ = index;

          records.push(record);

          for (const key in record) {
            batch.push(record[key]);
          }

          if (!eventModule) {
            var currentModule = this.lookupFieldValue(record, "event.module");
            var currentDataset = this.lookupFieldValue(record, "event.dataset");
            if (eventModule == null && currentModule) {
              eventModule = currentModule.toLowerCase();
              if (currentDataset) {
                eventDataset = currentDataset.toLowerCase();
              }
            }
          }
        });

        route.$root.batchLookup(batch, route);

        for (const key in records[0]) {
          fields.push(key);
        }
      }

      this.populateEventHeaders(this.filterVisibleFields(eventModule, eventDataset, fields));
      this.eventData = records;
    },
    lookupFieldValue(record, field) {
      if (field in record) {
        return record[field];
      }

      for (const key in record) {
        if (key.endsWith(".fields." + field)) {
          return record[key];
        }
      }

      return '';
    },
    populateEventHeaders(defaultFields) {
      var fields = defaultFields;
      if (this.queryTableFields.length > 0) {
        fields = this.queryTableFields;
      }

      let headers = this.constructHeaders(fields);

      if (this.isCategory('detections')) {
        const enabledCol = headers.findIndex(h => h.value === 'so_detection.isEnabled');
        const overrideHeader = { title: this.i18n.overrides, value: 'override_count' };

        if (enabledCol > -1) {
          headers = [...headers.slice(0, enabledCol + 1), overrideHeader, ...headers.slice(enabledCol + 1)];
        } else {
          headers.push(overrideHeader);
        }
      }

      this.eventHeaders = headers;
    },
    repopulateEventHeaders() {
      this.populateEventHeaders();

      // This is a UI interaction so update the query and route to reflect the new table segment
      var segments = this.query.split("|");
      var newQuery = segments[0];
      for (var i = 1; i < segments.length; i++) {
        if (segments[i].trim().indexOf("table") == 0) {
          continue;
        }
        newQuery = newQuery.trim() + " | " + segments[i].trim();
      }
      if (this.queryTableFields.length > 0) {
        newQuery = newQuery + " | table " + this.queryTableFields.join(" ");
      }

      this.updateActiveQuery(newQuery);
    },
    updateActiveQuery(newQuery) {
      var route = this.buildCurrentRoute();
      route.query.q = newQuery;

      this.disableRouteLoad = true;
      this.$router.push(route);
      this.query = newQuery;
      const thisRoute = this;
      setTimeout(function () { thisRoute.disableRouteLoad = false; }, 1000);
    },
    toggleColumnHeader(field) {
      if (!this.isColumnHeader(field)) {
        this.addColumnHeader(field);
      } else {
        this.removeColumnHeader(field);
      }
    },
    populateQueryTableFields() {
      if (this.queryTableFields.length == 0) {
        // Pre-populate with the default field headers already in eventHeaders (from populateEventTable)
        for (const idx in this.eventHeaders) {
          const field = this.eventHeaders[idx].value;
          this.queryTableFields.push(field);
        }
      }
    },
    moveColumnHeader(field, left) {
      this.populateQueryTableFields();
      for (var idx = -1; idx < this.queryTableFields.length; idx++) {
        const currentField = this.queryTableFields[idx];
        if (field == currentField) {
          break;
        }
      }

      if (idx > -1) {
        if (left) {
          if (idx > 0) {
            var tmpFields = this.queryTableFields.slice(0, idx - 1);
            tmpFields.push(field);
            tmpFields = tmpFields.concat(this.queryTableFields.slice(idx - 1, idx));
            this.queryTableFields = tmpFields.concat(this.queryTableFields.slice(idx + 1));
          }
        } else {
          if (idx < this.queryTableFields.length - 1) {
            var tmpFields = this.queryTableFields.slice(0, idx);
            tmpFields = tmpFields.concat(this.queryTableFields.slice(idx + 1, idx + 2));
            tmpFields.push(field);
            this.queryTableFields = tmpFields.concat(this.queryTableFields.slice(idx + 2));
          }
        }
      }
      this.repopulateEventHeaders(); // no defaults fields will be supplied since we know they aren't going to be used.
    },
    addColumnHeader(field) {
      this.populateQueryTableFields();
      this.queryTableFields.push(field);
      this.repopulateEventHeaders(); // no defaults fields will be supplied since we know they aren't going to be used.
    },
    removeColumnHeader(field) {
      this.populateQueryTableFields();
      this.queryTableFields = this.queryTableFields.filter(item => item != field);

      // do not revert back to the predefined headers if this was the last column that was just removed. Otherwise
      // users would get frustrated if they're trying to remove all the columns to then add their own.
      this.repopulateEventHeaders(); // no defaults fields provided
    },
    isColumnHeader(field) {
      return this.eventHeaders.find((item) => {
        if (item.value == field) {
          return true;
        }
      }) != null;
    },
    displayTable(group, groupIdx) {
      group.chart_type = "";
      this.groupBys[groupIdx] = group;
    },
    displayPieChart(group, groupIdx) {
      group.chart_type = "pie";
      group.chart_options = {};
      group.chart_data = {};
      this.setupPieChart(group.chart_options, group.chart_data, group.title);
      this.applyLegendOption(group, groupIdx);
      this.populateChart(group.chart_data, group.chart_metrics);
      this.groupBys[groupIdx] = group;
    },
    displayBarChart(group, groupIdx) {
      group.chart_type = "bar";
      group.chart_options = {};
      group.chart_data = {};
      this.setupBarChart(group.chart_options, group.chart_data, group.title, groupIdx);
      this.applyLegendOption(group, groupIdx);
      this.populateChart(group.chart_data, group.chart_metrics);
      this.groupBys[groupIdx] = group;
    },
    displaySankeyChart(group, groupIdx) {
      if (!this.isGroupSankeyCapable(group)) {
        return;
      }
      group.chart_type = "sankey";
      group.chart_options = {};
      group.chart_data = {};

      // Sankey has a unique dataset format, build it out here instead of using populateChartData().
      // While building the new format, also calculate the max value across all nodes to be used
      // as a scale factor for choosing colors of the sankey flows.
      var flowMax = 0;
      var updateMaxMap = function (map, key, value) {
        var max = map[key];
        if (!max) {
          max = 0;
        }
        max = max + value;
        map[key] = max;
        flowMax = Math.max(flowMax, max);
      };

      var isRecursive = function (map, from, to, current, max) {
        if (current > max || from == to) {
          return true;
        }

        for (var i = 0; i < map.length; i++) {
          var item = map[i];
          if (item.from == to) {
            if (isRecursive(map, item.from, item.to, current + 1, max)) {
              return true;
            }
          }
        }
        return false;
      };

      var data = [];
      var maxFlowMap = {};
      group.data.forEach(function (item, index) {
        for (var idx = 0; idx < group.fields.length - 1; idx++) {
          var from = item[group.fields[idx]];
          var to = item[group.fields[idx + 1]];
          var flow = { from: from, to: to, flow: item.count };
          data.push(flow);

          if (isRecursive(data, from, to, 0, group.fields.length)) {
            group.is_incomplete = true;
            data.pop();
          } else {
            updateMaxMap(maxFlowMap, from, item.count);
            updateMaxMap(maxFlowMap, to, item.count);
          }
        }
      });

      if (group.is_incomplete) {
        group.title += " " + this.i18n.chartTitleIncomplete;
      }
      this.setupSankeyChart(group.chart_options, group.chart_data, group.title);
      this.applyLegendOption(group, groupIdx);

      group.chart_data.datasets[0].data = data;
      group.chart_data.flowMax = flowMax;
      this.groupBys[groupIdx] = group;
    },
    isGroupSankeyCapable(group, groupIdx) {
      return group.fields != undefined && group.fields.length >= 2;
    },
    applyLegendOption(group, groupIdx) {
      const options = this.queryGroupByOptions[groupIdx];
      if (options.indexOf("legend") != -1) {
        group.chart_options.plugins.legend.display = true;
      } else if (options.indexOf("nolegend") != -1) {
        group.chart_options.plugins.legend.display = false;
      }
    },
    populateChart(chart, data) {
      chart.key++;
      chart.labels = [];
      chart.datasets[0].data = [];
      if (!data) return;
      const route = this;
      data.forEach(function (item, index) {
        chart.labels.push(route.$root.truncate(route.localizeValue(route.lookupSocId(item.keys[0])), route.chartLabelMaxLength));
        chart.datasets[0].data.push(item.value);
      });
    },
    isMultiSelect() {
      return this.isCategory('detections');
    },
    getExpandedData(data) {
      const ignored = ['_isSelected', 'playbooks', '_row_idx_', 'playbookErr', 'questions'];
      var records = [];
      for (let key in data) {
        if (ignored.includes(key)) {
          continue;
        }

        records.push({
          key: key,
          value: data[key],
        });
      }
      return records;
    },
    canQuery(key) {
      return !key.startsWith("soc_");
    },
    lookupGroupByMetricKey(metrics, groupIdx, longest) {
      var desiredKey = null;
      for (const key in metrics) {
        if (key.startsWith("groupby_" + groupIdx + "|")) {
          if (desiredKey == null) {
            desiredKey = key;
          } else if (longest && key.length > desiredKey.length) {
            desiredKey = key;
          } else if (!longest && key.length < desiredKey.length) {
            desiredKey = key;
          }
        }
      }
      return desiredKey;
    },
    getGroupByFieldStartIndex() {
      return this.aggregationActionsEnabled ? 2 : 1;
    },
    lookupTopMetricKey(metrics) {
      return this.lookupGroupByMetricKey(metrics, 0, false);
    },
    showDateRangePicker() {
      if (this.relativeTimeEnabled) return;
      $('#huntdaterange').click();
    },
    hideDateRangePicker() {
      if (this.relativeTimeEnabled) return;
      this.dateRange = $('#huntdaterange')[0].value;
      this.notifyInputsChanged();
    },
    getEndDate() {
      if (this.dateRange != '') {
        var pieces = this.dateRange.split(" - ");
        if (pieces.length == 2) {
          return moment(pieces[1], this.i18n.timePickerFormat);
        }
      }
      return moment();
    },
    getStartDate() {
      if (this.dateRange != '') {
        var pieces = this.dateRange.split(" - ");
        if (pieces.length == 2) {
          return moment(pieces[0], this.i18n.timePickerFormat);
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

      $('#huntdaterange').daterangepicker({
        ranges: this.$root.generateDatePickerPreselects(),
        timePicker: true,
        timePickerSeconds: true,
        endDate: this.getEndDate(),
        startDate: this.getStartDate(),
        locale: {
          format: this.i18n.timePickerFormat
        }
      });
      var route = this;
      if (route.dateRange == '') {
        route.dateRange = $('#huntdaterange')[0].value;
      }
      $('#huntdaterange').on('hide.daterangepicker', function (ev, picker) {
        route.hideDateRangePicker();
      });
    },
    showAbsoluteTime() {
      this.relativeTimeEnabled = false;
      setTimeout(this.setupDateRangePicker, 10);
    },
    showRelativeTime() {
      this.relativeTimeEnabled = true;
    },
    setupCharts() {
      this.setupBarChart(this.topChartOptions, this.topChartData, this.i18n.chartTitleTop);
      this.setupTimelineChart(this.timelineChartOptions, this.timelineChartData, this.i18n.chartTitleTimeline);
      this.setupBarChart(this.bottomChartOptions, this.bottomChartData, this.i18n.chartTitleBottom);

      this.topChartData.key = 0;
      this.timelineChartData.key = 0;
      this.bottomChartData.key = 0;
    },
    setupBarChart(options, data, title, groupIdx) {
      var fontColor = this.$root.getColor("#888888", -40);
      var dataColor = this.$root.getColor("primary");
      var gridColor = this.$root.getColor("#888888", 65);
      options.onClick = this.handleChartClick(groupIdx);
      options.onResize = this.debounceChartResize;
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
      options.onResize = this.debounceChartResize;
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
    setupSankeyChart(options, data, title) {
      const route = this;
      options.onResize = this.debounceChartResize;
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
      data.flowMax = 0; // This is a custom attribute used for color selection
      data.labels = [];
      data.datasets = [{
        data: [],
        label: this.i18n.field_count,
        color: this.$root.$vuetify && this.$root.$vuetify.theme.current.dark ? 'white' : 'black',
        colorFrom: c => route.getSankeyColor('from', 'out', c, data.flowMax),
        colorTo: c => route.getSankeyColor('to', 'in', c, data.flowMax),
        size: 'max',
      }];
    },
    getSankeyColor(tag, dir, source, max) {
      var color = 'steelblue';
      if (source && source.parsed && source.parsed._custom) {
        var value = source.parsed._custom[tag][dir] / (max > 0 ? max : 1);
        if (value > 0.90) {
          color = 'crimson';
        } else if (value > 0.80) {
          color = 'red';
        } else if (value > 0.70) {
          color = 'orangered';
        } else if (value > 0.60) {
          color = 'darkorange';
        } else if (value > 0.50) {
          color = 'orange';
        } else if (value > 0.40) {
          color = 'goldenrod';
        } else if (value > 0.30) {
          color = 'gold';
        } else if (value > 0.25) {
          color = 'yellow';
        } else if (value > 0.20) {
          color = 'yellowgreen';
        } else if (value > 0.15) {
          color = 'limegreen';
        } else if (value > 0.10) {
          color = 'green';
        } else if (value > 0.05) {
          color = 'aquamarine';
        } else if (value > 0.04) {
          color = 'cyan';
        } else if (value > 0.03) {
          color = 'darkturquoise';
        } else if (value > 0.02) {
          color = 'lightskyblue';
        } else if (value > 0.01) {
          color = 'royalblue';
        }
      }
      return color;
    },
    handleChartClick(groupIdx) {
      if (!groupIdx) {
        groupIdx = 0;
      }
      return (e, activeElement, chart) => {
        if (activeElement.length > 0) {
          var clickedValue = chart.data.labels[activeElement[0].index] + "";
          if (clickedValue && clickedValue.length > 0) {
            if (this.canQuery(clickedValue)) {
              var chartGroupByField = this.groupBys[groupIdx].fields[0];
              this.toggleQuickAction(e, {}, groupIdx, chartGroupByField, clickedValue);
            }
          }
          return true;
        }
        return false;
      };
    },
    groupByLimitChanged() {
      if (this.groupByItemsPerPage > this.groupByLimit) {
        this.groupByItemsPerPage = this.groupByLimit;
      }
      this.saveLocalSettings();
    },
    groupByItemsPerPageChanged() {
      if (this.groupByLimit < this.groupByItemsPerPage) {
        this.groupByLimit = this.groupByItemsPerPage;
      }
      this.saveLocalSettings();
    },
    eventLimitChanged() {
      if (this.itemsPerPage > this.eventLimit) {
        this.itemsPerPage = this.eventLimit;
      }
      this.saveLocalSettings();
    },
    itemsPerPageChanged() {
      if (this.eventLimit < this.itemsPerPage) {
        this.eventLimit = this.itemsPerPage;
      }
      this.saveLocalSettings();
    },
    lookupAlertSeverityScore(sev) {
      if (sev.toLowerCase) {
        sev = sev.toLowerCase();
        switch (sev) {
          case 'critical': sev = 400; break;
          case 'high': sev = 300; break;
          case 'medium': sev = 200; break;
          case 'low': sev = 100; break;
        }
      }
      return sev
    },
    defaultSort(a, b, isDesc) {
      if (!isDesc) {
        return a < b ? -1 : 1;
      }
      return b < a ? -1 : 1;
    },
    sortEvents(items, index, isDesc) {
      const route = this;
      if (index && index.length > 0) {
        index = index[0];
      }
      if (isDesc && isDesc.length > 0) {
        isDesc = isDesc[0];
      }
      items.sort((a, b) => {
        if (index === "event.severity_label") {
          return route.defaultSort(route.lookupAlertSeverityScore(a[index]), route.lookupAlertSeverityScore(b[index]), isDesc);
        } else {
          return route.defaultSort(a[index], b[index], isDesc);
        }
      });
      return items
    },
    switchToHunt() {
      this.category = "hunt";
      this.hunt();
    },
    saveSetting(name, value, defaultValue = null) {
      var item = 'settings.' + this.category + '.' + name;
      if (defaultValue == null || value != defaultValue) {
        localStorage[item] = value;
      } else {
        localStorage.removeItem(item);
      }
    },
    formatCaseSummary(socCase) {
      return socCase.title;
    },
    saveTimezone() {
      localStorage['timezone'] = this.zone;
    },
    async toggleShowDetailsPanel() {
      this.saveLocalSettings();
      await this.$nextTick();
      this.calculateEventColumnWidth();
    },
    saveLocalSettings() {
      this.saveSetting('groupBySortBy', this.groupBySortBy, 'count');
      this.saveSetting('groupBySortDesc', this.groupBySortDesc, true);
      this.saveSetting('groupByItemsPerPage', this.groupByItemsPerPage, this.params['groupItemsPerPage']);
      this.saveSetting('groupByLimit', this.groupByLimit, this.params['groupFetchLimit']);
      this.saveSetting('sortBy', this.sortBy[0].key, 'timestamp');
      this.saveSetting('sortDesc', this.sortBy[0].order, 'desc');
      this.saveSetting('itemsPerPage', this.itemsPerPage, this.params['eventItemsPerPage']);
      this.saveSetting('eventLimit', this.eventLimit, this.params['eventFetchLimit']);
      this.saveSetting('mruQueries', JSON.stringify(this.mruQueries), '[]');
      this.saveSetting('relativeTimeValue', this.relativeTimeValue, this.params['relativeTimeValue']);
      this.saveSetting('relativeTimeUnit', this.relativeTimeUnit, this.params['relativeTimeUnit']);
      this.saveSetting('autohunt', this.autohunt, true);
      this.saveSetting('showDetailsPanel', this.showDetailsPanel, this.isCategory('alerts'));
      this.saveSetting('advanced', this.advanced, false);
      this.saveSetting('gridLayoutExpansions', this.gridLayoutExpansions, true);
      this.saveSetting('showGuidedAnalysisFirst', this.showGuidedAnalysisFirst, true);
    },
    loadLocalSettings() {
      // Global settings
      if (localStorage['timezone']) this.zone = localStorage['timezone'];

      // Module settings
      var prefix = 'settings.' + this.category;
      if (localStorage[prefix + '.groupBySortBy']) this.groupBySortBy = localStorage[prefix + '.groupBySortBy'];
      if (localStorage[prefix + '.groupBySortDesc']) this.groupBySortDesc = localStorage[prefix + '.groupBySortDesc'] == "true";
      if (localStorage[prefix + '.groupByItemsPerPage']) this.groupByItemsPerPage = parseInt(localStorage[prefix + '.groupByItemsPerPage']);
      if (localStorage[prefix + '.groupByLimit']) this.groupByLimit = parseInt(localStorage[prefix + '.groupByLimit']);
      if (localStorage[prefix + '.sortBy']) this.sortBy[0].key = localStorage[prefix + '.sortBy'];
      if (localStorage[prefix + '.sortDesc']) this.sortBy[0].order = localStorage[prefix + '.sortDesc'];
      if (localStorage[prefix + '.itemsPerPage']) this.itemsPerPage = parseInt(localStorage[prefix + '.itemsPerPage']);
      if (localStorage[prefix + '.eventLimit']) this.eventLimit = parseInt(localStorage[prefix + '.eventLimit']);
      if (localStorage[prefix + '.mruQueries']) this.mruQueries = JSON.parse(localStorage[prefix + '.mruQueries']);
      if (localStorage[prefix + '.relativeTimeValue']) this.relativeTimeValue = parseInt(localStorage[prefix + '.relativeTimeValue']);
      if (localStorage[prefix + '.relativeTimeUnit']) this.relativeTimeUnit = parseInt(localStorage[prefix + '.relativeTimeUnit']);
      if (localStorage[prefix + '.autohunt']) this.autohunt = localStorage[prefix + '.autohunt'] == 'true';
      if (localStorage[prefix + '.showDetailsPanel']) this.showDetailsPanel = localStorage[prefix + '.showDetailsPanel'] == 'true';
      if (localStorage[prefix + '.advanced']) this.advanced = localStorage[prefix + '.advanced'] == 'true';
      if (localStorage[prefix + '.gridLayoutExpansions']) this.gridLayoutExpansions = localStorage[prefix + '.gridLayoutExpansions'] == 'true';
      if (localStorage[prefix + '.showGuidedAnalysisFirst']) this.showGuidedAnalysisFirst = localStorage[prefix + '.showGuidedAnalysisFirst'] == 'true';
      if (localStorage[prefix + '.autoRefreshInterval']) this.autoRefreshInterval = parseInt(localStorage[prefix + '.autoRefreshInterval']);

      if (localStorage['settings.case.mruCases']) this.mruCases = JSON.parse(localStorage['settings.case.mruCases']);
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
    subMissing(value) {
      if (value === this.i18n.__missing__) {
        return '__missing__';
      }

      return value;
    },
    getRelativeTimeUnits() {
      let text = 'hours';

      this.relativeTimeUnits.forEach((unit) => {
        if (unit.value == this.relativeTimeUnit) {
          text = unit.title;
          return false;
        }
      });

      return text;
    },
    setRelativeTimeUnits(m) {
      let value = 30;

      this.relativeTimeUnits.forEach((unit) => {
        if (unit.title.toLowerCase() == m.toLowerCase()) {
          value = unit.value;
          return false;
        }
      });

      this.relativeTimeUnit = value;
    },
    isNumeric(str) {
      return !isNaN(str) && !isNaN(parseFloat(str));
    },
    showBetweenDialog() {
      this.betweenDialogVisible = true;
      this.quickActionIsNumeric = false;
    },
    cancelBetweenDialog() {
      this.betweenDialogVisible = false;
      this.quickActionIsNumeric = false;
    },
    huntBetween() {
      this.betweenError = '';
      const start = parseFloat(this.betweenStart);
      const end = parseFloat(this.betweenEnd);

      if (isNaN(start) || isNaN(end)) {
        this.betweenError = this.i18n.startEndNumericErr;
        return;
      }

      if (start > end) {
        this.betweenError = this.i18n.startEndOrderErr;
        return;
      }

      let range = '';

      if (this.betweenStartEquals) {
        range += '[';
      } else {
        range += '{';
      }

      range += start + ' TO ' + end;

      if (this.betweenEndEquals) {
        range += ']';
      } else {
        range += '}';
      }

      this.betweenDialogVisible = false;
      this.quickActionIsNumeric = false;

      this.$router.push(this.buildFilterRoute(this.quickActionField, range, FILTER_INCLUDE, true));
    },
    performAction($event, action) {
      let shouldNavigate = true;

      if (action && action.jsCall && this[action.jsCall]) {
        // no need to navigate, made JS call instead
        this[action.jsCall](action);
        shouldNavigate = false;
      }

      this.$root.performAction($event, action);

      this.quickActionVisible = false;

      return shouldNavigate;
    },
    async openAddToCaseDialog() {
      // this function is meant to be called by performAction($event, action)
      this.addToCaseDialogVisible = true;

      if (this.$refs && this.$refs['evidence']) {
        this.$refs['evidence'].resetValidation()
      }

      this.mruCases = [
        {
          title: this.i18n.createNewCase,
          value: 'New Case',
        }
      ];
      this.selectedMruCase = 'New Case';

      const rawMRU = localStorage.getItem('settings.case.mruCases');
      if (rawMRU) {
        const cases = JSON.parse(rawMRU);
        for (let i = 0; i < cases.length; i++) {
          this.mruCases.push({
            title: cases[i].title,
            value: cases[i],
          });
        }
      }
    },
    cancelAddToCaseDialog() {
      this.addToCaseDialogVisible = false;
    },
    addToCase(newTab) {
      if (this.$refs && this.$refs['evidence'] && !this.$refs['evidence'].validate()) return;

      this.addToCaseDialogVisible = false;

      let url = window.location.origin + '/#/case/';

      if (this.selectedMruCase !== 'New Case') {
        url += this.selectedMruCase.id;
      } else {
        url += 'create';
      }

      url += '?type=evidence&value=' + encodeURIComponent(this.quickActionValue);

      let target = '_self';
      if (newTab) {
        if (this.selectedMruCase === 'New Case') {
          target = '_blank';
        } else {
          target = encodeURIComponent(this.selectedMruCase.id);
        }
      }

      window.open(url, target);
    },
    updateBulkSelector(item) {
      if (item._isSelected) {
        this.selectedCount = Math.min(this.selectedCount + 1, this.totalEvents);
      } else {
        this.selectedCount = Math.max(this.selectedCount - 1, 0);
      }

      switch (this.selectedCount) {
        case 0:
          this.selectAllState = false;
          this.selectAllIndeterminate = false;
          break;
        case this.totalEvents:
          this.selectAllState = true;
          this.selectAllIndeterminate = false;
          break;
        default:
          this.selectAllState = false;
          this.selectAllIndeterminate = true;
          break;
      }
    },
    toggleSelectAll() {
      if (this.selectAllIndeterminate) {
        this.selectAllState = false;
        this.selectAllIndeterminate = false;
        this.selectAllEvents(false);
        this.selectedCount = 0;
      } else {
        if (this.selectAllState) {
          this.selectAllState = false;
          this.selectAllIndeterminate = false;
          this.selectAllEvents(false);
        } else {
          this.selectAllState = false;
          this.selectAllIndeterminate = true;
          this.selectCurrentPage(true);
        }
      }
    },
    selectAllEvents(selection = true, ALL = false) {
      for (let i = 0; i < this.eventData.length; i++) {
        if (this.eventData[i]._isSelected !== selection) {
          this.eventData[i]._isSelected = selection;
          if (selection) {
            this.selectedCount++;
          } else {
            this.selectedCount--;
          }
        }
      }

      this.selectedCount = Math.max(Math.min(this.selectedCount, this.totalEvents), 0);

      if (ALL && selection) {
        this.selectAllState = true;
        this.selectAllIndeterminate = false;
      }
    },
    selectCurrentPage(selection = true) {
      this.eventCurrentItems.forEach((item) => {
        if (item._isSelected !== selection) {
          item._isSelected = selection;
          if (selection) {
            this.selectedCount++;
          } else {
            this.selectedCount--;
          }
        }
      });

      this.selectedCount = Math.max(Math.min(this.selectedCount, this.totalEvents), 0);
    },
    isPageSelected() {
      return this.eventCurrentItems.every((item) => item._isSelected);
    },
    countSelected() {
      let count = 0;
      for (let i = 0; i < this.eventData.length; i++) {
        if (this.eventData[i]._isSelected) {
          count++;
        }
      }

      this.selectedCount = count;
    },
    async bulkAction(confirmed) {
      let payload = {};

      if (this.selectedAction === 'delete' && !confirmed) {
        this.showBulkDeleteConfirmDialog = true;
        return;
      }

      this.showBulkDeleteConfirmDialog = false;

      this.$root.startLoading();

      if (this.selectAllState) {
        payload.query = this.query;
      } else if (this.selectAllIndeterminate) {
        let ids = [];
        for (let i = 0; i < this.eventData.length; i++) {
          if (this.eventData[i]._isSelected) {
            ids.push(this.eventData[i].soc_id);
          }
        }

        payload.ids = ids;
      } else {
        return;
      }

      try {
        const request = await this.$root.papi.post('detection/bulk/' + this.selectedAction, payload);

        let msg = this.i18n.bulkActionStarted;
        if (this.selectedAction === 'delete') {
          msg = this.i18n.bulkActionDeleteStarted;
        }

        msg = msg.replace('{total}', request.data.count.toLocaleString());

        this.$root.showTip(msg);

        this.selectAllState = false;
        this.selectedCount = 0;
        this.hunt(false);
      } catch (e) {
        this.$root.showError(e);
      } finally {
        this.$root.stopLoading();
      }
    },
    bulkDeleteDialogCancel() {
      this.showBulkDeleteConfirmDialog = false;
    },
    bulkUpdateReport(stats) {
      if (stats.error > 0) {
        let msg = this.i18n.bulkError.replace('{error}', stats.error.toLocaleString());
        this.$root.showError(msg);
      } else {
        let seconds = Math.floor(stats.time);
        let hours = Math.floor(seconds / 3600);
        seconds %= 3600;
        let minutes = Math.floor(seconds / 60);
        seconds = Math.floor(seconds % 60);

        let t = '';

        if (hours > 0) {
          t += hours + 'h ';
        }

        if (minutes > 0 || t.length > 0) {
          if (t.length > 0) {
            minutes = `0${minutes}`;
          }

          t += minutes + 'm ';
        }

        t += seconds.toFixed(0) + 's';

        if (stats.filtered) {
          let msg = this.i18n.bulkSuccessFiltered;
          msg = msg.replaceAll('{filtered}', stats.filtered.toLocaleString());
          msg = msg.replaceAll('{modified}', stats.modified.toLocaleString());
          msg = msg.replaceAll('{total}', stats.total.toLocaleString());
          msg = msg.replaceAll('{time}', t);

          this.$root.showWarning(msg, true);
        } else {
          let msg;
          switch (stats.verb) {
            case 'delete':
              msg = this.i18n.bulkSuccessDelete;
              break;
            case 'update':
              msg = this.i18n.bulkSuccessUpdate;
              break;
            case 'create':
              msg = this.i18n.bulkSuccessCreate;
          }

          msg = msg.replaceAll('{modified}', stats.modified.toLocaleString());
          msg = msg.replaceAll('{total}', stats.total.toLocaleString());
          msg = msg.replaceAll('{time}', t);

          this.$root.showInfo(msg, true);
        }
      }
    },
    startManualSync(engine, type) {
      if (!engine) {
        this.$root.showTip(this.i18n.engineSelect);
        return;
      }
      try {
        this.$root.papi.post(`detection/sync/${engine}/${type}`);

        let msg = this.i18n.startSyncFull;
        if (type !== 'full') {
          msg = this.i18n.startSyncUpdate;
        }

        msg = msg.replace("{engine}", engine);
        this.$root.showTip(msg);
      } catch (e) {
        this.$root.showError(e);
      }
    },
    buildDetectionEngineHuntQuery(engine) {
      const status = this.$root.getDetectionEngineStatus(engine);

      let query = `tags:so-soc AND ` + engine + ` | groupby log.level | groupby event.action | groupby soc.fields.error`;

      if (this.detectionEngineStatusQueries?.[engine]?.default) {
        query = this.detectionEngineStatusQueries[engine].default;
      }

      if (this.detectionEngineStatusQueries?.[engine]?.[status]) {
        query = this.detectionEngineStatusQueries[engine][status];
      }

      return query;
    },
    huntQueryWidth() {
      return this.$refs.huntQueryInput?.$el?.clientWidth || 0;
    },
    async highlightDetection(publicId, event, groupIdx) {
      if (this.highlightedAlertInfo?.item === event) {
        return;
      }

      if (this.highlightedDetection?.publicId !== publicId) {
        this.highlightedDetection = null;

        const response = await this.$root.papi.get(`detection/public/${publicId}`);

        this.highlightedDetection = response.data;
      }

      this.highlightedAlertInfo = {
        item: event,
        groupIndex: typeof groupIdx === 'number' ? groupIdx : -1,
      };
    },
    closeAckManyDialog() {
      this.showAckManyDialog = false;
      this.ackManyArgs = [];
    },
    checkAllFieldTruncation() {
      if (!this.gridLayoutExpansions) return;
      const cards = this.$el.querySelectorAll('.expanded-field-card');
      cards.forEach(card => {
        const valueEl = card.querySelector('.expanded-field-value');
        if (valueEl && valueEl.scrollWidth > valueEl.clientWidth) {
          card.classList.add('is-truncated');
        } else {
          card.classList.remove('is-truncated');
        }
      });
    },
    initDefaultTab(rowIdx, item) {
      if (!this.isCategory('alerts') || this.activeTabs[rowIdx] !== undefined) return;
      this.activeTabs[rowIdx] = this.showGuidedAnalysisFirst ? 'playbook' : 'alert';
      if (this.activeTabs[rowIdx] === 'playbook' && item) {
        this.loadPlaybook(item, rowIdx);
      }
    },
    showFieldValueDialog(key, value) {
      this.fieldValueDialogKey = key;
      this.fieldValueDialogValue = value;
      this.fieldValueDialogVisible = true;
    },
    closeFieldValueDialog() {
      this.fieldValueDialogVisible = false;
    },
    async saveMenuScrollPos(isOpen, target) {
      if (isOpen) {
        // target doesn't exist yet, wait for it to be added to DOM
        await this.$nextTick();
      }

      const scrollContainer = document.querySelector(target);
      if (!scrollContainer) return;

      if (isOpen) {
        // opening
        scrollContainer.scrollTop = this.menuScrollPos;
      } else {
        // closing
        this.menuScrollPos = scrollContainer.scrollTop;
      }
    },
    calculateEventColumnWidth() {
      const el = this.$refs?.eventColumn?.$el || this.$refs?.eventColumn;
      this.eventColumnWidth = el?.clientWidth || 0;
      if (this.eventColumnWidth === 0) {
        setTimeout(() => {
          this.calculateEventColumnWidth();
        }, 300);
      }
    },
    async loadPlaybook(event, index) {
      if ('playbooks' in event || 'playbookLoading' in event || 'playbookErr' in event) return;

      const socId = event?.['soc_id'];
      if (!socId) {
        event.playbookErr = true;
        return;
      }

      event.playbookLoading = true;

      let playbooks;
      let pbErr = false;

      try {
        const response = await this.$root.papi.get(`playbook/event/${socId}`);

        playbooks = response.data;
      } catch (e) {
        pbErr = true;
        playbooks = null;
      }
      event.playbooks = playbooks;
      event.playbookErr = pbErr;
      delete event.playbookLoading;

      if (playbooks) {
        // answer the questions and
        // stable sort them by results
        let ips = [];
        let good = []; // has answers
        let bad = [];  // no answers
        for (let pb of event.playbooks) {
          for (let q of pb.questions) {
            if (q.queryResults.length > 0) {
              good.push(q);
            } else {
              bad.push(q);
            }
            
            for (let answer of q.queryResults) {
              if (answer.payload) {
                for (let v of Object.values(answer.payload)) {
                  if (v && typeof v === 'string') {
                    ips.push(v);
                  }
                }
              }
            }
            
            q.isAggregate = this.isQuestionAggregate(q);

            if (q.isAggregate) {
              q.fields = [this.i18n.count, ...q.fields];
            } else {
              q.fields = ['@timestamp', ...q.fields];
            }
          }
        }
        this.$root.batchLookup(ips, this);

        event.questions = [...good, ...bad];

        this.expandedPlaybookQuestions[index] = [];
        for (let i = 0; i < good.length; i++) {
          this.expandedPlaybookQuestions[index].push(i);
        }
      }
    },
    buildQuestionRange(event, range) {
      if (!range) {
        return '';
      }

      let t = this.getEventTimestamp(event);

      let plusMinus = false;
      let lookingBack = false;

      if (range.startsWith('+/-')) {
        plusMinus = true;
        range = range.substring(3);
      } else if (range.startsWith('-')) {
        lookingBack = true;
        range = range.substring(1);
      }

      let unit = range[range.length - 1].toLowerCase();
      range = range.substring(0, range.length - 1);

      let value = parseInt(range);
      if (isNaN(value)) {
        return '';
      }

      unit = { d: 'days', h: 'hours', m: 'minutes', s: 'seconds' }[unit];
      if (!unit) {
        return '';
      }

      let t1, t2;

      if (plusMinus) {
        t1 = moment.tz(t, this.zone).subtract(value, unit).format(this.i18n.timePickerFormat);
        t2 = moment.tz(t, this.zone).add(value, unit).format(this.i18n.timePickerFormat);
      } else if (lookingBack) {
        t1 = moment.tz(t, this.zone).subtract(value, unit).format(this.i18n.timePickerFormat);
        t2 = moment.tz(t, this.zone).format(this.i18n.timePickerFormat);
      } else {
        t1 = moment.tz(t, this.zone).format(this.i18n.timePickerFormat);
        t2 = moment.tz(t, this.zone).add(value, unit).format(this.i18n.timePickerFormat);
      }

      return `${t1} - ${t2}`;
    },
    getEventTimestamp(event) {
      return event?.['event_data.@timestamp'] || event?.['@timestamp'] || event?.['soc_timestamp'] || '';
    },
    buildHuntQuestionParams(question, event) {
      let payload = {
        name: 'hunt',
        query: {
          q: question.oqlQuery,
        },
      };

      if (question.range) {
        payload.query.t = this.buildQuestionRange(event, question.range);
      } else {
        payload.query.t = this.dateToRange(this.getEventTimestamp(event));
      }

      return payload;
    },
    isQuestionAggregate(question) {
      if ('isAggregate' in question) return question.isAggregate;

      try {
        const yaml = jsyaml.load(question.query, { schema: jsyaml.FAILSAFE_SCHEMA });
        question.isAggregate = typeof yaml.aggregation === 'string' && yaml.aggregation.toLowerCase() === 'true';
      } catch {
        const match = question.query.match(/^\s*aggregation\s*:\s*(true|false)\s*$/im)
        if (match) {
          question.isAggregate = match[1].toLowerCase() === 'true';
        } else { 
          question.isAggregate = false;
        }
      }

      return question.isAggregate;
    },
    translateValue(value) {
      if (typeof value === 'string' && value.startsWith('__')) {
        return this.i18n[value];
      }

      return value;
    },
    async fetchNewestEvent(item) {
      if (item.newest) return;

      let parts = [];

      if (this.queryBaseFilter) parts.push(this.queryBaseFilter);

      this.obtainQueryDetails();
      if (this.querySearch) {
        parts.push(`(${this.querySearch})`);
      }

      for (let field in item) {
        let label = field;
        if (field.startsWith('_')) continue;
        if (field.startsWith('event_data.')) {
          label = field.replace('event_data.', '');
        }

        if (label.toLowerCase() === 'count') continue;

        if (item[field] && !Array.isArray(item[field])) {
          parts.push(`${label}:"${item[field]}"`);
        }
      }

      if (this.isFilterToggleEnabled('acknowledged')) {
        parts.push('event.acknowledged:true');
      } else {
        parts.push('NOT event.acknowledged:true');
      }

      if (this.isFilterToggleEnabled('escalated')) {
        parts.push('event.escalated:true');
      } else {
        parts.push('NOT event.escalated:true');
      }

      const q = parts.join(' AND ') + ` | sortby @timestamp`;

      let params = {
        query: q,
        range: this.dateRange,
        format: this.i18n.timePickerSample,
        zone: this.zone,
        metricLimit: 0,
        eventLimit: 1
      };

      if (this.gridId && this.gridId.length > 0) {
        params.gridId = this.gridId;
      }

      let response = await this.$root.papi.get('events/', { params });
      if (response.data.events.length === 0) {
        this.$root.showWarning('No events found');
        return;
      }

      item.newest = this.extractSocValues(response.data.events[0]);
      if (this.activeTabs[item._row_idx_] === 'playbook') {
        this.loadPlaybook(item.newest, item._row_idx_);
      }
      this.$nextTick(() => this.checkAllFieldTruncation());
    },
    extractSocValues(event) {
      var record = event.payload;
      record.soc_id = event.id;
      record.soc_score = event.score;
      record.soc_type = event.type;
      record.soc_timestamp = event.timestamp;
      record.soc_source = event.source;

      return record;
    },
    getEventField(event, field) {
      if (field in event) {
        return event[field];
      }

      // check with/without event_data
      // let edField = 'event_data.' + field;
      // if (edField in event) {
      //   return event[edField];
      // }
      //
      // if (field.startsWith('event_data.')) {
      //   let shortened = field.substring(11);
      //   if (shortened in event) {
      //     return event[shortened];
      //   }
      // }

      return '';
    },
    toggleAllQuestions(event, index, expand) {
      if (event.playbookErr) return;

      event = (event || {}).newest || event;

      if (event.playbookLoading || !('questions' in event)) {
        setTimeout(() => {
          this.toggleAllQuestions(event, index, expand);
        }, 100)
        return;
      }

      if (event.questions) {
        if (!Array.isArray(this.expandedPlaybookQuestions[index]) || !expand) this.expandedPlaybookQuestions[index] = [];
        if (expand) {
          for (let i = 0; i < event.questions.length; i++) {
            if (!this.expandedPlaybookQuestions[index].includes(i)) {
              this.expandedPlaybookQuestions[index].push(i);
            }
          }
        }
      }
    },
    pickQuestionColor(question) {
      if (question.queryResults && question.queryResults.length > 0) {
        return 'has-answers';
      }

      return 'no-data';
    },
    // AI Investigation methods
    async startAIInvestigation(item, event = null) {
      // Only respond to left-click (button === 0) or middle-click (button === 1)
      // Ignore right-click (button === 2) and other mouse buttons
      if (event && event.button !== 0 && event.button !== 1) {
        return;
      }

      let targetItem = item;

      // Check if this is a grouped alert (has count > 1)
      if (item.count) {
        // For grouped alerts, fetch the newest event to get the most recent alert's soc_id
        try {
          await this.fetchNewestEvent(item);
          if (item.newest) {
            targetItem = item.newest;
          } else {
            this.$root.showError(this.i18n.aiInvestigationUnableToFetchNewest);
            return;
          }
        } catch (error) {
          this.$root.showError(this.i18n.aiInvestigationUnableToFetchNewest + ': ' + error.message);
          return;
        }
      }

      const socId = targetItem.soc_id;
      if (!socId) {
        this.$root.showError(this.i18n.aiInvestigationUnableToIdentify);
        return;
      }

      // Check if investigation already exists for this specific soc_id
      if (targetItem['event.investigated'] && targetItem['event.investigation_session_id']) {
        // Check for middle-click (button === 1) to open in new tab
        if (event && event.button === 1) {
          // Middle-click: open in new tab
          const url = this.$router.resolve({
            name: 'assistant',
            params: { sessionId: targetItem['event.investigation_session_id'] }
          }).href;
          window.open(url, '_blank');
        } else {
          // Left-click: navigate in current tab
          this.$router.push({
            name: 'assistant',
            params: { sessionId: targetItem['event.investigation_session_id'] }
          });
        }
        return;
      }

      const chatSessionId = this.generateChatId();

      // Create the investigation prompt with alert data
      const queryList = this.generateQueryList(targetItem);

      // Check for middle-click (button === 1) to open in new tab
      if (event && event.button === 1) {
        // Middle-click: open in new tab
        const url = this.$router.resolve({
          name: 'assistant',
          params: { sessionId: chatSessionId },
          query: queryList
        }).href;
        window.open(url, '_blank');
      } else {
        // Left-click: navigate in current tab
        this.$router.push({
          name: 'assistant',
          params: { sessionId: chatSessionId },
          query: queryList
        });
      }
    },

    generateQueryList(item) {
      
      const alertData = {
        socId: item.soc_id,
        ruleUuid: item['rule.uuid'],
        ruleName: item['rule.name'],
        severity: item['event.severity_label'],
        timestamp: item['soc_timestamp'] || item['@timestamp'],
        sourceIp: item['source.ip'],
        destIp: item['destination.ip'],
        eventModule: item['event.module'],
        eventDataset: item['event.dataset'],
        message: item['message'],
        alertRule: item['rule.rule']
      };

      queryList = { investigation : true };

      for (let alertKey in alertData) {
        if (this.investigationMsg.includes('{' + alertKey.toString() + '}')) {
          queryList[alertKey] = alertData[alertKey];
        }
      }

      return queryList;
    },

    getAIInvestigationButtonColor(item) {
      // Grouped alerts
      if (item.count) {
        return '';
      }
      // Individual alerts
      if (item['event.investigated']) {
        return 'icon';
      }
      // Not investigated
      return '';
    },

    getAIInvestigationTooltip(item) {
      // Grouped alerts
      if (item.count) {
        return this.i18n.aiInvestigateMostRecent;
      }
      // Individual alerts
      if (item['event.investigation_session_id']) {
        return this.i18n.aiInvestigateView;
      }
      return this.i18n.aiInvestigate;
    },

    generateChatId() {
      return crypto.randomUUID();
    },
  }
};

routes.push({ path: '/hunt', name: 'hunt', component: huntComponent });

const alertsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/alerts', name: 'alerts', component: alertsComponent });

const casesComponent = Object.assign({}, huntComponent);
routes.push({ path: '/cases', name: 'cases', component: casesComponent });

const dashboardsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/dashboards', name: 'dashboards', component: dashboardsComponent });

const detectionsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/detections', name: 'detections', component: detectionsComponent });
