// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const RELATIVE_TIME_SECONDS = 10;
const RELATIVE_TIME_MINUTES = 20;
const RELATIVE_TIME_HOURS   = 30;
const RELATIVE_TIME_DAYS    = 40;
const RELATIVE_TIME_WEEKS   = 50;
const RELATIVE_TIME_MONTHS  = 60;
const FILTER_INCLUDE = 'INCLUDE';
const FILTER_EXCLUDE = 'EXCLUDE';
const FILTER_EXACT = 'EXACT';
const FILTER_DRILLDOWN = 'DRILLDOWN';

const huntComponent = {
  template: '#page-hunt',
  data() { return {
    i18n: this.$root.i18n,
    params: null,
    category: '',
    advanced: false,
    query: '',
    queries: [],
    queryBaseFilter: "",
    queryName: '',
    queryFilters: [],
    queryGroupBys: [],
    queryGroupByOptions: [],
    querySortBys: [],
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
    expanded: [],
    chartHeight: 200,
    zone: '',
    huntPending: false,
    ackEnabled: false,
    escalateEnabled: false,
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
    groupByLimitOptions: [10,25,50,100,200,500],
    groupByLimit: 10,
    groupByFilter: '',
    groupByItemsPerPage: 10,
    groupByFooters: { 'items-per-page-options': [10,25,50,100,200,500] },
    groupByPage: 1,
    groupBySortBy: 'count',
    groupBySortDesc: true,
    chartLabelMaxLength: 30,
    chartLabelOtherLimit: 10,
    chartLabelFieldSeparator: ', ',

    eventLimitOptions: [10,25,50,100,200,500,1000,2000,5000],
    eventLimit: 100,
    eventData: [],
    eventFilter: '',  
    eventHeaders: [],
    eventPage: 1,
    sortBy: 'soc_timestamp',
    sortDesc: true,
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,25,50,100,200,500,1000] },

    expandedHeaders: [
      { text: "key", value: "key" },
      { text: "value", value: "value" }
    ],

    totalEvents: 0,
    fetchTimeSecs: 0,
    roundTripTimeSecs: 0,
    mruQueries: [],
    mruCases: [],

    autohunt: true,

    filterRouteInclude: "",
    filterRouteExclude: "",
    filterRouteExact: "",
    filterRouteDrilldown: "",
    groupByRoute: "",
    groupByNewRoute: "",
    quickActionVisible: false,
    quickActionX: 0,
    quickActionY: 0,
    quickActionEvent: null,
    quickActionField: "",
    quickActionValue: "",
    escalationMenuVisible: false,
    escalationMenuX: 0,
    escalationMenuY: 0,
    escalationItem: null,
    escalationGroupIdx: -1,
    escalateRelatedEventsEnabled: false,
    aggregationActionsEnabled: false,
    actions: [],
  }},
  created() {
    this.$root.initializeCharts();
    this.relativeTimeUnits = [
      { text: this.i18n.seconds, value: RELATIVE_TIME_SECONDS },
      { text: this.i18n.minutes, value: RELATIVE_TIME_MINUTES },
      { text: this.i18n.hours, value: RELATIVE_TIME_HOURS },
      { text: this.i18n.days, value: RELATIVE_TIME_DAYS },
      { text: this.i18n.weeks, value: RELATIVE_TIME_WEEKS },
      { text: this.i18n.months, value: RELATIVE_TIME_MONTHS }
    ];
    this.autoRefreshIntervals = [
      { text: this.i18n.interval0s, value: 0 },
      { text: this.i18n.interval5s, value: 5 },
      { text: this.i18n.interval10s, value: 10 },
      { text: this.i18n.interval15s, value: 15 },
      { text: this.i18n.interval30s, value: 30 },
      { text: this.i18n.interval1m, value: 60 },
      { text: this.i18n.interval2m, value: 120 },
      { text: this.i18n.interval5m, value: 300 },
      { text: this.i18n.interval10m, value: 600 },
      { text: this.i18n.interval15m, value: 900 },
      { text: this.i18n.interval30m, value: 1800 },
      { text: this.i18n.interval1h, value: 3600 },
      { text: this.i18n.interval2h, value: 7200 },
      { text: this.i18n.interval5h, value: 18000 },
      { text: this.i18n.interval10h, value: 36000 },
      { text: this.i18n.interval24h, value: 86400 },
    ];
    Vue.filter('colorSeverity', this.colorSeverity);
  },
  beforeDestroy() {
    this.$root.setSubtitle("");
    this.stopRefreshTimer();
  },
  mounted() {
    this.$root.startLoading();
    this.category = this.$route.path.replace("/", "");
    this.$root.loadParameters(this.category, this.initHunt);
  },
  watch: {
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
  },
  methods: {
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
    initHunt(params) {
      this.params = params;
      this.groupByItemsPerPage = params["groupItemsPerPage"];
      this.groupByLimit = params["groupFetchLimit"];
      this.itemsPerPage = params["eventItemsPerPage"];
      this.eventLimit = params["eventFetchLimit"];
      this.relativeTimeValue = params["relativeTimeValue"];
      this.relativeTimeUnit = params["relativeTimeUnit"];
      this.mruQueryLimit = params["mostRecentlyUsedLimit"];
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
      if (this.queries != null && this.queries.length > 0) {
        this.query = this.queries[0].query;
      }
      this.actions = params["actions"];
      this.zone = moment.tz.guess();

      this.loadLocalSettings();
      if (this.mruQueries.length > 0 && this.isAdvanced()) {
        this.query = this.mruQueries[0];
      }

      if (this.$route.query.t) {
        // This page was either refreshed, or opened from an existing hunt hyperlink, 
        // so switch to absolute time since the URL has the absolute time defined.
        this.relativeTimeEnabled = false;
        this.dateRange = this.$route.query.t;
      }

      setTimeout(this.setupDateRangePicker, 10);
      this.setupCharts();
      this.$root.stopLoading();

      if (!this.parseUrlParameters()) return;
      
      if (this.$route.query.q || (this.shouldAutohunt() && this.query)) {
        this.hunt(true);
      }
    },
    applyQuerySubstitutions(queries) {
      queries.forEach(query => {
        query.query = query.query.replace(/\{myId\}/g, this.$root.user.id);
      });
      return queries;
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
      var route = this;
      var onSuccess = function() {};
      var onFail = function() { 
        // When navigating to the same URL, simply refresh data
        route.loadData(); 
      };
      if (this.relativeTimeEnabled) {
        this.dateRange = '';
        this.dateRange = this.getStartDate().format(this.i18n.timePickerFormat) + " - " + this.getEndDate().format(this.i18n.timePickerFormat);
      }
      if (replaceHistory === true) {
        this.$router.replace(this.buildCurrentRoute(), onSuccess, onFail);
      } else {
        this.$router.push(this.buildCurrentRoute(), onSuccess, onFail);
      }
      this.resetRefreshTimer();

      if (document.activeElement) {
        // Release focus to avoid clicking away causing a second hunt
        document.activeElement.blur();
      }
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
        this.autoRefreshTimer = setTimeout(function() { route.hunt(true); }, this.autoRefreshInterval * 1000);
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

      for (var i = 0; i < this.filterToggles.length; i++) {
        filter = this.filterToggles[i];

        if (q.length > 0) {
          q = q + " AND ";
        }

        if (filter.enabled) {
          q = q + filter.filter;
        } else if (filter.exclusive) {
          q = q + "NOT " + filter.filter;
        }
      }

      if (q.length > 0) {
        const response = await this.$root.papi.get('query/filtered', { params: { 
          query: this.query,
          field: "",
          value: q,
          scalar: true,
          mode: FILTER_INCLUDE,
          condense: true,
        }});

        return response.data;
      }
      return this.query;
    },
    parseUrlParameters() {
      this.category = this.$route.path.replace("/", "");

      if (this.$route.query.q) {
        this.query = this.$route.query.q;
      }
      if (this.$route.query.t) {
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

      // Check for special params that force a re-route
      var reRoute = false;
      if (this.$route.query.filterValue) {
        this.filterQuery(this.$route.query.filterField, this.$route.query.filterValue, this.$route.query.filterMode);
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
      if (!this.parseUrlParameters()) return;

      this.$root.startLoading();
      try {
        this.obtainQueryDetails();

        // This must occur before the following await, so that Vue flushes the old groupby DOM renders
        this.groupBys.splice(0);

        const response = await this.$root.papi.get('events/', { params: { 
          query: await this.getQuery(),
          range: this.dateRange, 
          format: this.i18n.timePickerSample, 
          zone: this.zone, 
          metricLimit: this.groupByLimit, 
          eventLimit: this.eventLimit 
        }});

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
        this.expanded = [];
        this.addMRUQuery(this.query);

        var subtitle = this.isAdvanced() ? this.query : this.queryName;
        this.$root.setSubtitle(this.i18n[this.category] + " - " + subtitle);       
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async filterQuery(field, value, filterMode, notify = true) {
      try {
        const valueType = typeof value;
        var scalar = false;
        if (valueType == "boolean" || valueType == "number" || valueType == "bigint") {
          scalar = true;
        }
        const response = await this.$root.papi.get('query/filtered', { params: { 
          query: this.query,
          field: filterMode == FILTER_EXACT ? "" : field,
          value: value,
          scalar: scalar,
          mode: filterMode,
        }});
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
        const response = await this.$root.papi.get('query/grouped', { params: { 
          query: this.query,
          field: field,
          group: group,
        }});
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
        title: title,
        description: description,
        severity: severity,
        template: template,
      };
    },
    async ack(event, item, idx, acknowledge, escalate, caseId, groupIdx) {
      this.$root.startLoading();
      try {
        var docEvent = item;
        if (item["soc_id"]) {
          // Strip away everything else for optimization
          docEvent = { "soc_id": item["soc_id"] };
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
            const response = await this.$root.papi.post('case/events', {
              fields: item,
              caseId: caseId,
            });
          }
        }
        if (isAlert) {
          const response = await this.$root.papi.post('events/ack', {
            searchFilter: await this.getQuery(),
            eventFilter: docEvent,
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
          if (item["count"] && item["count"] > 1) {
            this.$root.showTip(escalate ? this.i18n.escalatedMultipleTip : (acknowledge ? this.i18n.ackMultipleTip : this.i18n.ackUndoMultipleTip));
          } else {
            this.$root.showTip(escalate ? this.i18n.escalatedSingleTip : (acknowledge ? this.i18n.ackSingleTip : this.i18n.ackUndoSingleTip));
          }
          var data;
          if (item["count"] && groupIdx >= 0) {
            data = this.groupBys[groupIdx].data;
          } else {
            data = this.eventData;
          }
          this.removeDataItemFromView(data, item);
        } else if (escalate) {
          this.$root.showTip(this.i18n.escalatedEventTip);
          item['event.escalated'] = true;
        }
      } catch (error) {
        this.$root.showError(error);
      }      
      this.$root.stopLoading();
    },
    removeDataItemFromView(data, item) {
      for (var j = 0; j < data.length; j++) {
        if (data[j] == item) {
          Vue.delete(data, j);
          if (item["count"]) {
            this.totalEvents -= item["count"];
          } else {
            this.totalEvents--;
          }
          if (this.totalEvents < 0) {
            this.totalEvents = 0;
          }
          break;
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
    obtainQueryDetails() {
      this.queryName = "";
      this.queryFilters = [];
      this.queryGroupBys = [];
      this.queryGroupByOptions = [];
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
          } else if (this.query[i] == "\\") {
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
          var search = segments[0].trim();
          var matchingQueryName = this.i18n.custom;
          for (var i = 0; i < this.queries.length; i++) {
            if (this.query == this.queries[i].query) {
              matchingQueryName = this.queries[i].name;
            }
          }
          this.queryName = matchingQueryName;
          search.split(" AND ").forEach(function(item, index) {
            item = item.trim();
            if (item.length > 0 && item != "*") {
              route.queryFilters.push(item);
            }
          });
        }

        if (segments.length > 1) {
          for (var segmentIdx = 1; segmentIdx < segments.length; segmentIdx++) {
            var segment = segments[segmentIdx].trim().replace(/,/g, ' ');
            if (segment.indexOf("groupby") == 0) {
              var fields = [];
              var options = [];
              segment.split(" ").forEach(function(item, index) {
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
            if (segment.indexOf("sortby") == 0) {
              segment.split(" ").forEach(function(item, index) {
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
      return { path: this.category, query: { q: this.query, t: this.dateRange, z: this.zone, el: this.eventLimit, gl: this.groupByLimit }};
    },
    buildFilterRoute(filterField, filterValue, filterMode) {
      route = this.buildCurrentRoute()
      route.query.filterField = filterField;
      route.query.filterValue = filterValue;
      route.query.filterMode = filterMode;
      return route;
    },
    buildGroupByRoute(field) {
      route = this.buildCurrentRoute()
      route.query.groupByField = field;
      route.query.groupByGroup = this.groupBys.length - 1;
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
            removals.forEach(function(removal, index) {
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
      if ( (Object.keys(event).length == 2 && Object.keys(event)[0] == "count") || (Object.keys(event).length == 4 && Object.keys(event)[0] == "count" && Object.keys(event)[1] == "rule.name" && Object.keys(event)[2] == "event.module" && Object.keys(event)[3] == "event.severity_label") ) {
        this.filterRouteDrilldown = this.buildFilterRoute(Object.keys(event)[1], event[Object.keys(event)[1]], FILTER_DRILLDOWN);
        this.$router.push(this.filterRouteDrilldown);
      }
    },
    toggleEscalationMenu(domEvent, event, groupIdx) {
      if (!this.escalateRelatedEventsEnabled) {
        this.ack(domEvent, event, 0, true, true, null, groupIdx);
        return;
      }

      if (!domEvent || this.quickActionVisible || this.escalationMenuVisible) {
        this.quickActionVisible = false;
        this.escalationMenuVisible = false;
        return;
      }
      this.escalationMenuX = domEvent.clientX;
      this.escalationMenuY = domEvent.clientY;
      this.escalationItem = event;
      this.escalationGroupIdx = groupIdx;
      this.$nextTick(() => { 
        this.escalationMenuVisible = true; 
      });      
    },
    toggleQuickAction(domEvent, event, field, value) {
      if (!domEvent || this.quickActionVisible || this.escalationMenuVisible) {
        this.quickActionVisible = false;
        this.escalationMenuVisible = false;
        return;
      }

      if (value != null && this.canQuery(field)) {
        this.filterRouteInclude = this.buildFilterRoute(field, value, FILTER_INCLUDE);
        this.filterRouteExclude = this.buildFilterRoute(field, value, FILTER_EXCLUDE);
        this.filterRouteExact = this.buildFilterRoute(field, value, FILTER_EXACT);
        this.filterRouteDrilldown = this.buildFilterRoute(field, value, FILTER_DRILLDOWN);
        this.groupByRoute = this.buildGroupByRoute(field);
        this.groupByNewRoute = this.buildGroupByNewRoute(field);
        var route = this;
        this.actions.forEach(function(action, index) {
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

          if (action.enabled) {
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
        this.quickActionX = domEvent.native && domEvent.native.clientX ? domEvent.native.clientX : domEvent.clientX;
        this.quickActionY = domEvent.native && domEvent.native.clientY ? domEvent.native.clientY : domEvent.clientY;
        this.$nextTick(() => { 
          this.quickActionVisible = true; 
        });
      }
    },
    filterVisibleFields(eventModule, eventDataset, fields) {
      if (this.eventFields) {
        var filteredFields = null;
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
      var i18n = this.i18n;
      fields.forEach(function(item, index) {
        var i18nKey = "field_" + item;
        var header = {
          text: i18n[i18nKey] ? i18n[i18nKey] : item,
          value: item,
        };
        headers.push(header);
      });
      return headers;
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
      data.forEach(function(row, index) {
        var record = {
          count: row.value,
        };
        fields.forEach(function(field, index) {
          record[field] = route.localizeValue(row.keys[index]);
        });
        route.lookupSocIds(record);
        records.push(record);
      });
      return records;
    },
    constructChartMetrics(data) {
      const records = [];
      const route = this;
      var other = 0;
      data.forEach(function(row, index) {
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
        records.push({value: other, keys: [this.i18n.other]});
      }
      return records;
    },
    populateGroupByTables(metrics) {
      var idx = 0;
      this.groupBys = [];
      while (this.populateGroupByTable(metrics, idx++)) {};
    },
    populateGroupByTable(metrics, groupIdx) {
      const route = this;
      var key = this.lookupGroupByMetricKey(metrics, groupIdx, true);
      if (key) {
        var fields = key.split("|");
        if (fields.length > 1 && fields[0] == "groupby_" + groupIdx) {
          fields.shift();

          // Group objects have the following attributes:
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
          group.sortBy = 'count';
          group.sortDesc = true;
          if (this.groupBys.length == 0 && this.groupBySortBy) {
            group.sortBy = this.groupBySortBy;
            group.sortDesc = this.groupBySortDesc;
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
            const unmaximizeFn = function() {
              const newRoute = route.buildNonMaximizedRoute(group, groupIdx);
              route.$router.push(newRoute, function() {}, function() {});
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
    updateGroupBySort() {
      if (this.groupBys.length > 0) {
        this.groupBySortBy = this.groupBys[0].sortBy;
        this.groupBySortDesc = this.groupBys[0].sortDesc;
      }
    },
    populateEventTable(events) {
      var records = [];
      var fields = [];
      var eventModule;
      var eventDataset;
      var route = this;
      if (events != null && events.length > 0) {
        events.forEach(function(event, index) {
          var record = event.payload;
          record.soc_id = event.id;
          record.soc_score = event.score;
          record.soc_type = event.type;
          record.soc_timestamp = event.timestamp;
          record.soc_source = event.source;
          route.lookupSocIds(record);
          records.push(record);

          var currentModule = record["event.module"];
          var currentDataset = record["event.dataset"];
          if (eventModule == null && currentModule) {
            eventModule = currentModule.toLowerCase();
            if (currentDataset) {
              eventDataset = currentDataset.toLowerCase();
            }
          } else if (eventModule != currentModule || eventDataset != currentDataset) {
            // A variety of events returned in this query, can't show event-specific fields
            inconsistentEvents = true;
          }
        });
        for (const key in records[0]) {
          fields.push(key);
        }
      }
      this.eventHeaders = this.constructHeaders(this.filterVisibleFields(eventModule, eventDataset, fields));
      this.eventData = records;
    },
    displayTable(group, groupIdx) {
      group.chart_type = "";
      Vue.set(this.groupBys, groupIdx, group);
    },
    displayPieChart(group, groupIdx) {
      group.chart_type = "pie";
      group.chart_options = {};
      group.chart_data = {};
      this.setupPieChart(group.chart_options, group.chart_data, group.title);
      this.applyLegendOption(group, groupIdx);
      this.populateChart(group.chart_data, group.chart_metrics);
      Vue.set(this.groupBys, groupIdx, group);
    },
    displayBarChart(group, groupIdx) {
      group.chart_type = "bar";
      group.chart_options = {};
      group.chart_data = {};
      this.setupBarChart(group.chart_options, group.chart_data, group.title);
      this.applyLegendOption(group, groupIdx);
      this.populateChart(group.chart_data, group.chart_metrics);
      Vue.set(this.groupBys, groupIdx, group);
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
      var updateMaxMap = function(map, key, value) {
        var max = map[key];
        if (!max) {
          max = 0;
        }
        max = max + value;
        map[key] = max;
        flowMax = Math.max(flowMax, max);
      };

      var isRecursive = function(map, from, to, current, max) {
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
      group.data.forEach(function(item, index) {
        for (var idx = 0; idx < group.fields.length - 1; idx++) {
          var from = item[group.fields[idx]];
          var to = item[group.fields[idx+1]];
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
      Vue.set(this.groupBys, groupIdx, group);
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
      chart.labels = [];
      chart.datasets[0].data = [];
      if (!data) return;
      const route = this;
      data.forEach(function(item, index) {
        chart.labels.push(route.$root.truncate(route.localizeValue(route.lookupSocId(item.keys[0])), route.chartLabelMaxLength));
        chart.datasets[0].data.push(item.value);
      });
      if (chart.obj) {
        setTimeout(function() { chart.obj.renderChart(chart.obj.chartdata, chart.obj.options); }, 100);
      }
    },
    expand(item) {
      if (this.isExpanded(item)) {
        this.expanded = [];
      } else {
        this.expanded = [item];
      }
    },
    isExpanded(item) {
      return (this.expanded.length > 0 && this.expanded[0] == item);
    },
    getExpandedData() {
      var records = []
      if (this.expanded.length > 0) {
        var data = this.expanded[0];
        for (key in data) {
          var record = {};
          record.key = key;
          record.value = data[key];
          records.push(record);
        }
      }
      return records;
    },
    canQuery(key) {
      return !key.startsWith("soc_");
    },
    lookupGroupByMetricKey(metrics, groupIdx, longest) {
      var desiredKey = null;
      for (const key in metrics) {
        if (key.startsWith("groupby_" + groupIdx +"|")) {
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

      range = document.getElementById('huntdaterange');
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
      $('#huntdaterange').on('hide.daterangepicker', function(ev, picker) { 
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
    },
    setupBarChart(options, data, title) {
      var fontColor = this.$root.getColor("#888888", -40);
      var dataColor = this.$root.getColor("primary");
      var gridColor = this.$root.getColor("#888888", 65);
      options.onClick = this.handleChartClick;
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
        yAxes: {
          grid: {
            color: gridColor,
          },
          ticks: {
            beginAtZero: true,
            fontColor: fontColor,
            precision: 0,
          }
        },
        xAxes: {
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
      options.scales.xAxes.type = 'timeseries';
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
    setupSankeyChart(options, data, title) {
      const route = this;
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
        color: this.$root.$vuetify && this.$root.$vuetify.theme.dark ? 'white' : 'black',
        colorFrom: c => route.getSankeyColor('from', 'out', c, data.flowMax),
        colorTo: c => route.getSankeyColor('to', 'in', c, data.flowMax),
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
    async handleChartClick(e, activeElement, chart) {
      if (activeElement.length > 0) {
        var clickedValue = chart.data.labels[activeElement[0].index] + "";
        if (clickedValue && clickedValue.length > 0) {
          if (this.canQuery(clickedValue)) {
            var chartGroupByField = this.groupBys[0].fields[0];
            this.toggleQuickAction(e, {}, chartGroupByField, clickedValue);
          }
        }
        return true;
      }
      return false;
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
    colorSeverity(value) {
      if (value == "low_false") return "yellow";
      if (value == "medium_false") return "amber darken-1";
      if (value == "high_false") return "red darken-1";
      if (value == "critical_false") return "red darken-4";
      return "secondary";      
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
    saveLocalSettings() {
      this.saveSetting('groupBySortBy', this.groupBySortBy, 'count');
      this.saveSetting('groupBySortDesc', this.groupBySortDesc, true);
      this.saveSetting('groupByItemsPerPage', this.groupByItemsPerPage, this.params['groupItemsPerPage']);
      this.saveSetting('groupByLimit', this.groupByLimit, this.params['groupFetchLimit']);
      this.saveSetting('sortBy', this.sortBy, 'timestamp');
      this.saveSetting('sortDesc', this.sortDesc, true);
      this.saveSetting('itemsPerPage', this.itemsPerPage, this.params['eventItemsPerPage']);
      this.saveSetting('eventLimit', this.eventLimit, this.params['eventFetchLimit']);
      this.saveSetting('mruQueries', JSON.stringify(this.mruQueries), '[]');
      this.saveSetting('relativeTimeValue', this.relativeTimeValue, this.params['relativeTimeValue']);
      this.saveSetting('relativeTimeUnit', this.relativeTimeUnit, this.params['relativeTimeUnit']);
      this.saveSetting('autohunt', this.autohunt, true);
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
      if (localStorage[prefix + '.sortBy']) this.sortBy = localStorage[prefix + '.sortBy'];
      if (localStorage[prefix + '.sortDesc']) this.sortDesc = localStorage[prefix + '.sortDesc'] == "true";
      if (localStorage[prefix + '.itemsPerPage']) this.itemsPerPage = parseInt(localStorage[prefix + '.itemsPerPage']);
      if (localStorage[prefix + '.eventLimit']) this.eventLimit = parseInt(localStorage[prefix + '.eventLimit']);
      if (localStorage[prefix + '.mruQueries']) this.mruQueries = JSON.parse(localStorage[prefix + '.mruQueries']);
      if (localStorage[prefix + '.relativeTimeValue']) this.relativeTimeValue = parseInt(localStorage[prefix + '.relativeTimeValue']);
      if (localStorage[prefix + '.relativeTimeUnit']) this.relativeTimeUnit = parseInt(localStorage[prefix + '.relativeTimeUnit']);
      if (localStorage[prefix + '.autohunt']) this.autohunt = localStorage[prefix + '.autohunt'] == 'true';

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
    }
  }
};

routes.push({ path: '/hunt', name: 'hunt', component: huntComponent});

const alertsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/alerts', name: 'alerts', component: alertsComponent});

const casesComponent = Object.assign({}, huntComponent);
routes.push({ path: '/cases', name: 'cases', component: casesComponent});

const dashboardsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/dashboards', name: 'dashboards', component: dashboardsComponent});