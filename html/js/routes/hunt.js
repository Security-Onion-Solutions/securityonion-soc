// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
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
    eventFields: {},
    dateRange: '',
    relativeTimeEnabled: true,
    relativeTimeValue: 24,
    relativeTimeUnit: RELATIVE_TIME_HOURS,
    relativeTimeUnits: [],
    loaded: false,
    expanded: [],
    chartHeight: 200,
    zone: '',
    huntPending: false,

    filterToggles: [],

    timelineChartOptions: {},
    timelineChartData: {},

    metricsEnabled: false,
    eventsEnabled: true,
    topChartOptions: {},
    topChartData: {},
    bottomChartOptions: {},
    bottomChartData: {},
    groupByFields: '',
    groupByLimitOptions: [10,25,50,100,200,500],
    groupByLimit: 10,
    groupByFilter: '',
    groupByData: [],
    groupByHeaders: [],
    groupBySortBy: 'timestamp',
    groupBySortDesc: true,
    groupByItemsPerPage: 10,
    groupByFooters: { 'items-per-page-options': [10,25,50,100,200,500] },
    groupByPage: 1,

    eventLimitOptions: [10,25,50,100,200,500,1000,2000,5000],
    eventLimit: 100,
    eventData: [],
    eventFilter: '',  
    eventHeaders: [],
    eventPage: 1,
    sortBy: 'timestamp',
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

    autohunt: true,

    filterRouteInclude: "",
    filterRouteExclude: "",
    filterRouteExact: "",
    filterRouteDrilldown: "",
    groupByRoute: "",
    quickActionElement: null,
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
    Vue.filter('colorSeverity', this.colorSeverity);
  },
  beforeDestroy() {
    this.$root.setSubtitle("");
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
      this.queries = params["queries"];
      this.filterToggles = params["queryToggleFilters"];
      this.eventFields = params["eventFields"];
      this.advanced = params["advanced"];
      if (this.queries != null && this.queries.length > 0) {
        this.query = this.queries[0].query;
      }
      this.actions = params["actions"];
      this.zone = moment.tz.guess();

      this.loadLocalSettings();
      if (this.mruQueries.length > 0 && this.isAdvanced()) {
        this.query = this.mruQueries[0];
      }

      if (this.$route.query.t && this.isAdvanced()) {
        // This page was either refreshed, or opened from an existing hunt hyperlink, 
        // so switch to absolute time since the URL has the absolute time defined.
        this.relativeTimeEnabled = false;
        this.dateRange = this.$route.query.t;
      }

      setTimeout(this.setupDateRangePicker, 10);
      this.setupCharts();
      this.$root.stopLoading();

      if (this.$route.query.q || (this.shouldAutohunt() && this.query)) {
        this.loadData();
      }
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
    },
    huntQuery(query) {
      this.query = query;
      this.hunt();
    },
    getQuery() {
      var q = "";
      if (this.queryBaseFilter.length > 0) {
        q = this.queryBaseFilter + " AND ";
      }
      for (var i = 0; i < this.filterToggles.length; i++) {
        filter = this.filterToggles[i];
        if (filter.enabled) {
          q = q + filter.filter + " AND ";
        } else if (filter.exclusive) {
          q = q + " NOT " + filter.filter + " AND ";
        }
      }
      return q + this.query;
    },
    generatePcapLink(eventId) {
      return "/joblookup?id=" + encodeURIComponent(eventId);
    },
    async loadData() {
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
        this.groupQuery(this.$route.query.groupByField);
        reRoute = true;
      }
      if (reRoute) return;

      this.$root.startLoading();
      try {
        this.obtainQueryDetails();
        const response = await this.$root.papi.get('events/', { params: { 
          query: this.getQuery(),
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
          this.populateGroupByTable(response.data.metrics);
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
    async groupQuery(field, notify = true) {
      try {
        const response = await this.$root.papi.get('query/grouped', { params: { 
          query: this.query,
          field: field,
        }});
        this.query = response.data;
        if (notify) {
          this.notifyInputsChanged(true);
        }
      } catch (error) {
        this.$root.showError(error);
      }
    },
    async lookupPcap(id, newTab) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.post('job/', null, { params: { eventId: id }});
        if (response.data.id) {
          if (newTab) {
            window.open('/#/job/' + response.data.id, '_blank');
          } else {
            this.$root.$router.push({ name: 'job', params: { jobId: response.data.id }});
          }
        } else {
          this.$root.showError(this.i18n.eventLookupFailed);
        }
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },    
    async ack(event, item, idx, acknowledge, escalate = false) {
      this.$root.startLoading();
      try {
        var docEvent = item;
        if (item["soc_id"]) {
          // Strip away everything else for optimization
          docEvent = { "soc_id": item["soc_id"] };
        } 
        if (escalate) {
          var title = item['rule.name'];
          if (!title) {
            this.$root.showError(this.i18n.invalidEscalation);
          }

          var description = item['message'];
          if (!description) description = JSON.stringify(item);

          switch (item['event.severity_label']) {
          case 'low': severity = 1; break;
          case 'medium': severity = 2; break;
          default: severity = 3;
          }

          const response = await this.$root.papi.post('case', {
            title: title,
            description: description,
            severity: severity,
          });
        }
        const response = await this.$root.papi.post('events/ack', {
          searchFilter: this.getQuery(),
          eventFilter: docEvent,
          dateRange: this.dateRange, 
          dateRangeFormat: this.i18n.timePickerSample, 
          timezone: this.zone, 
          escalate: escalate,
          acknowledge: acknowledge,
        });
        if (item["count"] && item["count"] > 1) {
          this.$root.showTip(escalate ? this.i18n.escalatedMultipleTip : (acknowledge ? this.i18n.ackMultipleTip : this.i18n.ackUndoMultipleTip));
        } else {
          this.$root.showTip(escalate ? this.i18n.escalatedSingleTip : (acknowledge ? this.i18n.ackSingleTip : this.i18n.ackUndoSingleTip));
        }

        if (item["count"]) {
          Vue.delete(this.groupByData, idx);
        } else {
          Vue.delete(this.eventData, idx);
        }
      } catch (error) {
        this.$root.showError(error);
      }      
      this.$root.stopLoading();
    },
    isFilterToggleEnabled(name) {
      for (var i = 0; i < this.filterToggles.length; i++) {
        var filter = this.filterToggles[i];
        if (filter.name == name) {
          return filter.enabled;
        }
      }
      return false;
    },
    obtainQueryDetails() {
      this.queryName = "";
      this.queryFilters = [];
      this.queryGroupBys = [];
      var route = this;
      if (this.query) {
        var segments = this.query.split("|");
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
              segment.split(" ").forEach(function(item, index) {
                if (index > 0 && item.trim().length > 0) {
                  route.queryGroupBys.push(item);
                }
              });
              break;
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
      this.query = newQuery;
      if (!this.notifyInputsChanged()) {
        this.obtainQueryDetails();
      }
    },
    removeGroupBy(groupBy) {
      var segments = this.query.split("|");
      var newQuery = segments[0];
      for (var i = 1; i < segments.length; i++) {
        if (segments[i].trim().indexOf("groupby") == 0) {
          segments[i].replace(/,/g, ' ');
          segments[i] = segments[i].replace(" " + groupBy, "");
          if (segments[i].trim() == "groupby") {
            segments[i] = "";
          }
        }
        if (segments[i].length > 0) {
          newQuery = newQuery.trim() + " | " + segments[i];
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
      return route;
    },
    toggleQuickAction(domEvent, event, field, value) {
      if (!domEvent) {
        if (this.quickActionElement) {
          this.quickActionElement.remove();
          this.quickActionElement = null;
        }
        return;
      }

      if (this.quickActionElement && this.quickActionElement.parentElement == domEvent.target) {
        this.quickActionElement.remove();
        this.quickActionElement = null;
        return;
      }

      if (value && this.canQuery(field) && domEvent.target.classList.contains("quick-action-trigger")) {
        if (this.quickActionElement) {
          this.quickActionElement.remove();
          this.quickActionElement = null;
        }
        this.filterRouteInclude = this.buildFilterRoute(field, value, FILTER_INCLUDE);
        this.filterRouteExclude = this.buildFilterRoute(field, value, FILTER_EXCLUDE);
        this.filterRouteExact = this.buildFilterRoute(field, value, FILTER_EXACT);
        this.filterRouteDrilldown = this.buildFilterRoute(field, value, FILTER_DRILLDOWN);
        this.groupByRoute = this.buildGroupByRoute(field);
        var route = this;
        this.actions.forEach(function(action, index) {
          if (action.fields) {
            action.enabled = false;
            for (var x = 0; x < action.fields.length; x++) {
              if (action.fields[x] == field) {
                action.enabled = true;
                break;
              }
            }
          } else if (action.link.indexOf("{eventId}") == -1 || event['soc_id']) {
            action.enabled = true;
          } else {
            action.enabled = false;
          }
          action.linkFormatted = route.formatActionLink(action, event, field, value);
        });

        var route = this;
        setTimeout(function() {
          var quickActionTemplate = document.getElementById("hunt-quick-action");
          route.quickActionElement = quickActionTemplate.cloneNode(true);
          route.quickActionElement.style.display = "block";
          domEvent.target.appendChild(route.quickActionElement);
        }, 0);


      }
    },
    formatActionLink(action, event, field, value) {
      var link = action.link;
      link = link.replace("{eventId}", encodeURI(event["soc_id"]));
      link = link.replace("{field}", encodeURI(field));
      link = link.replace("{value}", encodeURI(value));
      return link;
    },
    isEventAction(action) {
      return action && action.link && !action.link.includes("{field}") && !action.link.includes("{value}");
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
    constructGroupByRows(fields, data) {
      var records = [];
      data.forEach(function(row, index) {
        var record = {
          count: row.value,
        };
        fields.forEach(function(field, index) {
          record[field] = row.keys[index];
        });
        records.push(record);
      });
      return records;
    },
    populateGroupByTable(metrics) {
      var key = this.lookupFullGroupByMetricKey(metrics);
      var fields = key.split("|");
      if (fields.length > 1 && fields[0] == "groupby") {
        fields.shift();
        this.groupByFields = [...fields];
        this.groupByData = this.constructGroupByRows(fields, metrics[key])
        fields.unshift("count");
        fields.unshift(""); // Leave empty header column for optional action buttons/icons
        this.groupByHeaders = this.constructHeaders(fields);
      }
    },
    populateEventTable(events) {
      var records = [];
      var fields = [];
      var eventModule;
      var eventDataset;
      if (events != null && events.length > 0) {
        events.forEach(function(event, index) {
          var record = event.payload;
          record.soc_id = event.id;
          record.soc_score = event.score;
          record.soc_type = event.type;
          record.soc_timestamp = event.timestamp;
          record.soc_source = event.source;
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
    populateChart(chart, data) {
      chart.labels = [];
      chart.datasets[0].data = [];
      if (!data) return;
      data.forEach(function(item, index) {
        chart.labels.push(item.keys[0]);
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
    lookupFullGroupByMetricKey(metrics) {
      var desiredKey = null;
      for (const key in metrics) {
        if (key.startsWith("groupby|")) {
          if (desiredKey == null) {
            desiredKey = key;
          } else if (key.length > desiredKey.length) {
            desiredKey = key;
          }
        }
      }
      return desiredKey;
    },
    lookupTopMetricKey(metrics) {
      var desiredKey = null;
      for (const key in metrics) {
        if (key.startsWith("groupby|")) {
          if (desiredKey == null) {
            desiredKey = key;
          } else if (key.length < desiredKey.length) {
            desiredKey = key;
          }
        }
      }
      return desiredKey;
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
        case RELATIVE_TIME_WEEEKS: unit = "weeks"; break;
        case RELATIVE_TIME_MONTHS: unit = "months"; break;
      }
      return moment().subtract(this.relativeTimeValue, unit);
    },
    setupDateRangePicker() {
      if (this.relativeTimeEnabled) return;
      
      range = document.getElementById('huntdaterange');
      $('#huntdaterange').daterangepicker({
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
      if (!this.isAdvanced()) return;
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
      options.events = ['click'];
      options.onClick = this.handleChartClick;
      options.responsive = true;
      options.maintainAspectRatio = false;
      options.legend = {
        display: false,
      };
      options.title = {
        display: true,
        text: title,
      };
      options.scales = {
        yAxes: [{
          gridLines: {
            color: gridColor,
          },
          ticks: {
            beginAtZero: true,
            fontColor: fontColor,
            precision: 0,
          }
        }],
        xAxes: [{
          gridLines: {
            color: gridColor,
          },
          ticks: {
            fontColor: fontColor,
          }
        }],
      };

      data.labels = [];
      data.datasets = [{
        backgroundColor: dataColor,
        borderColor: dataColor,
        pointRadius: 3,
        fill: false,
        data: [],
      }];
    },
    setupTimelineChart(options, data, title) {
      this.setupBarChart(options, data, title);
      options.scales.xAxes[0].type = 'time';
      options.scales.xAxes[0].distribution = 'series';
      options.scales.xAxes[0].time = {
        displayFormats: {
          hour: 'MMM D hA',
        }
      };
    },
    async handleChartClick(e, activeElement) {
      if (activeElement.length > 0) {
        var clickedValue = activeElement[0]._model.label;
        if (clickedValue && clickedValue.length > 0) {
          if (this.canQuery(clickedValue)) {
            this.query = "*";
            for (var index = 1; index < this.groupByFields.length; index++) {
              var field = this.groupByFields[index];
              await this.groupQuery(field, false);
            }
            this.filterQuery(this.groupByFields[0], clickedValue, FILTER_EXACT, true);
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
    saveLocalSettings() {
      this.saveSetting('groupBySortBy', this.groupBySortBy, 'timestamp');
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
    },
  }
};

routes.push({ path: '/hunt', name: 'hunt', component: huntComponent});

const alertsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/alerts', name: 'alerts', component: alertsComponent});