// Copyright 2020 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/hunt', name: 'hunt', component: {
  template: '#page-hunt',
  data() { return {
    i18n: this.$root.i18n,
    query: '',
    queries: [],
    eventFields: {},
    dateRange: '',
    dateRangeInitialized: false,
    dateRangeMinutes: 1440,
    loaded: false,
    expanded: [],
    chartHeight: 200,

    timelineChartOptions: {},
    timelineChartData: {},

    metricsEnabled: false,
    topChartOptions: {},
    topChartData: {},
    bottomChartOptions: {},
    bottomChartData: {},
    groupByLimitOptions: [10,25,50,100],
    groupByLimit: 10,
    groupByFilter: '',
    groupByData: [],
    groupByHeaders: [],
    groupBySortBy: 'timestamp',
    groupBySortDesc: true,
    groupByItemsPerPage: 10,
    groupByFooters: { 'items-per-page-options': [10,25,50,250,1000] },

    eventLimitOptions: [10,25,50,100,200,500,1000,2000,5000],
    eventLimit: 100,
    eventFilter: '',
    eventData: [],
    eventHeaders: [],
    sortBy: 'timestamp',
    sortDesc: true,
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,25,50,250,1000] },

    expandedHeaders: [
      { text: "key", value: "key" },
      { text: "value", value: "value" }
    ],

    totalEvents: 0,
    fetchTimeSecs: 0,
    roundTripTimeSecs: 0,
    mruQueries: [],
  }},
  mounted() {
    this.$root.loadParameters("hunt", this.initHunt);
  },
  watch: {
    '$route': 'loadData',
    'groupBySortBy': 'saveLocalSettings',
    'groupBySortDesc': 'saveLocalSettings',
    'groupByItemsPerPage': 'saveLocalSettings',
    'groupByLimit': 'saveLocalSettings',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
    'eventLimit': 'saveLocalSettings',
  },
  methods: {
    loading() {
      return this.$root.loading;
    },
    initHunt(params) {
      this.groupByLimit = params["groupFetchLimit"];
      this.eventLimit = params["eventFetchLimit"];
      this.dateRangeMinutes = params["dateRangeMinutes"];
      this.mruQueryLimit = params["mostRecentlyUsedLimit"];
      this.queries = params["queries"];
      this.eventFields = params["eventFields"];
      if (this.queries.length > 0) {
        this.query = this.queries[0].query;
      }
      this.loadLocalSettings();
      this.setupDateRangePicker();
      this.setupCharts();
      if (this.$route.query.q) {
        this.loadData();
      }
    },
    notifyInputsChanged() {
      if (!this.loading()) {
        this.$root.drawAttention('#hunt');
      }
    },
    addMRUQuery(query) {
      if (query && query.length > 1) {
        if (this.mruQueries.indexOf(query) == -1) {
          this.mruQueries.unshift(query);
          if (this.mruQueries.length > this.mruQueryLimit) {
            this.mruQueries.pop();
          }
          this.saveLocalSettings();
        }
      }
    },
    hunt() {
      var route = this;
      var onSuccess = function() {};
      var onFail = function() { 
        // When navigating to the same URL, simply refresh data
        route.loadData(); 
      };
      this.$router.push({ name: 'hunt', query: { q: this.query, t: this.dateRange, el: this.eventLimit, gl: this.groupByLimit }}, onSuccess, onFail);
    },
    huntQuery(query) {
      this.query = query;
      this.hunt();
    },
    generatePcapLink(eventId) {
      return "/joblookup?id=" + encodeURIComponent(eventId);
    },
    async loadData() {
      this.$root.startLoading();
      if (this.$route.query.q) {
        this.query = this.$route.query.q;
      }
      if (this.$route.query.t) {
        this.dateRange = this.$route.query.t;
      }
      if (this.$route.query.el) {
        this.eventLimit = parseInt(this.$route.query.el);
      }
      if (this.$route.query.gl) {
        this.groupByLimit = parseInt(this.$route.query.gl);
      }
      try {
        var zone = moment.tz.guess();
        const response = await this.$root.papi.get('events', { params: { 
          query: this.query, 
          range: this.dateRange, 
          format: this.i18n.timePickerSample, 
          zone: zone, 
          metricLimit: this.groupByLimit, 
          eventLimit: this.eventLimit 
        }});
        this.totalEvents = response.data.totalEvents;
        this.fetchTimeSecs = response.data.fetchElapsedMs / 1000;
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
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async filterQuery(field, value, include) {
      try {
        const response = await this.$root.papi.get('query/filtered', { params: { 
          query: this.query,
          field: field,
          value: value,
          include: include,
        }});
        this.query = response.data;
        this.notifyInputsChanged();
      } catch (error) {
        this.$root.showError(error);
      }
    },
    async groupQuery(field) {
      try {
        const response = await this.$root.papi.get('query/grouped', { params: { 
          query: this.query,
          field: field,
        }});
        this.query = response.data;
        this.notifyInputsChanged();
      } catch (error) {
        this.$root.showError(error);
      }
    },
    filterVisibleFields(eventType, fields) {
      if (this.eventFields) {
        var filteredFields = null;
        if (eventType) {
          filteredFields = this.eventFields[eventType.toLowerCase()];
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
        this.groupByData = this.constructGroupByRows(fields, metrics[key])
        fields.unshift("count");
        this.groupByHeaders = this.constructHeaders(fields);
      }
    },
    populateEventTable(events) {
      var records = [];
      var fields = [];
      var eventType = null;
      if (events != null && events.length > 0) {
        events.forEach(function(event, index) {
          var record = event.payload;
          record.soc_id = event.id;
          record.soc_score = event.score;
          record.soc_type = event.type;
          record.soc_timestamp = event.timestamp;
          record.soc_source = event.source;
          records.push(record);

          if (eventType == null) {
            eventType = record["event_type"];
          } else if (eventType != record["event_type"]) {
            eventType = "default";
          }
        });
        for (const key in records[0]) {
          fields.push(key);
        }
      }
      this.eventHeaders = this.constructHeaders(this.filterVisibleFields(eventType, fields));
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
        chart.obj.renderChart(chart.obj.chartdata, chart.obj.options);
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
    async lookupPcap(id, newTab) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.post('job/', { params: { eventId: id }});
        if (response.data.id) {
          if (newTab) {
            window.open('/#/job/' + response.data.id, '_blank');
          } else {
            this.$root.$router.push({ name: 'job', params: { jobId: response.data.id }});
          }
        } else {
          this.$root.showError(i18n.eventLookupFailed);
        }
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    showDateRangePicker() {
      $('#huntdaterange').click();
    },
    hideDateRangePicker() {
      this.dateRange = $('#huntdaterange')[0].value;
      this.notifyInputsChanged();
    },
    setupDateRangePicker() {
      range = document.getElementById('huntdaterange');
      $('#huntdaterange').daterangepicker({
        timePicker: true,
        timePickerSeconds: true,
        endDate: moment().startOf('hour'),
        startDate: moment().startOf('hour').subtract(this.dateRangeMinutes, 'minute'),
        locale: {
          format: this.i18n.timePickerFormat
        }
      });
      var route = this;
      route.dateRange = $('#huntdaterange')[0].value;
      $('#huntdaterange').on('hide.daterangepicker', function(ev, picker) { 
        route.hideDateRangePicker();
      });
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
    saveLocalSettings() {
      localStorage['settings.hunt.groupBySortBy'] = this.groupBySortBy;
      localStorage['settings.hunt.groupBySortDesc'] = this.groupBySortDesc;
      localStorage['settings.hunt.groupByItemsPerPage'] = this.groupByItemsPerPage;
      localStorage['settings.hunt.groupByLimit'] = this.groupByLimit;
      localStorage['settings.hunt.sortBy'] = this.sortBy;
      localStorage['settings.hunt.sortDesc'] = this.sortDesc;
      localStorage['settings.hunt.itemsPerPage'] = this.itemsPerPage;
      localStorage['settings.hunt.eventLimit'] = this.eventLimit;
      localStorage['settings.hunt.mruQueries'] = JSON.stringify(this.mruQueries);
    },
    loadLocalSettings() {
      if (localStorage['settings.hunt.groupBySortBy']) this.groupBySortBy = localStorage['settings.hunt.groupBySortBy'];
      if (localStorage['settings.hunt.groupBySortDesc']) this.groupBySortDesc = localStorage['settings.hunt.groupBySortDesc'] == "true";
      if (localStorage['settings.hunt.groupByItemsPerPage']) this.groupByItemsPerPage = parseInt(localStorage['settings.hunt.groupByItemsPerPage']);
      if (localStorage['settings.hunt.groupByLimit']) this.groupByLimit = parseInt(localStorage['settings.hunt.groupByLimit']);
      if (localStorage['settings.hunt.sortBy']) this.sortBy = localStorage['settings.hunt.sortBy'];
      if (localStorage['settings.hunt.sortDesc']) this.sortDesc = localStorage['settings.hunt.sortDesc'] == "true";
      if (localStorage['settings.hunt.itemsPerPage']) this.itemsPerPage = parseInt(localStorage['settings.hunt.itemsPerPage']);
      if (localStorage['settings.hunt.eventLimit']) this.eventLimit = parseInt(localStorage['settings.hunt.eventLimit']);
      if (localStorage['settings.hunt.mruQueries']) this.mruQueries = JSON.parse(localStorage['settings.hunt.mruQueries']);
    },
  }
}});
