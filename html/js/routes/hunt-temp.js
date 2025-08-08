// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Temporary bundled version of hunt.js that doesn't use ES6 modules

loadPageTemplate('page-hunt', 'pages/hunt.html');

// Define hunt component with all methods inline
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
      relativeTimeUnit: 30, // RELATIVE_TIME_HOURS
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
      groupByItemsPerPageOptions: [10,25,50,100,200,500,1000],
      groupByPage: 1,
      sortBy: 'timestamp',
      sortByOptions: [],
      sortDesc: true,
      eventData: [],
      eventItemsPerPage: 10,
      eventItemsPerPageOptions: [10,25,50,100],
      eventLimit: 100,
      eventLimitOptions: [25,50,100,200,500,1000,2000,5000,10000],
      eventViewRows: 20,
      totalEvents: 0,
      eventPage: 1,
      selectedAction: '',
      bulkActions: [
        { title: this.$root.i18n.enable, value: 'enable' },
        { title: this.$root.i18n.disable, value: 'disable' },
        { title: this.$root.i18n.delete, value: 'delete' },
      ],
      selectAllState: false,
      selectAllIndeterminate: false,
      selectedCount: 0,
      expandedEventIndex: -1,
      expandedEvent: {},
      showAcknowledgeDialog: false,
      showEscalateDialog: false,
      showDeleteDialog: false,
      showBulkDeleteConfirmDialog: false,
      showDetails: false,
      showBottomChart: false,
      showTopChart: false,
      caseEscalated: null,
      escalateRelatedEventsEnabled: false,
      showDetailsPanel: true,
      relatedAlertId: null,
      bulkDeleteTimeout: null,
      autohunt: false,
      timeoutId: null,
      disableRouteLoad: false,
      eventSegmentsLimit: 5,
      eventSegmentsLimitOptions: [1, 2, 5, 10],
      chartSankeyLimit: 10,
      chartSankeyLimitOptions: [10, 25, 50, 100],
      chartTimelineLimit: 10,
      chartTimelineLimitOptions: [5, 10, 25, 50, 100, 200, 500],
      topChartHeight: 350,
      bottomChartHeight: 350,
      canQuery: false,
      filterRouteDrilldown: '/',
      prevRelatedEventId: '',
      aiEnabled: false,
      aiInvestigations: {},
      aiInvestigationExpanded: true,
      aiInvestigationLimit: 5,
      firstEventTime: null,
      mouseDownTime: 0,
      playbookRunning: false,
      pendingExpandedEventIndex: -1,
      pendingExpandedEvent: null,
      chartResizeObserver: null,
      chartResizeTimeout: null,
      chartResizeTracker: {},
      eventColumnWidth: null,
      eventFieldObservations: {},
      chartHeightObserver: null,
      groupBySortBy: ['count'],
      groupBySortDesc: [true],
    };
  },
  created() {
    this.$root.initializeCharts();
    this.initializeTimeAndIntervals();
  },
  beforeUnmount() {
    this.$root.setSubtitle("");
    this.stopRefreshTimer();
    this.$root.unsubscribe('detections:bulkUpdate', this.bulkUpdateReport);
    this.$root.unsubscribe('related:bulkCreate', this.bulkUpdateReport);

    if (this.isCategory('alerts')) {
      window.removeEventListener('resize', this.calculateEventColumnWidth);
    }
  },
  mounted() {
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
  },
  methods: {
    // Core methods required by the template
    initializeTimeAndIntervals() {
      console.log('Hunt component initializing time and intervals');
      // Initialize relative time units
      this.relativeTimeUnits = [
        { text: this.i18n.seconds, value: 10 },
        { text: this.i18n.minutes, value: 20 },
        { text: this.i18n.hours, value: 30 },
        { text: this.i18n.days, value: 40 },
        { text: this.i18n.weeks, value: 50 },
        { text: this.i18n.months, value: 60 }
      ];
      // Initialize auto refresh intervals
      this.autoRefreshIntervals = [
        { title: this.i18n.disabled, value: 0 },
        { title: '30 ' + this.i18n.seconds, value: 30 },
        { title: '1 ' + this.i18n.minute, value: 60 },
        { title: '2 ' + this.i18n.minutes, value: 120 },
        { title: '5 ' + this.i18n.minutes, value: 300 },
        { title: '10 ' + this.i18n.minutes, value: 600 },
        { title: '30 ' + this.i18n.minutes, value: 1800 },
        { title: '60 ' + this.i18n.minutes, value: 3600 }
      ];
    },
    stopRefreshTimer() {
      if (this.autoRefreshTimer) {
        clearTimeout(this.autoRefreshTimer);
        this.autoRefreshTimer = null;
      }
    },
    isCategory(category) {
      return this.category === category;
    },
    isAdvanced() {
      return this.advanced || this.isCategory('hunt') || this.isCategory('cases');
    },
    loading() {
      return this.$root.loading;
    },
    calculateEventColumnWidth() {
      // Placeholder
    },
    loadData() {
      console.log('Hunt component loading data');
    },
    saveLocalSettings() {
      // Save settings to localStorage
      var settings = {};
      if (localStorage[this.category + 'Settings']) {
        settings = JSON.parse(localStorage[this.category + 'Settings']);
      }
      settings['advanced'] = this.advanced;
      settings['autohunt'] = this.autohunt;
      settings['relativeTimeValue'] = this.relativeTimeValue;
      settings['relativeTimeUnit'] = this.relativeTimeUnit;
      settings['autoRefreshInterval'] = this.autoRefreshInterval;
      settings['showDetailsPanel'] = this.showDetailsPanel;
      localStorage[this.category + 'Settings'] = JSON.stringify(settings);
    },
    saveTimezone() {
      this.saveSetting('timezone', this.zone);
    },
    saveSetting(setting, value) {
      var settings = {};
      if (localStorage[this.category + 'Settings']) {
        settings = JSON.parse(localStorage[this.category + 'Settings']);
      }
      settings[setting] = value;
      localStorage[this.category + 'Settings'] = JSON.stringify(settings);
    },
    groupByItemsPerPageChanged() {
      this.saveLocalSettings();
    },
    groupByLimitChanged() {
      this.saveLocalSettings();
    },
    itemsPerPageChanged() {
      this.saveLocalSettings();
    },
    eventLimitChanged() {
      this.saveLocalSettings();
    },
    resetRefreshTimer() {
      this.stopRefreshTimer();
      // Restart timer if needed
    },
    toggleShowDetailsPanel() {
      // Placeholder
    },
    initHunt() {
      console.log('Hunt component initialized');
      this.$root.stopLoading();
    },
    bulkUpdateReport() {
      // Placeholder
    },
    filterToggled(event, toggle) {
      // Placeholder
    },
    notifyInputsChanged() {
      // Placeholder - this would trigger a new search
    },
    getPresets(type) {
      // Return empty array for now
      return [];
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

const detectionsComponent = Object.assign({}, huntComponent);
routes.push({ path: '/detections', name: 'detections', component: detectionsComponent });