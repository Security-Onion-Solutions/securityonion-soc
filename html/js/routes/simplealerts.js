// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-simple-alerts', 'pages/simplealerts.html');

// Simple Alerts is an alternate, lower-ceremony triage view for alerts; the expert-mode
// screen at /alerts (served by hunt.js) remains the default. The page's methods are split
// by concern across sibling simplealerts.*.js files, each of which loads before this one
// (see index.html) and publishes a plain object on globalThis; they are merged into
// `methods` below so the component is fully assembled when routes.push runs.

routes.push({ path: '/simple-alerts', name: 'simple-alerts', component: {
  template: '#page-simple-alerts',
  data() { return {
    i18n: this.$root.i18n,

    alerts: [],
    loading: false,
    totalAlerts: 0,
    hasMore: false,
    // {high, medium, low} across every matching alert, from the groupby aggregation
    // that rides along with the events request; null when the backend sent none.
    severityTotals: null,
    eventLimit: 100,
    metricLimit: 10,
    zone: moment.tz.guess(),

    filterSeverity: 'all',
    filterStatus: 'active',
    filterTimeRange: '24h',
    filterCategory: 'all',

    // 'rule' groups by detection, 'source-dest' by network pair, 'none' is the flat list.
    groupingMode: 'rule',
    groupAlerts: true,
    alertGroups: [],
    sourceDestGroups: [],
    expandedGroups: [],
    // Aggregation buckets to request, i.e. the maximum number of groups shown.
    groupLimit: 50,
    // Alerts fetched when a group is first expanded.
    groupAlertLimit: 500,
    // Of those, how many render before the user asks for the rest.
    subGroupDisplayLimit: 50,

    detailsDialog: false,
    selectedAlertDetails: null,

    selectionMode: false,
    // Object maps rather than Sets, so template reads stay reactive.
    selectedAlertIds: {},
    selectedGroupKeys: {},
    actionLoading: false,
    pcapLoading: false,

    severityOptions: [
      { value: 'all', title: this.$root.i18n.simpleAlertsAllSeverities },
      { value: 'high', title: this.$root.i18n.simpleAlertsSeverityHigh },
      { value: 'medium', title: this.$root.i18n.simpleAlertsSeverityMedium },
      { value: 'low', title: this.$root.i18n.simpleAlertsSeverityLow },
    ],
    statusOptions: [
      { value: 'all', title: this.$root.i18n.simpleAlertsAllStatuses },
      { value: 'active', title: this.$root.i18n.simpleAlertsStatusActive },
      { value: 'acknowledged', title: this.$root.i18n.acknowledged },
      { value: 'escalated', title: this.$root.i18n.escalated },
    ],
    timeRangeOptions: [
      { value: '1h', title: this.$root.i18n.simpleAlertsRangeHour },
      { value: '24h', title: this.$root.i18n.simpleAlertsRangeDay },
      { value: '7d', title: this.$root.i18n.simpleAlertsRangeWeek },
      { value: '30d', title: this.$root.i18n.simpleAlertsRangeMonth },
    ],
    categoryOptions: [],
    groupingOptions: [
      { value: 'rule', title: this.$root.i18n.simpleAlertsGroupByRule },
      { value: 'source-dest', title: this.$root.i18n.simpleAlertsGroupBySourceDest },
      { value: 'none', title: this.$root.i18n.simpleAlertsGroupByNone },
    ],

    sortBy: [{ key: 'timestamp', order: 'desc' }],
    itemsPerPage: 25,
    itemsPerPageOptions: [10, 25, 50, 100],
    headers: [
      { title: this.$root.i18n.time, value: 'timestamp' },
      { title: this.$root.i18n.severity, value: 'severityLabel' },
      { title: this.$root.i18n.simpleAlertsRuleName, value: 'ruleName' },
      { title: this.$root.i18n.source, value: 'sourceIp' },
      { title: this.$root.i18n.destination, value: 'destIp' },
    ],
  }},
  computed: {
    // Category is derived from the rule name rather than an indexed field, so unlike
    // the other filters it is applied here instead of being pushed into the query.
    processedAlerts() {
      if (this.filterCategory === 'all') return this.alerts;
      return this.alerts.filter(alert => alert['rule.category'] === this.filterCategory);
    },
    // The stat pills describe the whole result set, not the loaded page, so they read
    // from the aggregation. A dash is shown when no aggregation came back, rather than
    // a zero that would read as "none matched".
    highSeverityCount() {
      return this.severityTotals ? this.formatCompactNumber(this.severityTotals.high) : this.i18n.simpleAlertsStatUnavailable;
    },
    mediumSeverityCount() {
      return this.severityTotals ? this.formatCompactNumber(this.severityTotals.medium) : this.i18n.simpleAlertsStatUnavailable;
    },
    lowSeverityCount() {
      return this.severityTotals ? this.formatCompactNumber(this.severityTotals.low) : this.i18n.simpleAlertsStatUnavailable;
    },
    visibleGroups() {
      const groups = this.activeGroups();
      if (this.filterCategory === 'all' || !this.categoryFilterEnabled()) return groups;
      return groups.filter(g => g['rule.category'] === this.filterCategory);
    },
    // Counts a selected group as every alert it represents, not the rows on screen,
    // so the number matches what the bulk action will actually affect.
    bulkSelectionLabel() {
      const summary = this.selectionSummary();
      let key = 'simpleAlertsBulkSelection';
      if (summary.groups === 1) key = 'simpleAlertsBulkSelectionGroup';
      else if (summary.groups > 1) key = 'simpleAlertsBulkSelectionGroups';
      return this.$root.localizeMessage(key, {
        count: this.formatCompactNumber(summary.total),
        groups: summary.groups,
      });
    },
    // Mirrors the active status filter so the headline number is never ambiguous.
    totalAlertsLabel() {
      const option = this.statusOptions.find(o => o.value === this.filterStatus);
      return option ? option.title : this.i18n.simpleAlertsAllStatuses;
    },
  },
  created() {
    this.loadLocalSettings();
    this.loadAlerts();
  },
  methods: Object.assign({},
    SimpleAlertsData,
    SimpleAlertsGrouping,
    SimpleAlertsDetails,
    SimpleAlertsRules,
    SimpleAlertsActions,
    SimpleAlertsPivots,
    SimpleAlertsPlaybook,
    {
    }
  ),
}});
