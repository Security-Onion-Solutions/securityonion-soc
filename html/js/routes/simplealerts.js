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
    eventLimit: 100,
    metricLimit: 10,
    zone: moment.tz.guess(),

    filterSeverity: 'all',
    filterStatus: 'active',
    filterTimeRange: '24h',
    filterCategory: 'all',

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
    activeAlertCount() {
      return this.alerts.filter(a => !a.acknowledged && !a.escalated).length;
    },
    highSeverityCount() {
      return this.alerts.filter(a => this.getSeverityLevel(a) === 'high').length;
    },
    mediumSeverityCount() {
      return this.alerts.filter(a => this.getSeverityLevel(a) === 'medium').length;
    },
    lowSeverityCount() {
      return this.alerts.filter(a => this.getSeverityLevel(a) === 'low').length;
    },
  },
  created() {
    this.loadAlerts();
  },
  methods: Object.assign({},
    SimpleAlertsData,
    {
    }
  ),
}});
