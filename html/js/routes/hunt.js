// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.


// Wait for modules to be loaded
(function() {
  // Poll for modules to be available
  function initHuntComponent() {
    if (!window.huntModules) {
      setTimeout(initHuntComponent, 10);
      return;
    }

    const huntData = window.huntModules.data;
    const huntMethods = window.huntModules.methods;
    const huntActions = window.huntModules.actions;
    const huntCharts = window.huntModules.charts;

    loadPageTemplate('page-hunt', 'pages/hunt.html');

    const huntComponent = {
      template: '#page-hunt',
      data() {
       const data = huntData;
       data.i18n = this.$root.i18n;
       data.bulkActions = [
         { title: this.$root.i18n.enable, value: 'enable' },
         { title: this.$root.i18n.disable, value: 'disable' },
         { title: this.$root.i18n.delete, value: 'delete' },
       ];
       return data;
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
    ...huntMethods,
    ...huntActions,
    ...huntCharts,
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
  }

  // Start initialization
  initHuntComponent();
})();