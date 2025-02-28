// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-queries', 'pages/queries.html');

routes.push({ path: '/queries', name: 'queries', component: {
  template: '#page-queries',
  data() { return {
    i18n: this.$root.i18n,
    queries: [],
    headers: [
      { title: this.$root.i18n.id, value: 'taskId' },
      { title: this.$root.i18n.gridId, value: 'gridId', align: '' },
      { title: this.$root.i18n.details, value: 'details' },
      { title: this.$root.i18n.uptime, value: 'elapsedMs' },
      { title: this.$root.i18n.actions },
    ],
    sortBy: [{ key: 'elapsedMs', order: 'asc' }],
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
    filterEnabled: true,
    cancelQueryTask: null,
    cancelQueryConfirmVisible: false,
  }},
  created() {
    this.loadData();
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
    'filterEnabled': 'loadData',
  },
  methods: {
    async loadData() {
      this.$root.startLoading();
      this.$root.adjustSubgridColVisibility(this.headers);
      try {
        const response = await this.$root.papi.get('query/active', {params: { filter: this.filterEnabled ? 'true' : 'false' }});
        this.queries = response.data;
        this.loadLocalSettings();
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    saveLocalSettings() {
      localStorage['settings.queries.sortBy'] = this.sortBy;
      localStorage['settings.queries.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.queries.sortBy']) {
        this.sortBy = localStorage['settings.queries.sortBy'];
        this.itemsPerPage = parseInt(localStorage['settings.queries.itemsPerPage']);
      }
    },
    async cancelQuery() {
      try {
        const response = await this.$root.papi.post('query/cancel/' + this.cancelQueryTask.taskId, {
            gridId: this.cancelQueryTask.gridId
        });
        this.$root.showTip(this.i18n.queryCancelled);
      } catch (error) {
        this.$root.showError(error);
      }
      this.hideCancelQueryConfirm();
    },
    showCancelQueryConfirm(item) {
        this.cancelQueryTask = item;
        this.cancelQueryConfirmVisible = true;
    },
    hideCancelQueryConfirm() {
        this.cancelQueryTask = null;
        this.cancelQueryConfirmVisible = false;
    },
  }
}});
