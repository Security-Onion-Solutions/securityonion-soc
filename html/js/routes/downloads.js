// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-downloads', 'pages/downloads.html');

routes.push({ path: '/downloads', name: 'downloads', component: {
  template: '#page-downloads',
  data() { return {
    i18n: this.$root.i18n,
    remoteAgentSupported: true,
  }},
  created() {
    this.$root.subscribe("node", this.updateNode);
  },
  unmounted() {
    this.$root.unsubscribe("node", this.updateNode);
  },
  watch: {
  },
  methods: {
    updateNode(node) {
      if (['so-eval', 'so-import'].includes(node.role)) {
        this.remoteAgentSupported = false;
      }
    },
    getBaseUrl() {
      if (this.$root.selectedGridId) {
        const grid = this.$root.getSelectedGrid()
        if (grid) {
          return grid.managerUrl;
        }
      }
      return ''
    },
  }
}});
