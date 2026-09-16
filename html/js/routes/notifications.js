// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-notifications', 'pages/notifications.html');

routes.push({
  path: '/notifications',
  name: 'notifications',
  component: {
    template: '#page-notifications',
    data() {
      return {
        i18n: this.$root?.i18n || {},
        tab: 'schedules',
      };
    },
    methods: {
      refresh() {
        if (this.$refs.schedulesManager && typeof this.$refs.schedulesManager.loadData === 'function') {
          this.$refs.schedulesManager.loadData();
        }
      },
    },
  },
});
