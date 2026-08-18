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
  }},
  methods: {
  },
}});
