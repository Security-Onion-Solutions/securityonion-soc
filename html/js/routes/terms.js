// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '/terms', name: 'terms', component: {
  template: '#page-terms',
  data() { return {
    i18n: this.$root.i18n,
  }},
  created() {
  },
  watch: {
  },
  methods: {
  }
}});
