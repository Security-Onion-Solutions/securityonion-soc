// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const termsComponent = {
  template: '#page-terms',
  data() { return {
    i18n: this.$root.i18n,
    tab: null,
  }},
  created() {
  },
  mounted() {
    this.tab = this.$route.path == "/terms" ? "terms" : "key";
  },
  watch: {
  },
  methods: {
  }
};

routes.push({ path: '/terms', name: 'terms', component: termsComponent});
routes.push({ path: '/license', name: 'terms', component: termsComponent});
routes.push({ path: '/licensekey', name: 'terms', component: termsComponent});
