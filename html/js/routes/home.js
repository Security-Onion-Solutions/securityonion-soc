// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '/', name: 'home', component: {
  template: '#page-home',
  data() { return {
    i18n: this.$root.i18n,
    changeDetails: {},
    motd: "",
  }},
  created() {
    this.loadChanges();
  },
  watch: {
  },
  methods: {
    async loadChanges() {
      try {
        const response = await this.$root.papi.get('motd.md?v=' + Date.now());
        if (response.data) {
          this.motd = response.data;
        }
      } catch (error) {
        this.$root.showError(error);
      }
    },
  }
}});
