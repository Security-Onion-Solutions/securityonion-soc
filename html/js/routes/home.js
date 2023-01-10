// Copyright 2020-2023 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
        const response = await this.$root.createApi().get('motd.md?v=' + Date.now());
        if (response.data) {
          this.motd = response.data;
        }
      } catch (error) {
        this.$root.showError(error);
      }
    },
  }
}});
