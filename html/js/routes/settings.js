// Copyright 2020,2021 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/settings', name: 'settings', component: {
  template: '#page-settings',
  data() { return {
    i18n: this.$root.i18n,
    showSettingsForm: false,
    showPassword: false,
    usingDefaults: false,
    form: {
      valid: false,
      password: null,
      csrfToken: null,
      method: null,
    },
    rules: {
      required: value => !!value || this.$root.i18n.required,
      matches: value => (!!value && value == this.form.password) || this.$root.i18n.passwordMustMatch,
    },
    authSettingsUrl: null,
  }},
  mounted() {
    if (!this.$root.getAuthFlowId()) {
      this.reloadSettings();
    } else {
      this.showSettingsForm = true;
      this.authSettingsUrl = this.$root.authUrl + 'settings' + location.search;
      this.loadData()
    }
    this.usingDefaults = localStorage.length == 0;
  },
  watch: {
  },
  methods: {
    reloadSettings() {
      location.pathname = this.$root.settingsUrl;
    },
    resetDefaults() {
      localStorage.clear();
      this.usingDefaults = true;
    },
    async loadData() {
      try {
        const response = await this.$root.authApi.get('settings/flows?id=' + this.$root.getAuthFlowId());
        this.form.csrfToken = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'csrf_token').attributes.value;
        this.form.method = "password";
        var errors = [];
        if (response.data.ui.messages) {
          const error = response.data.ui.messages.find(item => item.type == "error");
          if (error && error.text) {
            errors.push(error.text);
          }
        }
        if (errors.length > 0) {
          this.$root.showWarning(this.i18n.settingsInvalid + errors.join("\n"));
        } else if (response.data.state == "success") {
          this.$root.showInfo(this.i18n.settingsSaved);
        }
      } catch (error) {
        if (error != null && error.response != null && error.response.status == 410) {
          this.reloadSettings();
        } else {
          this.$root.showError(error);
        }
      }
    },
  }
}});
