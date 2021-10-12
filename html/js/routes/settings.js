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
    maxInputLen: 100,
    maxPassLen: 72,
    minEmailLen: 6,
    showSettingsForm: false,
    showPassword: false,
    usingDefaults: false,
    profileForm: {
      valid: false,
      csrfToken: null,
      email: null,
      firstName: null,
      lastName: null,
      note: null,
    },
    passwordForm: {
      valid: false,
      password: null,
      csrfToken: null,
    },
    rules: {
      required: value => !!value || this.$root.i18n.required,
      matches: value => (!!value && value == this.passwordForm.password) || this.$root.i18n.passwordMustMatch,
      minemaillen: value => (!value || value.length >= this.minEmailLen) || this.$root.i18n.ruleMinLen,
      maxlen: value => (!value || value.length <= this.maxInputLen) || this.$root.i18n.ruleMaxLen,
      maxpasslen: value => (!value || value.length <= this.maxPassLen) || this.$root.i18n.ruleMaxLen,
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
        this.passwordForm.csrfToken = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'csrf_token').attributes.value;
        this.profileForm.csrfToken = this.passwordForm.csrfToken;
        if (response.data.identity && response.data.identity.traits && response.data.identity.traits.email) {
          this.profileForm.email = response.data.identity.traits.email;
          this.profileForm.firstName = response.data.identity.traits.firstName;
          this.profileForm.lastName = response.data.identity.traits.lastName;
          this.profileForm.note = response.data.identity.traits.note;
        }

        var errorsMessage = null;
        if (response.data.ui.messages && response.data.ui.messages.length > 0) {
          const error = response.data.ui.messages.find(item => item.type == "error");
          if (error && error.text) {
            errorsMessage = error.text;
          }
        } else if (response.data.ui.nodes) {
          const item = response.data.ui.nodes.find(item => item.messages && item.messages.length > 0);
          if (item) {
            const error = item.messages.find(item => item.type == "error");
            if (error && error.text) {
              errorsMessage = error.text;
            }
          }
        }
        if (errorsMessage) {
          this.$root.showWarning(this.i18n.settingsInvalid + errorsMessage);
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
