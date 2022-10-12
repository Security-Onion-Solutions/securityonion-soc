// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '/settings', name: 'settings', component: {
  template: '#page-settings',
  data() { return {
    i18n: this.$root.i18n,
    maxInputLen: 100,
    minPassLen: 8,
    maxPassLen: 72,
    minTotpCodeLen: 6,
    maxTotpCodeLen: 6,
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
    totpForm: {
      valid: false,
      code: null,
      secret: null,
      qr: null,
    },
    rules: {
      required: value => !!value || this.$root.i18n.required,
      matches: value => (!!value && value == this.passwordForm.password) || this.$root.i18n.passwordMustMatch,
      minemaillen: value => (!value || value.length >= this.minEmailLen) || this.$root.i18n.ruleMinLen,
      maxlen: value => (!value || value.length <= this.maxInputLen) || this.$root.i18n.ruleMaxLen,
      minpasslen: value => (!value || value.length >= this.minPassLen) || this.$root.i18n.ruleMinLen,
      maxpasslen: value => (!value || value.length <= this.maxPassLen) || this.$root.i18n.ruleMaxLen,
      mintotplen: value => (!value || value.length >= this.minTotpCodeLen) || this.$root.i18n.ruleMinLen,
      maxtotplen: value => (!value || value.length <= this.maxTotpCodeLen) || this.$root.i18n.ruleMaxLen,
    },
    authSettingsUrl: null,
    unlink_totp_available: false,
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
        this.totpForm.csrfToken = this.passwordForm.csrfToken;
        if (response.data.identity && response.data.identity.traits && response.data.identity.traits.email) {
          this.profileForm.email = response.data.identity.traits.email;
          this.profileForm.firstName = response.data.identity.traits.firstName;
          this.profileForm.lastName = response.data.identity.traits.lastName;
          this.profileForm.note = response.data.identity.traits.note;
        }
        this.extractTotpData(response);

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
          this.$root.showTip(this.i18n.saveSuccess);
        }
      } catch (error) {
        if (error != null && error.response != null && error.response.status == 410) {
          this.reloadSettings();
        } else {
          this.$root.showError(error);
        }
      }
    },
    extractTotpData(response) {
      const qr_node = response.data.ui.nodes.find(item => item.attributes && item.attributes.id == 'totp_qr');
      if (qr_node) {
        this.totpForm.qr = qr_node.attributes.src;
        this.totpForm.secret = response.data.ui.nodes.find(item => item.attributes && item.attributes.id == 'totp_secret_key' && item.attributes.text).attributes.text.text;
      }
      this.unlink_totp_available = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'totp_unlink') != null;
    },
  }
}});
