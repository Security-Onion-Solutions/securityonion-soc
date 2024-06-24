// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '/settings', name: 'settings', component: {
  template: '#page-settings',
  data() { return {
    i18n: this.$root.i18n,
    maxInputLen: 100,
    minTotpCodeLen: 6,
    maxTotpCodeLen: 6,
    minEmailLen: 6,
    showSettingsForm: false,
    showPassword: false,
    usingDefaults: false,
    csrfToken: null,
    profileForm: {
      valid: false,
      email: null,
      firstName: null,
      lastName: null,
      note: null,
    },
    passwordForm: {
      valid: false,
      password: null,
    },
    totpForm: {
      valid: false,
      code: null,
      secret: null,
      qr: null,
    },
    webauthnForm: {
      valid: false,
      onclick: null,
      name: null,
      key: null,
      script: null,
      existingKeys: [],
    },
    passwordEnabled: false,
    oidcEnabled: false,
    oidcProviders: [],
    rules: {
      required: value => !!value || this.$root.i18n.required,
      matches: value => (!!value && value == this.passwordForm.password) || this.$root.i18n.passwordMustMatch,
      minemaillen: value => (!value || value.length >= this.minEmailLen) || this.$root.i18n.ruleMinLen,
      maxlen: value => (!value || value.length <= this.maxInputLen) || this.$root.i18n.ruleMaxLen,
      minpasslen: value => (!value || value.length >= USER_PASSWORD_LENGTH_MIN) || this.$root.i18n.ruleMinLen,
      maxpasslen: value => (!value || value.length <= USER_PASSWORD_LENGTH_MAX) || this.$root.i18n.ruleMaxLen,
      badpasschs: value => (!value || !value.match(USER_PASSWORD_INVALID_RX)) || this.$root.i18n.rulePassBadChars,
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
        this.csrfToken = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'csrf_token').attributes.value;
        if (response.data.identity && response.data.identity.traits && response.data.identity.traits.email) {
          this.profileForm.email = response.data.identity.traits.email;
          this.profileForm.firstName = response.data.identity.traits.firstName;
          this.profileForm.lastName = response.data.identity.traits.lastName;
          this.profileForm.note = response.data.identity.traits.note;
        }
        this.extractPasswordData(response);
        this.extractTotpData(response);
        this.extractWebauthnData(response);
        this.extractOidcData(response);

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
    extractWebauthnData(response) {
      if (response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'webauthn_register_trigger')) {
        this.webauthnForm.onclick = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'webauthn_register_trigger').attributes.onclick;
        this.webauthnForm.name = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'webauthn_register_displayname').attributes.value;
        this.webauthnForm.key = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'webauthn_register').attributes.value;
        this.webauthnForm.script = response.data.ui.nodes.find(item => item.attributes && item.attributes.id == 'webauthn_script').attributes;
        this.webauthnForm.existingKeys = response.data.ui.nodes.filter(item => item.attributes && item.attributes.name == 'webauthn_remove').map(key => {
          return {value: key.attributes.value, id: key.meta.label.id, name: key.meta.label.context.display_name, date: key.meta.label.context.added_at};
        });

        const script = document.createElement('script');
        script.setAttribute('type', this.webauthnForm.script.type);
        script.setAttribute('id', this.webauthnForm.script.id);
        script.setAttribute('crossorigin', this.webauthnForm.script.crossorigin);
        script.setAttribute('referrerpolicy', this.webauthnForm.script.referrerpolicy);
        script.setAttribute('integrity', this.webauthnForm.script.integrity);
        script.setAttribute('nonce', this.webauthnForm.script.nonce);
        script.setAttribute('src', this.webauthnForm.script.src); 
        document.body.appendChild(script);
      }
    },
    runWebauthn() {
      eval(this.webauthnForm.onclick);
    },
    extractPasswordData(response) {
      if (response.data.ui.nodes.find(item => item.group == "password")) {
        this.passwordEnabled = true;
      }
    },
    extractOidcData(response) {
      response.data.ui.nodes.filter(item => item.group == "oidc").forEach((oidc) => {
        this.oidcEnabled = true;
        this.oidcProviders.push({op: oidc.attributes.name, id: oidc.attributes.value});
      });
    }
  }
}});
