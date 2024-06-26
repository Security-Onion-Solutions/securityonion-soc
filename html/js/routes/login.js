// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

routes.push({ path: '*', name: 'login', component: {
  template: '#page-login',
  data() { return {
    i18n: this.$root.i18n,
    showLoginForm: false,
    showPassword: false,
    csrfToken: null,
    form: {
      valid: false,
      email: null,
      password: null,
      totpCode: null,
      method: null,
    },
    webauthnForm: {
      enabled: false,
      continue: false,
      valid: false,
      onclick: null,
      key: null,
      script: null,
      email: null,
    },
    passwordEnabled: false,
    totpEnabled: false,
    oidc: [],
    totpCodeLength: 6,
    rules: {
      required: value => !!value || this.$root.i18n.required,
    },
    authLoginUrl: null,
    banner: "",
    throttled: false,
    countdown: 0,
  }},
  created() {
    const throttled = this.$root.getSearchParam("thr");
    if (throttled) {
      this.throttled = true;
      try {
        this.countdown = parseInt(throttled);
        if (!this.countdown) {
          this.countdown = 30;
        }
      } catch (error) {
        this.countdown = 30;
      }
      setTimeout(this.countdownRelogin, 1000);
    } else if (!this.$root.getAuthFlowId()) {
      this.$root.showLogin();
    } else {
      this.showLoginForm = true;
      this.authLoginUrl = this.$root.authUrl + 'login?flow=' + this.$root.getAuthFlowId();
      this.loadData()
    }
  },
  watch: {
  },
  methods: {
    countdownRelogin() {
      this.countdown--;
      if (this.countdown <= 0) {
        this.$root.showLogin();
      } else {
        setTimeout(this.countdownRelogin, 1000);
      }
    },
    async loadData() {
      try {
        const motd = await this.$root.createApi().get('/login/banner.md?v=' + Date.now());
        if (motd.data) {
          this.banner = marked.parse(motd.data);
        }

        const errID = this.$root.getSearchParam('id')
        if (errID) {
          this.$root.authApi.get('/errors?id=' + errID).then(response => {
            if (!response || !response.data) return;
            let parts = [];

            const err = response.data.error;
            if (!err) return;

            if (err.status) {
              parts.push(err.status);
            }
            if (err.reason) {
              parts.push(err.reason);
            }

            this.$root.showError(parts.join(': '));
          });
        }

        const flow = await this.$root.authApi.get('login/flows?id=' + this.$root.getAuthFlowId());
        if (!flow.data.ui || !flow.data.ui.nodes) {
          // throw out current flowID and start over
          localStorage.removeItem('flowID');
          this.$root.showLogin();

          return;
        }

        this.csrfToken = flow.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'csrf_token').attributes.value;

        this.extractPasswordData(flow);
        this.extractTotpData(flow);
        this.extractWebauthnData(flow);
        this.extractOidcData(flow);
        this.$nextTick(function () {
          // Wait for next Vue tick to set focus, since at the time of this function call (or even mounted() hook), this element won't be
          // loaded, due to v-if's that have yet to process.
          if (this.totpEnabled) {
            const ele = document.getElementById("totp--0");
            if (ele) {
              ele.focus();
            }
          }
        });
        if (flow.data.ui.messages) {
          const error = flow.data.ui.messages.find(item => item.type == "error");
          if (error && error.text) {
            this.$root.showWarning(this.i18n.loginInvalid);
          }
        }
      } catch (error) {
        if (error.response && error.response.status == 410) {
          localStorage.removeItem('flowID');
          document.location = "/login";
        } else {
          this.$root.showError(error);
        }
      }
    },
    submitTotp(code) {
      this.form.totpCode = code;
      document.getElementById("totp_code").value = code;
      document.getElementById("loginForm").submit();
    },
    extractWebauthnData(response) {
      this.webauthnForm.enabled = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'method' && item.attributes.value == 'webauthn') != null;
      const trigger = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'webauthn_login_trigger')
      if (trigger) {
        this.webauthnForm.continue = true;
        this.webauthnForm.onclick = trigger.attributes.onclick;
        this.webauthnForm.key = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'webauthn_login').attributes.value;
        this.webauthnForm.script = response.data.ui.nodes.find(item => item.attributes && item.attributes.id == 'webauthn_script').attributes;
        this.webauthnForm.email = response.data.ui.nodes.find(
          item => item.attributes && item.attributes.name == 'identifier'
        ).attributes.value;

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
    extractOidcData(response) {
      this.oidc = response.data.ui.nodes.filter(item => item.group == "oidc" && item.type == "input" ).map(item => item.attributes.value);
    },
    extractPasswordData(response) {
      if (response.data.ui.nodes.find(item => item.group == "password")) {
        this.passwordEnabled = true;
      }
    },
    extractTotpData(response) {
      if (response.data.ui.nodes.find(item => item.group == "totp")) {
        this.totpEnabled = true;
      }
    },
  },
}});
