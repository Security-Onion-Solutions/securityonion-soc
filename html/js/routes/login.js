// Copyright 2020-2023 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '*', name: 'login', component: {
  template: '#page-login',
  data() { return {
    i18n: this.$root.i18n,
    showLoginForm: false,
    showPassword: false,
    form: {
      valid: false,
      email: null,
      password: null,
      totpCode: null,
      csrfToken: null,
      method: null,
    },
    totpCodeLength: 6,
    rules: {
      required: value => !!value || this.$root.i18n.required,
    },
    authLoginUrl: null,
    banner: "",
  }},
  created() {
    if (!this.$root.getAuthFlowId()) {
      this.$root.showLogin();
    } else {
      this.showLoginForm = true;
      this.authLoginUrl = this.$root.authUrl + 'login' + location.search;
      this.loadData()
    }
  },
  watch: {
  },
  methods: {
    async loadData() {
      try {
        var response = await axios.create().get('/login/banner.md?v=' + Date.now());
        if (response.data) {
          this.banner = marked.parse(response.data);
        }
        response = await this.$root.authApi.get('login/flows?id=' + this.$root.getAuthFlowId());
        this.form.csrfToken = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'csrf_token').attributes.value;
        this.form.method = response.data.ui.nodes.find(item => item.attributes && item.attributes.name == 'method').attributes.value;
        this.$nextTick(function () {
          // Wait for next Vue tick to set focus, since at the time of this function call (or even mounted() hook), this element won't be 
          // loaded, due to v-if's that have yet to process.
          if (this.form.method == "totp") {
            const ele = document.getElementById("totp--0");
            if (ele) {
              ele.focus();
            }
          }
        });
        if (response.data.ui.messages) {
          const error = response.data.ui.messages.find(item => item.type == "error");
          if (error && error.text) {
            this.$root.showWarning(this.i18n.loginInvalid);
          }
        }
      } catch (error) {
        if (error.response.status == 410) {
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
    }
  },
}});
