// Copyright 2020,2021 Security Onion Solutions. All rights reserved.
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
      csrfToken: null,
    },
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
      this.authLoginUrl = this.$root.authUrl + 'login/methods/password' + location.search;
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
          this.banner = marked(response.data);
        }
        response = await this.$root.authApi.get('login/flows?id=' + this.$root.getAuthFlowId());
        this.form.csrfToken = response.data.methods.password.config.fields.find(item => item.name == 'csrf_token').value;
        if (response.data.methods.password.config.messages) {
          this.$root.showWarning(this.i18n.loginInvalid);
        }
      } catch (error) {
        if (error.response.status == 410) {
          document.location = "/login";
        } else {
          this.$root.showError(error);
        }
      }
    },
  }
}});
