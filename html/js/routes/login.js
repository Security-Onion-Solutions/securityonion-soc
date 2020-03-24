// Copyright 2020 Security Onion Solutions. All rights reserved.
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
    requestId: null,
    rules: {
      required: value => !!value || this.$root.i18n.required,
    },
    authLoginUrl: null,
  }},
  created() {
    if (location.search.indexOf("request=") == -1) {
      this.$root.showLogin();
    } else {
      this.showLoginForm = true;
      this.authLoginUrl = this.$root.authUrl + 'login/strategies/password' + location.search;
      this.loadData()
    }
  },
  watch: {
  },
  methods: {
    async loadData() {
      try {
        const response = await this.$root.authApi.get('requests/login' + location.search);
        this.form.csrfToken = response.data.methods.password.config.fields.find(item => item.name == 'csrf_token').value;
        if (response.data.methods.password.config.errors) {
          this.$root.showInfo(this.i18n.loginInvalid);
        }
      } catch (error) {
        this.$root.showError(error);
      }
    },
  }
}});
