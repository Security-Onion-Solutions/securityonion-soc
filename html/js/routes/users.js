// Copyright 2020-2023 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/users', name: 'users', component: {
  template: '#page-users',
  data() { return {
    i18n: this.$root.i18n,
    users: [],
    headers: [
      { text: this.$root.i18n.email, value: 'email' },
      { text: this.$root.i18n.firstName, value: 'firstName' },
      { text: this.$root.i18n.lastName, value: 'lastName' },
      { text: this.$root.i18n.note, value: 'note' },
      { text: this.$root.i18n.role, value: 'role' },
      { text: this.$root.i18n.status, value: 'status' },
      { text: this.$root.i18n.actions },
    ],
    sortBy: 'email',
    sortDesc: false,
    itemsPerPage: 10,
    dialog: false,
    deleteUserDialog: false,
    deleteUserEmail: '',
    deleteUserId: '',
    form: {
      valid: false,
      email: null,
      password: null,
      firstName: null,
      lastName: null,
      note: null,
      csrfToken: null,
    },
    showPassword: false,
    requestId: null,
    rules: {
      required: value => !!value || this.$root.i18n.required,
    },
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
  }},
  created() {
    Vue.filter('formatUserRole', this.formatUserRole);
    Vue.filter('colorUserRole', this.colorUserRole);
    this.loadData()
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    async loadData() {
      this.$root.startLoading();
      this.users = await this.$root.getUsers();
      this.loadLocalSettings();
      this.$root.stopLoading();
    },
    saveLocalSettings() {
      localStorage['settings.users.sortBy'] = this.sortBy;
      localStorage['settings.users.sortDesc'] = this.sortDesc;
      localStorage['settings.users.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.users.sortBy']) {
        this.sortBy = localStorage['settings.users.sortBy'];
        this.sortDesc = localStorage['settings.users.sortDesc'] == "true";
        this.itemsPerPage = parseInt(localStorage['settings.users.itemsPerPage']);
      }
    },
    updateUser(user) {
      for (var i = 0; i < this.users.length; i++) {
        if (this.users[i].id == user.id) {
          this.$set(this.users, i, user);
          break;
        }
      }
    },
    submitAddUser(event) {
      this.addUser(this.form.email, this.form.password, this.form.firstName, this.form.lastName, this.form.note, this.form.csrfToken);
      this.dialog = false;
      this.form.email = null;
      this.form.password = null;
      this.form.firstName = null;
      this.form.lastName = null;
      this.form.note = null;
    },
    async addUser(email, password, firstName, lastName, note, csrfToken) {
      try {
        if (!email) {
          this.$root.showError(this.i18n.emailRequired);
        } else if (!password) {
          this.$root.showError(this.i18n.passwordRequired);
        } else {
          const response = await this.$root.authApi.post('self-service/registration/methods/password?flow=' + requestId, {
            "traits.email": email,
            password: password,
            "traits.firstName": firstName,
            "traits.lastName": lastName,
            "traits.note": note,
            csrf_token: csrfToken,
          });
          this.users.push(response.data);
        }
      } catch (error) {
         this.$root.showError(error);
      }
    },
    showDeleteConfirm(user) {
      this.deleteUserEmail = user.email;
      this.deleteUserId = user.id;
      this.deleteUserDialog = true;
    },
    hideDeleteConfirm() {
      this.deleteUserDialog = false;
    },
    async removeUser(id) {
      const response = await this.$root.papi.delete('users/' + id);
      if (response.status != 200) {
        this.$root.showError(response.statusText);
      } else {
        for (var i = 0; i < this.users.length; i++) {
          if (this.users[i].id == id) {
            this.$delete(this.users, i);
            break;
          }
        }  
      }
      this.hideDeleteConfirm();
      return false;
    },
    formatUserRole(user) {
      var status = this.i18n.admin;
      if (user.status == 1) {
        status = this.i18n.analyst
      }
      return status;
    },
    colorUserRole(user) {
      var color = "primary";
      if (user.status == 1) {
        color = "warning";
      }
      return color;
    }
  }
}});
