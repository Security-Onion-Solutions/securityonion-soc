// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

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
    ],
    sortBy: 'email',
    sortDesc: false,
    itemsPerPage: 10,
    dialog: false,
    deleteUserDialog: false,
    form: {
      valid: false,
      id: null,
      email: null,
      password: null,
      firstName: null,
      lastName: null,
      note: null,
      role: null,
    },
    showPassword: false,
    rules: {
      required: value => !!value || this.$root.i18n.required,
    },
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
    expanded: [],
    roles: [],
  }},
  created() {
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
      const response = await this.$root.papi.get('roles/');
      if (response.data) {
        response.data.forEach((role) => {
          if (role != "agent") { // Agent is intended only for services, not humans
            this.roles.push(role);
          }
        });
      }
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
    expand(user) {
      if (this.isExpanded(user)) {
        this.expanded = [];
      } else {
        this.form.id = user.id;
        this.form.email = user.email;
        this.form.password = null;
        this.form.firstName = user.firstName;
        this.form.lastName = user.lastName;
        this.form.note = user.note;
        this.expanded = [user];
      }
    },
    isExpanded(user) {
      return this.expanded.length > 0 && this.expanded[0] == user;
    },
    hideAdd() {
      this.dialog = false;
    },
    showAdd() {
      this.expanded = [];
      this.form.email = null;
      this.form.password = null;
      this.form.role = null;
      this.form.firstName = null;
      this.form.lastName = null;
      this.form.note = null;
      this.dialog = true;
    },
    showDeleteConfirm(user) {
      this.deleteUserDialog = true;
    },
    hideDeleteConfirm() {
      this.deleteUserDialog = false;
    },
    async add() {
      if (!this.form.email) {
        this.$root.showError(this.i18n.emailRequired);
      } else if (!this.form.password) {
        this.$root.showError(this.i18n.passwordRequired);
      } else {
        this.$root.startLoading();
        try {
          const response = await this.$root.papi.post('users/', {
            "email": this.form.email,
            "password": this.form.password,
            "roles": [this.form.role],
            "firstName": this.form.firstName,
            "lastName": this.form.lastName,
            "note": this.form.note,
          });

          this.users = await this.$root.getUsers();
          this.$root.showTip(this.i18n.userAdded);
          this.hideAdd();
        } catch (error) {
           this.$root.showError(error);
        }
      }
      this.$root.stopLoading();
    },
    async updateProfile(user) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.put('users/' + user.id, {
          "firstName": this.form.firstName,
          "lastName": this.form.lastName,
          "note": this.form.note,
        });

        this.users = await this.$root.getUsers();
        this.$root.showTip(this.i18n.userProfileUpdated);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    hasRole(item, role) {
      return item != null && item.roles != null && item.roles.indexOf(role) != -1;
    },
    toggleRole(item, role) {
      if (this.hasRole(item, role)) {
        this.removeRole(item, role);
      } else {
        this.addRole(item, role);
      }
    },
    async addRole(user, role) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.post('users/' + user.id + '/role/' + role);
        this.users = await this.$root.getUsers();
        this.$root.showTip(this.i18n.userRoleAdded);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async removeRole(user, role) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.delete('users/' + user.id + "/role/" + role);
        this.users = await this.$root.getUsers();
        this.$root.showTip(this.i18n.userRoleDeleted);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async updatePassword(user) {
      if (!this.form.password) {
        this.$root.showError(this.i18n.passwordRequired);
      } else {
        this.$root.startLoading();
        try {
          const response = await this.$root.papi.put('users/' + user.id + '/password', {
            "password": this.form.password,
          });

          this.$root.showTip(this.i18n.userPasswordChanged);
        } catch (error) {
           this.$root.showError(error);
        }
      }
      this.$root.stopLoading();
    },
    async removeUser(id) {
      this.hideDeleteConfirm();
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.delete('users/' + id);
        for (var i = 0; i < this.users.length; i++) {
          if (this.users[i].id == id) {
            this.$delete(this.users, i);
            break;
          }
        }  
        this.$root.showTip(this.i18n.userDeleted);
      } catch (error) {
         this.$root.showError(error);
      }      
      this.$root.stopLoading();
    },
    async toggleStatus(user) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.put('users/' + user.id + '/' + (user.status == 'locked' ? 'enable' : 'disable'));
        this.users = await this.$root.getUsers()
        this.$root.showTip(user.status == 'locked' ? this.i18n.userEnabled : this.i18n.userDisabled);
        this.hideDeleteConfirm();
      } catch (error) {
         this.$root.showError(error);
      }      
      this.$root.stopLoading();
    },
    async sync() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.put('users/sync');
        this.users = await this.$root.getUsers()
        this.$root.showTip(this.i18n.usersSynchronized);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    countUsersEnabled() {
      return this.users.filter((user) => user.status != 'locked' ).length;
    },
    countUsers() {
      return this.users.length;
    },
  }
}});
