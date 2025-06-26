// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const NOTE_TRUNCATE_LEN = 50;

loadPageTemplate('page-clients', 'pages/clients.html');

routes.push({ path: '/clients', name: 'clients', component: {
  template: '#page-clients',
  data() { return {
    i18n: this.$root.i18n,
    clients: [],
    headers: [
      { value: 'expand' },
      { title: this.$root.i18n.id, value: 'id' },
      { title: this.$root.i18n.name, value: 'name' },
      { title: this.$root.i18n.note, value: 'note', align: ' d-none d-lg-table-cell' },
    ],
    sortBy: [{ key: 'id', order: 'asc' }],
    itemsPerPage: 10,
    dialog: false,
    deleteClientDialog: false,
    form: {
      valid: false,
      id: null,
      name: null,
      note: null,
      searchUsername: null,
    },
    rules: {
      required: value => !!value || this.$root.i18n.required,
      name: value => !value || value.length < 50 || this.$root.i18n.ruleMaxLen,
      note: value => !value || value.length < 100 || this.$root.i18n.ruleMaxLen,
      searchUsername: value => !value || value.length < 50 || this.$root.i18n.ruleMaxLen,
    },
    itemsPerPageOptions: [10,50,250,1000],
    expanded: [],
    perms: [],
    new_client_credentials: null,
    showCredentialsDialog: false,
  }},
  created() {
    this.loadData()
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    async loadData() {
      this.$root.startLoading();
      this.clients = await this.getClients();
      const response = await this.$root.papi.get('roles/permissions');
      this.perms = response.data;
      this.loadLocalSettings();
      this.$root.stopLoading();
    },
    saveLocalSettings() {
      localStorage['settings.clients.sortBy'] = this.sortBy[0].key;
      localStorage['settings.clients.sortDesc'] = this.sortDesc[0].order;
      localStorage['settings.clients.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.clients.sortBy']) {
        this.sortBy[0].key = localStorage['settings.clients.sortBy'];
        this.sortBy[0].order = localStorage['settings.clients.sortDesc'];
        this.itemsPerPage = parseInt(localStorage['settings.clients.itemsPerPage']);
      }
    },
    updateClient(client) {
      for (var i = 0; i < this.clients.length; i++) {
        if (this.clients[i].id == client.id) {
          this.clients[i] = client;
          break;
        }
      }
    },
    updateForm(client) {
      this.form.id = client.id;
      this.form.name = client.name;
      this.form.note = client.note;
      this.form.searchUsername = client.searchUsername;
    },
    hideAdd() {
      this.dialog = false;
    },
    showAdd() {
      this.expanded = [];
      this.form.name = null;
      this.form.note = null;
      this.form.searchUsername = null;
      this.dialog = true;
    },
    showDeleteConfirm() {
      this.deleteClientDialog = true;
    },
    hideDeleteConfirm() {
      this.deleteClientDialog = false;
    },
    async getClients() {
      try {
        const response = await this.$root.papi.get('clients/');
        this.clients = response.data;
      } catch (error) {
        if (error.response && error.response.status == 400) {
          this.$root.showError(this.i18n.clientCheckHydraEnabled);
        } else {
          this.$root.showError(error);
        }
      }
      return this.clients;
    },
    async add() {
      if (!this.form.name) {
        this.$root.showError(this.i18n.clientNameRequired);
      } else {
        this.$root.startLoading();
        try {
          const response = await this.$root.papi.post('clients/', {
            "name": this.form.name,
            "note": this.form.note,
          });
          this.new_client_credentials = response.data;
          this.showCredentialsDialog = true
          this.clients = await this.getClients();
          this.$root.showTip(this.i18n.clientAdded);
          this.hideAdd();
        } catch (error) {
           this.$root.showError(error);
        }
      }
      this.$root.stopLoading();
    },
    async update(client) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.put('clients/' + client.id, {
          "name": this.form.name,
          "note": this.form.note,
          "searchUsername": this.form.searchUsername,
        });

        this.clients = await this.getClients();
        this.$root.showTip(this.i18n.clientUpdated);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    hasPermission(item, resource, privilege) {
      return item != null && item.permissions != null && item.permissions.indexOf(resource + '/' + privilege) != -1;
    },
    togglePermission(item, resource, privilege) {
      if (this.hasPermission(item, resource, privilege)) {
        this.removePermission(item, resource, privilege);
      } else {
        this.addPermission(item, resource, privilege);
      }
    },
    async addPermission(client, resource, privilege) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.post('clients/' + client.id + '/permission/' + resource + '/' + privilege);
        this.clients = await this.getClients();
        this.$root.showTip(this.i18n.clientPermissionAdded);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async removePermission(client, resource, privilege) {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.delete('clients/' + client.id + "/permission/" + resource + '/' + privilege);
        this.clients = await this.getClients();
        this.$root.showTip(this.i18n.clientPermissionDeleted);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async generateSecret(client) {
      this.$root.startLoading();
      try {
          const response = await this.$root.papi.put('clients/' + client.id + '/secret');
          this.new_client_credentials = response.data;
          this.showCredentialsDialog = true
          this.$root.showTip(this.i18n.clientSecretGenerated);
      } catch (error) {
          this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    async removeClient(id) {
      this.hideDeleteConfirm();
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.delete('clients/' + id);
        for (var i = 0; i < this.clients.length; i++) {
          if (this.clients[i].id == id) {
            this.clients.splice(i, 1);
            break;
          }
        }
        this.$root.showTip(this.i18n.clientDeleted);
      } catch (error) {
         this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    countClients() {
      return this.clients.length;
    },
    dismissCredentials() {
      this.showCredentialsDialog = false;
    },
    truncateNote(note) {
      if (note.length > NOTE_TRUNCATE_LEN) {
        return note.substring(0, NOTE_TRUNCATE_LEN) + "...";
      }
      return note
    },
  }
}});
