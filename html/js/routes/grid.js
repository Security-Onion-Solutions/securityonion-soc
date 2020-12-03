// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

routes.push({ path: '/grid', name: 'grid', component: {
  template: '#page-grid',
  data() { return {
    i18n: this.$root.i18n,
    nodes: [],
    headers: [
      { text: this.$root.i18n.id, value: 'id' },
      { text: this.$root.i18n.role, value: 'role' },
      { text: this.$root.i18n.address, value: 'address' },
      { text: this.$root.i18n.description, value: 'description' },
      { text: this.$root.i18n.version, value: 'version' },
      { text: this.$root.i18n.dateOnline, value: 'onlineTime' },
      { text: this.$root.i18n.dateUpdated, value: 'updateTime' },
      { text: this.$root.i18n.dateDataEpoch, value: 'epochTime' },
      { text: this.$root.i18n.uptime, value: 'uptimeSeconds' },
    ],
    sortBy: 'id',
    sortDesc: false,
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
  }},
  created() { 
    this.loadData() 
  },
  destroyed() {
    this.$root.unsubscribe("node", this.updateNode);
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
      try {
        const response = await this.$root.papi.get('grid');
        this.nodes = response.data;
        this.loadLocalSettings();
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
      this.$root.subscribe("node", this.updateNode);
    },
    saveLocalSettings() {
      localStorage['settings.grid.sortBy'] = this.sortBy;
      localStorage['settings.grid.sortDesc'] = this.sortDesc;
      localStorage['settings.grid.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['settings.grid.sortBy']) {
        this.sortBy = localStorage['settings.grid.sortBy'];
        this.sortDesc = localStorage['settings.grid.sortDesc'] == "true";
        this.itemsPerPage = parseInt(localStorage['settings.grid.itemsPerPage']);
      }
    },
    updateNode(node) {
      for (var i = 0; i < this.nodes.length; i++) {
        if (this.nodes[i].id == node.id) {
          this.$set(this.nodes, i, node);
          break;
        }
      }
    }
  }
}});
