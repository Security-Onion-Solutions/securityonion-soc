// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
const NodeStatusUnknown = "unknown";
const NodeStatusOffline = "offline";
const NodeStatusError = "error";
const NodeStatusOk = "ok";

routes.push({ path: '/grid', name: 'grid', component: {
  template: '#page-grid',
  data() { return {
    i18n: this.$root.i18n,
    nodes: [],
    gridFilter: '',
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
      { text: this.$root.i18n.status, value: 'status' },
      { text: '', value: 'keywords', align: ' d-none' },
    ],
    sortBy: 'id',
    sortDesc: false,
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,50,250,1000] },
  }},
  created() { 
    Vue.filter('colorNodeStatus', this.colorNodeStatus);    
  },
  beforeDestroy() {
  },  
  destroyed() {
    this.$root.unsubscribe("node", this.updateNode);
  },
  mounted() {
    this.$root.loadParameters("grid", this.initGrid);
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'sortDesc': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
  },
  methods: {
    initGrid(params) {
      this.loadData();
    },
    async loadData() {
      this.$root.startLoading();
      try {
        const response = await this.$root.papi.get('grid');
        this.nodes = this.formatNode(response.data);
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
          this.$set(this.nodes, i, this.formatNode(node));
          break;
        }
      }
    },
    formatNode(node) {
      node['keywords'] = this.$root.localizeMessage(node["role"] + '-keywords');
      return node;
    },
    colorNodeStatus(status) {
      var color = "gray";
      switch (status) {
        case NodeStatusOffline: color = "warning"; break;
        case NodeStatusError: color = "error"; break;
        case NodeStatusOk: color = "success"; break;
      }
      return color;
    }
  }
}});
