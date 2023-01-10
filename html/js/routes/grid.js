// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2023 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

const NodeStatusUnknown = "unknown";
const NodeStatusFault = "fault";
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
      { text: this.$root.i18n.model, value: 'model' },
      { text: this.$root.i18n.eps, value: 'productionEps' },
      { text: this.$root.i18n.dateUpdated, value: 'updateTime' },
      { text: this.$root.i18n.dateDataEpoch, value: 'epochTime' },
      { text: this.$root.i18n.uptime, value: 'uptimeSeconds' },
      { text: this.$root.i18n.status, value: 'status' },
      { text: '', value: 'keywords', align: ' d-none' },
    ],
    expanded: [],
    sortBy: 'id',
    sortDesc: false,
    itemsPerPage: 10,
    footerProps: { 'items-per-page-options': [10,25,50,100,250,1000] },
    gridEps: 0,
    metricsEnabled: false,
  }},
  created() { 
    Vue.filter('colorNodeStatus', this.colorNodeStatus);    
  },
  beforeDestroy() {
  },  
  destroyed() {
    this.$root.unsubscribe("node", this.updateNode);
    this.$root.unsubscribe("status", this.updateStatus);
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
      var route = this;
      try {
        const response = await this.$root.papi.get('grid');
        this.nodes = response.data;
        this.nodes.forEach(function(node) {
          route.updateNode(node);
        });
        this.updateMetricsEnabled();
        this.loadLocalSettings();
      } catch (error) {
        this.$root.showError(error);
      }
      this.$root.stopLoading();
      this.$root.subscribe("node", this.updateNode);
      this.$root.subscribe("status", this.updateStatus);
    },
    updateMetricsEnabled() {
      this.metricsEnabled = !this.nodes.every(function(node) { return !node.metricsEnabled; });

      const route = this;
      const epsColumn = this.headers.find(function(item) { 
        return item.text == route.i18n.eps 
      });
      if (epsColumn) {
        if (!this.metricsEnabled) {
          epsColumn.align = ' d-none';
        } else {
          epsColumn.align = '';
        }
      }
    },
    expand(item) {
      if (this.isExpanded(item)) {
        this.expanded = [];
      } else {
        this.expanded = [item];
      }
    },
    isExpanded(item) {
      return (this.expanded.length > 0 && this.expanded[0] == item);
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
      this.updateNodeDetails(node);
      this.updateMetricsEnabled()
    },
    updateNodeDetails(node) {
      var found = false;
      for (var i = 0; i < this.nodes.length; i++) {
        if (this.nodes[i].id == node.id) {
          const exp = this.isExpanded(this.nodes[i]);
          this.$set(this.nodes, i, this.formatNode(node));
          if (exp) {
            this.expand(this.nodes[i]);
          }
          found = true;
          break;
        }
      }
      if (!found) {
        this.nodes.push(this.formatNode(node));
      }
    },
    updateStatus(status) {
      this.gridEps = status.grid.eps;
    },
    formatNode(node) {
      node['keywords'] = this.$root.localizeMessage(node["role"] + '-keywords');
      return node;
    },
    colorNodeStatus(status) {
      var color = "gray";
      switch (status) {
        case NodeStatusFault: color = "error"; break;
        case NodeStatusOk: color = "success"; break;
      }
      return color;
    }
  }
}});
