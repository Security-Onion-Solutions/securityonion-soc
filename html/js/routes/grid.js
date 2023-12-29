// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const NodeStatusUnknown = "unknown";
const NodeStatusFault = "fault";
const NodeStatusOk = "ok";
const NodeStatusPending = "pending";

routes.push({ path: '/grid', name: 'grid', component: {
  template: '#page-grid',
  data() { return {
    i18n: this.$root.i18n,
    nodes: [],
    gridFilter: '',
    headers: [
      { text: "", value: 'indicators' },
      { text: this.$root.i18n.id, value: 'id' },
      { text: this.$root.i18n.role, value: 'role', align: ' d-none d-md-table-cell' },
      { text: this.$root.i18n.address, value: 'address', align: ' d-none d-lg-table-cell' },
      { text: this.$root.i18n.version, value: 'version', align: ' d-none d-lg-table-cell' },
      { text: this.$root.i18n.model, value: 'model', align: ' d-none d-lg-table-cell' },
      { text: this.$root.i18n.eps, value: 'consumptionEps', align: ' d-none d-lg-table-cell' },
      { text: this.$root.i18n.memUsageAbbr, value: 'memUsedPct', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.diskUsageRootAbbr, value: 'diskUsedRootPct', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.diskUsageNsmAbbr, value: 'diskUsedNsmPct', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.cpuUsageAbbr, value: 'cpuUsedPct', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.trafficManInAbbr, value: 'trafficManInMbs', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.trafficManOutAbbr, value: 'trafficManOutMbs', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.trafficMonInAbbr, value: 'trafficMonInMbs', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.trafficMonInDropsAbbr, value: 'trafficMonInDropsMbs', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.captureLossAbbr, value: 'captureLossPct', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.zeekLossAbbr, value: 'zeekLossPct', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.suricataLossAbbr, value: 'suriLossPct', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.stenoLossAbbr, value: 'stenoLossPct', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.pcapRetentionAbbr, value: 'pcapDays', align: ' d-none d-xl-table-cell' },
      { text: this.$root.i18n.dateUpdated, value: 'updateTime', align: ' d-none d-lg-table-cell' },
      { text: this.$root.i18n.uptime, value: 'uptimeSeconds', align: ' d-none d-lg-table-cell' },
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
    selectedId: null,
    selectedNode: null,
    gridMemberTestConfirmDialog: false,
    gridMemberRestartConfirmDialog: false,
    gridMemberUploadConfirmDialog: false,
    uploadForm: { valid: true, attachment: null },
    maxUploadSizeBytes: 25 * 1024 * 1024,
    staleMetricsMs: 120000,
    rules: {
      fileSizeLimit: value => (value == null || value.size < this.maxUploadSizeBytes) || this.$root.i18n.fileTooLarge.replace("{maxUploadSizeBytes}", this.$root.formatCount(this.maxUploadSizeBytes)),
      fileNotEmpty: value => (value == null || value.size > 0) || this.$root.i18n.fileEmpty,
      fileRequired: value => (value != null) || this.$root.i18n.required,
    },
    attachment: null,
    zone: '',
    moreColumns: false,
  }},
  created() {
    Vue.filter('colorNodeStatus', this.colorNodeStatus);
    Vue.filter('iconNodeStatus', this.iconNodeStatus);
    Vue.filter('toTZ', this.toTZ);
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
    'moreColumns': 'saveLocalSettings',
  },
  methods: {
    initGrid(params) {
      if (params.maxUploadSize) {
        this.maxUploadSizeBytes = params.maxUploadSize;
      }
      if (params.staleMetricsMs) {
        this.staleMetricsMs = params.staleMetricsMs;
      }

      this.zone = moment.tz.guess();

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
    updateColumnClass(text, wide, size) {
      const column = this.headers.find(function(item) {
        return item.text == text
      });
      if (column) {
        if (!wide) {
          column.align = ' d-none';
        } else {
          column.align = ' d-none ' + size;
        }
      }
    },
    areMetricsCurrent(node) {
      const lastUpdated = Date.parse(node["updateTime"]);
      const now = Date.now();
      const age = now - lastUpdated;
      return age < this.staleMetricsMs;
    },
    updateMetricsEnabled() {
      this.metricsEnabled = !this.nodes.every(function(node) { return !node.metricsEnabled; });

      this.updateColumnClass(this.i18n.eps, this.metricsEnabled, 'd-lg-table-cell');
      this.updateColumnClass(this.i18n.memUsageAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.diskUsageRootAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.diskUsageNsmAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.cpuUsageAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.trafficManInAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.trafficManOutAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.trafficMonInAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.trafficMonInDropsAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.captureLossAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.zeekLossAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.suricataLossAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.stenoLossAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.updateColumnClass(this.i18n.pcapRetentionAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
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
      localStorage['settings.grid.moreColumns'] = this.moreColumns;
      localStorage['settings.grid.sortBy'] = this.sortBy;
      localStorage['settings.grid.sortDesc'] = this.sortDesc;
      localStorage['settings.grid.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['timezone']) this.zone = localStorage['timezone'];
      if (localStorage['settings.grid.moreColumns']) this.moreColumns = localStorage['settings.grid.moreColumns'] == "true";

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
    showTestConfirm(id) {
      this.selectedId = id;
      this.gridMemberTestConfirmDialog = true;
    },
    hideTestConfirm() {
      this.gridMemberTestConfirmDialog = false;
      const tmpId = this.selectedId;
      this.selectedId = null;
      return tmpId;
    },
    canTest(node) {
      if (node['keywords'] && node['keywords'].indexOf("Sensor") != -1) {
          return true;
      }
      return false;
    },
    canUpload(node) {
      return this.canUploadPCAP(node) || this.canUploadEvtx(node);
    },
    canUploadPCAP(node) {
      return !!node['keywords'] && (node['keywords'].indexOf("Sensor") != -1 || node['keywords'].indexOf("Import") != -1);
    },
    canUploadEvtx(node) {
      return !!node['keywords'] && node['keywords'].indexOf("Manager") != -1;
    },
    async gridMemberTest() {
      const nodeId = this.hideTestConfirm().replace('_so-', '_');
      this.$root.startLoading();
      try {
        await this.$root.papi.post('gridmembers/' + nodeId + "/test");
        this.$root.showTip(this.i18n.gridMemberTestSuccess);
      } catch (error) {
          this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    showUploadConfirm(node) {
      this.selectedNode = node;
      this.uploadForm = { valid: true, attachment: null };
      this.gridMemberUploadConfirmDialog = true;
      if (this.$refs && this.$refs.gridUpload) {
        this.$refs.gridUpload.reset();
      }
    },
    pickUploadDialogTitle() {
      if (!this.selectedNode) {
        return '';
      }

      // One or both of these should always be true. If neither are true, we
      // shouldn't be showing the upload dialog.
      const pcap = this.canUploadPCAP(this.selectedNode);
      const evtx = this.canUploadEvtx(this.selectedNode);

      if (pcap && evtx) {
        return this.i18n.gridMemberUploadTitleBoth;
      } else if (pcap) {
        return this.i18n.gridMemberUploadTitlePcap;
      } else {
        return this.i18n.gridMemberUploadTitleEvtx;
      }
    },
    pickUploadDialogAccept() {
      if (!this.selectedNode) {
        // in case of bug, don't hinder user
        return '*.*';
      }

      let accept = [];

      if (this.canUploadPCAP(this.selectedNode)) {
        accept.push('.pcap');
      }

      if (this.canUploadEvtx(this.selectedNode)) {
        accept.push('.evtx');
      }

      return accept.join(',');
    },
    hideUploadConfirm() {
      this.gridMemberUploadConfirmDialog = false;
      this.selectedNode = null;
    },
    async gridMemberUpload() {
      const data = new FormData();
      data.append("attachment", this.uploadForm.attachment);
      headers = { 'Content-Type': 'multipart/form-data; boundary=' + data._boundary }
      config = { 'headers': headers };

      let nodeName = this.selectedNode.id + '_' + this.selectedNode.role.replace('so-', '');

      try {
        await this.$root.papi.post(`gridmembers/${nodeName}/import`, data, config);
        this.$root.showTip(this.i18n.gridMemberUploadSuccess);
      } catch (error) {
        if (error.response.status === 409) {
          this.$root.showError(this.i18n.gridMemberUploadConflict);
        } else {
          this.$root.showError(this.i18n.gridMemberUploadFailure);
        }
      }

      this.hideUploadConfirm();
    },
    showRestartConfirm(id) {
      this.selectedId = id;
      this.gridMemberRestartConfirmDialog = true;
    },
    hideRestartConfirm() {
      this.gridMemberRestartConfirmDialog = false;
      const tmpId = this.selectedId;
      this.selectedId = null;
      return tmpId;
    },
    async gridMemberRestart() {
      const nodeId = this.hideRestartConfirm().replace('_so-', '_');
      this.$root.startLoading();
      try {
        await this.$root.papi.post('gridmembers/' + nodeId + "/restart");
        this.$root.showTip(this.i18n.gridMemberRestartSuccess);
      } catch (error) {
          this.$root.showError(error);
      }
      this.$root.stopLoading();
    },
    hasQueuestore(item) {
      return item && item.containers && item.containers.find(function(x) {
        return x.Name == 'so-redis';
      }) != null;
    },
    hasEventstore(item) {
      return item && item.containers && item.containers.find(function(x) {
        return x.Name == 'so-elasticsearch';
      }) != null;
    },
    hasMetricstore(item) {
      return item && item.containers && item.containers.find(function(x) {
        return x.Name == 'so-influxdb';
      }) != null;
    },
    formatNode(node) {
      node['keywords'] = this.$root.localizeMessage(node["role"] + '-keywords');
      node['dashboardLink'] = this.$root.getMetricsUrl() + "?vars%5BRole%5D=" + node.role.substring(3) + "&vars%5BHost%5D=" + node.id;
      if (node.processJson) {
        const details = JSON.parse(node.processJson);
        if (details) {
          node.statusCode = details.status_code;
          if (details.containers) {
            node.containers = details.containers.sort((a, b) => {
              return a.Name > b.Name ? 1 : -1
            });
          } else {
            node.containers = [];
          }
        }
      }
      return node;
    },
    colorNodeStatus(status, nonCritical) {
      var color = "warning";
      switch (status) {
        case NodeStatusFault: color = nonCritical ? "warning" : "error"; break;
        case NodeStatusOk: color = "success"; break;
        case NodeStatusPending: color = "warning"; break;
      }
      return color;
    },
    iconNodeStatus(status) {
      var icon = "fa-circle-question";
      switch (status) {
        case NodeStatusFault: icon = "fa-triangle-exclamation"; break;
        case NodeStatusOk: icon = "fa-circle-check"; break;
        case NodeStatusPending: icon = "fa-circle-exclamation"; break;
      }
      return icon;
    },
    colorContainerStatus(status) {
      return status == "running" ? "success" : "error";
    },
    formatLinearColor(val, caution, warn, crit) {
      if (val >= crit) {
        return "error";
      } else if (val >= warn) {
        return "warning";
      } else if (val >= caution) {
        return "info";
      }
      return "success";
    },
    saveTimezone() {
      localStorage['timezone'] = this.zone;
    },
    toTZ(data) {
      // expecting date in format YYYY-MM-DDTHH:mm:ss.SSSSSSSSS-HH:mm
      const zoned = moment.utc(data, 'YYYY-MM-DDTHH:mm:ss.SSSSSSSSSZ').tz(this.zone);
      return zoned.format(this.i18n.timestampFormat);
    }
  }
}});
