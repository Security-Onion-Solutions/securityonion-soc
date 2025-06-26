// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('page-grid', 'pages/grid.html');

const NodeStatusUnknown = "unknown";
const NodeStatusFault = "fault";
const NodeStatusOk = "ok";
const NodeStatusPending = "pending";
const NodeStatusRestart = "restart";
const UNREALISTIC_AGE = 1700000000; // About 54 years
const STALENESS_CHECK_INTERVAL_MS = 30000

routes.push({ path: '/grid', name: 'grid', component: {
  template: '#page-grid',
  data() { return {
    i18n: this.$root.i18n,
    moment: moment,
    nodes: [],
    gridFilter: '',
    headers: [
      { title: "", value: 'expand' },
      { title: "", value: 'indicators' },
      { title: this.$root.i18n.gridId, value: 'gridId', align: '' },
      { title: this.$root.i18n.id, value: 'id' },
      { title: this.$root.i18n.role, value: 'role', align: ' d-none d-md-table-cell' },
      { title: this.$root.i18n.address, value: 'address', align: ' d-none d-lg-table-cell' },
      { title: this.$root.i18n.version, value: 'version', align: ' d-none d-lg-table-cell' },
      { title: this.$root.i18n.model, value: 'model', align: ' d-none d-lg-table-cell' },
      { title: this.$root.i18n.eps, value: 'consumptionEps', align: ' d-none d-lg-table-cell', metricsEnabled: true },
      { title: this.$root.i18n.memUsageAbbr, value: 'memoryUsedPct', align: ' d-none d-xl-table-cell', metricsEnabled: true },
      { title: this.$root.i18n.diskUsageRootAbbr, value: 'diskUsedRootPct', align: ' d-none d-xl-table-cell', metricsEnabled: true },
      { title: this.$root.i18n.diskUsageNsmAbbr, value: 'diskUsedNsmPct', align: ' d-none d-xl-table-cell', metricsEnabled: true },
      { title: this.$root.i18n.cpuUsageAbbr, value: 'cpuUsedPct', align: ' d-none d-xl-table-cell', metricsEnabled: true },
      { title: this.$root.i18n.trafficManInAbbr, value: 'trafficManInMbs', align: ' d-none d-xl-table-cell', metricsEnabled: true },
      { title: this.$root.i18n.trafficManOutAbbr, value: 'trafficManOutMbs', align: ' d-none d-xl-table-cell', metricsEnabled: true },
      { title: this.$root.i18n.trafficMonInAbbr, value: 'trafficMonInMbs', align: ' d-none d-xl-table-cell', moreColumns: true, metricsEnabled: true },
      { title: this.$root.i18n.trafficMonInDropsAbbr, value: 'trafficMonInDropsMbs', align: ' d-none d-xl-table-cell', moreColumns: true, metricsEnabled: true },
      { title: this.$root.i18n.captureLossAbbr, value: 'captureLossPct', align: ' d-none d-xl-table-cell', moreColumns: true, metricsEnabled: true },
      { title: this.$root.i18n.zeekLossAbbr, value: 'zeekLossPct', align: ' d-none d-xl-table-cell', moreColumns: true, metricsEnabled: true },
      { title: this.$root.i18n.suricataLossAbbr, value: 'suriLossPct', align: ' d-none d-xl-table-cell', moreColumns: true, metricsEnabled: true },
      { title: this.$root.i18n.stenoLossAbbr, value: 'stenoLossPct', align: ' d-none d-xl-table-cell', moreColumns: true, metricsEnabled: true },
      { title: this.$root.i18n.pcapRetentionAbbr, value: 'pcapDays', align: ' d-none d-xl-table-cell', moreColumns: true, metricsEnabled: true },
      { title: this.$root.i18n.uptime, value: 'uptimeSeconds', align: ' d-none d-lg-table-cell' },
      { title: this.$root.i18n.status, value: 'status' },
      { title: '', value: 'keywords', align: ' d-none' },
    ],
    expanded: [],
    sortBy: [{ key: 'id', order: 'asc' }],
    itemsPerPage: 10,
    itemsPerPageOptions: [10,25,50,100,250,1000],
    gridEps: 0,
    metricsEnabled: false,
    selectedNode: null,
    gridMemberTestConfirmDialog: false,
    gridMemberRestartConfirmDialog: false,
    gridMemberUploadConfirmDialog: false,
    uploadForm: { valid: true, attachment: null },
    maxUploadSizeBytes: 25 * 1024 * 1024,
    staleMetricsMs: 120000,
    rules: {
      fileSizeLimit: value => (value == null || value.length == 0 || value[0].size < this.maxUploadSizeBytes) || this.$root.i18n.fileTooLarge.replace("{maxUploadSizeBytes}", this.$root.formatCount(this.maxUploadSizeBytes)),
      fileNotEmpty: value => (value == null || value.length == 0 || value[0].size > 0) || this.$root.i18n.fileEmpty,
      fileRequired: value => (value != null && value.length != 0) || this.$root.i18n.required,
    },
    attachment: null,
    zone: '',
    moreColumns: false,
    NodeStatusUnknown: NodeStatusUnknown,
    NodeStatusFault: NodeStatusFault,
    NodeStatusOk: NodeStatusOk,
    NodeStatusPending: NodeStatusPending,
    NodeStatusRestart: NodeStatusRestart,
    UNREALISTIC_AGE: UNREALISTIC_AGE,
    stalenessInterval: null,
  }},
  created() {
  },
  unmounted() {
    this.$root.unsubscribe("node", this.updateNode);
    this.$root.unsubscribe("status", this.updateStatus);
    clearInterval(this.stalenessInterval);
  },
  mounted() {
    this.$root.loadParameters("grid", this.initGrid);
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
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
      this.stalenessInterval = setInterval(this.checkStaleness, STALENESS_CHECK_INTERVAL_MS);
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
    generateContainerLink(node, container) {
      const link = {};
      link.name = 'hunt';
      link.query = {};
      link.query.q = `tags:"${container.Name}" | groupby log.level | groupby event.action`;
      link.query.t = moment().subtract(1, 'hours').format(this.i18n.timePickerFormat) + ' - ' + moment().format(this.i18n.timePickerFormat);
      link.query.socExcludeToggle = false;
      if (node.gridId) {
        link.query.gridId = node.gridId;
      }
      return link;
    },
    checkStaleness() {
      this.$forceUpdate();
    },
    areMetricsCurrent(node) {
      const lastUpdated = Date.parse(node["updateTime"]);
      const now = Date.now();
      const age = now - lastUpdated;
      return age < this.staleMetricsMs;
    },
    updateMetricsEnabled() {
      this.$root.adjustSubgridColVisibility(this.headers);
      this.metricsEnabled = !this.nodes.every(function(node) { return !node.metricsEnabled; });

      this.$root.updateColumnClass(this.headers, this.i18n.eps, this.metricsEnabled, 'd-lg-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.memUsageAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.diskUsageRootAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.diskUsageNsmAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.cpuUsageAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.trafficManInAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.trafficManOutAbbr, this.metricsEnabled, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.trafficMonInAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.trafficMonInDropsAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.captureLossAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.zeekLossAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.suricataLossAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.stenoLossAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
      this.$root.updateColumnClass(this.headers, this.i18n.pcapRetentionAbbr, this.metricsEnabled && this.moreColumns, 'd-xl-table-cell');
    },
    showHeader(header) {
      let show = true;
      if (header.moreColumns) {
        show = show && this.moreColumns;
      }
      if (header.metricsEnabled) {
        show = show && this.metricsEnabled;
      }

      return show;
    },
    saveLocalSettings() {
      localStorage['settings.grid.moreColumns'] = this.moreColumns;
      localStorage['settings.grid.sortBy'] = this.sortBy[0].key;
      localStorage['settings.grid.sortDesc'] = this.sortBy[0].order;
      localStorage['settings.grid.itemsPerPage'] = this.itemsPerPage;
    },
    loadLocalSettings() {
      if (localStorage['timezone']) this.zone = localStorage['timezone'];
      if (localStorage['settings.grid.moreColumns']) this.moreColumns = localStorage['settings.grid.moreColumns'] == "true";

      if (localStorage['settings.grid.sortBy']) {
        this.sortBy[0].key = localStorage['settings.grid.sortBy'];
        this.sortBy[0].order = localStorage['settings.grid.sortDesc'];
        this.itemsPerPage = parseInt(localStorage['settings.grid.itemsPerPage']);
      }
    },
    updateNode(node) {
      if (node.gridId == this.$root.selectedGridId) {
        this.updateNodeDetails(node);
        this.updateMetricsEnabled()
      }
    },
    updateNodeDetails(node) {
      var found = false;
      for (var i = 0; i < this.nodes.length; i++) {
        if (this.nodes[i].id == node.id && this.nodes[i].gridId == node.gridId) {
          const exp = this.isExpanded(this.nodes[i]);
          this.nodes[i] = this.formatNode(node);
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
    isExpanded(node) {
      return this.expanded.includes(node.id);
    },
    expand(node) {
      if (!this.isExpanded(node)) {
        this.expanded.push(node.id);
      }
    },
    updateStatus(status) {
      if (status.gridId == this.$root.selectedGridId) {
        this.gridEps = status.grid.eps;
      }
    },
    showTestConfirm(node) {
      this.selectedNode = node;
      this.gridMemberTestConfirmDialog = true;
    },
    hideTestConfirm() {
      this.gridMemberTestConfirmDialog = false;
      this.selectedNode = null;
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
      return !!node['keywords'] && // If keywords don't exist, return false
        (node['keywords'].indexOf("Sensor") != -1 || node['keywords'].indexOf("Import") != -1) &&
        node.role != 'so-heavynode'; // Heavy nodes do not support importing pcap
    },
    canUploadEvtx(node) {
      return !!node['keywords'] && node['keywords'].indexOf("Manager") != -1;
    },
    getNodeName(node) {
      return node.id + '_' + node.role.replace('so-', '');
    },
    async gridMemberTest() {
      const nodeId = this.getNodeName(this.selectedNode);
      this.$root.startLoading();
      try {
        await this.$root.papi.post('gridmembers/' + nodeId + "/test", null, {params: {gridId: this.selectedNode.gridId}});
        this.$root.showTip(this.i18n.gridMemberTestSuccess);
      } catch (error) {
          this.$root.showError(error);
      }
      this.$root.stopLoading();
      this.hideTestConfirm()
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
      config = { headers: headers, params: {gridId: this.selectedNode.gridId} };

      let nodeName = this.getNodeName(this.selectedNode);

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
    showRestartConfirm(node) {
      this.selectedNode = node;
      this.gridMemberRestartConfirmDialog = true;
    },
    hideRestartConfirm() {
      this.gridMemberRestartConfirmDialog = false;
      this.selectedNode = null;
    },
    async gridMemberRestart() {
      const nodeId = this.getNodeName(this.selectedNode);
      this.$root.startLoading();
      try {
        await this.$root.papi.post('gridmembers/' + nodeId + "/restart", null, {params: {gridId: this.selectedNode.gridId}});
        this.$root.showTip(this.i18n.gridMemberRestartSuccess);
      } catch (error) {
          this.$root.showError(error);
      }
      this.$root.stopLoading();
      this.hideRestartConfirm();
    },
    hasContainer(item, container) {
      return item && item.containers && item.containers.find(function(x) {
        return x.Name == container;
      }) != null;
    },
    hasQueuestore(item) {
      return this.hasContainer(item, 'so-redis');
    },
    hasEventstore(item) {
      return this.hasContainer(item, 'so-elasticsearch');
    },
    hasEventstoreHealth(item) {
      return ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-heavynode', 'so-import'].indexOf(item.role) != -1;
    },
    hasMetricstore(item) {
      return this.hasContainer(item, 'so-influxdb');
    },
    hasSteno(item) {
      return this.hasContainer(item, 'so-steno');
    },
    hasSuri(item) {
      return this.hasContainer(item, 'so-suricata');
    },
    hasZeek(item) {
      return this.hasContainer(item, 'so-zeek');
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
        case NodeStatusRestart: color = "info"; break;
      }
      return color;
    },
    colorContainerDetails(str) {
      var color = "normal";
      if (str.indexOf("unhealthy") != -1) {
        color = "error";
      } else if (str.indexOf("second") != -1) {
        color = "warning";
      } else if (str.indexOf("minutes") != -1) {
        color = "info";
      }
      return color;
    },
    iconNodeStatus(status) {
      var icon = "fa-circle-question";
      switch (status) {
        case NodeStatusFault: icon = "fa-triangle-exclamation"; break;
        case NodeStatusOk: icon = "fa-circle-check"; break;
        case NodeStatusPending: icon = "fa-circle-exclamation"; break;
        case NodeStatusRestart: icon = "fa-circle-info"; break;
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
