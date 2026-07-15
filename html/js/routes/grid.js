// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

const ROLES_WITH_EVENTSTORE_HEALTH = ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-heavynode', 'so-import'];
// Of those, roles running their own node-local Elasticsearch, which SOC's ES connection cannot reach
const ROLES_WITH_LOCAL_EVENTSTORE = ['so-heavynode'];

routes.push({ path: '/grid', name: 'grid', component: {
  template: '#page-grid',
  data() { return {
    i18n: this.$root.i18n,
    moment: moment,
    showOptionsDialog: false,
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
    esHealthDialog: false,
    esHealthLoading: false,
    esHealth: null,
    esHealthAbort: null,
    esHealthExpanded: {},
    esHealthIndicators: [],
    esHealthIssues: [],
    esHealthHealthy: [],
    esShardVerdicts: [],
    esDiskFindings: [],
    uploadForm: { valid: true, attachment: null },
    maxUploadSizeBytes: 25 * 1024 * 1024,
    staleMetricsMs: 120000,
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
    metricsLoading: false,
    metricsNodeId: '',
    metricsNodeItems: [],
    activeTab: 'nodes',
    metricsEnabled: false,
    historicalMetricsEnabled: false,
    selectedMetricsTitle: '',
    metricsTimeRange: '1h',
    metricsAutoRefresh: 0,
    metricsRefreshInterval: null,
    timeRangeItems: [
      { title: this.$root.i18n.metricsLastHour, value: '1h' },
      { title: this.$root.i18n.metricsLast24Hours, value: '24h' },
      { title: this.$root.i18n.metricsLast7Days, value: '7d' }
    ],
    autoRefreshItems: [
      { title: this.$root.i18n.interval0s, value: 0 },
      { title: this.$root.i18n.interval30s, value: 30 },
      { title: this.$root.i18n.interval1m, value: 60 },
      { title: this.$root.i18n.interval5m, value: 300 }
    ],
    chartCpuData: { key: 0, datasets: [] },
    chartCpuOptions: {},
    chartMemoryData: { key: 0, datasets: [] },
    chartMemoryOptions: {},
    chartLoadData: { key: 0, datasets: [] },
    chartLoadOptions: {},
    chartDiskData: { key: 0, datasets: [] },
    chartDiskOptions: {},
    chartNetData: { key: 0, datasets: [] },
    chartNetOptions: {},
    chartEpsData: { key: 0, datasets: [] },
    chartEpsOptions: {},
  }},
  created() {
    this.$root.initializeCharts();
  },
  unmounted() {
    this.$root.unsubscribe("node", this.updateNode);
    this.$root.unsubscribe("status", this.updateStatus);
    clearInterval(this.stalenessInterval);
    this.abortEsHealth();
    if (this.metricsRefreshInterval) {
      clearInterval(this.metricsRefreshInterval);
    }
  },
  mounted() {
    this.$root.loadParameters("grid", this.initGrid);
    this.initMetricsCharts();
  },
  watch: {
    '$route': 'loadData',
    'sortBy': 'saveLocalSettings',
    'itemsPerPage': 'saveLocalSettings',
    'moreColumns': 'saveLocalSettings',
    'esHealthDialog': 'onEsHealthDialogChanged',
    'activeTab'(val) {
      if (val === 'metrics') {
        if (this.metricsNodeId === undefined || this.metricsNodeId === null) {
          this.metricsNodeId = '';
        }
        this.initMetricsCharts();
        this.loadHistoricalMetrics();
        this.setupMetricsAutoRefresh();
      } else {
        if (this.metricsRefreshInterval) {
          clearInterval(this.metricsRefreshInterval);
          this.metricsRefreshInterval = null;
        }
      }
    }
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
      this.historicalMetricsEnabled = !this.nodes.every(function(node) { return !node.historicalMetricsEnabled; });
      this.metricsNodeItems = [
        { title: this.i18n.metricsGridDashboard, value: '' }
      ].concat(this.nodes.map(n => ({ title: n.id, value: n.id })));

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
      return this.$root.isUserAdmin() && (node['keywords'] && node['keywords'].indexOf("Sensor") != -1);
    },
    canRestart(node) {
      return this.$root.isUserAdmin();
    },
    canUpload(node) {
      return (this.canUploadPCAP(node) || this.canUploadEvtx(node));
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
      this.$root.startLoading();
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
      } finally {
        this.$root.stopLoading();
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
    canShowEsHealth(node) {
      return ROLES_WITH_LOCAL_EVENTSTORE.indexOf(node.role) == -1;
    },
    showEsHealth(node) {
      this.esHealthDialog = true;
      this.loadEsHealth(node.gridId);
    },
    hideEsHealth() {
      this.esHealthDialog = false;
    },
    abortEsHealth() {
      if (this.esHealthAbort) {
        this.esHealthAbort.abort();
        this.esHealthAbort = null;
      }
    },
    onEsHealthDialogChanged(open) {
      // Every close path (Close button, ESC, outside-click) lands here via v-model
      if (!open) this.abortEsHealth();
    },
    async loadEsHealth(gridId) {
      // Aborting a superseded request also cancels its ES diagnostic calls server-side
      if (this.esHealthAbort) this.esHealthAbort.abort();
      const abort = new AbortController();
      this.esHealthAbort = abort;
      this.esHealthLoading = true;
      this.esHealth = null;
      this.esHealthExpanded = {};
      this.digestEsHealth();
      try {
        const response = await this.$root.papi.get('eshealth', { params: { gridId: gridId }, signal: abort.signal });
        if (this.esHealthAbort != abort) return;
        this.esHealth = response.data;
        this.digestEsHealth();
      } catch (error) {
        // No global error popup: the dialog shows its own unavailable message
        if (this.esHealthAbort != abort) return;
      }
      this.esHealthAbort = null;
      this.esHealthLoading = false;
    },
    // The health payload never changes after load, so the view data is derived
    // once here rather than on every render.
    digestEsHealth() {
      this.esHealthIndicators = this.digestEsIndicators();
      this.esHealthIssues = this.esHealthIndicators.filter(function(indicator) { return indicator.status != 'green'; });
      this.esHealthHealthy = this.esHealthIndicators.filter(function(indicator) { return indicator.status == 'green'; });
      this.esDiskFindings = this.digestEsDiskFindings();
      this.esShardVerdicts = this.digestEsShardVerdicts();
    },
    colorEsHealthStatus(status) {
      var color = "secondary";
      switch (status) {
        case "green": color = "success"; break;
        case "yellow": color = "warning"; break;
        case "red": color = "error"; break;
      }
      return color;
    },
    iconEsHealthStatus(status) {
      var icon = "fa-circle-question";
      switch (status) {
        case "green": icon = "fa-circle-check"; break;
        case "yellow": icon = "fa-circle-exclamation"; break;
        case "red": icon = "fa-triangle-exclamation"; break;
      }
      return icon;
    },
    formatEsIndicatorName(id) {
      const cased = this.$root.correctCasing(id);
      if (cased != id) return cased;
      const name = id.replace(/_/g, ' ');
      return name.charAt(0).toUpperCase() + name.slice(1);
    },
    digestEsIndicators() {
      if (!this.esHealth || !this.esHealth.healthReport || !this.esHealth.healthReport.indicators) return [];
      const route = this;
      const order = { red: 0, yellow: 1, unknown: 2, green: 3 };
      const indicators = this.esHealth.healthReport.indicators;
      return Object.keys(indicators).map(function(id) {
        const indicator = indicators[id];
        return {
          id: id,
          name: route.formatEsIndicatorName(id),
          status: indicator.status,
          symptom: indicator.symptom,
          causes: (indicator.diagnosis || []).filter(function(d) { return d.cause; }).map(function(d) {
            const resources = d.affected_resources || {};
            return {
              cause: d.cause,
              nodes: (resources.nodes || []).map(function(n) { return n.name; }),
              indices: resources.indices || [],
            };
          }),
        };
      }).sort(function(a, b) {
        const rankA = order[a.status] !== undefined ? order[a.status] : 2;
        const rankB = order[b.status] !== undefined ? order[b.status] : 2;
        return (rankA - rankB) || a.name.localeCompare(b.name);
      });
    },
    toggleEsHealthDetails(id) {
      this.esHealthExpanded[id] = !this.esHealthExpanded[id];
    },
    hasEsHealthDetails(indicator) {
      if (indicator.id == 'shards_availability' && this.esShardVerdicts.length > 0) return true;
      if (indicator.id == 'disk' && this.esDiskFindings.length > 0) return true;
      return indicator.causes.length > 0;
    },
    digestEsDiskFindings() {
      if (!this.esHealth || !this.esHealth.healthReport || !this.esHealth.healthReport.indicators) return [];
      const disk = this.esHealth.healthReport.indicators.disk;
      if (!disk || disk.status == 'green') return [];
      const findings = [];
      const readonly = disk.details ? disk.details.indices_with_readonly_block : 0;
      if (readonly > 0) {
        findings.push(this.$root.localizeMessage('esHealthDiskReadonly', { count: readonly }));
      }
      return findings;
    },
    esShardGroupLabel(group) {
      return group.count + ' ' + (group.primary ? this.i18n.esHealthPrimary : this.i18n.esHealthReplica) + ' (' + group.reason + ')';
    },
    digestEsShardVerdicts() {
      const route = this;
      const unassigned = this.esHealth ? this.esHealth.unassignedShards : null;
      if (!unassigned || !unassigned.groups) return [];

      // Keyed on ES's stable identifiers (can_allocate, decider names), never its
      // free-text prose; unknown deciders show ES's explanation verbatim.
      const canAllocateVerdicts = {
        no_valid_shard_copy: { severity: 0, summary: this.i18n.esHealthVerdictNoValidShardCopy },
      };
      const deciderVerdicts = {
        disk_threshold: { severity: 1, summary: this.i18n.esHealthVerdictDiskThreshold },
        same_shard: { severity: 2, summary: this.i18n.esHealthVerdictSameShard },
        throttling: { severity: 2, summary: this.i18n.esHealthVerdictThrottling },
      };
      const icons = ['fa-triangle-exclamation', 'fa-circle-exclamation', 'fa-circle-info'];
      const colors = ['error', 'warning', 'info'];

      const verdicts = [];
      unassigned.groups.forEach(function(group) {
        const scope = route.esShardGroupLabel(group);
        const before = verdicts.length;
        const outcome = canAllocateVerdicts[group.canAllocate];
        if (outcome) {
          verdicts.push({ severity: outcome.severity, scope: scope, summary: outcome.summary, decider: null, detail: null, nodes: [] });
        }
        (group.deciders || []).forEach(function(decider) {
          const known = deciderVerdicts[decider.name];
          verdicts.push({
            severity: known ? known.severity : 1,
            scope: scope,
            summary: known ? known.summary : decider.name + ': ' + decider.explanation,
            decider: decider.name,
            detail: known ? decider.explanation : null,
            nodes: decider.nodes || [],
          });
        });
        // Transient outcomes (throttled, allocation_delayed, awaiting_info...) report
        // no blocking deciders; every explained group still gets a verdict row
        if (verdicts.length == before && group.canAllocate) {
          verdicts.push({
            severity: 2,
            scope: scope,
            summary: route.$root.localizeMessage('esHealthVerdictUnexplained', { value: group.canAllocate }),
            decider: null,
            detail: null,
            nodes: [],
          });
        }
      });
      verdicts.sort(function(a, b) { return a.severity - b.severity; });
      verdicts.forEach(function(verdict) {
        verdict.icon = icons[verdict.severity] || icons[1];
        verdict.color = colors[verdict.severity] || colors[1];
      });
      return verdicts;
    },
    esAllocationLines(explain) {
      if (!explain) return [];
      const lines = [];
      lines.push('Shard: ' + explain.index + '[' + explain.shard + '] ' + (explain.primary ? '(primary)' : '(replica)'));
      if (explain.unassigned_info) {
        lines.push('Unassigned reason: ' + explain.unassigned_info.reason + (explain.unassigned_info.at ? ', since ' + explain.unassigned_info.at : ''));
      }
      if (explain.can_allocate) {
        lines.push('Can allocate: ' + explain.can_allocate);
      }
      (explain.node_allocation_decisions || []).forEach(function(node) {
        lines.push('  * Node ' + node.node_name + ': ' + node.node_decision);
        (node.deciders || []).forEach(function(decider) {
          lines.push('    - ' + decider.decider + ': ' + decider.explanation);
        });
      });
      return lines;
    },
    formatEsReportList(label, items) {
      const max = 10;
      var display = items.slice(0, max).join(', ');
      if (items.length > max) {
        display += this.$root.localizeMessage('esHealthMoreItems', { count: items.length - max });
      }
      return label + ' (' + items.length + '): ' + display;
    },
    buildEsHealthReport() {
      if (!this.esHealth) return '';
      const route = this;
      const lines = [];

      lines.push('ELASTICSEARCH HEALTH REPORT');
      lines.push('Generated: ' + moment().format());
      if (this.$root.version) {
        lines.push('Security Onion: ' + this.$root.version);
      }

      const nodes = this.esHealth.catNodes;
      if (nodes && nodes.length) {
        // ES reports null for stats that are momentarily unavailable
        const stat = function(value) { return value == null ? '-' : value; };
        lines.push('');
        lines.push('--- Nodes (_cat/nodes) ---');
        nodes.forEach(function(node) {
          lines.push('  * ' + stat(node.name) + ' (' + stat(node.ip) + ') roles=' + stat(node['node.role']) + ' master=' + stat(node.master) +
              ' version=' + stat(node.version) + ' heap=' + stat(node['heap.percent']) + '% ram=' + stat(node['ram.percent']) + '%' +
              ' cpu=' + stat(node.cpu) + '% load_1m=' + stat(node.load_1m) +
              ' disk_used=' + stat(node['disk.used_percent']) + '% of ' + stat(node['disk.total']) + ' uptime=' + stat(node.uptime));
        });
      }

      const settings = this.esHealth.clusterSettings;
      if (settings) {
        lines.push('');
        lines.push('--- Cluster Settings (_cluster/settings) ---');
        ['persistent', 'transient'].forEach(function(scope) {
          const keys = Object.keys(settings[scope] || {});
          if (!keys.length) {
            lines.push(scope + ': (none)');
          } else {
            lines.push(scope + ':');
            keys.sort().forEach(function(key) {
              lines.push('  ' + key + ': ' + JSON.stringify(settings[scope][key]));
            });
          }
        });
      }

      lines.push('');
      lines.push('--- Indicators (_health_report) ---');
      this.esHealthIndicators.forEach(function(indicator) {
        lines.push('[' + (indicator.status || 'unknown').toUpperCase() + '] ' + indicator.name + (indicator.symptom ? ' - ' + indicator.symptom : ''));
        if (indicator.id == 'disk') {
          route.esDiskFindings.forEach(function(finding) {
            lines.push('  * ' + finding);
          });
        }
        indicator.causes.forEach(function(cause) {
          lines.push('  * ' + cause.cause);
          if (cause.nodes.length) {
            lines.push('    ' + route.formatEsReportList('Affected nodes', cause.nodes));
          }
          if (cause.indices.length) {
            lines.push('    ' + route.formatEsReportList('Affected indices', cause.indices));
          }
        });
      });

      const unassigned = this.esHealth.unassignedShards;
      if (unassigned) {
        lines.push('');
        lines.push('--- Unassigned Shards (_cat/shards, _cluster/allocation/explain) ---');
        lines.push('Total: ' + unassigned.total + ' unassigned (' + unassigned.primaries + ' primary, ' + unassigned.replicas + ' replica)');
        (unassigned.groups || []).forEach(function(group) {
          if (!group.explanation) {
            lines.push('No allocation explanation sampled for ' + route.esShardGroupLabel(group));
            return;
          }
          lines.push('Sampled shard for ' + route.esShardGroupLabel(group) + ':');
          route.esAllocationLines(group.explanation).forEach(function(line) {
            lines.push('  ' + line);
          });
        });
      }

      return lines.join('\n');
    },
    copyEsHealthReport() {
      this.$root.copyToClipboard(this.buildEsHealthReport());
      this.$root.showTip(this.i18n.esHealthCopied);
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
      return ROLES_WITH_EVENTSTORE_HEALTH.indexOf(item.role) != -1;
    },
    hasMetricstore(item) {
      return this.hasContainer(item, 'so-influxdb');
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
    colorSuriRules(item) {
      // Unknown status (container down, socket error, etc.)
      if (item.suriRulesStatus === "unknown") {
        return "";  // Gray/default color
      }
      // All rules failed to load - error
      if (item.suriRulesLoaded === 0 && item.suriRulesFailed > 0) {
        return "error";
      }
      // Some rules loaded but some failed - warning
      if (item.suriRulesLoaded > 0 && item.suriRulesFailed > 0) {
        return "warning";
      }
      // No rules configured (none loaded, none failed) - warning
      if (item.suriRulesLoaded === 0 && item.suriRulesFailed === 0) {
        return "warning";
      }
      // All rules loaded successfully
      return "success";
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
    },
    showNodeMetrics(nodeId) {
      this.metricsNodeId = nodeId;
      this.activeTab = 'metrics';
    },
  }
}});
