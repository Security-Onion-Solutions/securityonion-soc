// Copyright 2026 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-alarms-manager', 'pages/alarms-manager.html');

components.push({
  name: 'alarms-manager',
  component: {
    template: '#component-alarms-manager',
    props: {
      autoLoad: {
        type: Boolean,
        default: true,
      },
    },
    emits: ['alarms-loaded', 'alarm-saved', 'alarm-deleted'],
    data() {
      return {
        i18n: this.$root?.i18n || {},
        alarms: [],
        metrics: [],
        states: [],
        nodes: [],
        destinations: [],
        users: [],
        alarmHeaders: [
          { title: this.$root?.i18n?.status, value: 'state', sortable: false },
          { title: this.$root?.i18n?.name, value: 'name' },
          { title: this.$root?.i18n?.targetNode, value: 'node' },
          { title: this.$root?.i18n?.alarmMetric, value: 'metric' },
          { title: this.$root?.i18n?.condition, value: 'condition', sortable: false },
          { title: this.$root?.i18n?.currentValue, value: 'currentValue', sortable: false },
          { title: this.$root?.i18n?.severity, value: 'severity', sortable: false },
          { title: this.$root?.i18n?.alarmClearedSeverity, value: 'clearedSeverity', sortable: false },
          { title: this.$root?.i18n?.destinations, value: 'destinations', sortable: false },
          { title: this.$root?.i18n?.status, value: 'status', sortable: false },
          { title: this.$root?.i18n?.actions, value: 'actions', sortable: false, align: 'end' },
        ],
        alarmSortBy: [{ key: 'name', order: 'asc' }],
        alarmItemsPerPage: 10,
        alarmItemsPerPageOptions: [10, 25, 50, 100],
        alarmSearch: '',
        alarmDialog: false,
        deleteAlarmDialog: false,
        alarmToDelete: null,
        form: {
          isEdit: false,
          valid: false,
          id: '',
          name: '',
          enabled: true,
          nodeId: '',
          metric: 'cpu',
          metricKey: '',
          operator: 'gt',
          threshold: '80',
          durationSeconds: 120,
          severity: 'high',
          clearedSeverity: 'none',
          destinations: [],
          recipients: [],
          note: '',
        },
      };
    },
    computed: {
      tableHeaders() {
        let headers = this.alarmHeaders;
        if (!this.$root.isLicensed(this.$root.FEAT_NTF)) {
          headers = headers.filter(h => h.value !== 'destinations' && h.value !== 'clearedSeverity');
        }
        if (!this.$root.isUserAdmin()) {
          headers = headers.filter(h => h.value !== 'actions');
        }
        return headers;
      },
      nodeOptions() {
        const opts = [{ title: this.i18n.allNodes, value: '' }];
        (this.nodes || []).forEach(n => {
          if (n && n.id) {
            opts.push({ title: n.id, value: n.id });
          }
        });
        return opts;
      },
      metricOptions() {
        return (this.metrics || []).map(m => ({
          title: (m.titleKey && this.i18n[m.titleKey]) ? this.i18n[m.titleKey] : m.metric,
          metric: m.metric,
          keys: m.keys || [],
          labelKeys: m.labelKeys || [],
        }));
      },
      selectedMetricObj() {
        return (this.metrics || []).find(m => m.metric === this.form.metric);
      },
      selectedMetricType() {
        const metricObj = typeof this.selectedMetricObj === 'function' ? this.selectedMetricObj() : (this.selectedMetricObj || (this.metrics || []).find(m => m.metric === this.form.metric));
        return metricObj?.type || 'numeric';
      },
      booleanThresholdOptions() {
        return [
          { title: this.i18n.trueLabel, value: 'true' },
          { title: this.i18n.falseLabel, value: 'false' },
        ];
      },
      thresholdHint() {
        const metricObj = typeof this.selectedMetricObj === 'function' ? this.selectedMetricObj() : (this.selectedMetricObj || (this.metrics || []).find(m => m.metric === this.form.metric));
        if (!metricObj) {
          return '';
        }
        if (metricObj.type === 'string') {
          return this.i18n.alarmThresholdStringHint;
        }
        if (metricObj.type === 'bool') {
          return '';
        }
        switch (metricObj.units) {
          case 'percent':
            return this.i18n.unitPercent;
          case 'seconds':
            return this.i18n.unitSeconds;
          case 'days':
            return this.i18n.unitDays;
          case 'gb':
            return this.i18n.unitGigabytes;
          case 'mbs':
            return this.i18n.unitMbps;
          case 'bits':
            return this.i18n.unitBits;
          default:
            return '';
        }
      },
      metricKeyOptions() {
        const metricObj = typeof this.selectedMetricObj === 'function' ? this.selectedMetricObj() : (this.selectedMetricObj || (this.metrics || []).find(m => m.metric === this.form.metric));
        if (!metricObj || !metricObj.keys) {
          return [];
        }
        return metricObj.keys.map((k, idx) => ({
          title: (metricObj.labelKeys && this.i18n[metricObj.labelKeys[idx]]) ? this.i18n[metricObj.labelKeys[idx]] : k,
          value: k,
        }));
      },
      operatorOptions() {
        return this.getOperatorOptions();
      },
      severityOptions() {
        return [
          { title: this.i18n.severityCritical, value: 'critical' },
          { title: this.i18n.severityHigh, value: 'high' },
          { title: this.i18n.severityMedium, value: 'medium' },
          { title: this.i18n.severityLow, value: 'low' },
          { title: this.i18n.severityInfo, value: 'info' },
        ];
      },
      clearedSeverityOptions() {
        return [
          { title: this.i18n.none, value: 'none' },
          ...this.severityOptions,
        ];
      },
      destinationOptions() {
        return (this.destinations || []).map(d => ({
          title: d.name || (d.id === 'soc-bell' ? this.i18n.builtinSOCNotifications : d.id),
          value: d.id,
        }));
      },
      userOptions() {
        return (this.users || []).map(u => ({
          title: u.email || u.name || u.id,
          value: u.id,
        }));
      },
    },
    created() {
      if (this.autoLoad) {
        this.loadData();
      }
      if (this.$root?.subscribe) {
        this.$root.subscribe('alarm:state', this.onAlarmStateUpdate);
      }
    },
    unmounted() {
      if (this.$root?.unsubscribe) {
        this.$root.unsubscribe('alarm:state', this.onAlarmStateUpdate);
      }
    },
    methods: {
      onAlarmStateUpdate(state) {
        if (!state || !state.alarmId) return;
        if (!Array.isArray(this.states)) this.states = [];
        const idx = this.states.findIndex(s => s.alarmId === state.alarmId && s.nodeId === state.nodeId);
        if (idx !== -1) {
          this.states.splice(idx, 1, state);
        } else {
          this.states.push(state);
        }
      },
      async loadData() {
        this.$root?.startLoading?.();
        try {
          const promises = [
            this.getAlarms(),
            this.getMetrics(),
            this.getStates(),
            this.getNodes(),
          ];
          if (this.$root.isLicensed(this.$root.FEAT_NTF)) {
            promises.push(this.getDestinations(), this.getUsers());
          }
          await Promise.all(promises);
        } finally {
          this.$root?.stopLoading?.();
        }
      },
      async getAlarms() {
        try {
          const res = await this.$root.papi.get('alarms');
          this.alarms = res && res.data ? res.data : (res || []);
          if (typeof this.$emit === 'function') {
            this.$emit('alarms-loaded', this.alarms);
          }
        } catch (error) {
          if (this.$root?.showError) {
            this.$root.showError(error);
          }
        }
      },
      async getMetrics() {
        try {
          const res = await this.$root.papi.get('alarms/metrics');
          this.metrics = res && res.data ? res.data : (res || []);
        } catch (error) {
          this.metrics = [];
        }
      },
      async getStates() {
        try {
          const res = await this.$root.papi.get('alarms/states');
          this.states = Array.isArray(res?.data) ? res.data : (Array.isArray(res) ? res : []);
        } catch (error) {
          this.states = [];
        }
      },
      async getNodes() {
        try {
          const res = await this.$root.papi.get('grid/');
          this.nodes = res && res.data ? res.data : (res || []);
        } catch (error) {
          this.nodes = [];
        }
      },
      async getDestinations() {
        try {
          const res = await this.$root.papi.get('notifications/destinations');
          this.destinations = res && res.data ? res.data : (res || []);
        } catch (error) {
          this.destinations = [];
        }
      },
      async getUsers() {
        try {
          const res = await this.$root.papi.get('users');
          this.users = res && res.data ? res.data : (res || []);
        } catch (error) {
          this.users = [];
        }
      },
      showAddAlarm() {
        const defaultMetric = this.metrics.length > 0 ? this.metrics[0].metric : 'cpu';
        const defaultMetricObj = (this.metrics || []).find(m => m.metric === defaultMetric);
        const defaultOp = (defaultMetricObj?.type === 'string' || defaultMetricObj?.type === 'bool') ? 'eq' : 'gt';
        let defaultThreshold = '80';
        if (defaultMetricObj?.type === 'string') {
          defaultThreshold = '';
        } else if (defaultMetricObj?.type === 'bool') {
          defaultThreshold = 'true';
        }

        this.form = {
          isEdit: false,
          valid: false,
          id: '',
          name: '',
          enabled: true,
          nodeId: '',
          metric: defaultMetric,
          metricKey: (defaultMetricObj?.keys && defaultMetricObj.keys.length > 0) ? defaultMetricObj.keys[0] : '',
          operator: defaultOp,
          threshold: defaultThreshold,
          durationSeconds: 120,
          severity: 'high',
          clearedSeverity: 'info',
          destinations: [],
          recipients: [],
          note: '',
        };
        this.alarmDialog = true;
      },
      showEditAlarm(item) {
        this.form = {
          isEdit: true,
          valid: false,
          id: item.id,
          name: item.name,
          enabled: item.enabled !== false,
          nodeId: item.nodeId || '',
          metric: item.metric || 'cpu',
          metricKey: item.metricKey || '',
          operator: item.operator || 'gt',
          threshold: item.threshold || '',
          durationSeconds: item.durationSeconds || 0,
          severity: item.severity || 'high',
          clearedSeverity: item.clearedSeverity || 'none',
          destinations: item.destinations ? [...item.destinations] : [],
          recipients: item.recipients ? [...item.recipients] : [],
          note: item.note || '',
        };
        this.alarmDialog = true;
      },
      getOperatorOptions() {
        const metricObj = (this.metrics || []).find(m => m.metric === this.form.metric);
        const metricType = metricObj?.type || 'numeric';
        if (metricType === 'string') {
          return [
            { title: this.i18n.operatorEQ, value: 'eq' },
            { title: this.i18n.operatorNEQ, value: 'ne' },
            { title: this.i18n.operatorContains, value: 'contains' },
          ];
        }
        if (metricType === 'bool') {
          return [
            { title: this.i18n.operatorEQ, value: 'eq' },
            { title: this.i18n.operatorNEQ, value: 'ne' },
          ];
        }
        return [
          { title: this.i18n.operatorGT, value: 'gt' },
          { title: this.i18n.operatorGTE, value: 'gte' },
          { title: this.i18n.operatorLT, value: 'lt' },
          { title: this.i18n.operatorLTE, value: 'lte' },
          { title: this.i18n.operatorEQ, value: 'eq' },
          { title: this.i18n.operatorNEQ, value: 'ne' },
        ];
      },
      onMetricChange(metricName) {
        const metricObj = (this.metrics || []).find(m => m.metric === metricName);
        if (metricObj && metricObj.keys && metricObj.keys.length > 0) {
          this.form.metricKey = metricObj.keys[0];
        } else {
          this.form.metricKey = '';
        }
        const validOps = this.getOperatorOptions().map(o => o.value);
        if (!validOps.includes(this.form.operator)) {
          this.form.operator = validOps.length > 0 ? validOps[0] : 'eq';
        }
        if (metricObj?.type === 'bool') {
          if (this.form.threshold !== 'true' && this.form.threshold !== 'false') {
            this.form.threshold = 'true';
          }
        } else if (metricObj?.type === 'string') {
          if (this.form.threshold === '80' || this.form.threshold === 'true' || this.form.threshold === 'false') {
            this.form.threshold = '';
          }
        } else if (metricObj?.type === 'numeric') {
          if (this.form.threshold === 'true' || this.form.threshold === 'false') {
            this.form.threshold = '80';
          }
        }
      },
      async saveAlarm() {
        try {
          const payload = {
            id: this.form.id || undefined,
            name: this.form.name,
            enabled: this.form.enabled,
            nodeId: this.form.nodeId || undefined,
            metric: this.form.metric,
            metricKey: this.form.metricKey || undefined,
            operator: this.form.operator,
            threshold: String(this.form.threshold),
            durationSeconds: Number(this.form.durationSeconds) || 0,
            severity: this.form.severity,
            clearedSeverity: this.form.clearedSeverity || 'none',
            destinations: this.form.destinations || [],
            recipients: this.form.recipients || [],
            note: this.form.note || '',
          };

          if (this.form.isEdit) {
            await this.$root.papi.put(`alarms/${this.form.id}`, payload);
          } else {
            await this.$root.papi.post('alarms', payload);
          }

          this.alarmDialog = false;
          await this.loadData();
          if (typeof this.$emit === 'function') {
            this.$emit('alarm-saved', payload);
          }
        } catch (error) {
          if (this.$root?.showError) {
            this.$root.showError(error);
          }
        }
      },
      showDeleteAlarm(item) {
        this.alarmToDelete = item;
        this.deleteAlarmDialog = true;
      },
      async deleteAlarm() {
        if (!this.alarmToDelete) return;
        try {
          await this.$root.papi.delete(`alarms/${this.alarmToDelete.id}`);
          this.deleteAlarmDialog = false;
          const deleted = this.alarmToDelete;
          this.alarmToDelete = null;
          await this.loadData();
          if (typeof this.$emit === 'function') {
            this.$emit('alarm-deleted', deleted);
          }
        } catch (error) {
          if (this.$root?.showError) {
            this.$root.showError(error);
          }
        }
      },
      getAlarmStatesFor(alarm) {
        if (!alarm || !Array.isArray(this.states)) return [];
        return this.states.filter(s => s.alarmId === alarm.id);
      },
      isAlarmActive(alarm) {
        if (!alarm || alarm.enabled === false) return false;
        const states = this.getAlarmStatesFor(alarm);
        return states.some(s => s.status === 'alarm');
      },
      getAlarmStateLabel(alarm) {
        if (alarm.enabled === false) {
          return this.i18n.disabled;
        }
        if (this.isAlarmActive(alarm)) {
          return this.i18n.alarmActive;
        }
        return this.i18n.alarmCleared;
      },
      getAlarmStateColor(alarm) {
        if (alarm.enabled === false) return 'grey';
        if (this.isAlarmActive(alarm)) return 'error';
        return 'success';
      },
      getAlarmStateVariant(alarm) {
        if (alarm.enabled === false) return 'tonal';
        if (this.isAlarmActive(alarm)) return 'flat';
        return 'tonal';
      },
      getAlarmStateIcon(alarm) {
        if (alarm.enabled === false) return 'fa-ban';
        if (this.isAlarmActive(alarm)) return 'fa-triangle-exclamation';
        return 'fa-circle-check';
      },
      getMetricDisplay(alarm) {
        const m = (this.metrics || []).find(met => met.metric === alarm.metric);
        const title = m ? ((m.titleKey && this.i18n[m.titleKey]) ? this.i18n[m.titleKey] : (m.title || m.metric)) : alarm.metric;
        if (m && m.keys && m.keys.length > 1 && alarm.metricKey) {
          const idx = m.keys.indexOf(alarm.metricKey);
          if (idx >= 0 && m.labelKeys && m.labelKeys[idx] && this.i18n[m.labelKeys[idx]]) {
            return `${title} (${this.i18n[m.labelKeys[idx]]})`;
          }
        }
        return title;
      },
      formatCondition(alarm) {
        let opSymbol = alarm.operator;
        switch (alarm.operator) {
          case 'gt': opSymbol = '>'; break;
          case 'gte': opSymbol = '>='; break;
          case 'lt': opSymbol = '<'; break;
          case 'lte': opSymbol = '<='; break;
          case 'eq': opSymbol = '=='; break;
          case 'ne': opSymbol = '!='; break;
          case 'contains': opSymbol = 'contains'; break;
        }
        let res = `${opSymbol} ${alarm.threshold}`;
        if (alarm.durationSeconds && alarm.durationSeconds > 0) {
          const durStr = this.$root.formatDuration(alarm.durationSeconds);
          res += ` ${this.$root.replaceActionVar(this.i18n.alarmConditionFor, 'duration', durStr)}`;
        }
        return res;
      },
      getCurrentValue(alarm) {
        const states = this.getAlarmStatesFor(alarm);
        if (!states || states.length === 0) return '—';
        if (states.length === 1) return states[0].currentValue || '—';
        const active = states.find(s => s.status === 'alarm');
        if (active) return `${active.nodeId}: ${active.currentValue}`;
        return states[0].currentValue || '—';
      },
      colorSeverity(sev) {
        return this.$root.colorSeverity(sev);
      },
      getSeverityLabel(sev) {
        switch (sev) {
          case 'critical': return this.i18n.severityCritical;
          case 'high': return this.i18n.severityHigh;
          case 'medium': return this.i18n.severityMedium;
          case 'low': return this.i18n.severityLow;
          case 'info': return this.i18n.severityInfo;
          case 'none': return this.i18n.none;
          default: return sev;
        }
      },
      getDestinationName(id) {
        const dest = (this.destinations || []).find(d => d.id === id);
        if (dest && dest.name) {
          return dest.name;
        }
        if (id === 'soc-bell' || (dest && dest.id === 'soc-bell')) {
          return this.i18n.builtinSOCNotifications;
        }
        return dest?.name || id;
      },
    },
  },
});
