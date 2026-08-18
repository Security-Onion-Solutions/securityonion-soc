// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts page methods: query construction, the events/ fetch, and the
// normalization of raw event documents into the flat alert view model the page
// renders. Merged into the component's methods by simplealerts.js.

globalThis.SimpleAlertsData = (function() {
  // Rule names are prefixed by their ruleset and a category, e.g.
  // "ET MALWARE Observed DNS Query" or "GPL ATTACK_RESPONSE id check returned root".
  // The category drives the client-side category filter.
  const RULE_CATEGORY_REGEX = /^(?:ET|GPL|SURICATA)\s+([A-Z_]+)/;

  return {
    // The status and severity filters are pushed down to the backend as query terms;
    // the category filter is applied client-side in the processedAlerts computed,
    // because category is derived from the rule name rather than an indexed field.
    buildQuery() {
      let query = 'tags:alert';

      if (this.filterStatus === 'active') {
        query += ' AND NOT event.acknowledged:true AND NOT event.escalated:true';
      } else if (this.filterStatus === 'acknowledged') {
        query += ' AND event.acknowledged:true';
      } else if (this.filterStatus === 'escalated') {
        query += ' AND event.escalated:true';
      }

      if (this.filterSeverity !== 'all') {
        query += ' AND event.severity_label:' + this.filterSeverity;
      }

      return query;
    },

    // Returns the "<start> - <end>" range string the events/ route expects, formatted
    // with the same i18n-driven format hunt.js uses so both pages stay in step.
    getDateRange() {
      const units = {
        '1h': [1, 'hours'],
        '24h': [24, 'hours'],
        '7d': [7, 'days'],
        '30d': [30, 'days'],
      };
      const [value, unit] = units[this.filterTimeRange] || units['24h'];
      const end = moment();
      const start = moment().subtract(value, unit);
      return start.format(this.i18n.timePickerFormat) + ' - ' + end.format(this.i18n.timePickerFormat);
    },

    async loadAlerts() {
      this.loading = true;
      try {
        const params = {
          query: this.buildQuery(),
          range: this.getDateRange(),
          format: this.i18n.timePickerSample,
          zone: this.zone,
          metricLimit: this.metricLimit,
          eventLimit: this.eventLimit,
        };

        const response = await this.$root.papi.get('events/', { params: params });
        if (response && response.data) {
          this.alerts = this.processAlerts(response.data.events || []);
          this.totalAlerts = response.data.totalEvents || 0;
          this.hasMore = this.totalAlerts > this.alerts.length;
          this.lookupHostnames(this.alerts);
        }
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.loading = false;
      }
    },

    // Reverse DNS is opt-in at the app level; batchLookup is a no-op collector that
    // writes results back onto this component when it resolves.
    lookupHostnames(alerts) {
      if (!this.$root.enableReverseLookup) return;

      const ips = [];
      alerts.forEach(alert => {
        if (alert.sourceIp) ips.push(alert.sourceIp);
        if (alert.destIp) ips.push(alert.destIp);
      });
      if (ips.length > 0) {
        this.$root.batchLookup(ips, this);
      }
    },

    // Flattens an events/ response document into the shape the page renders. Field
    // placement varies by detection engine, so root, fields and event_data are all
    // merged before any field is read.
    processAlerts(events) {
      const categories = new Set();

      const alerts = events.map(event => {
        let data = event.payload || event;
        if (event.fields) {
          data = Object.assign({}, data, event.fields);
        }
        if (event.event_data) {
          data = Object.assign({}, data, event.event_data);
        }
        if (data.event_data) {
          data = Object.assign({}, data, data.event_data);
        }

        const ruleName = data['rule.name'] || this.i18n.simpleAlertsUnknownRule;
        let ruleCategory = '';
        const match = ruleName.match(RULE_CATEGORY_REGEX);
        if (match) {
          ruleCategory = match[1];
          categories.add(ruleCategory);
        }

        const sourceIp = data['source.ip'];
        const destIp = data['destination.ip'];

        return {
          id: data['soc_id'] || event.id,
          timestamp: event.timestamp,
          ruleName: ruleName,
          ruleUuid: data['rule.uuid'],
          ruleText: data['rule.rule'] || data['rule.text'] || '',
          severity: data['event.severity'],
          severityLabel: data['event.severity_label'] || this.i18n.simpleAlertsSeverityUnknown,
          sourceIp: sourceIp,
          sourcePort: data['source.port'],
          destIp: destIp,
          destPort: data['destination.port'],
          module: data['event.module'],
          category: data['event.category'],
          'rule.category': ruleCategory,
          acknowledged: data['event.acknowledged'] || false,
          escalated: data['event.escalated'] || false,
          dismissed: data['event.dismissed'] || false,
          // An alert with neither endpoint is host-based (sigma, yara, ossec) and is
          // rendered without the network source/destination columns.
          isHostBased: !sourceIp && !destIp,
          payload: data,
        };
      });

      this.categoryOptions = [{ value: 'all', title: this.i18n.simpleAlertsAllCategories }]
        .concat(Array.from(categories).sort().map(cat => ({ value: cat, title: cat })));

      return alerts;
    },

    // Collapses the backend's severity labels onto the three buckets the UI colors by.
    getSeverityLevel(alert) {
      const label = (alert.severityLabel || '').toLowerCase();
      if (label.includes('high') || label.includes('critical')) return 'high';
      if (label.includes('medium')) return 'medium';
      return 'low';
    },

    // Returns a Vuetify theme token rather than a literal color, so the chip tracks the
    // active theme. These three at the tonal variant are already covered by the "status"
    // chip group in the /colors contrast audit (js/routes/colors.js).
    severityColor(alert) {
      switch (this.getSeverityLevel(alert)) {
        case 'high': return 'error';
        case 'medium': return 'warning';
        default: return 'info';
      }
    },

    isPrivateIP(ip) {
      if (!ip) return false;

      const parts = ip.split('.');
      if (parts.length !== 4) return false;

      const first = parseInt(parts[0], 10);
      const second = parseInt(parts[1], 10);
      if (isNaN(first) || isNaN(second)) return false;

      if (first === 10) return true;                             // 10.0.0.0/8
      if (first === 172 && second >= 16 && second <= 31) return true;  // 172.16.0.0/12
      if (first === 192 && second === 168) return true;          // 192.168.0.0/16
      if (first === 127) return true;                            // 127.0.0.0/8

      return false;
    },

    // Alert counts run to the millions, so group headers show a compact form.
    formatCompactNumber(num) {
      if (num >= 1000000) return (num / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
      if (num >= 100000) return Math.round(num / 1000) + 'K';
      if (num >= 1000) return (num / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
      return String(num);
    },
  };
})();
