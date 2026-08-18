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

  const SEVERITY_FIELD = 'event.severity_label';

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

    // Severity always aggregates as groupby_0; the active grouped view, when there is
    // one, adds groupby_1. One request therefore returns the event page, the stat pill
    // totals and the group counts together.
    buildFullQuery() {
      let query = this.buildQuery() + ' | groupby ' + SEVERITY_FIELD;
      const groupFields = this.groupByFields();
      if (groupFields) {
        query += ' | groupby ' + groupFields.join(' ');
      }
      return query;
    },

    async loadAlerts() {
      this.loading = true;
      try {
        const params = {
          query: this.buildFullQuery(),
          range: this.getDateRange(),
          format: this.i18n.timePickerSample,
          zone: this.zone,
          // Groups come from the aggregation, so the limit has to cover the groups the
          // page intends to show, not just the severity buckets.
          metricLimit: this.groupAlerts ? this.groupLimit : this.metricLimit,
          eventLimit: this.eventLimit,
        };

        const response = await this.$root.papi.get('events/', { params: params });
        if (response && response.data) {
          this.alerts = this.processAlerts(response.data.events || []);
          this.totalAlerts = response.data.totalEvents || 0;
          this.hasMore = this.totalAlerts > this.alerts.length;
          this.severityTotals = this.parseSeverityTotals(response.data.metrics);
          this.applyGroupMetrics(response.data.metrics);
          this.lookupHostnames(this.alerts);
        }
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.loading = false;
      }
    },

    // Folds the severity_label aggregation into the same three buckets the UI colors by,
    // so the stat pills describe every matching alert rather than only the loaded page.
    // Returns null when the backend returned no aggregation, which the pills render as
    // "unavailable" instead of silently showing zero.
    parseSeverityTotals(metrics) {
      const rows = metrics && metrics['groupby_0|' + SEVERITY_FIELD];
      if (!rows) return null;

      const totals = { high: 0, medium: 0, low: 0 };
      rows.forEach(row => {
        const level = this.getSeverityLevel({ severityLabel: row.keys && row.keys[0] });
        totals[level] += row.value || 0;
      });
      return totals;
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
        const ruleCategory = this.ruleCategory(ruleName);
        if (ruleCategory) categories.add(ruleCategory);

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
          sourceGeo: this.extractGeo(data, 'source'),
          destIp: destIp,
          destPort: data['destination.port'],
          destGeo: this.extractGeo(data, 'destination'),
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

    // Pulls the ECS geo and autonomous-system fields for one endpoint. Returns null when
    // the document carries none, which the UI reports as "not available" rather than
    // rendering an empty location.
    extractGeo(data, prefix) {
      const geo = {
        city: data[prefix + '.geo.city_name'],
        regionCode: data[prefix + '.geo.region_iso_code'],
        regionName: data[prefix + '.geo.region_name'],
        country: data[prefix + '.geo.country_name'] || data[prefix + '.geo.country_iso_code'],
        asOrg: data[prefix + '.as.organization.name'] || data[prefix + '.as.organization'],
      };
      return Object.values(geo).some(v => v) ? geo : null;
    },

    // A short, human-readable location for an endpoint. Private addresses are labelled
    // as such rather than reported as having no geo data, since that is expected.
    formatGeoInfo(geo, ip) {
      if (this.isPrivateIP(ip)) return this.i18n.simpleAlertsGeoPrivate;
      if (!geo) return this.i18n.simpleAlertsGeoUnavailable;

      const parts = [];
      if (geo.city) parts.push(geo.city);
      if (geo.regionCode) parts.push(geo.regionCode);
      else if (geo.regionName) parts.push(geo.regionName);
      if (geo.country) parts.push(geo.country);

      const location = parts.join(', ');
      if (location && geo.asOrg) return location + ' · ' + geo.asOrg;
      return location || geo.asOrg || this.i18n.simpleAlertsGeoUnavailable;
    },

    // Rule names carry their ruleset and category as a prefix, e.g. "ET MALWARE ..." or
    // "GPL ATTACK_RESPONSE ...". Returns '' for rules that follow no such convention.
    ruleCategory(ruleName) {
      const match = (ruleName || '').match(RULE_CATEGORY_REGEX);
      return match ? match[1] : '';
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
