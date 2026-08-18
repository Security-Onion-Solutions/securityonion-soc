// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts page methods: the grouped views. Counts come from a groupby
// aggregation that rides along with the events request, so they are exact; a group's
// own alerts are fetched only when it is expanded. Merged into the component's methods
// by simplealerts.js.

globalThis.SimpleAlertsGrouping = (function() {
  // Absent fields come back from the aggregation as this sentinel rather than empty.
  const MISSING = '__missing__';

  // rule.uuid rides along so an expanded group can pivot to its detection without a
  // second lookup. A rule's severity and uuid are effectively constant, so grouping on
  // all three still yields one row per rule in practice.
  const RULE_FIELDS = ['rule.name', 'event.severity_label', 'rule.uuid'];
  const SOURCE_DEST_FIELDS = ['source.ip', 'destination.ip'];

  const SETTINGS_PREFIX = 'settings.simplealerts.';

  function present(value) {
    return (value === undefined || value === null || value === MISSING || value === '') ? null : value;
  }

  return {
    // The groups backing the active view, before any client-side filtering.
    activeGroups() {
      return this.groupingMode === 'source-dest' ? this.sourceDestGroups : this.alertGroups;
    },

    // Category is parsed from the rule name, so it can only filter the rule-grouped
    // view. The select is disabled elsewhere rather than silently doing nothing. This is
    // a method rather than a computed so that other computeds can call it: Vue exposes
    // computeds as properties, so calling one from another would throw at runtime.
    categoryFilterEnabled() {
      return this.groupingMode !== 'source-dest';
    },

    // The fields to aggregate on for the active view, or null when ungrouped.
    groupByFields() {
      if (!this.groupAlerts) return null;
      return this.groupingMode === 'source-dest' ? SOURCE_DEST_FIELDS : RULE_FIELDS;
    },

    // Aggregation rows arrive under a key naming the group index and its fields.
    groupMetricKey(fields) {
      return 'groupby_1|' + fields.join('|');
    },

    applyGroupMetrics(metrics) {
      const fields = this.groupByFields();
      if (!fields) {
        this.alertGroups = [];
        this.sourceDestGroups = [];
        return;
      }

      const rows = (metrics && metrics[this.groupMetricKey(fields)]) || [];
      if (this.groupingMode === 'source-dest') {
        this.sourceDestGroups = this.parseSourceDestGroups(rows);
        this.alertGroups = [];
      } else {
        this.alertGroups = this.parseRuleGroups(rows);
        this.sourceDestGroups = [];
      }
    },

    // Folds (rule, severity, uuid) rows into one entry per rule. Counts are summed
    // rather than estimated, and a rule spanning severities takes its highest.
    parseRuleGroups(rows) {
      const groups = new Map();
      const rank = { high: 3, medium: 2, low: 1 };

      rows.forEach(row => {
        const keys = row.keys || [];
        const ruleName = present(keys[0]) || this.i18n.simpleAlertsUnknownRule;
        const severityLabel = present(keys[1]) || this.i18n.simpleAlertsSeverityUnknown;
        const ruleUuid = present(keys[2]);

        let group = groups.get(ruleName);
        if (!group) {
          group = this.newGroup('rule', ruleName, {
            ruleName: ruleName,
            ruleUuid: ruleUuid,
            severityLabel: severityLabel,
            'rule.category': this.ruleCategory(ruleName),
          });
          groups.set(ruleName, group);
        }

        group.count += row.value || 0;
        if (!group.ruleUuid) group.ruleUuid = ruleUuid;

        const current = rank[this.getSeverityLevel({ severityLabel: group.severityLabel })] || 0;
        const candidate = rank[this.getSeverityLevel({ severityLabel: severityLabel })] || 0;
        if (candidate > current) group.severityLabel = severityLabel;
      });

      return Array.from(groups.values()).sort((a, b) => b.count - a.count);
    },

    // One entry per source/destination pair. Host-based alerts have neither endpoint
    // and aggregate into a single "missing" pair, which is dropped rather than shown
    // as a meaningless group.
    parseSourceDestGroups(rows) {
      const groups = [];

      rows.forEach(row => {
        const keys = row.keys || [];
        const sourceIp = present(keys[0]);
        const destIp = present(keys[1]);
        if (!sourceIp && !destIp) return;

        groups.push(this.newGroup('source-dest', sourceIp + ' ' + destIp, {
          sourceIp: sourceIp,
          destIp: destIp,
          count: row.value || 0,
        }));
      });

      return groups.sort((a, b) => b.count - a.count);
    },

    newGroup(kind, key, fields) {
      return Object.assign({
        kind: kind,
        key: key,
        count: 0,
        // Nothing below a group is fetched until it is expanded.
        subGroups: [],
        subGroupsLoaded: false,
        subGroupsLoading: false,
        alerts: [],
        alertsLoaded: false,
        alertsLoading: false,
        alertsTruncated: false,
        showAll: false,
      }, fields);
    },

    isGroupExpanded(group) {
      return this.expandedGroups.indexOf(group.key) !== -1;
    },

    // A rule group opens into its source/destination pairs; a pair group, and a rule
    // whose alerts have no network endpoints, opens straight into alerts.
    toggleGroup(group) {
      const idx = this.expandedGroups.indexOf(group.key);
      if (idx !== -1) {
        this.expandedGroups.splice(idx, 1);
        return;
      }

      this.expandedGroups.push(group.key);
      if (group.kind === 'rule') {
        if (!group.subGroupsLoaded) this.loadSubGroups(group);
      } else if (!group.alertsLoaded) {
        this.loadGroupAlerts(group);
      }
    },

    subGroupKey(group, subGroup) {
      return group.key + ' > ' + subGroup.key;
    },

    isSubGroupExpanded(group, subGroup) {
      return this.expandedSubGroups.indexOf(this.subGroupKey(group, subGroup)) !== -1;
    },

    toggleSubGroup(group, subGroup) {
      const key = this.subGroupKey(group, subGroup);
      const idx = this.expandedSubGroups.indexOf(key);
      if (idx === -1) {
        this.expandedSubGroups.push(key);
        if (!subGroup.alertsLoaded) this.loadSubGroupAlerts(group, subGroup);
      } else {
        this.expandedSubGroups.splice(idx, 1);
      }
    },

    // The terms that narrow the page query down to a single group.
    groupTerms(group) {
      if (group.kind === 'source-dest') {
        const terms = [];
        if (group.sourceIp) terms.push({ field: 'source.ip', value: group.sourceIp });
        if (group.destIp) terms.push({ field: 'destination.ip', value: group.destIp });
        return terms;
      }
      return [{ field: 'rule.name', value: group.ruleName }];
    },

    // A pair inside a rule is identified by all three, so acting on it affects only
    // that rule's traffic between those endpoints.
    subGroupTerms(group, subGroup) {
      const terms = this.groupTerms(group);
      if (subGroup.sourceIp) terms.push({ field: 'source.ip', value: subGroup.sourceIp });
      if (subGroup.destIp) terms.push({ field: 'destination.ip', value: subGroup.destIp });
      return terms;
    },

    // Aggregates a rule's alerts into source/destination pairs. Counts are exact for the
    // same reason the rule counts are: they come from the backend, not from a sample.
    async loadSubGroups(group) {
      group.subGroupsLoading = true;
      try {
        const narrowed = await this.narrowQuery(this.buildQuery(), this.groupTerms(group));
        const response = await this.$root.papi.get('events/', { params: {
          query: narrowed + ' | groupby ' + SOURCE_DEST_FIELDS.join(' '),
          range: this.getDateRange(),
          format: this.i18n.timePickerSample,
          zone: this.zone,
          metricLimit: this.groupLimit,
          // only the aggregation is wanted here; alerts come when a pair is opened
          eventLimit: 1,
        }});

        const rows = (response && response.data && response.data.metrics
          && response.data.metrics['groupby_0|' + SOURCE_DEST_FIELDS.join('|')]) || [];
        group.subGroups = this.parseSourceDestGroups(rows);
        group.subGroupsLoaded = true;

        // Host-based detections (sigma, yara, ossec) have no endpoints to group by, so
        // the pair aggregation comes back empty. Those rules open straight into alerts.
        if (!group.subGroups.length && !group.alertsLoaded) {
          await this.loadGroupAlerts(group);
        }
      } catch (error) {
        this.$root.showError(error);
      } finally {
        group.subGroupsLoading = false;
      }
    },

    async loadSubGroupAlerts(group, subGroup) {
      subGroup.alertsLoading = true;
      try {
        const query = await this.narrowQuery(this.buildQuery(), this.subGroupTerms(group, subGroup));
        const response = await this.$root.papi.get('events/', { params: {
          query: query,
          range: this.getDateRange(),
          format: this.i18n.timePickerSample,
          zone: this.zone,
          metricLimit: this.metricLimit,
          eventLimit: this.groupAlertLimit,
        }});

        if (response && response.data) {
          subGroup.alerts = this.processAlerts(response.data.events || []);
          subGroup.alertsLoaded = true;
          subGroup.alertsTruncated = subGroup.count > subGroup.alerts.length;
          this.lookupHostnames(subGroup.alerts);
        }
      } catch (error) {
        this.$root.showError(error);
      } finally {
        subGroup.alertsLoading = false;
      }
    },

    // True once a rule group has resolved to pairs rather than a flat alert list.
    hasSubGroups(group) {
      return group.kind === 'rule' && group.subGroups.length > 0;
    },

    // Escaping a value into OQL is the server's job; query/filtered returns the query
    // with the term applied, which keeps rule names containing quotes or colons safe.
    async narrowQuery(baseQuery, terms) {
      let query = baseQuery;
      for (const term of terms) {
        const response = await this.$root.papi.get('query/filtered', { params: {
          query: query,
          field: term.field,
          value: term.value,
          scalar: false,
          mode: 'INCLUDE',
        }});
        query = response.data;
      }
      return query;
    },

    async loadGroupAlerts(group) {
      group.alertsLoading = true;
      try {
        const query = await this.narrowQuery(this.buildQuery(), this.groupTerms(group));
        const response = await this.$root.papi.get('events/', { params: {
          query: query,
          range: this.getDateRange(),
          format: this.i18n.timePickerSample,
          zone: this.zone,
          metricLimit: this.metricLimit,
          eventLimit: this.groupAlertLimit,
        }});

        if (response && response.data) {
          group.alerts = this.processAlerts(response.data.events || []);
          group.alertsLoaded = true;
          // The group's exact total came from the aggregation; this only reports that
          // the fetched sample stopped short of it.
          group.alertsTruncated = group.count > group.alerts.length;
          this.lookupHostnames(group.alerts);
        }
      } catch (error) {
        this.$root.showError(error);
      } finally {
        group.alertsLoading = false;
      }
    },

    // Long groups render a capped slice until the user asks for the rest.
    getDisplayedAlerts(group) {
      if (group.showAll) return group.alerts;
      return group.alerts.slice(0, this.subGroupDisplayLimit);
    },

    shouldShowLoadMore(group) {
      return group.alerts.length > this.subGroupDisplayLimit;
    },

    toggleLoadMore(group) {
      group.showAll = !group.showAll;
    },

    getLoadMoreText(group) {
      if (group.showAll) return this.i18n.simpleAlertsShowFewer;
      return this.$root.localizeMessage('simpleAlertsShowAll', {
        count: this.formatCompactNumber(group.alerts.length),
      });
    },

    // A short "42 alerts, 3 hosts" style line for the collapsed group header.
    getGroupSummary(group) {
      const parts = [this.$root.localizeMessage('simpleAlertsGroupCount', {
        count: this.formatCompactNumber(group.count),
      })];

      if (group.kind === 'rule' && group.severityLabel) {
        parts.push(group.severityLabel);
      }
      if (group.alertsTruncated) {
        parts.push(this.$root.localizeMessage('simpleAlertsGroupSample', {
          count: this.formatCompactNumber(group.alerts.length),
        }));
      }
      return parts.join(' · ');
    },

    // Inside a rule > pair, the rule and both addresses are already named by the two
    // headers above, so the rows only need the time and the port pair.
    subGroupHeaders() {
      return [
        { title: this.i18n.time, value: 'timestamp' },
        { title: this.i18n.simpleAlertsPorts, value: 'sourcePort' },
      ];
    },

    // A rule group already names its rule in the header, so its rows show endpoints;
    // a source/destination group already names the pair, so its rows show the rule.
    groupHeaders(group) {
      const headers = [{ title: this.i18n.time, value: 'timestamp' }];
      if (group.kind === 'rule') {
        headers.push({ title: this.i18n.source, value: 'sourceIp' });
        headers.push({ title: this.i18n.destination, value: 'destIp' });
      } else {
        headers.push({ title: this.i18n.simpleAlertsRuleName, value: 'ruleName' });
      }
      return headers;
    },

    setGroupingMode(mode) {
      this.groupingMode = mode;
      this.groupAlerts = mode !== 'none';
      this.expandedGroups = [];
      this.saveLocalSettings();
      this.loadAlerts();
    },

    onFilterChanged() {
      this.saveLocalSettings();
      this.loadAlerts();
    },

    // Page-level preferences, stored the same way hunt.js stores its own, so a chosen
    // view and filter set survive a reload.
    saveSetting(name, value, defaultValue = null) {
      const item = SETTINGS_PREFIX + name;
      if (defaultValue == null || value != defaultValue) {
        localStorage[item] = value;
      } else {
        localStorage.removeItem(item);
      }
    },

    saveLocalSettings() {
      this.saveSetting('groupingMode', this.groupingMode, 'rule');
      this.saveSetting('filterStatus', this.filterStatus, 'active');
      this.saveSetting('filterSeverity', this.filterSeverity, 'all');
      this.saveSetting('filterTimeRange', this.filterTimeRange, '24h');
    },

    loadLocalSettings() {
      if (localStorage[SETTINGS_PREFIX + 'groupingMode']) {
        this.groupingMode = localStorage[SETTINGS_PREFIX + 'groupingMode'];
        this.groupAlerts = this.groupingMode !== 'none';
      }
      if (localStorage[SETTINGS_PREFIX + 'filterStatus']) this.filterStatus = localStorage[SETTINGS_PREFIX + 'filterStatus'];
      if (localStorage[SETTINGS_PREFIX + 'filterSeverity']) this.filterSeverity = localStorage[SETTINGS_PREFIX + 'filterSeverity'];
      if (localStorage[SETTINGS_PREFIX + 'filterTimeRange']) this.filterTimeRange = localStorage[SETTINGS_PREFIX + 'filterTimeRange'];
    },
  };
})();
