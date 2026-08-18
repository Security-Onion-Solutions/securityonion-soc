// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts page methods: selection, acknowledge and escalate. The events/ack route
// takes a filter rather than a list of ids, so a whole-group action is a single request
// covering every matching alert, not just the page that happens to be loaded. Merged
// into the component's methods by simplealerts.js.

globalThis.SimpleAlertsActions = (function() {
  const SAFE_TITLE_MAX_LENGTH = 100;

  return {
    toggleSelectionMode() {
      this.selectionMode = !this.selectionMode;
      if (!this.selectionMode) this.clearSelection();
    },

    clearSelection() {
      this.selectedAlertIds = {};
      this.selectedGroupKeys = {};
    },

    isAlertSelected(alert) {
      return !!this.selectedAlertIds[alert.id];
    },

    toggleAlertSelection(alert) {
      if (this.selectedAlertIds[alert.id]) {
        delete this.selectedAlertIds[alert.id];
      } else {
        this.selectedAlertIds[alert.id] = true;
      }
    },

    isGroupSelected(group) {
      return !!this.selectedGroupKeys[group.key];
    },

    // Selecting a group means every alert it represents, including those never fetched,
    // so it is tracked separately from individually picked alerts rather than by
    // ticking the rows that happen to be on screen.
    toggleGroupSelection(group) {
      if (this.selectedGroupKeys[group.key]) {
        delete this.selectedGroupKeys[group.key];
      } else {
        this.selectedGroupKeys[group.key] = true;
      }
    },

    selectedGroups() {
      return this.activeGroups().filter(g => this.selectedGroupKeys[g.key]);
    },

    selectedAlertCount() {
      return Object.keys(this.selectedAlertIds).length;
    },

    // Groups contribute their full count, which is why this can exceed what is on screen.
    selectionSummary() {
      const groups = this.selectedGroups();
      const fromGroups = groups.reduce((sum, g) => sum + (g.count || 0), 0);
      return {
        alerts: this.selectedAlertCount(),
        groups: groups.length,
        total: this.selectedAlertCount() + fromGroups,
      };
    },

    hasSelection() {
      return this.selectedAlertCount() > 0 || this.selectedGroups().length > 0;
    },

    // Mirrors hunt.js's buildCase so an escalation from either page produces the same
    // case shape.
    buildCase(alert) {
      let title = alert.ruleName || this.i18n.eventCaseTitle;
      if (title.length > SAFE_TITLE_MAX_LENGTH) {
        title = title.substring(0, SAFE_TITLE_MAX_LENGTH - 3) + '...';
      }

      return {
        title: title,
        description: this.i18n.caseEscalatedDescription,
        severity: alert.severity ? String(alert.severity) : '',
        template: alert.payload && alert.payload['rule.case_template']
          ? String(alert.payload['rule.case_template']) : '',
      };
    },

    // The shared shape of every events/ack request this page makes.
    ackRequest(searchFilter, eventFilter, acknowledge, escalate) {
      return {
        searchFilter: searchFilter,
        eventFilter: eventFilter,
        dateRange: this.getDateRange(),
        dateRangeFormat: this.i18n.timePickerSample,
        timezone: this.zone,
        acknowledge: acknowledge,
        escalate: escalate,
      };
    },

    async postAck(request) {
      const response = await this.$root.papi.post('events/ack', request);
      if (response && response.data && response.data.errors && response.data.errors.length > 0) {
        this.$root.showWarning(this.i18n.ackPartialSuccess);
      }
      return response;
    },

    // Creates the case and attaches the matching events to it, returning the case id.
    async escalateToCase(alert, eventFilter) {
      const caseResponse = await this.$root.papi.post('case/', this.buildCase(alert));
      const caseId = caseResponse && caseResponse.data ? caseResponse.data.id : null;
      if (!caseId) return null;

      await this.$root.papi.post('case/events', {
        fields: eventFilter,
        caseId: caseId,
        acknowledged: this.filterStatus === 'acknowledged',
        escalated: this.filterStatus === 'escalated',
        dateRange: this.getDateRange(),
        dateRangeFormat: this.i18n.timePickerSample,
        timezone: this.zone,
      });

      return caseId;
    },

    async acknowledgeAlert(alert) {
      await this.applyAlertAction(alert, true, false);
    },

    async escalateAlert(alert) {
      await this.applyAlertAction(alert, true, true);
    },

    async applyAlertAction(alert, acknowledge, escalate) {
      this.actionLoading = true;
      this.$root.startLoading();
      try {
        const eventFilter = { 'soc_id': alert.id };
        if (escalate) {
          await this.escalateToCase(alert, eventFilter);
        }
        await this.postAck(this.ackRequest(this.buildQuery(), eventFilter, acknowledge, escalate));

        this.$root.showTip(escalate ? this.i18n.escalatedSingleTip : this.i18n.ackSingleTip);
        this.removeAlertFromView(alert);
        this.detailsDialog = false;
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.actionLoading = false;
        this.$root.stopLoading();
      }
    },

    // One request for the whole group. The filter is the group's own identity, so alerts
    // that were never fetched are included, which is what selecting a group implies.
    async applyGroupAction(group, acknowledge, escalate) {
      const eventFilter = {};
      this.groupTerms(group).forEach(term => { eventFilter[term.field] = term.value; });

      if (escalate) {
        const sample = group.alerts && group.alerts.length
          ? group.alerts[0]
          : { ruleName: group.ruleName, severity: null, payload: {} };
        await this.escalateToCase(sample, eventFilter);
      }
      await this.postAck(this.ackRequest(this.buildQuery(), eventFilter, acknowledge, escalate));
    },

    async applySelection(acknowledge, escalate) {
      if (!this.hasSelection()) return;

      this.actionLoading = true;
      this.$root.startLoading();
      try {
        for (const group of this.selectedGroups()) {
          await this.applyGroupAction(group, acknowledge, escalate);
        }

        for (const alert of this.selectedAlerts()) {
          const eventFilter = { 'soc_id': alert.id };
          if (escalate) await this.escalateToCase(alert, eventFilter);
          await this.postAck(this.ackRequest(this.buildQuery(), eventFilter, acknowledge, escalate));
        }

        const summary = this.selectionSummary();
        this.$root.showTip(summary.total > 1
          ? (escalate ? this.i18n.escalatedMultipleTip : this.i18n.ackMultipleTip)
          : (escalate ? this.i18n.escalatedSingleTip : this.i18n.ackSingleTip));

        this.clearSelection();
        this.selectionMode = false;
        await this.loadAlerts();
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.actionLoading = false;
        this.$root.stopLoading();
      }
    },

    // Individually selected alerts, resolved from whichever view holds them.
    selectedAlerts() {
      const found = [];
      const seen = {};
      const consider = (alert) => {
        if (this.selectedAlertIds[alert.id] && !seen[alert.id]) {
          seen[alert.id] = true;
          found.push(alert);
        }
      };

      this.alerts.forEach(consider);
      this.alertGroups.forEach(g => g.alerts.forEach(consider));
      this.sourceDestGroups.forEach(g => g.alerts.forEach(consider));
      return found;
    },

    bulkAcknowledge() {
      return this.applySelection(true, false);
    },

    bulkEscalate() {
      return this.applySelection(true, true);
    },

    // Drops an actioned alert from whatever list is on screen, so the row disappears
    // without waiting for a refetch.
    removeAlertFromView(alert) {
      const drop = (list) => {
        const idx = list.indexOf(alert);
        if (idx !== -1) list.splice(idx, 1);
      };

      drop(this.alerts);
      this.alertGroups.forEach(g => drop(g.alerts));
      this.sourceDestGroups.forEach(g => drop(g.alerts));
      delete this.selectedAlertIds[alert.id];
    },
  };
})();
