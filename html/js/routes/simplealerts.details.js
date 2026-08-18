// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts page methods: the single-alert details dialog. Merged into the
// component's methods by simplealerts.js.

globalThis.SimpleAlertsDetails = (function() {
  // Fields already surfaced by the dialog's own header, chips and network panel; the
  // full field list omits them rather than repeating them.
  const PROMOTED_FIELDS = [
    'rule.name', 'rule.uuid', 'rule.rule', 'rule.text',
    'event.severity_label', 'event.severity', 'event.module', 'event.category',
    'event.acknowledged', 'event.escalated', 'event.dismissed',
    'source.ip', 'source.port', 'destination.ip', 'destination.port',
  ].concat(['source', 'destination'].reduce((fields, prefix) => fields.concat([
    // the network panel already renders these as a formatted location
    prefix + '.geo.city_name',
    prefix + '.geo.region_iso_code',
    prefix + '.geo.region_name',
    prefix + '.geo.country_name',
    prefix + '.geo.country_iso_code',
    prefix + '.as.organization.name',
    prefix + '.as.organization',
  ]), []));

  return {
    showDetails(alert) {
      this.selectedAlertDetails = alert;
      this.detailsDialog = true;
      // Guided analysis runs several queries, so it starts only once the analyst has
      // actually opened the alert, and only once per alert.
      this.loadAlertPlaybook(alert);
      // No-op without the licence; see simplealerts.ai.js.
      this.loadAiSummary(alert);
    },

    closeDetails() {
      this.detailsDialog = false;
    },

    // Everything not already promoted into the dialog chrome, sorted so the layout is
    // stable between alerts rather than following document order.
    getDetailFields(alert) {
      if (!alert || !alert.payload) return [];

      return Object.keys(alert.payload)
        .filter(key => PROMOTED_FIELDS.indexOf(key) === -1)
        .filter(key => {
          const value = alert.payload[key];
          return value !== null && value !== undefined && value !== '';
        })
        .sort()
        .map(key => ({ key: key, value: alert.payload[key] }));
    },

    // Source and destination as a pair of panels, skipped entirely for host-based
    // alerts which have no network dimension to show.
    getEndpoints(alert) {
      if (!alert || alert.isHostBased) return [];

      return [
        {
          role: this.i18n.source,
          ip: alert.sourceIp,
          port: alert.sourcePort,
          portLabel: this.i18n.simpleAlertsSourcePort,
          geo: this.formatGeoInfo(alert.sourceGeo, alert.sourceIp),
          isPrivate: this.isPrivateIP(alert.sourceIp),
        },
        {
          role: this.i18n.destination,
          ip: alert.destIp,
          port: alert.destPort,
          portLabel: this.i18n.simpleAlertsDestinationPort,
          geo: this.formatGeoInfo(alert.destGeo, alert.destIp),
          isPrivate: this.isPrivateIP(alert.destIp),
        },
      ].filter(e => e.ip);
    },

    // Opens the alert in the expert-mode hunt screen, reusing that page's own route
    // shape so the query and time range carry over.
    getHuntRoute(alert) {
      if (!alert) return null;
      return {
        path: '/alerts',
        query: {
          q: 'tags:alert AND soc_id:"' + String(alert.id).replace(/"/g, '\\"') + '"',
          t: this.getDateRange(),
          z: this.zone,
        },
      };
    },

    async copyAlertId(alert) {
      if (!alert || !alert.id) return;
      try {
        await navigator.clipboard.writeText(String(alert.id));
        this.$root.showTip(this.i18n.simpleAlertsCopied);
      } catch (error) {
        this.$root.showError(error);
      }
    },
  };
})();
