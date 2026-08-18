// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts page methods: pivots to the pages that already own a task — the
// detection page for tuning a noisy rule, and the job page for reviewing a packet
// capture. Merged into the component's methods by simplealerts.js.

globalThis.SimpleAlertsPivots = (function() {
  // Strelka detections have no tuning tab; their overrides live on the source tab.
  const SOURCE_TAB_ENGINES = ['strelka'];

  // The window of packets to capture either side of the alert.
  const PCAP_WINDOW_MS = 30000;

  return {
    // Resolves the detection behind a rule and opens it on its tuning tab, the same
    // pivot hunt.js offers from its quick-action menu. Suppression is expressed as a
    // detection override, so it belongs on that page rather than being duplicated here.
    async tuneDetection(item) {
      const uuid = item && (item.ruleUuid || (item.payload && item.payload['rule.uuid']));
      if (!uuid) {
        this.$root.showWarning(this.i18n.simpleAlertsNoDetection);
        return;
      }

      this.actionLoading = true;
      try {
        const response = await this.$root.papi.get('detection/public/' + encodeURIComponent(uuid));
        const detection = response && response.data;
        if (!detection || !detection.id) {
          this.$root.showWarning(this.i18n.simpleAlertsNoDetection);
          return;
        }

        const tab = SOURCE_TAB_ENGINES.indexOf(detection.engine) !== -1 ? 'source' : 'tuning';
        this.$router.push({ name: 'detection', params: { id: detection.id }, query: { tab: tab } });
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.actionLoading = false;
      }
    },

    canRequestPcap(alert) {
      return !!(alert && alert.sourceIp && alert.destIp && this.pcapNodeId(alert));
    },

    // The sensor that observed the traffic, and so the node holding the packets.
    pcapNodeId(alert) {
      if (!alert || !alert.payload) return null;
      return alert.payload['observer.name'] || alert.payload['agent.name'] || null;
    },

    // Enqueues the capture and hands off to the job page, which already renders packets,
    // hex and the download stream. Polling and rendering them here would duplicate it.
    async requestPcap(alert) {
      if (!this.canRequestPcap(alert)) {
        this.$root.showWarning(this.i18n.simpleAlertsPcapUnavailable);
        return;
      }

      this.pcapLoading = true;
      try {
        const alertTime = moment(alert.timestamp);
        const filter = {
          beginTime: alertTime.clone().subtract(PCAP_WINDOW_MS, 'ms').toISOString(),
          endTime: alertTime.clone().add(PCAP_WINDOW_MS, 'ms').toISOString(),
          srcIp: alert.sourceIp,
          dstIp: alert.destIp,
        };
        if (alert.sourcePort) filter.srcPort = parseInt(alert.sourcePort, 10);
        if (alert.destPort) filter.dstPort = parseInt(alert.destPort, 10);

        const response = await this.$root.papi.post('job/', {
          nodeId: this.pcapNodeId(alert),
          filter: filter,
        });

        const jobId = response && response.data ? response.data.id : null;
        if (!jobId) {
          this.$root.showWarning(this.i18n.simpleAlertsPcapFailed);
          return;
        }

        this.detailsDialog = false;
        this.$router.push({ name: 'job', params: { jobId: String(jobId) } });
      } catch (error) {
        this.$root.showError(error);
      } finally {
        this.pcapLoading = false;
      }
    },
  };
})();
