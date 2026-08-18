// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts page methods: the AI features, which require the 'oai' license feature
// and the assistant to be enabled server-side. Everything here is additive — with no
// license the page behaves exactly as it does now, with the AI controls absent rather
// than present-but-disabled. Merged into the component's methods by simplealerts.js.

globalThis.SimpleAlertsAi = (function() {
  return {
    // Called back by $root.loadParameters('assistant', ...). The licence is checked here
    // rather than at the call site so the flag is never read before the params land.
    //
    // Only one section is requested even though two are needed: loadParameters keeps a
    // single pending callback, so a second call before the parameters arrive silently
    // replaces the first. The detection section is read directly instead.
    initAssistant(params) {
      this.assistantEnabled = !!(params && params['enabled']);
      this.investigationMsg = (params && params['investigationPrompt']) || '';
      this.aiEnabled = this.$root.isLicensed('oai') && this.assistantEnabled;

      const detection = (this.$root.parameters && this.$root.parameters['detection']) || {};
      this.showUnreviewedAiSummaries = !!detection['showUnreviewedAiSummaries'];
    },

    // A detection's AI summary explains in plain language what the rule looks for, which
    // is the question a triage view exists to answer. Unreviewed summaries stay hidden
    // unless the grid opts in, matching the detection page.
    showAiSummary(alert) {
      if (!this.aiEnabled || !alert) return false;
      return !!(alert.aiSummary && (alert.aiSummaryReviewed || this.showUnreviewedAiSummaries));
    },

    // Fetched per rule rather than per alert, and cached, since every alert for a rule
    // shares the same detection.
    async loadAiSummary(alert) {
      if (!this.aiEnabled || !alert || alert.aiSummaryLoaded) return;

      const uuid = alert.ruleUuid || (alert.payload && alert.payload['rule.uuid']);
      if (!uuid) return;

      alert.aiSummaryLoaded = true;
      const cached = this.aiSummaryCache[uuid];
      if (cached) {
        alert.aiSummary = cached.aiSummary;
        alert.aiSummaryReviewed = cached.aiSummaryReviewed;
        return;
      }

      try {
        const response = await this.$root.papi.get('detection/public/' + encodeURIComponent(uuid));
        const detection = (response && response.data) || {};
        const summary = {
          aiSummary: detection.aiSummary || '',
          aiSummaryReviewed: !!detection.aiSummaryReviewed,
        };
        this.aiSummaryCache[uuid] = summary;
        alert.aiSummary = summary.aiSummary;
        alert.aiSummaryReviewed = summary.aiSummaryReviewed;
      } catch (error) {
        // A missing summary is not worth interrupting triage over; the section simply
        // does not appear.
        alert.aiSummary = '';
      }
    },

    // Mirrors hunt.js: an alert already investigated reopens its session rather than
    // starting a second one for the same alert.
    aiInvestigationSessionId(alert) {
      const payload = (alert && alert.payload) || {};
      return payload['event.investigated'] ? payload['event.investigation_session_id'] : null;
    },

    isAiInvestigated(alert) {
      return !!this.aiInvestigationSessionId(alert);
    },

    aiInvestigateTooltip(alert) {
      return this.isAiInvestigated(alert) ? this.i18n.aiInvestigateView : this.i18n.aiInvestigate;
    },

    // Only the fields the configured investigation prompt actually interpolates are
    // passed along, so the assistant is not handed alert data the prompt never asked for.
    buildInvestigationQuery(alert) {
      const payload = (alert && alert.payload) || {};
      const alertData = {
        socId: payload['soc_id'],
        ruleUuid: payload['rule.uuid'],
        ruleName: payload['rule.name'],
        severity: payload['event.severity_label'],
        timestamp: payload['soc_timestamp'] || payload['@timestamp'],
        sourceIp: payload['source.ip'],
        destIp: payload['destination.ip'],
        eventModule: payload['event.module'],
        eventDataset: payload['event.dataset'],
        message: payload['message'],
        alertRule: payload['rule.rule'],
      };

      const query = { investigation: true };
      Object.keys(alertData).forEach(key => {
        if (this.investigationMsg && this.investigationMsg.includes('{' + key + '}')) {
          query[key] = alertData[key];
        }
      });
      return query;
    },

    // crypto.randomUUID is only defined in a secure context, so it is absent over plain
    // http and in some embedded browsers. Falling back to getRandomValues keeps the
    // session id unguessable rather than dropping to Math.random.
    generateChatId() {
      if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
      }

      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
      bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
      const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
      return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
              hex.slice(16, 20), hex.slice(20)].join('-');
    },

    aiInvestigate(alert) {
      if (!this.aiEnabled) return;

      const payload = (alert && alert.payload) || {};
      if (!payload['soc_id']) {
        this.$root.showError(this.i18n.aiInvestigationUnableToIdentify);
        return;
      }

      const existing = this.aiInvestigationSessionId(alert);
      if (existing) {
        this.$router.push({ name: 'assistant', params: { sessionId: existing } });
        return;
      }

      this.detailsDialog = false;
      this.$router.push({
        name: 'assistant',
        params: { sessionId: this.generateChatId() },
        query: this.buildInvestigationQuery(alert),
      });
    },
  };
})();
