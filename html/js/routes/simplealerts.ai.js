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

    // The alert fields the configured investigation prompt can interpolate. Unlike the
    // hunt screen's version these are handed to the chat component in memory rather than
    // through the URL, so there is no need to strip the fields the prompt does not use --
    // generateInvestigationPrompt only substitutes the placeholders the prompt contains.
    buildInvestigationFields(alert) {
      const payload = (alert && alert.payload) || {};
      return {
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
    },

    // Opens the investigation inside the details dialog rather than navigating to the
    // assistant page: the analyst keeps the alert, its fields and its playbook answers
    // in view while the assistant works on it. An alert already investigated resumes its
    // session instead of starting a second one for the same alert.
    aiInvestigate(alert) {
      if (!this.aiEnabled) return;

      const payload = (alert && alert.payload) || {};
      if (!payload['soc_id']) {
        this.$root.showError(this.i18n.aiInvestigationUnableToIdentify);
        return;
      }

      // Handing an alert to the assistant is what the data privacy notice covers, so it
      // has to be accepted first. Showing it replaces the whole page (index.html swaps it
      // in for the router view), so it is raised instead of opening the panel rather than
      // over it -- opening first would only lose the dialog when the page unmounts. It is
      // the same notice and acknowledgement the assistant page uses, so a user who has
      // accepted it there never sees it here.
      if (localStorage.getItem(ONIONAI_DISCLAIMER_KEY) !== 'true') {
        this.$root.showDisclaimer(this.i18n.assistantDisclaimerMessage,
          this.i18n.assistantDisclaimerTitle, this.i18n.getStarted, ONIONAI_DISCLAIMER_KEY);
        return;
      }

      const existing = this.aiInvestigationSessionId(alert);
      this.aiChatAlert = alert;
      this.aiChatSessionId = existing || null;
      this.aiChatFields = existing ? null : this.buildInvestigationFields(alert);
      // Remounts the chat component when switching alerts or resuming a different
      // session, so a stale conversation can never be shown against a new alert.
      this.aiChatKey += 1;
      this.aiChatOpen = true;
    },

    closeAiChat() {
      this.aiChatOpen = false;
      this.aiChatAlert = null;
      this.aiChatFields = null;
      this.aiChatSessionId = null;
    },

    // The backend records the session against the alert; mirroring it locally means
    // reopening the alert in this session resumes the conversation rather than starting
    // a second investigation of the same alert.
    onAiSessionStarted(sessionId) {
      this.aiChatSessionId = sessionId;
      const alert = this.aiChatAlert;
      if (!alert || !alert.payload) return;
      alert.payload['event.investigated'] = true;
      alert.payload['event.investigation_session_id'] = sessionId;
    },

    // Hands the conversation off to the full assistant page, which loads it by id.
    openAiSessionInAssistant() {
      if (!this.aiChatSessionId) return;
      this.detailsDialog = false;
      this.$router.push({ name: 'assistant', params: { sessionId: this.aiChatSessionId } });
    },
  };
})();
