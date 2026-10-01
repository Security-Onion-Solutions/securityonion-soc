// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-alert-investigation', 'pages/alert-investigation.html');

const ALERT_INVESTIGATIONS_FIELD = 'event.so_investigations';

// Oldest first. Older alerts hold single values until their next investigation write converts them.
globalThis.alertManualInvestigations = function(alert) {
  if (!alert) return [];
  const list = value => (Array.isArray(value) ? value : (value === undefined || value === null || value === '' ? [] : [value]));
  const by = list(alert['event.investigated_by']);
  const times = list(alert['event.investigated_timestamp']);
  const older = list(alert['event.investigation_session_id'])
    .map((sessionId, i) => ({ sessionId: sessionId, by: by[i] || '', time: times[i] || '' }));
  const entries = list(alert[ALERT_INVESTIGATIONS_FIELD])
    .filter(entry => entry && typeof entry === 'object')
    .map(entry => ({ sessionId: entry.session_id, by: entry.user_id || '', time: entry.timestamp || '' }));
  const seen = new Set();
  return older.concat(entries).filter(inv => inv.sessionId && !seen.has(inv.sessionId) && seen.add(inv.sessionId));
};

// { id: bool } for the first MAX_SESSION_ACCESS_IDS; the rest stay unknown, never a no.
const MAX_SESSION_ACCESS_IDS = 50;
globalThis.fetchSessionAccess = async function(papi, sessionIds) {
  if (!sessionIds.length) return {};
  const response = await papi.post('/assistant/sessions/access', { sessionIds: sessionIds.slice(0, MAX_SESSION_ACCESS_IDS) });
  return response.data || {};
};

components.push({
  name: "alert-investigation", component: {
    template: '#component-alert-investigation',
    props: {
      alert: { type: Object, default: null },
      // A group's newest triaged alert; when set, the tab describes it instead of alert.
      triagedAlert: { type: Object, default: null },
      grouped: { type: Boolean, default: false },
      routeForQuery: { type: Function, required: true },
      newInvestigationLink: { type: Function, required: true },
    },
    data() {
      return {
        i18n: this.$root.i18n,
        summaries: {},
        userNames: {},
        // By soc_id, so re-renders reuse one new session id.
        newLinks: {},
        access: {},
        manualHeaders: [
          { title: this.$root.i18n.sessionId, value: 'sessionId', sortable: false },
          { title: this.$root.i18n.aiInvestigationInvestigator, value: 'by', sortable: false },
          { title: this.$root.i18n.startTime, value: 'time', sortable: false },
          { title: '', value: 'open', sortable: false },
        ],
      };
    },
    watch: {
      alert: { immediate: true, handler() { this.loadAll(); } },
      triagedAlert: { handler() { this.loadAll(); } },
    },
    methods: {
      loadAll() {
        this.load(this.automatedId());
        this.manualInvestigations().forEach(inv => this.loadUserName(inv.by));
        this.loadAccess();
      },
      async loadAccess() {
        this.access = {};
        const ids = this.manualInvestigations().filter(inv => !this.isMine(inv)).map(inv => inv.sessionId);
        if (!ids.length) return;
        try {
          this.access = await fetchSessionAccess(this.$root.papi, ids);
        } catch (error) {
          // Unknown leaves rows open; the server still enforces access.
        }
      },
      isMine(inv) {
        return !!this.$root.user && inv.by === this.$root.user.id;
      },
      blocked(inv) {
        return !this.isMine(inv) && this.access[inv.sessionId] === false;
      },
      privateLabel(inv) {
        return this.i18n.aiInvestigationPrivateTo.replace('{name}', this.userName(inv.by) || this.i18n.unknown);
      },
      subject() {
        return this.triagedAlert || this.alert;
      },
      triageField(name) {
        const subject = this.subject();
        return subject ? subject['event.so_alerttriage.' + name] : undefined;
      },
      automatedId() {
        return this.triageField('session_id') || '';
      },
      manualInvestigations() {
        return alertManualInvestigations(this.subject()).reverse();
      },
      async loadUserName(id) {
        if (!id || this.userNames[id]) return;
        const user = await this.$root.getUserById(id);
        this.userNames[id] = user ? this.$root.getUserDisplayName(user) : id;
      },
      userName(id) {
        return this.userNames[id] || id;
      },
      startLink() {
        const subject = this.subject();
        if (!subject || !subject.soc_id) return null;
        if (!this.newLinks[subject.soc_id]) this.newLinks[subject.soc_id] = this.newInvestigationLink(subject);
        return this.newLinks[subject.soc_id];
      },
      failedCount() {
        return this.triageField('failed_count') || 0;
      },
      acknowledged() {
        const subject = this.subject();
        return !!subject && String(subject['event.acknowledged']) === 'true';
      },
      groupNote() {
        return this.triagedAlert ? this.i18n.aiInvestigationGroupNewestTriaged : this.i18n.aiInvestigationGroupNewest;
      },
      summary(sessionId) {
        return this.summaries[sessionId] || { loading: true };
      },
      async load(sessionId) {
        if (!sessionId || this.summaries[sessionId]) return;
        this.summaries[sessionId] = { loading: true };
        try {
          const response = await this.$root.papi.get(`/assistant/sessions/${sessionId}`);
          this.summaries[sessionId] = this.summarize(response.data);
        } catch (error) {
          this.summaries[sessionId] = { error: error.message || String(error) };
        }
      },
      messageText(message) {
        if (message.contentStr) return message.contentStr;
        return (message.contentBlocks || []).filter(b => b.type === 'text').map(b => b.text).join('\n');
      },
      // Report is the agent's last text reply; notifications are its send_notification calls.
      summarize(data) {
        const history = (data && data.history) || [];
        const results = this.toolResults(history);
        let report = '';
        const notifications = [];
        for (const entry of history) {
          const message = entry.message || {};
          // Partial entries are replies still streaming.
          if (message.role !== 'assistant' || (entry.tags || []).includes('partial')) continue;
          const tools = (message.contentBlocks || []).filter(b => b.type === 'tool_use' && b.name === 'send_notification');
          for (const tool of tools) {
            const input = tool.input || {};
            const result = results[tool.id];
            notifications.push({
              title: input.title || '',
              summary: input.summary || '',
              severity: input.severity || 'info',
              failed: !!(result && result.failed),
              error: (result && result.error) || '',
            });
          }
          const text = this.messageText(message);
          if (text && !tools.length) report = text;
        }
        const last = history[history.length - 1];
        return {
          report: report,
          notifications: notifications,
          time: last ? last.createTime : '',
          agent: (data && data.session && data.session.model) || '',
        };
      },
      toolResults(history) {
        const results = {};
        for (const entry of history) {
          if (!(entry.tags || []).includes('tool_result')) continue;
          for (const block of ((entry.message || {}).contentBlocks || [])) {
            const result = block.toolResult;
            if (!result || !result.toolUseId) continue;
            const failed = !!result.isError || result.status === 'error' || result.status === 'rejected';
            const first = (result.content || [])[0] || {};
            results[result.toolUseId] = { failed: failed, error: failed ? (first.text || '') : '' };
          }
        }
        return results;
      },
      severityLabel(severity) {
        return String(severity || 'info').toUpperCase();
      },
      sessionLink(sessionId) {
        return { name: 'assistant', params: { sessionId: sessionId } };
      },
      automatedLink() {
        return this.alertSessionLink(this.automatedId());
      },
      manualLink(inv) {
        return this.alertSessionLink(inv.sessionId);
      },
      alertSessionLink(sessionId) {
        const link = this.sessionLink(sessionId);
        link.query = { alert: this.subject().soc_id };
        return link;
      },
      bucketLink() {
        return this.routeForQuery('event.so_alerttriage.session_id:"' + this.automatedId() + '"');
      },
      failedLabel() {
        return this.i18n.aiInvestigationFailedAttempts.replace('{count}', this.failedCount());
      },
      formatMarkdown(text) {
        return text ? this.$root.formatMarkdown(text) : '';
      },
    },
  }
});
