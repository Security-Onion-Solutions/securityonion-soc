// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Simple Alerts page methods: guided analysis for the alert shown in the details dialog.
// The request sequence and query handling live in js/playbook.js, shared with the
// hunt/alerts screen, so both pages answer a playbook identically. Merged into the
// component's methods by simplealerts.js.

globalThis.SimpleAlertsPlaybook = (function() {
  return {
    // The time the server windows its lookups on: the alert document's own timestamp
    // where present, otherwise the event time.
    playbookTimestamp(alert) {
      return (alert.payload && alert.payload['soc_timestamp']) || alert.timestamp;
    },

    async loadAlertPlaybook(alert) {
      if (!alert || alert.playbookLoading || 'playbooks' in alert) return;

      const socId = alert.payload && alert.payload['soc_id'];
      if (!socId) {
        alert.playbookErr = true;
        return;
      }

      alert.playbookLoading = true;
      alert.playbooks = null;
      alert.questions = [];

      let playbooks = null;
      let playbookErr = false;
      let convertPromise;
      const convertAbort = new AbortController();

      try {
        const ts = this.playbookTimestamp(alert);
        convertPromise = PlaybookRunner.startConversion(this.$root.papi, socId, ts, convertAbort);
        playbooks = await PlaybookRunner.fetchSkeleton(
          this.$root.papi, socId, ts, alert.ruleUuid);
      } catch (e) {
        playbookErr = true;
        playbooks = null;
      }

      // a detection with no playbook is a valid state, not a failure
      alert.playbookNone = !playbookErr && !playbooks;
      alert.playbookErr = playbookErr;
      alert.playbooks = playbooks;
      alert.playbookLoading = false;

      if (!playbooks) {
        convertAbort.abort();
        return;
      }

      // render the questions immediately; their answers arrive as the queries finish
      alert.questions = PlaybookRunner.collectQuestions(playbooks);
      // Open the first straight away so the section does not read as empty while the
      // queries run; the rest open themselves as they find something.
      this.expandedQuestions = alert.questions.length ? [0] : [];
      await this.answerAlertQuestions(alert, convertPromise);
    },

    async answerAlertQuestions(alert, convertPromise) {
      let converted = null;
      try {
        const response = await convertPromise;
        converted = (response && response.data) || [];
      } catch (e) {
        converted = null;
      }

      PlaybookRunner.attachConvertedQueries(alert.playbooks, converted, this.i18n);
      PlaybookRunner.markUnanswerableQuestions(alert.questions);

      await PlaybookRunner.runQuestions(alert.questions,
        (question, index) => this.runAlertQuestion(alert, question, index));
    },

    async runAlertQuestion(alert, question, index) {
      if (question.status === PlaybookRunner.STATUS_ERROR) return;

      // a question without a range is answered by the alert itself; copy the fields
      // without the playbook bookkeeping so the answer does not reference itself
      if (!question.range) {
        question.queryResults = [{
          payload: Object.assign({}, alert.payload),
          timestamp: alert.timestamp,
        }];
        question.status = PlaybookRunner.STATUS_DONE;
        this.revealAnsweredQuestion(question, index);
        return;
      }

      await PlaybookRunner.runQuery(this.$root.papi, question, this.playbookTimestamp(alert));
      this.revealAnsweredQuestion(question, index);
    },

    // A question that found something opens itself, as it does on the hunt screen.
    // Without this the answers are fetched but stay behind a collapsed panel, which
    // reads as the playbook having produced nothing.
    revealAnsweredQuestion(question, index) {
      if (index === undefined || index === null) return;
      if (!question.queryResults || question.queryResults.length === 0) return;
      if (this.expandedQuestions.indexOf(index) === -1) {
        this.expandedQuestions.push(index);
      }
    },

    hasPlaybook(alert) {
      return !!(alert && alert.questions && alert.questions.length);
    },

    questionStatusColor(question) {
      switch (question.status) {
        case PlaybookRunner.STATUS_DONE:
          return question.queryResults && question.queryResults.length ? 'success' : 'info';
        case PlaybookRunner.STATUS_ERROR:
          return 'error';
        default:
          return 'info';
      }
    },

    questionAnswerCount(question) {
      return question.queryResults ? question.queryResults.length : 0;
    },

    isQuestionRunning(question) {
      return question.status === PlaybookRunner.STATUS_RUNNING;
    },

    // The columns a question's answers render into, as assembled during conversion.
    questionColumns(question) {
      return question.fields || [];
    },

    // Answers are rendered through v-data-table rather than a hand-written table:
    // page templates are parsed as HTML, and raw <thead>/<tbody> inside a <v-table>
    // are discarded by the parser's table-nesting rules, leaving an empty table.
    questionHeaders(question) {
      return this.questionColumns(question).map(field => ({ title: field, value: field }));
    },

    questionRows(question) {
      const columns = this.questionColumns(question);
      return (question.queryResults || []).map(answer => {
        const row = {};
        columns.forEach(field => { row[field] = this.questionRowValue(answer, field); });
        return row;
      });
    },

    questionRowValue(answer, field) {
      if (!answer || !answer.payload) return '';
      if (field === '@timestamp') return answer.timestamp;
      const value = answer.payload[field];
      return value === undefined || value === null ? '' : value;
    },
  };
})();
