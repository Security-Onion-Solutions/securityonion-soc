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
        (question) => this.runAlertQuestion(alert, question));
    },

    async runAlertQuestion(alert, question) {
      if (question.status === PlaybookRunner.STATUS_ERROR) return;

      // a question without a range is answered by the alert itself; copy the fields
      // without the playbook bookkeeping so the answer does not reference itself
      if (!question.range) {
        question.queryResults = [{
          payload: Object.assign({}, alert.payload),
          timestamp: alert.timestamp,
        }];
        question.status = PlaybookRunner.STATUS_DONE;
        return;
      }

      await PlaybookRunner.runQuery(this.$root.papi, question, this.playbookTimestamp(alert));
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

    questionRowValue(answer, field) {
      if (!answer || !answer.payload) return '';
      if (field === '@timestamp') return answer.timestamp;
      const value = answer.payload[field];
      return value === undefined || value === null ? '' : value;
    },
  };
})();
