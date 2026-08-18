// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Guided analysis: fetching a detection's playbook questions, attaching the converted
// queries to them, and running those queries. Shared by the hunt/alerts screen and the
// Simple Alerts page so both answer a playbook the same way.
//
// The pages keep their own presentation state; this module only owns the parts that must
// agree between them — the skeleton-then-convert request pair, matching converted
// playbooks back to their questions, and the bounded query runner.

globalThis.PlaybookRunner = (function() {
  const QUESTION_STATUS_RUNNING = 'running';
  const QUESTION_STATUS_DONE = 'done';
  const QUESTION_STATUS_ERROR = 'error';

  // Playbook queries are relatively expensive, so only a few run at a time.
  const MAX_CONCURRENT_QUERIES = 4;

  return {
    STATUS_RUNNING: QUESTION_STATUS_RUNNING,
    STATUS_DONE: QUESTION_STATUS_DONE,
    STATUS_ERROR: QUESTION_STATUS_ERROR,

    // Issues the slow conversion so it overlaps the skeleton fetch. Deliberately not
    // async: callers start it inside their own try block, so a request layer that fails
    // outright is reported without yielding to the microtask queue first.
    startConversion(papi, socId, ts, abort) {
      const promise = papi.get(
        `playbook/event/${socId}?stage=convert&ts=${encodeURIComponent(ts)}`,
        { signal: abort.signal });
      if (promise && typeof promise.catch === 'function') {
        promise.catch(() => {}); // consumed later by attachConvertedQueries
      }
      return promise;
    },

    // Fetches the questions themselves. Returns null both when the request failed and
    // when the detection genuinely has no playbook; the caller distinguishes those,
    // since having none is a valid state rather than a failure.
    async fetchSkeleton(papi, socId, ts, ruleUuid) {
      // rule.uuid allows the skeleton to come from the cheaper detection route
      const response = ruleUuid
        ? await papi.get(`playbook/detection/${encodeURIComponent(ruleUuid)}`)
        : await papi.get(`playbook/event/${socId}?stage=skeleton&ts=${encodeURIComponent(ts)}`);

      const playbooks = response.data;
      return (!playbooks || playbooks.length === 0) ? null : playbooks;
    },

    // Flattens a playbook list into the question list a page renders, marking each as
    // running so the UI can show progress before any query returns.
    collectQuestions(playbooks) {
      const questions = [];
      for (const pb of playbooks || []) {
        for (const q of pb.questions || []) {
          q.status = QUESTION_STATUS_RUNNING;
          questions.push(q);
        }
      }
      return questions;
    },

    // Copies each converted query onto its question. Playbooks are matched strictly by
    // id: a positional guess could attach another playbook's queries to this one.
    attachConvertedQueries(playbooks, converted, i18n) {
      if (!converted) return;

      const convertedById = {};
      for (const pb of converted) {
        if (pb.id) convertedById[pb.id] = pb;
      }

      for (const pb of playbooks) {
        const conv = convertedById[pb.id];

        for (let i = 0; i < pb.questions.length; i++) {
          const q = pb.questions[i];
          const cq = conv && conv.questions ? conv.questions[i] : null;
          if (!cq || !cq.oqlQuery) continue;

          q.oqlQuery = cq.oqlQuery;
          q.queryFields = cq.fields || [];
          q.isAggregate = !!cq.isAggregate;
          q.fields = q.isAggregate
            ? [i18n.count, ...q.queryFields]
            : ['@timestamp', ...q.queryFields];
        }
      }
    },

    // A ranged question cannot be answered without a converted query; a rangeless one is
    // answered by the alert itself and only needs a column to render.
    markUnanswerableQuestions(questions) {
      for (const q of questions) {
        if (q.range && !q.oqlQuery) {
          q.queryResults = [];
          q.status = QUESTION_STATUS_ERROR;
        } else if (!q.range && !q.fields) {
          q.fields = ['soc_timestamp'];
        }
      }
    },

    // Runs `run(question, index)` over every question, a few at a time.
    async runQuestions(questions, run) {
      const queue = questions.map((q, qi) => [q, qi]);
      const workers = Array.from(
        { length: Math.min(MAX_CONCURRENT_QUERIES, queue.length) },
        async () => {
          while (queue.length > 0) {
            const [q, qi] = queue.shift();
            await run(q, qi);
          }
        });
      await Promise.all(workers);
    },

    // Executes one ranged question and records its answer on the question.
    async runQuery(papi, question, ts) {
      if (question.status === QUESTION_STATUS_ERROR) return;

      question.status = QUESTION_STATUS_RUNNING;
      try {
        const response = await papi.post(`playbook/question?ts=${encodeURIComponent(ts)}`, {
          range: question.range,
          oqlQuery: question.oqlQuery,
          fields: question.queryFields,
          isAggregate: question.isAggregate,
        });
        question.queryResults = response.data.queryResults || [];
        question.status = QUESTION_STATUS_DONE;
      } catch (e) {
        question.queryResults = [];
        question.status = QUESTION_STATUS_ERROR;
      }
    },
  };
})();
