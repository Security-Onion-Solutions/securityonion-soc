// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const FILTER_INCLUDE = 'INCLUDE';
const FILTER_EXCLUDE = 'EXCLUDE';
const FILTER_EXACT = 'EXACT';
const FILTER_DRILLDOWN = 'DRILLDOWN';

export default {
  applyQuerySubstitutions(queries) {
    if (Array.isArray(queries)) {
      queries.forEach(query => {
        query.query = query.query.replace(/\{myId\}/g, this.$root.user.id);
      });

      return queries;
    } else {
      return [];
    }
  },
  reconstructQuery() {
    if (this.isAdvanced() && !this.showFullQuery) {
      this.query = this.querySearch + " " + this.queryRemainder;
    }
  },
  submitQuery() {
    this.reconstructQuery();
    this.hunt();
  },
  queryModified() {
    this.reconstructQuery();
    return this.notifyInputsChanged();
  },
  addMRUQuery(query) {
    if (query && query.length > 1 && this.isAdvanced()) {
      var existingIndex = this.mruQueries.indexOf(query);
      if (existingIndex >= 0) {
        this.mruQueries.splice(existingIndex, 1);
      }
      this.mruQueries.unshift(query);
      while (this.mruQueries.length > this.mruQueryLimit) {
        this.mruQueries.pop();
      }
      this.saveLocalSettings();
    }
  },
  async getQuery() {
    var q = "";
    if (this.queryBaseFilter.length > 0) {
      q = this.queryBaseFilter;
    }

    if (Array.isArray(this.filterToggles)) {
      for (var i = 0; i < this.filterToggles.length; i++) {
        filter = this.filterToggles[i];

        if (filter.enabled) {
          if (q.length > 0) {
            q = q + " AND ";
          }
          q = q + filter.filter;
        } else if (filter.exclusive) {
          if (q.length > 0) {
            q = q + " AND ";
          }
          q = q + "NOT " + filter.filter;
        }
      }
    }

    if (q.length > 0) {
      const response = await this.$root.papi.get('query/filtered', { params: {
        query: this.query,
        field: "",
        value: q,
        scalar: true,
        mode: FILTER_INCLUDE,
        condense: true,
      }});

      return response.data;
    }
    return this.query;
  },
  isComplexQuery(query) {
    // Test for a query containing opening parenthesis outside of a double quoted value string.
    var quoting = false;
    var escaping = false;
    for (var idx = 0; idx < query.length; idx++) {
      var ch = query[idx];
      if (ch == '"' && !escaping) {
        quoting = !quoting;
      } else if (ch == '(' && !quoting) {
        return true;
      }

      if (ch == '\\') {
        escaping = !escaping;
      } else {
        escaping = false;
      }
    }
    return false;
  },
  buildDetectionEngineHuntQuery(engine) {
    const status = this.$root.getDetectionEngineStatus(engine);

    let query = `tags:so-soc AND ` + engine + ` | groupby log.level | groupby event.action | groupby soc.fields.error`;

    if (this.detectionEngineStatusQueries?.[engine]?.default) {
      query = this.detectionEngineStatusQueries[engine].default;
    }

    if (this.detectionEngineStatusQueries?.[engine]?.[status]) {
      query = this.detectionEngineStatusQueries[engine][status];
    }

    return query;
  }
};