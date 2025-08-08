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
  },

  obtainQueryDetails() {
    this.queryAltered = false;
    this.queryName = "";
    this.querySearch = "";
    this.queryRemainder = "";
    this.queryFilters = [];
    this.queryGroupBys = [];
    this.queryGroupByOptions = [];
    this.queryTableFields = [];
    this.queryTableOptions = [];
    this.querySortBys = [];
    var route = this;
    if (this.query) {
      this.query = this.query.trim();

      // find first segment
      var insideQuote = false;
      var escaping = false;
      var segmentDelimIdx = -1;
      for (var i = 0; i < this.query.length; i++) {
        if (this.query[i] == "|" && !insideQuote && !escaping) {
          segmentDelimIdx = i;
          break;
        } else if (this.query[i] == "\"" && !escaping) {
          insideQuote = !insideQuote;
        } else if (this.query[i] == "\\" && !escaping) {
          escaping = true;
        } else {
          escaping = false;
        }
      }

      var segments = [];

      if (segmentDelimIdx > -1 && this.query.length > segmentDelimIdx + 1) {
        // Filter/group/sort/etc segments cannot have | in them.
        segments = this.query.substring(segmentDelimIdx + 1).split("|");
        segments.unshift(this.query.substring(0, segmentDelimIdx));
      } else {
        segments = [this.query];
      }

      if (segments.length > 0) {
        this.querySearch = segments[0].trim();
        if (segments.length > 1) {
          // Used for reconstructing full query from simplified filter-only view
          this.queryRemainder = this.query.substring(segmentDelimIdx);
        }
        var matchingQueryName = this.i18n.custom;
        for (var i = 0; i < this.queries.length; i++) {
          if (this.query == this.queries[i].query) {
            matchingQueryName = this.queries[i].name;
          }
        }
        this.queryName = matchingQueryName;
        if (!route.isComplexQuery(this.querySearch)) {
          this.querySearch.split(" AND ").forEach(function(item, index) {
            item = item.trim();
            if (item.length > 0 && item != "*") {
              route.queryFilters.push(item);
            }
          });
        }
      }

      if (segments.length > 1) {
        for (var segmentIdx = 1; segmentIdx < segments.length; segmentIdx++) {
          var segment = segments[segmentIdx].trim().replace(/,/g, ' ');
          if (segment.indexOf("groupby") == 0) {
            var fields = [];
            var options = [];
            segment.split(" ").forEach(function(item, index) {
              // Skip empty fields and segment options (they start with a hyphen)
              if (item[0] == "-") {
                options.push(item.substring(1));
              } else if (index > 0 && item.trim().length > 0) {
                if (item.split("\"").length % 2 == 1) {
                  // Will currently skip quoted items with spaces.
                  fields.push(item);
                }
              }
            });
            route.queryGroupBys.push(fields);
            route.queryGroupByOptions.push(options);
          }
          if (segment.indexOf("table") == 0) {
            var fields = [];
            var options = [];
            segment.split(" ").forEach(function(item, index) {
              // Skip empty fields and segment options (they start with a hyphen)
              if (item[0] == "-") {
                options.push(item.substring(1));
              } else if (index > 0 && item.trim().length > 0) {
                if (item.split("\"").length % 2 == 1) {
                  // Will currently skip quoted items with spaces.
                  fields.push(item);
                }
              }
            });
            route.queryTableFields = fields;
            route.queryTableOptions = options;
          }
          if (segment.indexOf("sortby") == 0) {
            segment.split(" ").forEach(function(item, index) {
              if (index > 0 && item.trim().length > 0) {
                if (item.split("\"").length % 2 == 1) {
                  // Will currently skip quoted items with spaces.
                  route.querySortBys.push(item);
                }
              }
            });
          }
        }
      }
    }
  },

  removeFilter(filter) {
    var newQuery = this.query.replace(" AND " + filter, "");
    if (newQuery == this.query) {
      newQuery = this.query.replace(filter + " AND ", "");
      if (newQuery == this.query) {
        newQuery = this.query.replace(filter, "");
      }
    }
    if (newQuery.trim().indexOf("|") == 0) {
      newQuery = "* " + newQuery.trim()
    }
    if (newQuery.trim().length == 0) {
      newQuery = "*";
    }
    this.query = newQuery;
    if (!this.notifyInputsChanged()) {
      this.obtainQueryDetails();
    }
  },

  removeGroupBy(groupIdx, fieldIdx) {
    if (groupIdx < 0 || groupIdx >= this.queryGroupBys.length) {
      return;
    }
    var group = this.queryGroupBys[groupIdx];
    if (fieldIdx >= group.length) {
      return;
    }
    var field = null;
    if (fieldIdx >= 0) {
      field = group[fieldIdx];
    }

    var segments = this.query.split("|");
    var newQuery = segments[0];
    var currentGroupIdx = 0;
    for (var i = 1; i < segments.length; i++) {
      if (segments[i].trim().indexOf("groupby") == 0) {
        if (currentGroupIdx == groupIdx) {
          segments[i] = segments[i].replace(/,/g, ' ');
          segments[i] = segments[i].replace(" " + field, "");
          if (segments[i].trim() == "groupby") {
            segments[i] = "";
          }
        }
        currentGroupIdx++;
      }
      if (segments[i].length > 0) {
        newQuery = newQuery.trim() + " | " + segments[i].trim();
      }
    }
    this.query = newQuery.trim();
    if (!this.notifyInputsChanged()) {
      this.obtainQueryDetails();
    }
  },

  removeSortBy(sortBy) {
    var segments = this.query.split("|");
    var newQuery = segments[0];
    for (var i = 1; i < segments.length; i++) {
      if (segments[i].trim().indexOf("sortby") == 0) {
        segments[i].replace(/,/g, ' ');
        segments[i] = segments[i].replace(" " + sortBy, "");
        if (segments[i].trim() == "sortby") {
          segments[i] = "";
        }
      }
      if (segments[i].length > 0) {
        newQuery = newQuery.trim() + " | " + segments[i].trim();
      }
    }
    this.query = newQuery.trim();
    if (!this.notifyInputsChanged()) {
      this.obtainQueryDetails();
    }
  }
};