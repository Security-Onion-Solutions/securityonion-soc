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
  parseUrlParameters() {
    this.category = this.$route.path.replace("/", "");

    if (this.$route.query.q) {
      this.query = this.$route.query.q;
    }

    if (this.$route.query.rt) {
      this.relativeTimeEnabled = true;
      this.relativeTimeValue = parseInt(this.$route.query.rt);
    }
    if (this.$route.query.rtu) {
      this.relativeTimeEnabled = true;
      this.setRelativeTimeUnits(this.$route.query.rtu);
    }
    if (this.$route.query.t) {
      this.relativeTimeEnabled = false;
      setTimeout(this.setupDateRangePicker, 10);

      this.dateRange = this.$route.query.t;
    }
    if (this.$route.query.z) {
      this.zone = this.$route.query.z;
    }
    if (this.$route.query.el) {
      this.eventLimit = parseInt(this.$route.query.el);
    }
    if (this.$route.query.gl) {
      this.groupByLimit = parseInt(this.$route.query.gl);
    }
    if (this.$route.query.ar) {
      let found = false;
      this.autoRefreshIntervals.forEach(inter => {
        if (inter.value === parseInt(this.$route.query.ar)) {
          found = true;
          return false;
        }
      });

      this.autoRefreshInterval = found ? parseInt(this.$route.query.ar) : 0;
      this.autoRefreshEnabled = found;
    } else {
      this.autoRefreshEnabled = false;
      this.autoRefreshInterval = 0;
    }
    if (this.$route.query.tab) {
      this.activeTabs[0] = this.$route.query.tab;
    }
    if (this.$route.query.expand) {
      const items = this.$route.query.expand.split('|');
      for (let item of items) {
        this.expandedEvents.push(item);
      }
    }
    if (Array.isArray(this.filterToggles)) {
      for (const q in this.$route.query) {
        this.filterToggles.forEach(toggle => {
          if (toggle.name === q) {
            let enabled = this.$route.query[q];
            if (typeof enabled === 'string') {
              enabled = enabled.toLowerCase() === 'true';
            }
            toggle.enabled = enabled;
          }
        });
      }
    }

    this.gridId = this.$route.query.gridId;

    // Check for special params that force a re-route. This is needed when async functions will handle the hunt themselves.
    // So setting reroute=true tells the current thread not to perform the hunt, because the async thread will be doing it momentarily.
    var reRoute = false;
    if (this.$route.query.filterValue) {
      this.filterQuery(this.$route.query.filterField, this.$route.query.filterValue, this.$route.query.filterMode, undefined, this.$route.query.scalar === 'true');
      reRoute = true;
    }
    if (this.$route.query.groupByField) {
      this.groupQuery(this.$route.query.groupByField, this.$route.query.groupByGroup);
      reRoute = true;
    }
    if (reRoute) return false;

    return true;
  },
  buildCurrentRoute() {
    let queryObj = { q: this.query, z: this.zone, el: this.eventLimit, gl: this.groupByLimit };

    if (this.relativeTimeEnabled) {
      queryObj.rt = this.relativeTimeValue;
      queryObj.rtu = this.getRelativeTimeUnits();
    } else {
      queryObj.t = this.dateRange;
    }

    if (this.autoRefreshInterval > 0) {
      queryObj.ar = this.autoRefreshInterval;
    }

    if (this.gridId) {
      queryObj.gridId = this.gridId;
    }

    return { path: this.category, query: queryObj };
  },
  buildFilterRoute(filterField, filterValue, filterMode, scalar) {
    route = this.buildCurrentRoute()

    route.query.filterField = filterField;
    route.query.filterValue = this.subMissing(filterValue);
    route.query.filterMode = filterMode;

    if (arguments.length > 3) {
      route.query.scalar = scalar ? 'true' : 'false';
    }

    return route;
  },
  buildGroupByRoute(field) {
    const route = this.buildCurrentRoute();
    route.query.groupByField = field;

    const groups = (this.query || '').replaceAll(/\s/g, '').match(/\|groupby/gi);
    if (groups) {
      route.query.groupByGroup = groups.length - 1;
    } else {
      route.query.groupByGroup = 1;
    }

    return route;
  },
  buildGroupByNewRoute(field) {
    const route = this.buildCurrentRoute();
    route.query.groupByField = field;
    route.query.groupByGroup = -1;
    return route;
  },
  buildGroupOptionRoute(groupIdx, removals, addition) {
    var segments = this.query.split("|");
    var newQuery = segments[0];
    var currentGroupIdx = 0;
    for (var i = 1; i < segments.length; i++) {
      if (segments[i].trim().indexOf("groupby") == 0) {
        if (currentGroupIdx++ == groupIdx) {
          segments[i].replace(/,/g, ' ');
          removals.forEach(function(removal, index) {
            segments[i] = segments[i].replace(" -" + removal + " ", " ");
          });
          if (addition) {
            segments[i] = "groupby -" + addition + " " + segments[i].substring("groupby ".length + 1);
          }
        }
      }
      newQuery = newQuery.trim() + " | " + segments[i].trim();
    }
    var route = this.buildCurrentRoute();
    route.query.q = newQuery;
    return route;
  },
  buildToggleLegendRoute(group, groupIdx) {
    var addition = group.chart_options && group.chart_options.plugins.legend.display ? "nolegend" : "legend";
    var removal = group.chart_options && group.chart_options.plugins.legend.display ? "legend" : "nolegend";
    return this.buildGroupOptionRoute(groupIdx, [removal], addition);
  },
  buildMaximizeRoute(group, groupIdx) {
    return this.buildGroupOptionRoute(groupIdx, [], "maximize");
  },
  buildNonMaximizedRoute(group, groupIdx) {
    return this.buildGroupOptionRoute(groupIdx, ["maximize"], '');
  },
  buildGroupWithoutOptionsRoute(groupIdx) {
    const removals = ["pie", "bar", "legend", "nolegend", "sankey", "maximize"];
    return this.buildGroupOptionRoute(groupIdx, removals, '');
  },
  countDrilldown(event) {
    const keys = Object.keys(event).filter(field => field != 'newest' && !field.startsWith('_'));
    if ( (keys.length == 2 && keys[0] == "count") || (keys.length == 5 && keys[0] == "count" && keys[1] == "rule.name" && keys[2] == "event.module" && keys[3] == "event.severity_label" && keys[4] == "rule.uuid") ) {
      this.filterRouteDrilldown = this.buildFilterRoute(keys[1], event[keys[1]], FILTER_DRILLDOWN);
      this.$router.push(this.filterRouteDrilldown);
    }
  },
  updateFilterRoutes() {
    // Update filter routes when quickActionField or quickActionValue changes
    if (this.quickActionField && this.quickActionValue !== undefined && this.quickActionValue !== null) {
      this.filterRouteInclude = this.buildFilterRoute(this.quickActionField, this.quickActionValue, FILTER_INCLUDE);
      this.filterRouteExclude = this.buildFilterRoute(this.quickActionField, this.quickActionValue, FILTER_EXCLUDE);
      this.filterRouteExact = this.buildFilterRoute(this.quickActionField, this.quickActionValue, FILTER_EXACT);
      this.filterRouteDrilldown = this.buildFilterRoute(this.quickActionField, this.quickActionValue, FILTER_DRILLDOWN);
    }
  }
};