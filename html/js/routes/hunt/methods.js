// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const RELATIVE_TIME_SECONDS = 10;
const RELATIVE_TIME_MINUTES = 20;
const RELATIVE_TIME_HOURS   = 30;
const RELATIVE_TIME_DAYS    = 40;
const RELATIVE_TIME_WEEKS   = 50;
const RELATIVE_TIME_MONTHS  = 60;
const FILTER_INCLUDE = 'INCLUDE';
const FILTER_EXCLUDE = 'EXCLUDE';
const FILTER_EXACT = 'EXACT';
const FILTER_DRILLDOWN = 'DRILLDOWN';

import queryMethods from './query.js';
import routingMethods from './routing.js';
import dataHandlerMethods from './dataHandlers.js';
import actionMethods from './actions.js';
import chartMethods from './charts.js';
import playbookMethods from './playbook.js';
import aiMethods from './ai.js';
import uiMethods from './ui.js';
import localStorageMethods from './localStorage.js';

export default {
  ...queryMethods,
  ...routingMethods,
  ...dataHandlerMethods,
  ...actionMethods,
  ...chartMethods,
  ...playbookMethods,
  ...aiMethods,
  ...uiMethods,
  ...localStorageMethods,
  moment: typeof moment !== 'undefined' ? moment : { tz: { guess: () => 'UTC' } },
  isAdvanced() {
    return this.advanced;
  },
  shouldAutohunt() {
    return this.autohunt || !this.isAdvanced();
  },
  isCategory(testCategory) {
    return testCategory == this.category;
  },
  isMultiSelect() {
    return this.isCategory('detections');
  },
  loading() {
    return this.$root.loading;
  },
  initHunt(params) {
    this.params = params;
    this.groupByItemsPerPage = params["groupItemsPerPage"];
    this.groupByLimit = params["groupFetchLimit"];
    this.itemsPerPage = params["eventItemsPerPage"];
    this.eventLimit = params["eventFetchLimit"];
    this.relativeTimeValue = params["relativeTimeValue"];
    this.relativeTimeUnit = params["relativeTimeUnit"];
    this.mruQueryLimit = params["mostRecentlyUsedLimit"];
    this.safeStringMaxLength = params["safeStringMaxLength"];
    this.queryBaseFilter = params["queryBaseFilter"];
    this.queries = this.applyQuerySubstitutions(params["queries"]);
    this.filterToggles = params["queryToggleFilters"];
    this.eventFields = params["eventFields"];
    this.advanced = params["advanced"];
    this.ackEnabled = params["ackEnabled"];
    this.escalateEnabled = params["escalateEnabled"];
    this.escalateRelatedEventsEnabled = params["escalateRelatedEventsEnabled"];
    this.aggregationActionsEnabled = params["aggregationActionsEnabled"];
    this.viewEnabled = params["viewEnabled"];
    this.createLink = params["createLink"];
    this.chartLabelMaxLength = params["chartLabelMaxLength"]
    this.chartLabelOtherLimit = params["chartLabelOtherLimit"]
    this.chartLabelFieldSeparator = params["chartLabelFieldSeparator"]
    this.presets = params["presets"];
    this.manualSyncTargetEngine = this.getPresets("manualSync")[0];
    this.maxEscalate = params["maxBulkEscalateEvents"];
    if (params["detectionEngineStatusQueries"]) {
      try {
        this.detectionEngineStatusQueries = jsyaml.load(params["detectionEngineStatusQueries"], { schema: jsyaml.FAILSAFE_SCHEMA })
      } catch {
        this.detectionEngineStatusQueries = {};
      }
    }
    if (this.queries != null && this.queries.length > 0) {
      this.query = this.queries[0].query;
    }
    this.actions = params["actions"] || [];
    this.zone = moment.tz.guess();

    this.loadLocalSettings();
    this.loadAIInvestigations();
    if (this.mruQueries.length > 0 && this.isAdvanced()) {
      this.query = this.mruQueries[0];
    }

    if (!this.isCategory('alerts')) {
      this.showDetailsPanel = false;
    }

    if (this.$route.query.t) {
      // This page was either refreshed, or opened from an existing hunt hyperlink,
      // so switch to absolute time since the URL has the absolute time defined.
      this.relativeTimeEnabled = false;
      this.dateRange = this.$route.query.t;
    }

    this.setupCharts();
    this.$root.stopLoading();

    if (!this.parseUrlParameters()) return;

    if (this.$route.query.q || (this.shouldAutohunt() && this.query)) {
      this.hunt(true);
    }
  },
  initializeTimeAndIntervals() {
    this.relativeTimeUnits = [
      { title: this.i18n.seconds, value: RELATIVE_TIME_SECONDS },
      { title: this.i18n.minutes, value: RELATIVE_TIME_MINUTES },
      { title: this.i18n.hours, value: RELATIVE_TIME_HOURS },
      { title: this.i18n.days, value: RELATIVE_TIME_DAYS },
      { title: this.i18n.weeks, value: RELATIVE_TIME_WEEKS },
      { title: this.i18n.months, value: RELATIVE_TIME_MONTHS }
    ];
    this.autoRefreshIntervals = [
      { title: this.i18n.interval0s, value: 0 },
      { title: this.i18n.interval5s, value: 5 },
      { title: this.i18n.interval10s, value: 10 },
      { title: this.i18n.interval15s, value: 15 },
      { title: this.i18n.interval30s, value: 30 },
      { title: this.i18n.interval1m, value: 60 },
      { title: this.i18n.interval2m, value: 120 },
      { title: this.i18n.interval5m, value: 300 },
      { title: this.i18n.interval10m, value: 600 },
      { title: this.i18n.interval15m, value: 900 },
      { title: this.i18n.interval30m, value: 1800 },
      { title: this.i18n.interval1h, value: 3600 },
      { title: this.i18n.interval2h, value: 7200 },
      { title: this.i18n.interval5h, value: 18000 },
      { title: this.i18n.interval10h, value: 36000 },
      { title: this.i18n.interval24h, value: 86400 },
    ];
  },
  hunt(replaceHistory = false) {
    this.huntPending = false;
    this.selectAllState = false;
    this.selectAllIndeterminate = false;
    this.selectedCount = 0;
    this.expandedPlaybookQuestions = {};

    var onSuccess = () => {};
    var onFail = () => {
      // When navigating to the same URL, simply refresh data
      this.loadData();
    };
    if (this.relativeTimeEnabled) {
      this.dateRange = '';
      this.dateRange = this.getStartDate().format(this.i18n.timePickerFormat) + " - " + this.getEndDate().format(this.i18n.timePickerFormat);
    }

    const targetRoute = this.$router.resolve(this.buildCurrentRoute());
    const currentRoute = this.$router.resolve(this.$router.currentRoute.value);

    if (currentRoute.fullPath === targetRoute.fullPath) {
      this.loadData();
    } else {
      if (replaceHistory === true) {
        this.$router.replace(targetRoute, onSuccess, onFail);
      } else {
        this.$router.push(targetRoute);
      }
    }

    this.resetRefreshTimer();

    this.selectAllState = false;
    this.selectedCount = 0;
  },
  stopRefreshTimer() {
    if (this.autoRefreshTimer) {
      clearTimeout(this.autoRefreshTimer);
    }
  },
  resetRefreshTimer() {
    var route = this;
    this.stopRefreshTimer();
    if (this.autoRefreshInterval > 0) {
      this.autoRefreshTimer = setTimeout(function() { route.hunt(true); }, this.autoRefreshInterval * 1000);
    }
  },
  huntQuery(query) {
    this.query = query;
    this.hunt();
  },

  getFilterToggle(name) {
    for (var i = 0; i < this.filterToggles.length; i++) {
      var filter = this.filterToggles[i];
      if (filter.name == name) {
        return filter;
      }
    }
    return null;
  },

  isFilterToggleEnabled(name) {
    var toggle = this.getFilterToggle(name);
    if (toggle) {
      return toggle.enabled;
    }
    return false;
  },

  filterToggled(event, filterToggle) {
    if (filterToggle.enabled && filterToggle.enablesToggles) {
      filterToggle.enablesToggles.forEach((name) => {
        var toggle = this.getFilterToggle(name)
        if (toggle) {
          toggle.enabled = true;
        }
      });
    } else if (!filterToggle.enabled && filterToggle.disablesToggles) {
      filterToggle.disablesToggles.forEach((name) => {
        var toggle = this.getFilterToggle(name)
        if (toggle) {
          toggle.enabled = false;
        }
      });
    }
  },
};