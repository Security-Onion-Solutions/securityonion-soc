// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

export default {
  saveSetting(setting, value) {
    var settings = {};
    if (localStorage[this.category + 'Settings']) {
      settings = JSON.parse(localStorage[this.category + 'Settings']);
    }
    settings[setting] = value;
    localStorage[this.category + 'Settings'] = JSON.stringify(settings);
  },

  saveTimezone() {
    this.saveSetting('timezone', this.zone);
  },

  saveLocalSettings() {
    var settings = {
      autohunt: this.autohunt,
      advanced: this.advanced,
      relativeTimeValue: this.relativeTimeValue,
      relativeTimeUnit: this.relativeTimeUnit,
      sortBy: this.sortBy,
      sortDesc: this.sortDesc,
      itemsPerPage: this.itemsPerPage,
      eventLimit: this.eventLimit,
      groupBySortBy: this.groupBySortBy,
      groupBySortDesc: this.groupBySortDesc,
      groupByItemsPerPage: this.groupByItemsPerPage,
      groupByLimit: this.groupByLimit,
      mruQueries: this.mruQueries,
      zone: this.zone,
      queryTableFields: this.queryTableFields,
      showDetailsPanel: this.showDetailsPanel,
    };
    localStorage[this.category + 'Settings'] = JSON.stringify(settings);
  },

  loadLocalSettings() {
    if (localStorage[this.category + 'Settings']) {
      var settings = JSON.parse(localStorage[this.category + 'Settings']);
      if (settings.autohunt !== undefined) {
        this.autohunt = settings.autohunt;
      }
      if (settings.advanced !== undefined) {
        this.advanced = settings.advanced;
      }
      if (settings.relativeTimeValue) {
        this.relativeTimeValue = settings.relativeTimeValue;
      }
      if (settings.relativeTimeUnit) {
        this.relativeTimeUnit = settings.relativeTimeUnit;
      }
      if (settings.sortBy) {
        this.sortBy = settings.sortBy;
      }
      if (settings.sortDesc) {
        this.sortDesc = settings.sortDesc;
      }
      if (settings.itemsPerPage) {
        this.itemsPerPage = settings.itemsPerPage;
      }
      if (settings.eventLimit) {
        this.eventLimit = settings.eventLimit;
      }
      if (settings.groupBySortBy) {
        this.groupBySortBy = settings.groupBySortBy;
      }
      if (settings.groupBySortDesc) {
        this.groupBySortDesc = settings.groupBySortDesc;
      }
      if (settings.groupByItemsPerPage) {
        this.groupByItemsPerPage = settings.groupByItemsPerPage;
      }
      if (settings.groupByLimit) {
        this.groupByLimit = settings.groupByLimit;
      }
      if (settings.mruQueries) {
        this.mruQueries = settings.mruQueries;
      }
      if (settings.zone) {
        this.zone = settings.zone;
      }
      if (settings.queryTableFields) {
        this.queryTableFields = settings.queryTableFields;
      }
      if (settings.showDetailsPanel !== undefined) {
        this.showDetailsPanel = settings.showDetailsPanel;
      }
    }
  },

  saveAIInvestigations() {
    // Save AI investigation results to localStorage
    try {
      localStorage['aiInvestigations'] = JSON.stringify(this.aiInvestigations);
    } catch (error) {
      console.error('Failed to save AI investigations to localStorage:', error);
    }
  },

  loadAIInvestigations() {
    // Load AI investigation results from localStorage
    try {
      if (localStorage['aiInvestigations']) {
        this.aiInvestigations = JSON.parse(localStorage['aiInvestigations']);
      }
    } catch (error) {
      console.error('Failed to load AI investigations from localStorage:', error);
      this.aiInvestigations = {};
    }
  },
};