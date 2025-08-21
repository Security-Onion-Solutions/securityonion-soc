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

export default {
  async saveMenuScrollPos(isOpen, target) {
    if (isOpen) {
      // target doesn't exist yet, wait for it to be added to DOM
      await this.$nextTick();
    }

    const scrollContainer = document.querySelector(target);
    if (!scrollContainer) return;

    if (isOpen) {
      // opening
      scrollContainer.scrollTop = this.menuScrollPos;
    } else {
      // closing
      this.menuScrollPos = scrollContainer.scrollTop;
    }
  },
  updateBulkSelector(item) {
    if (item._isSelected) {
      this.selectedCount = Math.min(this.selectedCount + 1, this.totalEvents);
    } else {
      this.selectedCount = Math.max(this.selectedCount - 1, 0);
    }

    switch (this.selectedCount) {
      case 0:
        this.selectAllState = false;
        this.selectAllIndeterminate = false;
        break;
      case this.totalEvents:
        this.selectAllState = true;
        this.selectAllIndeterminate = false;
        break;
      default:
        this.selectAllState = false;
        this.selectAllIndeterminate = true;
        break;
    }
  },

  toggleSelectAll() {
    if (this.selectAllIndeterminate) {
      this.selectAllState = false;
      this.selectAllIndeterminate = false;
      this.selectAllEvents(false);
      this.selectedCount = 0;
    } else {
      if (this.selectAllState) {
        this.selectAllState = false;
        this.selectAllIndeterminate = false;
        this.selectAllEvents(false);
      } else {
        this.selectAllState = false;
        this.selectAllIndeterminate = true;
        this.selectCurrentPage(true);
      }
    }
  },

  selectAllEvents(selection = true, ALL = false) {
    for (let i = 0; i < this.eventData.length; i++) {
      if (this.eventData[i]._isSelected !== selection) {
        this.eventData[i]._isSelected = selection;
        if (selection) {
          this.selectedCount++;
        } else {
          this.selectedCount--;
        }
      }
    }

    this.selectedCount = Math.max(Math.min(this.selectedCount, this.totalEvents), 0);

    if (ALL && selection) {
      this.selectAllState = true;
      this.selectAllIndeterminate = false;
    }
  },

  selectCurrentPage(selection = true) {
    this.eventCurrentItems.forEach((item) => {
      if (item._isSelected !== selection) {
        item._isSelected = selection;
        if (selection) {
          this.selectedCount++;
        } else {
          this.selectedCount--;
        }
      }
    });

    this.selectedCount = Math.max(Math.min(this.selectedCount, this.totalEvents), 0);
  },

  isPageSelected() {
    return this.eventCurrentItems.every((item) => item._isSelected);
  },

  countSelected() {
    let count = 0;
    for (let i = 0; i < this.eventData.length; i++) {
      if (this.eventData[i]._isSelected) {
        count++;
      }
    }

    this.selectedCount = count;
  },

  getDisplayedQueryVar() {
    if (this.isAdvanced()) {
      if (this.showFullQuery) {
        return 'query'
      } else {
        return 'querySearch'
      }
    }
    return 'queryName'
  },

  formatSafeString(item) {
    if (item.length > this.safeStringMaxLength) {
      return item.substring(0, this.safeStringMaxLength - 3) + "...";
    }
    return item;
  },

  isColumnHeader(field) {
    return this.eventHeaders.find((item) => {
      if (item.value == field) {
        return true;
      }
    }) != null;
  },

  toggleColumnHeader(field) {
    if (!this.isColumnHeader(field)) {
      this.addColumnHeader(field);
    } else {
      this.removeColumnHeader(field);
    }
  },

  moveColumnHeader(field, left) {
    this.populateQueryTableFields();
    for (var idx = -1; idx < this.queryTableFields.length; idx++) {
      const currentField = this.queryTableFields[idx];
      if (field == currentField) {
        break;
      }
    }

    if (idx > -1) {
      if (left) {
        if (idx > 0) {
          var tmpFields = this.queryTableFields.slice(0, idx - 1);
          tmpFields.push(field);
          tmpFields = tmpFields.concat(this.queryTableFields.slice(idx - 1, idx));
          this.queryTableFields = tmpFields.concat(this.queryTableFields.slice(idx + 1));
        }
      } else {
        if (idx < this.queryTableFields.length - 1) {
          var tmpFields = this.queryTableFields.slice(0, idx);
          tmpFields = tmpFields.concat(this.queryTableFields.slice(idx + 1, idx + 2));
          tmpFields.push(field);
          this.queryTableFields = tmpFields.concat(this.queryTableFields.slice(idx + 2));
        }
      }
    }
    this.repopulateEventHeaders(); // no defaults fields will be supplied since we know they aren't going to be used.
  },

  addColumnHeader(field) {
    this.populateQueryTableFields();
    this.queryTableFields.push(field);
    this.repopulateEventHeaders(); // no defaults fields will be supplied since we know they aren't going to be used.
  },

  removeColumnHeader(field) {
    this.populateQueryTableFields();
    this.queryTableFields = this.queryTableFields.filter(item => item != field);

    // do not revert back to the predefined headers if this was the last column that was just removed. Otherwise
    // users would get frustrated if they're trying to remove all the columns to then add their own.
    this.repopulateEventHeaders(); // no defaults fields provided
  },

  populateQueryTableFields() {
    if (this.queryTableFields.length == 0) {
      // Pre-populate with the default field headers already in eventHeaders (from populateEventTable)
      for (const idx in this.eventHeaders) {
        const field = this.eventHeaders[idx].value;
        this.queryTableFields.push(field);
      }
    }
  },

  getGroupByFieldStartIndex() {
    return this.aggregationActionsEnabled ? 2 : 1;
  },

  lookupTopMetricKey(metrics) {
    return this.lookupGroupByMetricKey(metrics, 0, false);
  },

  isNumeric(str) {
    return !isNaN(str) && !isNaN(parseFloat(str));
  },

  getRelativeTimeUnits() {
    let text = 'hours';

    this.relativeTimeUnits.forEach((unit) => {
      if (unit.value == this.relativeTimeUnit) {
        text = unit.title;
        return false;
      }
    });

    return text;
  },

  setRelativeTimeUnits(m) {
    let value = 30;

    this.relativeTimeUnits.forEach((unit) => {
      if (unit.title.toLowerCase() == m.toLowerCase()) {
        value = unit.value;
        return false;
      }
    });

    this.relativeTimeUnit = value;
  },

  canQuery(key) {
    return !key.startsWith("soc_");
  },

  translateValue(value) {
    if (typeof value === 'string' && value.startsWith('__')) {
      return this.i18n[value];
    }

    return value;
  },

  huntQueryWidth() {
    return this.$refs.huntQueryInput?.$el?.clientWidth || 0;
  },

  hideDateRangePicker() {
    if (this.relativeTimeEnabled) return;
    this.dateRange = $('#huntdaterange')[0].value;
    this.notifyInputsChanged();
  },

  getEndDate() {
    if (this.dateRange != '') {
      var pieces = this.dateRange.split(" - ");
      if (pieces.length == 2) {
        return moment(pieces[1], this.i18n.timePickerFormat);
      }
    }
    return moment();
  },

  getStartDate() {
    if (this.dateRange != '') {
      var pieces = this.dateRange.split(" - ");
      if (pieces.length == 2) {
        return moment(pieces[0], this.i18n.timePickerFormat);
      }
    }
    var unit = "hour";
    switch (this.relativeTimeUnit) {
      case RELATIVE_TIME_SECONDS: unit = "seconds"; break;
      case RELATIVE_TIME_MINUTES: unit = "minutes"; break;
      case RELATIVE_TIME_HOURS: unit = "hours"; break;
      case RELATIVE_TIME_DAYS: unit = "days"; break;
      case RELATIVE_TIME_WEEKS: unit = "weeks"; break;
      case RELATIVE_TIME_MONTHS: unit = "months"; break;
    }
    return moment().subtract(this.relativeTimeValue, unit);
  },

  setupDateRangePicker() {
    if (this.relativeTimeEnabled) return;

    $('#huntdaterange').daterangepicker({
      ranges: this.$root.generateDatePickerPreselects(),
      timePicker: true,
      timePickerSeconds: true,
      endDate: this.getEndDate(),
      startDate: this.getStartDate(),
      locale: {
        format: this.i18n.timePickerFormat
      }
    });
    var route = this;
    if (route.dateRange == '') {
      route.dateRange = $('#huntdaterange')[0].value;
    }
    $('#huntdaterange').on('hide.daterangepicker', function(ev, picker) {
      route.hideDateRangePicker();
    });
  },

  showAbsoluteTime() {
    this.relativeTimeEnabled = false;
    setTimeout(this.setupDateRangePicker, 10);
  },

  showRelativeTime() {
    this.relativeTimeEnabled = true;
  },

  toggleShowSection(item) {
    if (this.isExpandedSection(item)) {
      this.collapsedSections.push(item);
    } else {
      this.collapsedSections.splice(this.collapsedSections.indexOf(item), 1);
    }
  },

  isExpandedSection(item) {
    return (this.collapsedSections.indexOf(item) == -1);
  },

  subMissing(value) {
    if (value === this.i18n.__missing__) {
      return '__missing__';
    }

    return value;
  },

  calculateEventColumnWidth() {
    this.eventColumnWidth = this.$refs?.eventColumn?.$el?.clientWidth || 0;
    if (this.eventColumnWidth === 0) {
      setTimeout(() => {
        this.calculateEventColumnWidth();
      }, 300);
    }
  },
};