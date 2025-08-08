// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

export default {
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
};