// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

export default {
  async loadData() {
    if (this.disableRouteLoad) return;

    if (!this.parseUrlParameters()) return;

    this.$root.startLoading();
    try {
      this.obtainQueryDetails();

      // This must occur before the following await, so that Vue flushes the old groupby DOM renders
      this.groupBys.splice(0);

      let range = this.dateRange;
      if (this.isCategory('detections')) {
        range = moment(0).format(this.i18n.timePickerFormat) + " - " + moment().format(this.i18n.timePickerFormat);
      }
      const params = {
        query: await this.getQuery(),
        range: range,
        format: this.i18n.timePickerSample,
        zone: this.zone,
        metricLimit: this.groupByLimit,
        eventLimit: this.eventLimit,
      };

      if (this.gridId && this.gridId.length > 0) {
        params.gridId = this.gridId;
      }

      if (this.loaded) {
        this.activeTabs = {};
        this.expandedEvents = [];
      }

      let response = await this.$root.papi.get('events/', { params: params });

      this.eventPage = 1;
      this.groupByPage = 1;
      this.totalEvents = response.data.totalEvents;
      this.fetchTimeSecs = response.data.elapsedMs / 1000;
      this.roundTripTimeSecs = Math.abs(moment(response.data.completeTime) - moment(response.data.createTime)) / 1000;
      this.populateChart(this.timelineChartData, response.data.metrics["timeline"]);
      this.populateEventTable(response.data.events);

      this.metricsEnabled = false;
      if (response.data.metrics["bottom"] != undefined) {
        this.metricsEnabled = true;
        this.populateGroupByTables(response.data.metrics);
        this.populateChart(this.topChartData, response.data.metrics[this.lookupTopMetricKey(response.data.metrics)]);
        this.populateChart(this.bottomChartData, response.data.metrics["bottom"]);
      }
      this.loaded = true;
      this.addMRUQuery(this.query);

      if (this.activeTabs[0] === 'playbook') {
        // this should only happen when the user is opening a
        // playbook for a specific alert from another page
        for (let item of this.eventData) {
          this.loadPlaybook(item);
        }
      }

      var subtitle = this.isAdvanced() ? this.query : this.queryName;
      this.$root.setSubtitle(this.i18n[this.category] + " - " + subtitle);
    } catch (error) {
      this.$root.showError(error);
    }

    this.$root.stopLoading();

    if (this.isCategory('alerts')) {
      this.$nextTick(() => {
        this.calculateEventColumnWidth();
      });
    }
  },
  getPresets(kind) {
    if (this.presets && this.presets[kind]) {
      return this.presets[kind].labels;
    }

    return [];
  },
  filterVisibleFields(eventModule, eventDataset, fields) {
    let relatedFields = '';
    for (const field of fields) {
      const match = field.match(/so_[^.]*\.fields./);
      if (match) {
        relatedFields = match[0];
        break;
      }
    }
    if (this.eventFields) {
      var filteredFields = null;
      if (eventDataset) {
        if(eventDataset.indexOf('.') !== -1) {
          eventDataset = eventDataset.substring(eventDataset.indexOf('.') + 1);
        }
      }
      if (eventModule && eventDataset) {
        filteredFields = this.eventFields[":" + eventModule + ":" + eventDataset];
      }
      if (!filteredFields && eventDataset) {
        filteredFields = this.eventFields["::" + eventDataset];
      }
      if (!filteredFields && eventModule) {
        filteredFields = this.eventFields[":" + eventModule + ":"];
      }
      if (!filteredFields) {
        filteredFields = this.eventFields["default"];
      }
      if (filteredFields && filteredFields.length > 0) {
        fields = filteredFields;
        if (relatedFields) {
          fields = fields.map(f => relatedFields + f);
        }
      }
    }
    return fields;
  },
  localizeValue(value) {
    if (value && value.startsWith && value.startsWith("__")) {
      value = this.$root.localizeMessage(value);
    }
    return value;
  },
  constructHeaders(fields) {
    var headers = [];

    const customSorts = {
      'event.severity_label': this.sortBySeverity,
    };

    if (fields && fields.length > 0) {
      var i18n = this.i18n;
      fields.forEach((item) => {
        var i18nKey = "field_" + item;
        var header = {
          title: i18n[i18nKey] ? i18n[i18nKey] : item,
          value: item,
        };

        const sort = customSorts[item];
        if (sort) {
          header.sort = sort;
        }

        headers.push(header);
      });
    }
    return headers;
  },
  sortBySeverity(a, b) {
    // normalize
    const na = (typeof a === 'string' ? a : String(a)).toLowerCase();
    const nb = (typeof b === 'string' ? b : String(b)).toLowerCase();

    // map
    const levels = ['unknown', 'informational', 'low', 'medium', 'high', 'critical'];
    const sevA = levels.findIndex(x => x === na);
    const sevB = levels.findIndex(x => x === nb);

    // compare
    return sevA - sevB;
  },
  lookupSocId(data) {
    if (data && data.length == 36 && data.indexOf("-") == 8) {
      const user = this.$root.getUserByIdViaCache(data);
      if (user && user.email) {
        data = user.email;
      }
    }
    return data;
  },
  lookupSocIds(record) {
    for (const key in record) {
      if (key.endsWith("case.assigneeId") || key.endsWith("case.userId")) {
        record[key] = this.lookupSocId(record[key]);
      }
    }
  },
  constructGroupByRows(fields, data) {
    const records = [];
    const route = this;
    let batch = [];
    data.forEach(function(row, index) {
      var record = {
        count: row.value,
        _index: index,
      };
      fields.forEach(function(field, index) {
        record[field] = route.localizeValue(row.keys[index]);
        batch.push(record[field]);
      });
      route.lookupSocIds(record);
      records.push(record);
    });
    this.$root.batchLookup(batch, this);
    return records;
  },
  populateGroupByTables(metrics) {
    var idx = 0;
    this.groupBys = [];
    while (this.populateGroupByTable(metrics, idx++)) {};
    
    // Apply any existing AI investigation results to the loaded group data
    this.applyAIInvestigationsToEvents();
    
    // Apply AI investigated filter if enabled
    if (this.aiInvestigatedFilter) {
      this.groupBys.forEach(group => {
        if (group.data && group.data.length > 0) {
          group.data = group.data.filter(item => {
            const alertId = item['rule.uuid'] || item.soc_id;
            return alertId && this.aiInvestigations[alertId];
          });
        }
      });
    }
  },
  populateGroupByTable(metrics, groupIdx) {
    const route = this;
    var key = this.lookupGroupByMetricKey(metrics, groupIdx, true);
    if (key) {
      var fields = key.split("|");
      if (fields.length > 1 && fields[0] == "groupby_" + groupIdx) {
        fields.shift();

        // Group objects have the following attributes:
        // title:         Chart title
        // fields:        Array of field names in the group, starting with an empty string (for the action
        //                buttons column, and then the 'count', followed by the actual field names.
        // data:          The rows of tabular data in the format:
        //                { count: <count>, keys: [fieldValue0, fieldValue1, fieldValueN] }
        // headers:       Array of header objects for the table view, in the format:
        //                { text: 'Human Friendly', value: 'field_name0' }
        // chart_metrics: Alternative data format for chart rendering, in the
        //                format: { value: <count>, keys: ["fieldValue0, fieldValue1, fieldValueN"] }
        //                Note that the keys array is always of length one, containing the concatenated
        //                 string of field values.
        // chart_type:    ChartJS type, such as pie, bar, sankey, etc.
        // chart_options: ChartJS options. See setupBarChart, etc.
        // chart_data:    ChartJS labels and datasets. See setupBarChart and populateBarChart.
        // is_incomplete: True if only partial data is rendered to avoid complete render failure.
        // sortBy:        Optional name of a field to sort by.
        // sortDesc:      True if the optional sort should be in descending order.
        // maximized:     True if this group view has been maximized.
        var group = {};
        group.title = fields.join(this.chartLabelFieldSeparator);
        group.fields = [...fields];
        group.data = this.constructGroupByRows(fields, metrics[key])
        fields.unshift("count");
        if (this.aggregationActionsEnabled) {
          fields.unshift(""); // Leave empty header column for optional action buttons/icons
        }
        group.headers = this.constructHeaders(fields);
        group.chart_metrics = this.constructChartMetrics(metrics[key]);

        // Preserve group-by sort settings only for first group. Useful for non-advanced views.
        group.sortBy = [{ key: 'count', order: 'desc' }];
        if (this.groupBys.length == 0 && this.groupBySortBy) {
          group.sortBy = [{key: this.groupBySortBy, order: this.groupBySortDesc ? 'desc' : 'asc'}];
        }

        this.groupBys.push(group);

        var options = this.queryGroupByOptions[groupIdx];
        if (options.indexOf("pie") != -1) {
          this.displayPieChart(group, groupIdx);
        } else if (options.indexOf("bar") != -1) {
          this.displayBarChart(group, groupIdx);
        } else if (options.indexOf("sankey") != -1) {
          this.displaySankeyChart(group, groupIdx);
        }
        group.maximized = options.indexOf("maximize") != -1;
        if (group.maximized) {
          const unmaximizeFn = function() {
            const newRoute = route.buildNonMaximizedRoute(group, groupIdx);
            route.$router.push(newRoute, function() {}, function() {});
          };
          this.$nextTick(() => {
            route.$root.maximizeById("group-" + groupIdx, unmaximizeFn);
          });
        }
      }

      return true;
    }
    return false;
  },
  populateEventTable(events) {
    var records = [];
    var fields = [];
    var eventModule;
    var eventDataset;
    var route = this;
    if (events != null && events.length > 0) {
      let batch = [];

      const multiSelect = this.isMultiSelect();
      events.forEach((event, index) => {
        var record = route.extractSocValues(event);
        route.lookupSocIds(record);

        if (multiSelect) {
          record._isSelected = false;
        }

        record._index = index;

        records.push(record);

        for (const key in record) {
          batch.push(record[key]);
        }

        if (!eventModule) {
          var currentModule = this.lookupFieldValue(record, "event.module");
          var currentDataset = this.lookupFieldValue(record, "event.dataset");
          if (eventModule == null && currentModule) {
            eventModule = currentModule.toLowerCase();
            if (currentDataset) {
              eventDataset = currentDataset.toLowerCase();
            }
          }
        }
      });

      route.$root.batchLookup(batch, route);

      for (const key in records[0]) {
        fields.push(key);
      }
    }

    this.populateEventHeaders(this.filterVisibleFields(eventModule, eventDataset, fields));
    this.eventData = records;
    
    // Apply any existing AI investigation results to the loaded events
    this.applyAIInvestigationsToEvents();
    
    // Apply AI investigated filter if enabled
    if (this.aiInvestigatedFilter) {
      this.eventData = this.eventData.filter(item => {
        const alertId = item['rule.uuid'] || item.soc_id;
        return alertId && this.aiInvestigations[alertId];
      });
    }
  },
  lookupFieldValue(record, field) {
    if (field in record) {
      return record[field];
    }

    for (const key in record) {
      if (key.endsWith(".fields." + field)) {
        return record[key];
      }
    }

    return '';
  },
  populateEventHeaders(defaultFields) {
    var fields = defaultFields;
    if (this.queryTableFields.length > 0) {
      fields = this.queryTableFields;
    }

    let headers = this.constructHeaders(fields);

    if (this.isCategory('detections')) {
      const enabledCol = headers.findIndex(h => h.value === 'so_detection.isEnabled');
      const overrideHeader = { title: this.i18n.overrides, value: 'override_count' };

      if (enabledCol > -1) {
        headers = [...headers.slice(0, enabledCol+1), overrideHeader, ...headers.slice(enabledCol+1)];
      } else {
        headers.push(overrideHeader);
      }
    }

    this.eventHeaders = headers;
  },
  repopulateEventHeaders() {
    this.populateEventHeaders();

    // This is a UI interaction so update the query and route to reflect the new table segment
    var segments = this.query.split("|");
    var newQuery = segments[0];
    for (var i = 1; i < segments.length; i++) {
      if (segments[i].trim().indexOf("table") == 0) {
        continue;
      }
      newQuery = newQuery.trim() + " | " + segments[i].trim();
    }
    if (this.queryTableFields.length > 0) {
      newQuery = newQuery + " | table " + this.queryTableFields.join(" ");
    }

    this.updateActiveQuery(newQuery);
  },
  getExpandedData(data) {
    const ignored = ['_isSelected', 'playbooks'];
    var records = [];
    for (let key in data) {
      if (ignored.includes(key)) {
        continue;
      }

      records.push({
        key: key,
        value: data[key],
      });
    }
    return records;
  },
  extractSocValues(event) {
    var record = event.payload;
    record.soc_id = event.id;
    record.soc_score = event.score;
    record.soc_type = event.type;
    record.soc_timestamp = event.timestamp;
    record.soc_source = event.source;

    return record;
  },
  getEventField(event, field) {
    if (field in event) {
      return event[field];
    }

    return '';
  },
  async fetchNewestEvent(item) {
    if (item.newest) return;

    let parts = [];

    // Include base filter and custom query as per upstream fix
    if (this.queryBaseFilter) parts.push(this.queryBaseFilter);

    this.obtainQueryDetails();
    if (this.querySearch) {
      parts.push(`(${this.querySearch})`);
    }

    for (let field in item) {
      let label = field;
      if (field.startsWith('_')) continue;
      if (field.startsWith('event_data.')) {
        label = field.replace('event_data.', '');
      }

      if (label.toLowerCase() === 'count') continue;

      if (item[field] && !Array.isArray(item[field])) {
        parts.push(`${label}:"${item[field]}"`);
      }
    }

    if (this.isFilterToggleEnabled('acknowledged')) {
      parts.push('event.acknowledged:true');
    } else {
      parts.push('NOT event.acknowledged:true');
    }

    if (this.isFilterToggleEnabled('escalated')) {
      parts.push('event.escalated:true');
    } else {
      parts.push('NOT event.escalated:true');
    }

    const q = parts.join(' AND ') + ` | sortby @timestamp`;

    let params = {
      query: q,
      range: this.dateRange,
      format: this.i18n.timePickerSample,
      zone: this.zone,
      metricLimit: 0,
      eventLimit: 1
    };

    if (this.gridId && this.gridId.length > 0) {
      params.gridId = this.gridId;
    }

    let response = await this.$root.papi.get('events/', { params });
    if (response.data.events.length === 0) {
      this.$root.showWarning('No events found');
      return;
    }

    item.newest = this.extractSocValues(response.data.events[0]);
  },

  lookupGroupByMetricKey(metrics, groupIdx, longest) {
    var desiredKey = null;
    for (const key in metrics) {
      if (key.startsWith("groupby_" + groupIdx +"|")) {
        if (desiredKey == null) {
          desiredKey = key;
        } else if (longest && key.length > desiredKey.length) {
          desiredKey = key;
        } else if (!longest && key.length < desiredKey.length) {
          desiredKey = key;
        }
      }
    }
    return desiredKey;
  }
};