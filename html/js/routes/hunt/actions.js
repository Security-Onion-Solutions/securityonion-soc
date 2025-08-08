// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

export default {
  buildCase(item) {
    var title = 'rule.name' in item && item['rule.name'] ? '' + item['rule.name'] : null;
    if (!title) {
      title = this.i18n.eventCaseTitle;
      if (item['event.module'] || item['event.dataset']) {
        title = title + ": ";
        if (item['event.module']) {
          title = title + item['event.module'];
          if (item['event.dataset']) {
            title = title + " - ";
          }
        }
        if (item['event.dataset']) {
          title = title + item['event.dataset'];
        }
      }
    }

    var description = this.i18n.caseEscalatedDescription;
    if (!this.escalateRelatedEventsEnabled) {
      var description = item['message'];
      if (!description) {
        description = JSON.stringify(item);
      }
    }

    var severity = 'event.severity' in item && item['event.severity'] ? '' + item['event.severity'] : '';
    var template = 'rule.case_template' in item && item['rule.case_template'] ? '' + item['rule.case_template'] : '';

    return {
      title: this.formatSafeString(title),
      description: description,
      severity: severity,
      template: template,
    };
  },
  panelAck(args) {
    args[1] = !this.isFilterToggleEnabled('acknowledged');
    this.ack(...args);
  },
  async ack(item, acknowledge, escalate, caseId, groupIdx, detectionRelated = false, skipDialog = false) {
    if (detectionRelated && !skipDialog) {
      if (escalate) {
        this.ackManyVerb = this.i18n.escalate.toLowerCase();
      } else {
        this.ackManyVerb = acknowledge ? this.i18n.acknowledge : this.i18n.acknowledgeUndo;
      }

      this.ackManyArgs = [item, acknowledge, escalate, caseId, groupIdx, detectionRelated, true];
      this.showAckManyDialog = true;

      return;
    } else {
      this.closeAckManyDialog();
    }

    this.$root.startLoading();
    try {
      var docEvent = {};
      if (item["soc_id"]) {
        // only send necessary fields
        docEvent["soc_id"] = item["soc_id"];
      } else {
        for (let field of Object.keys(item)) {
          if (field !== 'newest' && !field.startsWith('_')) docEvent[field] = item[field]
        }
      }
      var isAlert = ('rule.name' in item || 'event.severity_label' in item);
      if (escalate) {
        if (!caseId || !this.escalateRelatedEventsEnabled) {
          // Add to new case
          const response = await this.$root.papi.post('case/', this.buildCase(item));
          if (response && response.data) {
            caseId = response.data.id;
          }
        }

        // Attach the event to the case
        if (caseId && this.escalateRelatedEventsEnabled) {
          let payload = {
            fields: item,
            caseId: caseId,
            acknowledged: this.isFilterToggleEnabled('acknowledged'),
            escalated: this.isFilterToggleEnabled('escalated'),
            dateRange: this.dateRange,
            dateRangeFormat: this.i18n.timePickerSample,
            timezone: this.zone,
          };

          if (detectionRelated) {
            payload.fields = {
              'rule.uuid': item["rule.uuid"],
            };
          }

          await this.$root.papi.post('case/events', payload);
        }
      }
      if (isAlert) {
        let searchFilter;
        let eventFilter;

        if (!detectionRelated) {
          for (let prop in docEvent) {
            docEvent[prop] = this.subMissing(docEvent[prop]);
          }

          eventFilter = docEvent;
          searchFilter = await this.getQuery();
        } else {
          searchFilter = (acknowledge ? 'NOT ' : '') + 'event.acknowledged:true AND tags:alert';
          eventFilter = {
            'rule.uuid': item["rule.uuid"],
          };
        }

        const response = await this.$root.papi.post('events/ack', {
          searchFilter: searchFilter,
          eventFilter: eventFilter,
          dateRange: this.dateRange,
          dateRangeFormat: this.i18n.timePickerSample,
          timezone: this.zone,
          escalate: escalate,
          acknowledge: acknowledge,
        });
        if (response.data && response.data.errors && response.data.errors.length > 0) {
          this.$root.showWarning(this.i18n.ackPartialSuccess);
        }
      }
      if (this.isCategory('alerts')) {
        if ((item["count"] && item["count"] > 1) || detectionRelated) {
          this.$root.showTip(escalate ? this.i18n.escalatedMultipleTip : (acknowledge ? this.i18n.ackMultipleTip : this.i18n.ackUndoMultipleTip));
        } else {
          this.$root.showTip(escalate ? this.i18n.escalatedSingleTip : (acknowledge ? this.i18n.ackSingleTip : this.i18n.ackUndoSingleTip));
        }

        var data;
        if (item["count"] && groupIdx >= 0 && this.groupBys?.[groupIdx]?.data) {
          data = this.groupBys[groupIdx].data;
        } else {
          data = this.eventData;
        }

        this.removeDataItemFromView(data, item, detectionRelated);
      } else if (escalate) {
        this.$root.showTip(this.i18n.escalatedEventTip);
        item['event.escalated'] = true;
      }


      if (this.highlightedAlertInfo) {
        const inGroup = this.highlightedAlertInfo.groupIndex === -1

        if ((!inGroup && item === this.highlightedAlertInfo.item) ||
            (inGroup && this.highlightedDetection.publicId === item["rule.uuid"])) {
          this.highlightedDetection = null;
          this.highlightedAlertInfo = null;
        }
      }
    } catch (error) {
      this.$root.showError(error);
    }
    this.$root.stopLoading();
  },
  removeDataItemFromView(data, item, detectionRelated) {
    for (var j = 0; j < data.length; j++) {
      if (data[j] == item || (detectionRelated && data[j]["rule.uuid"] === item["rule.uuid"])) {
        data.splice(j, 1);
        if (item["count"]) {
          this.totalEvents -= item["count"];
        } else {
          this.totalEvents--;
        }
        if (this.totalEvents < 0) {
          this.totalEvents = 0;
        }
        if (!detectionRelated) {
          break;
        }
        j--;
      }
    }
  },
  performAction($event, action) {
    let shouldNavigate = true;

    if (action && action.jsCall && this[action.jsCall]) {
      // no need to navigate, made JS call instead
      this[action.jsCall](action);
      shouldNavigate = false;
    }

    this.$root.performAction($event, action);

    this.quickActionVisible = false;

    return shouldNavigate;
  },
  async bulkAction(confirmed) {
    let payload = {};

    if (this.selectedAction === 'delete' && !confirmed) {
      this.showBulkDeleteConfirmDialog = true;
      return;
    }

    this.showBulkDeleteConfirmDialog = false;

    this.$root.startLoading();

    if (this.selectAllState) {
      payload.query = this.query;
    } else if (this.selectAllIndeterminate) {
      let ids = [];
      for (let i = 0; i < this.eventData.length; i++) {
        if (this.eventData[i]._isSelected) {
          ids.push(this.eventData[i].soc_id);
        }
      }

      payload.ids = ids;
    } else {
      return;
    }

    try {
      const request = await this.$root.papi.post('detection/bulk/' + this.selectedAction, payload);

      let msg = this.i18n.bulkActionStarted;
      if (this.selectedAction === 'delete') {
        msg = this.i18n.bulkActionDeleteStarted;
      }

      msg = msg.replace('{total}', request.data.count.toLocaleString());

      this.$root.showTip(msg);

      this.selectAllState = false;
      this.selectedCount = 0;
      this.hunt(false);
    } catch (e) {
      this.$root.showError(e);
    } finally {
      this.$root.stopLoading();
    }
  },
  bulkDeleteDialogCancel() {
    this.showBulkDeleteConfirmDialog = false;
  },
  bulkUpdateReport(stats) {
    if (stats.error > 0) {
      let msg = this.i18n.bulkError.replace('{error}', stats.error.toLocaleString());
      this.$root.showError(msg);
    } else {
      let seconds = Math.floor(stats.time);
      let hours = Math.floor(seconds / 3600);
      seconds %= 3600;
      let minutes = Math.floor(seconds / 60);
      seconds = Math.floor(seconds % 60);

      let t = '';

      if (hours > 0) {
        t += hours + 'h ';
      }

      if (minutes > 0 || t.length > 0) {
        if (t.length > 0) {
          minutes = `0${minutes}`;
        }

        t += minutes + 'm ';
      }

      t += seconds.toFixed(0) + 's';

      if (stats.filtered) {
        let msg = this.i18n.bulkSuccessFiltered;
        msg = msg.replaceAll('{filtered}', stats.filtered.toLocaleString());
        msg = msg.replaceAll('{modified}', stats.modified.toLocaleString());
        msg = msg.replaceAll('{total}', stats.total.toLocaleString());
        msg = msg.replaceAll('{time}', t);

        this.$root.showWarning(msg, true);
      } else {
        let msg;
        switch (stats.verb) {
          case 'delete':
            msg = this.i18n.bulkSuccessDelete;
            break;
          case 'update':
            msg = this.i18n.bulkSuccessUpdate;
            break;
          case 'create':
            msg = this.i18n.bulkSuccessCreate;
        }

        msg = msg.replaceAll('{modified}', stats.modified.toLocaleString());
        msg = msg.replaceAll('{total}', stats.total.toLocaleString());
        msg = msg.replaceAll('{time}', t);

        this.$root.showInfo(msg, true);
      }
    }
  },
  startManualSync(engine, type) {
    if (!engine) {
      this.$root.showTip(this.i18n.engineSelect);
      return;
    }
    try {
      this.$root.papi.post(`detection/sync/${engine}/${type}`);

      let msg = this.i18n.startSyncFull;
      if (type !== 'full') {
        msg = this.i18n.startSyncUpdate;
      }

      msg = msg.replace("{engine}", engine);
      this.$root.showTip(msg);
    } catch (e) {
      this.$root.showError(e);
    }
  },
};