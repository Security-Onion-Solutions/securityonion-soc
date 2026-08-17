// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Explanations for the conditions SOC recognizes; anything missing falls back to
// the datastore's own prose. Inline entries interpolate that prose into the
// explanation rather than showing it on a separate line.
const FINDING_SUMMARY = {
  no_valid_shard_copy: { key: 'eventsHealthConditionNoValidShardCopy' },
  disk_threshold:      { key: 'eventsHealthConditionDiskThreshold' },
  same_shard:          { key: 'eventsHealthConditionSameShard' },
  throttling:          { key: 'eventsHealthConditionThrottling' },
  unexplained:         { key: 'eventsHealthConditionUnexplained', inline: true },
  indices_readonly:    { key: 'eventsHealthConditionIndicesReadonly', inline: true },
};

const FINDING_DISPLAY = {
  critical: { icon: 'fa-triangle-exclamation', color: 'error' },
  warning:  { icon: 'fa-circle-exclamation', color: 'warning' },
  info:     { icon: 'fa-circle-info', color: 'info' },
};

const STATUS_DISPLAY = {
  green:   { icon: 'fa-circle-check', color: 'success' },
  yellow:  { icon: 'fa-circle-exclamation', color: 'warning' },
  red:     { icon: 'fa-triangle-exclamation', color: 'error' },
  unknown: { icon: 'fa-circle-question', color: 'secondary' },
};

const gridRouteForEventsHealth = routes.find(r => r.name === 'grid');
if (gridRouteForEventsHealth && gridRouteForEventsHealth.component) {
  gridRouteForEventsHealth.component.computed = gridRouteForEventsHealth.component.computed || {};
  Object.assign(gridRouteForEventsHealth.component.computed, {
    eventsHealthIssueIndicators() {
      return this.digestEventsHealthIndicators().filter(function(indicator) { return indicator.status != 'green'; });
    },
    eventsHealthHealthyIndicators() {
      return this.digestEventsHealthIndicators().filter(function(indicator) { return indicator.status == 'green'; });
    },
  });
  Object.assign(gridRouteForEventsHealth.component.methods, {
    canShowEventsHealth(node) {
      return node.eventsHealthAvailable;
    },
    showEventsHealth(node) {
      this.eventsHealthDialog = true;
      this.loadEventsHealth(node.gridId);
    },
    hideEventsHealth() {
      this.eventsHealthDialog = false;
    },
    abortEventsHealth() {
      if (this.eventsHealthAbort) {
        this.eventsHealthAbort.abort();
        this.eventsHealthAbort = null;
      }
    },
    onEventsHealthDialogChanged(open) {
      // Every close path (Close button, ESC, outside-click) lands here via v-model
      if (!open) this.abortEventsHealth();
    },
    async loadEventsHealth(gridId) {
      // Aborting a superseded request also cancels its ES diagnostic calls server-side
      if (this.eventsHealthAbort) this.eventsHealthAbort.abort();
      const abort = new AbortController();
      this.eventsHealthAbort = abort;
      this.eventsHealthLoading = true;
      this.eventsHealth = null;
      this.eventsHealthExpanded = {};
      try {
        // Pin to the clicked node's grid; the papi interceptor would otherwise inject the globally selected grid
        const response = await this.$root.papi.get('events/health', { params: { gridId: gridId }, signal: abort.signal });
        if (this.eventsHealthAbort != abort) return;
        this.eventsHealth = response.data;
      } catch (error) {
        // No global error popup: the dialog shows its own unavailable message
      } finally {
        // A superseded request leaves the indicator to the request that replaced it
        if (this.eventsHealthAbort == abort) {
          this.eventsHealthAbort = null;
          this.eventsHealthLoading = false;
        }
      }
    },
    colorEventsHealthStatus(status) {
      return (STATUS_DISPLAY[status] || STATUS_DISPLAY.unknown).color;
    },
    iconEventsHealthStatus(status) {
      return (STATUS_DISPLAY[status] || STATUS_DISPLAY.unknown).icon;
    },
    formatEventsHealthIndicatorName(id) {
      const cased = this.$root.correctCasing(id);
      if (cased != id) return cased;
      const name = id.replace(/_/g, ' ');
      return name.charAt(0).toUpperCase() + name.slice(1);
    },
    // Indicators and their findings arrive ranked by the server
    digestEventsHealthIndicators() {
      if (!this.eventsHealth || !this.eventsHealth.indicators) return [];
      const route = this;
      return this.eventsHealth.indicators.map(function(indicator) {
        return {
          id: indicator.id,
          name: route.formatEventsHealthIndicatorName(indicator.id),
          status: indicator.status,
          symptom: indicator.symptom,
          causes: indicator.causes || [],
          findings: (indicator.findings || []).map(function(finding) {
            return route.formatEventsHealthFinding(finding);
          }),
        };
      });
    },
    formatEventsHealthFinding(finding) {
      const known = FINDING_SUMMARY[finding.condition];
      const display = FINDING_DISPLAY[finding.severity] || FINDING_DISPLAY.warning;
      return {
        icon: display.icon,
        color: display.color,
        scope: finding.scope ? this.eventsHealthShardGroupLabel(finding.scope) : '',
        summary: known
            ? this.$root.localizeMessage(known.key, { value: finding.detail, count: finding.count })
            : finding.condition + (finding.detail ? ': ' + finding.detail : ''),
        detail: (known && !known.inline && finding.detail) ? finding.condition + ': ' + finding.detail : '',
        nodes: finding.nodes || [],
      };
    },
    toggleEventsHealthDetails(id) {
      this.eventsHealthExpanded[id] = !this.eventsHealthExpanded[id];
    },
    hasEventsHealthDetails(indicator) {
      return indicator.causes.length > 0 || indicator.findings.length > 0;
    },
    eventsHealthShardGroupLabel(group) {
      return group.count + ' ' + (group.primary ? this.i18n.eventsHealthPrimary : this.i18n.eventsHealthReplica) + ' (' + group.reason + ')';
    },
    formatEventsHealthReportList(label, items) {
      const max = 10;
      var display = items.slice(0, max).join(', ');
      if (items.length > max) {
        display += this.$root.localizeMessage('eventsHealthMoreItems', { count: items.length - max });
      }
      return label + ' (' + items.length + '): ' + display;
    },
    buildEventsHealthReport() {
      if (!this.eventsHealth) return '';
      const route = this;
      const lines = [];

      lines.push(this.i18n.eventsHealthReportTitle);
      lines.push(this.i18n.eventsHealthReportGenerated + ': ' + moment().format());
      if (this.$root.version) {
        lines.push(this.i18n.product + ': ' + this.$root.version);
      }
      lines.push(this.i18n.eventsHealthReportStatus + ': ' + this.eventsHealth.status);
      const errors = this.eventsHealth.errors || {};
      Object.keys(errors).sort().forEach(function(section) {
        lines.push(route.$root.localizeMessage('eventsHealthReportUnavailable', { value: section }) + ': ' + errors[section]);
      });

      const nodes = this.eventsHealth.nodes;
      if (nodes && nodes.length) {
        // Unavailable stats are empty strings
        const stat = function(value) { return value ? value : '-'; };
        lines.push('');
        lines.push(this.i18n.eventsHealthReportSectionNodes);
        nodes.forEach(function(node) {
          lines.push('  * ' + stat(node.name) + ' (' + stat(node.ip) + ') roles=' + stat(node.roles) + ' master=' + stat(node.master) +
              ' version=' + stat(node.version) + ' heap=' + stat(node.heapPercent) + '% ram=' + stat(node.ramPercent) + '%' +
              ' cpu=' + stat(node.cpu) + '% load_1m=' + stat(node.load1m) +
              ' disk_used=' + stat(node.diskUsedPercent) + '% of ' + stat(node.diskTotal) + ' uptime=' + stat(node.uptime));
        });
      }

      const settings = this.eventsHealth.settings;
      if (settings) {
        lines.push('');
        lines.push(this.i18n.eventsHealthReportSectionSettings);
        ['persistent', 'transient'].forEach(function(scope) {
          const keys = Object.keys(settings[scope] || {});
          if (!keys.length) {
            lines.push(scope + ': ' + route.i18n.eventsHealthReportNone);
          } else {
            lines.push(scope + ':');
            keys.sort().forEach(function(key) {
              lines.push('  ' + key + ': ' + JSON.stringify(settings[scope][key]));
            });
          }
        });
      }

      lines.push('');
      lines.push(this.i18n.eventsHealthReportSectionIndicators);
      this.digestEventsHealthIndicators().forEach(function(indicator) {
        lines.push('[' + (indicator.status || 'unknown').toUpperCase() + '] ' + indicator.name + (indicator.symptom ? ' - ' + indicator.symptom : ''));
        indicator.findings.forEach(function(finding) {
          // Scoped findings are already covered by the unassigned shards section
          if (finding.scope) return;
          lines.push('  * ' + finding.summary);
        });
        indicator.causes.forEach(function(cause) {
          lines.push('  * ' + cause.cause);
          if (cause.nodes.length) {
            lines.push('    ' + route.formatEventsHealthReportList(route.i18n.eventsHealthAffectedNodes, cause.nodes));
          }
          if (cause.indices.length) {
            lines.push('    ' + route.formatEventsHealthReportList(route.i18n.eventsHealthAffectedIndices, cause.indices));
          }
        });
      });

      const unassigned = this.eventsHealth.unassignedShards;
      if (unassigned) {
        lines.push('');
        lines.push(this.i18n.eventsHealthReportSectionShards);
        lines.push(this.$root.localizeMessage('eventsHealthReportTotals', { total: unassigned.total, primaries: unassigned.primaries, replicas: unassigned.replicas }));
        (unassigned.groups || []).forEach(function(group) {
          if (group.sampleStatus != 'explained') {
            const reason = group.sampleStatus == 'failed' ? 'eventsHealthReportSampleFailed' : 'eventsHealthReportNoSample';
            lines.push(route.$root.localizeMessage(reason, { value: route.eventsHealthShardGroupLabel(group) }));
            return;
          }
          lines.push(route.$root.localizeMessage('eventsHealthReportSampledShard', { value: route.eventsHealthShardGroupLabel(group) }));
          lines.push('  ' + route.i18n.eventsHealthReportShard + ': ' + group.sampleIndex + '[' + group.sampleShard + '] (' + (group.primary ? route.i18n.eventsHealthPrimary : route.i18n.eventsHealthReplica) + ')');
          lines.push('  ' + route.i18n.eventsHealthReportUnassignedReason + ': ' + group.reason + (group.since ? route.$root.localizeMessage('eventsHealthReportSince', { value: group.since }) : ''));
          if (group.failureDetails) {
            lines.push('  ' + route.i18n.eventsHealthReportFailureDetails + ': ' + group.failureDetails);
          }
          if (group.canAllocate) {
            lines.push('  ' + route.i18n.eventsHealthReportCanAllocate + ': ' + group.canAllocate);
          }
          (group.deciders || []).forEach(function(decider) {
            lines.push('    - ' + decider.name + ': ' + decider.explanation);
            if (decider.nodes && decider.nodes.length) {
              lines.push('      ' + route.formatEventsHealthReportList(route.i18n.eventsHealthAffectedNodes, decider.nodes));
            }
          });
        });
      }

      return lines.join('\n');
    },
    copyEventsHealthReport() {
      this.$root.copyToClipboard(this.buildEventsHealthReport());
      this.$root.showTip(this.i18n.eventsHealthCopied);
    },
  });
}
