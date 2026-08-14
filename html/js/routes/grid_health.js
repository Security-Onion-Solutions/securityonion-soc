// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Explanations for the conditions SOC recognizes; anything missing falls back to
// the datastore's own prose. Inline entries interpolate that prose into the
// explanation rather than showing it on a separate line.
const FINDING_SUMMARY = {
  no_valid_shard_copy: { key: 'esHealthVerdictNoValidShardCopy' },
  disk_threshold:      { key: 'esHealthVerdictDiskThreshold' },
  same_shard:          { key: 'esHealthVerdictSameShard' },
  throttling:          { key: 'esHealthVerdictThrottling' },
  unexplained:         { key: 'esHealthVerdictUnexplained', inline: true },
  indices_readonly:    { key: 'esHealthDiskReadonly', inline: true },
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

const gridRouteForEsHealth = routes.find(r => r.name === 'grid');
if (gridRouteForEsHealth && gridRouteForEsHealth.component) {
  gridRouteForEsHealth.component.computed = gridRouteForEsHealth.component.computed || {};
  Object.assign(gridRouteForEsHealth.component.computed, {
    esHealthIndicators() {
      return this.digestEsIndicators();
    },
    esHealthIssues() {
      return this.digestEsIndicators().filter(function(indicator) { return indicator.status != 'green'; });
    },
    esHealthHealthy() {
      return this.digestEsIndicators().filter(function(indicator) { return indicator.status == 'green'; });
    },
  });
  Object.assign(gridRouteForEsHealth.component.methods, {
    canShowEsHealth(node) {
      return node.eventsHealthAvailable;
    },
    showEsHealth(node) {
      this.esHealthDialog = true;
      this.loadEsHealth(node.gridId);
    },
    hideEsHealth() {
      this.esHealthDialog = false;
    },
    abortEsHealth() {
      if (this.esHealthAbort) {
        this.esHealthAbort.abort();
        this.esHealthAbort = null;
      }
    },
    onEsHealthDialogChanged(open) {
      // Every close path (Close button, ESC, outside-click) lands here via v-model
      if (!open) this.abortEsHealth();
    },
    async loadEsHealth(gridId) {
      // Aborting a superseded request also cancels its ES diagnostic calls server-side
      if (this.esHealthAbort) this.esHealthAbort.abort();
      const abort = new AbortController();
      this.esHealthAbort = abort;
      this.esHealthLoading = true;
      this.esHealth = null;
      this.esHealthExpanded = {};
      try {
        // Pin to the clicked node's grid; the papi interceptor would otherwise inject the globally selected grid
        const response = await this.$root.papi.get('events/health', { params: { gridId: gridId }, signal: abort.signal });
        if (this.esHealthAbort != abort) return;
        this.esHealth = response.data;
      } catch (error) {
        // No global error popup: the dialog shows its own unavailable message
      } finally {
        // A superseded request leaves the indicator to the request that replaced it
        if (this.esHealthAbort == abort) {
          this.esHealthAbort = null;
          this.esHealthLoading = false;
        }
      }
    },
    colorEsHealthStatus(status) {
      return (STATUS_DISPLAY[status] || STATUS_DISPLAY.unknown).color;
    },
    iconEsHealthStatus(status) {
      return (STATUS_DISPLAY[status] || STATUS_DISPLAY.unknown).icon;
    },
    formatEsIndicatorName(id) {
      const cased = this.$root.correctCasing(id);
      if (cased != id) return cased;
      const name = id.replace(/_/g, ' ');
      return name.charAt(0).toUpperCase() + name.slice(1);
    },
    // Indicators and their findings arrive ranked by the server
    digestEsIndicators() {
      if (!this.esHealth || !this.esHealth.indicators) return [];
      const route = this;
      return this.esHealth.indicators.map(function(indicator) {
        return {
          id: indicator.id,
          name: route.formatEsIndicatorName(indicator.id),
          status: indicator.status,
          symptom: indicator.symptom,
          causes: indicator.causes || [],
          findings: (indicator.findings || []).map(function(finding) {
            return route.formatEsFinding(finding);
          }),
        };
      });
    },
    formatEsFinding(finding) {
      const known = FINDING_SUMMARY[finding.condition];
      const display = FINDING_DISPLAY[finding.severity] || FINDING_DISPLAY.warning;
      return {
        icon: display.icon,
        color: display.color,
        scope: finding.scope ? this.esShardGroupLabel(finding.scope) : '',
        summary: known
            ? this.$root.localizeMessage(known.key, { value: finding.detail, count: finding.count })
            : finding.condition + (finding.detail ? ': ' + finding.detail : ''),
        detail: (known && !known.inline && finding.detail) ? finding.condition + ': ' + finding.detail : '',
        nodes: finding.nodes || [],
      };
    },
    toggleEsHealthDetails(id) {
      this.esHealthExpanded[id] = !this.esHealthExpanded[id];
    },
    hasEsHealthDetails(indicator) {
      return indicator.causes.length > 0 || indicator.findings.length > 0;
    },
    esShardGroupLabel(group) {
      return group.count + ' ' + (group.primary ? this.i18n.esHealthPrimary : this.i18n.esHealthReplica) + ' (' + group.reason + ')';
    },
    formatEsReportList(label, items) {
      const max = 10;
      var display = items.slice(0, max).join(', ');
      if (items.length > max) {
        display += this.$root.localizeMessage('esHealthMoreItems', { count: items.length - max });
      }
      return label + ' (' + items.length + '): ' + display;
    },
    buildEsHealthReport() {
      if (!this.esHealth) return '';
      const route = this;
      const lines = [];

      lines.push(this.i18n.esHealthReportTitle);
      lines.push(this.i18n.esHealthReportGenerated + ': ' + moment().format());
      if (this.$root.version) {
        lines.push(this.i18n.product + ': ' + this.$root.version);
      }
      lines.push(this.i18n.esHealthReportStatus + ': ' + this.esHealth.status);
      const errors = this.esHealth.errors || {};
      Object.keys(errors).sort().forEach(function(section) {
        lines.push(route.$root.localizeMessage('esHealthReportUnavailable', { value: section }) + ': ' + errors[section]);
      });

      const nodes = this.esHealth.nodes;
      if (nodes && nodes.length) {
        // Unavailable stats are empty strings
        const stat = function(value) { return value ? value : '-'; };
        lines.push('');
        lines.push(this.i18n.esHealthReportSectionNodes);
        nodes.forEach(function(node) {
          lines.push('  * ' + stat(node.name) + ' (' + stat(node.ip) + ') roles=' + stat(node.roles) + ' master=' + stat(node.master) +
              ' version=' + stat(node.version) + ' heap=' + stat(node.heapPercent) + '% ram=' + stat(node.ramPercent) + '%' +
              ' cpu=' + stat(node.cpu) + '% load_1m=' + stat(node.load1m) +
              ' disk_used=' + stat(node.diskUsedPercent) + '% of ' + stat(node.diskTotal) + ' uptime=' + stat(node.uptime));
        });
      }

      const settings = this.esHealth.settings;
      if (settings) {
        lines.push('');
        lines.push(this.i18n.esHealthReportSectionSettings);
        ['persistent', 'transient'].forEach(function(scope) {
          const keys = Object.keys(settings[scope] || {});
          if (!keys.length) {
            lines.push(scope + ': ' + route.i18n.esHealthReportNone);
          } else {
            lines.push(scope + ':');
            keys.sort().forEach(function(key) {
              lines.push('  ' + key + ': ' + JSON.stringify(settings[scope][key]));
            });
          }
        });
      }

      lines.push('');
      lines.push(this.i18n.esHealthReportSectionIndicators);
      this.digestEsIndicators().forEach(function(indicator) {
        lines.push('[' + (indicator.status || 'unknown').toUpperCase() + '] ' + indicator.name + (indicator.symptom ? ' - ' + indicator.symptom : ''));
        indicator.findings.forEach(function(finding) {
          // Scoped findings are already covered by the unassigned shards section
          if (finding.scope) return;
          lines.push('  * ' + finding.summary);
        });
        indicator.causes.forEach(function(cause) {
          lines.push('  * ' + cause.cause);
          if (cause.nodes.length) {
            lines.push('    ' + route.formatEsReportList(route.i18n.esHealthAffectedNodes, cause.nodes));
          }
          if (cause.indices.length) {
            lines.push('    ' + route.formatEsReportList(route.i18n.esHealthAffectedIndices, cause.indices));
          }
        });
      });

      const unassigned = this.esHealth.unassignedShards;
      if (unassigned) {
        lines.push('');
        lines.push(this.i18n.esHealthReportSectionShards);
        lines.push(this.$root.localizeMessage('esHealthReportTotals', { total: unassigned.total, primaries: unassigned.primaries, replicas: unassigned.replicas }));
        (unassigned.groups || []).forEach(function(group) {
          if (group.sampleStatus != 'explained') {
            const reason = group.sampleStatus == 'failed' ? 'esHealthReportSampleFailed' : 'esHealthReportNoSample';
            lines.push(route.$root.localizeMessage(reason, { value: route.esShardGroupLabel(group) }));
            return;
          }
          lines.push(route.$root.localizeMessage('esHealthReportSampledShard', { value: route.esShardGroupLabel(group) }));
          lines.push('  ' + route.i18n.esHealthReportShard + ': ' + group.sampleIndex + '[' + group.sampleShard + '] (' + (group.primary ? route.i18n.esHealthPrimary : route.i18n.esHealthReplica) + ')');
          lines.push('  ' + route.i18n.esHealthReportUnassignedReason + ': ' + group.reason + (group.since ? route.$root.localizeMessage('esHealthReportSince', { value: group.since }) : ''));
          if (group.details) {
            lines.push('  ' + route.i18n.esHealthReportDetails + ': ' + group.details);
          }
          if (group.canAllocate) {
            lines.push('  ' + route.i18n.esHealthReportCanAllocate + ': ' + group.canAllocate);
          }
          (group.deciders || []).forEach(function(decider) {
            lines.push('    - ' + decider.name + ': ' + decider.explanation);
            if (decider.nodes && decider.nodes.length) {
              lines.push('      ' + route.formatEsReportList(route.i18n.esHealthAffectedNodes, decider.nodes));
            }
          });
        });
      }

      return lines.join('\n');
    },
    copyEsHealthReport() {
      this.$root.copyToClipboard(this.buildEsHealthReport());
      this.$root.showTip(this.i18n.esHealthCopied);
    },
  });
}
