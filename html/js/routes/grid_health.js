// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

// Roles running a node-local Elasticsearch that SOC's ES connection cannot reach
const ROLES_WITH_LOCAL_EVENTSTORE = ['so-heavynode'];

const gridRouteForEsHealth = routes.find(r => r.name === 'grid');
if (gridRouteForEsHealth && gridRouteForEsHealth.component) {
  Object.assign(gridRouteForEsHealth.component.methods, {
    canShowEsHealth(node) {
      return ROLES_WITH_LOCAL_EVENTSTORE.indexOf(node.role) == -1;
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
      this.digestEsHealth();
      try {
        // Pin to the clicked node's grid; the papi interceptor would otherwise inject the globally selected grid
        const response = await this.$root.papi.get('eventstore/health', { params: { gridId: gridId }, signal: abort.signal });
        if (this.esHealthAbort != abort) return;
        this.esHealth = response.data;
        this.digestEsHealth();
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
    // The payload never changes after load, so view data is derived once here
    // rather than on every render.
    digestEsHealth() {
      this.esHealthIndicators = this.digestEsIndicators();
      this.esHealthIssues = this.esHealthIndicators.filter(function(indicator) { return indicator.status != 'green'; });
      this.esHealthHealthy = this.esHealthIndicators.filter(function(indicator) { return indicator.status == 'green'; });
      this.esDiskFindings = this.digestEsDiskFindings();
      this.esShardVerdicts = this.digestEsShardVerdicts();
    },
    colorEsHealthStatus(status) {
      var color = "secondary";
      switch (status) {
        case "green": color = "success"; break;
        case "yellow": color = "warning"; break;
        case "red": color = "error"; break;
      }
      return color;
    },
    iconEsHealthStatus(status) {
      var icon = "fa-circle-question";
      switch (status) {
        case "green": icon = "fa-circle-check"; break;
        case "yellow": icon = "fa-circle-exclamation"; break;
        case "red": icon = "fa-triangle-exclamation"; break;
      }
      return icon;
    },
    formatEsIndicatorName(id) {
      const cased = this.$root.correctCasing(id);
      if (cased != id) return cased;
      const name = id.replace(/_/g, ' ');
      return name.charAt(0).toUpperCase() + name.slice(1);
    },
    digestEsIndicators() {
      if (!this.esHealth || !this.esHealth.healthReport || !this.esHealth.healthReport.indicators) return [];
      const route = this;
      const order = { red: 0, yellow: 1, unknown: 2, green: 3 };
      const indicators = this.esHealth.healthReport.indicators;
      return Object.keys(indicators).map(function(id) {
        const indicator = indicators[id];
        return {
          id: id,
          name: route.formatEsIndicatorName(id),
          status: indicator.status,
          symptom: indicator.symptom,
          causes: (indicator.diagnosis || []).filter(function(d) { return d.cause; }).map(function(d) {
            const resources = d.affected_resources || {};
            return {
              cause: d.cause,
              nodes: (resources.nodes || []).map(function(n) { return n.name; }),
              indices: resources.indices || [],
            };
          }),
        };
      }).sort(function(a, b) {
        const rankA = order[a.status] !== undefined ? order[a.status] : 2;
        const rankB = order[b.status] !== undefined ? order[b.status] : 2;
        return (rankA - rankB) || a.name.localeCompare(b.name);
      });
    },
    toggleEsHealthDetails(id) {
      this.esHealthExpanded[id] = !this.esHealthExpanded[id];
    },
    hasEsHealthDetails(indicator) {
      if (indicator.id == 'shards_availability' && this.esShardVerdicts.length > 0) return true;
      if (indicator.id == 'disk' && this.esDiskFindings.length > 0) return true;
      return indicator.causes.length > 0;
    },
    digestEsDiskFindings() {
      if (!this.esHealth || !this.esHealth.healthReport || !this.esHealth.healthReport.indicators) return [];
      const disk = this.esHealth.healthReport.indicators.disk;
      if (!disk || disk.status == 'green') return [];
      const findings = [];
      const readonly = disk.details ? disk.details.indices_with_readonly_block : 0;
      if (readonly > 0) {
        findings.push(this.$root.localizeMessage('esHealthDiskReadonly', { count: readonly }));
      }
      return findings;
    },
    esShardGroupLabel(group) {
      return group.count + ' ' + (group.primary ? this.i18n.esHealthPrimary : this.i18n.esHealthReplica) + ' (' + group.reason + ')';
    },
    digestEsShardVerdicts() {
      const route = this;
      const unassigned = this.esHealth ? this.esHealth.unassignedShards : null;
      if (!unassigned || !unassigned.groups) return [];

      // Keyed on ES's stable identifiers (can_allocate, decider names), never its
      // free-text prose; unknown deciders show ES's explanation verbatim.
      const canAllocateVerdicts = {
        no_valid_shard_copy: { severity: 0, summary: this.i18n.esHealthVerdictNoValidShardCopy },
      };
      const deciderVerdicts = {
        disk_threshold: { severity: 1, summary: this.i18n.esHealthVerdictDiskThreshold },
        same_shard: { severity: 2, summary: this.i18n.esHealthVerdictSameShard },
        throttling: { severity: 2, summary: this.i18n.esHealthVerdictThrottling },
      };
      const icons = ['fa-triangle-exclamation', 'fa-circle-exclamation', 'fa-circle-info'];
      const colors = ['error', 'warning', 'info'];

      const verdicts = [];
      unassigned.groups.forEach(function(group) {
        const scope = route.esShardGroupLabel(group);
        const before = verdicts.length;
        const outcome = canAllocateVerdicts[group.canAllocate];
        if (outcome) {
          verdicts.push({ severity: outcome.severity, scope: scope, summary: outcome.summary, decider: null, detail: null, nodes: [] });
        }
        (group.deciders || []).forEach(function(decider) {
          const known = deciderVerdicts[decider.name];
          verdicts.push({
            severity: known ? known.severity : 1,
            scope: scope,
            summary: known ? known.summary : decider.name + ': ' + decider.explanation,
            decider: decider.name,
            detail: known ? decider.explanation : null,
            nodes: decider.nodes || [],
          });
        });
        // Transient outcomes (throttled, allocation_delayed, awaiting_info...) report
        // no blocking deciders; every explained group still gets a verdict row
        if (verdicts.length == before && group.canAllocate) {
          verdicts.push({
            severity: 2,
            scope: scope,
            summary: route.$root.localizeMessage('esHealthVerdictUnexplained', { value: group.canAllocate }),
            decider: null,
            detail: null,
            nodes: [],
          });
        }
      });
      verdicts.sort(function(a, b) { return a.severity - b.severity; });
      verdicts.forEach(function(verdict) {
        verdict.icon = icons[verdict.severity] || icons[1];
        verdict.color = colors[verdict.severity] || colors[1];
      });
      return verdicts;
    },
    esAllocationLines(explain) {
      if (!explain) return [];
      const route = this;
      const lines = [];
      lines.push(this.i18n.esHealthReportShard + ': ' + explain.index + '[' + explain.shard + '] (' + (explain.primary ? this.i18n.esHealthPrimary : this.i18n.esHealthReplica) + ')');
      if (explain.unassigned_info) {
        lines.push(this.i18n.esHealthReportUnassignedReason + ': ' + explain.unassigned_info.reason + (explain.unassigned_info.at ? this.$root.localizeMessage('esHealthReportSince', { value: explain.unassigned_info.at }) : ''));
      }
      if (explain.can_allocate) {
        lines.push(this.i18n.esHealthReportCanAllocate + ': ' + explain.can_allocate);
      }
      (explain.node_allocation_decisions || []).forEach(function(node) {
        lines.push('  * ' + route.i18n.esHealthReportNode + ' ' + node.node_name + ': ' + node.node_decision);
        (node.deciders || []).forEach(function(decider) {
          lines.push('    - ' + decider.decider + ': ' + decider.explanation);
        });
      });
      return lines;
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

      const nodes = this.esHealth.catNodes;
      if (nodes && nodes.length) {
        // ES reports null for stats that are momentarily unavailable
        const stat = function(value) { return value == null ? '-' : value; };
        lines.push('');
        lines.push(this.i18n.esHealthReportSectionNodes);
        nodes.forEach(function(node) {
          lines.push('  * ' + stat(node.name) + ' (' + stat(node.ip) + ') roles=' + stat(node['node.role']) + ' master=' + stat(node.master) +
              ' version=' + stat(node.version) + ' heap=' + stat(node['heap.percent']) + '% ram=' + stat(node['ram.percent']) + '%' +
              ' cpu=' + stat(node.cpu) + '% load_1m=' + stat(node.load_1m) +
              ' disk_used=' + stat(node['disk.used_percent']) + '% of ' + stat(node['disk.total']) + ' uptime=' + stat(node.uptime));
        });
      }

      const settings = this.esHealth.clusterSettings;
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
      this.esHealthIndicators.forEach(function(indicator) {
        lines.push('[' + (indicator.status || 'unknown').toUpperCase() + '] ' + indicator.name + (indicator.symptom ? ' - ' + indicator.symptom : ''));
        if (indicator.id == 'disk') {
          route.esDiskFindings.forEach(function(finding) {
            lines.push('  * ' + finding);
          });
        }
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
          if (!group.explanation) {
            lines.push(route.$root.localizeMessage('esHealthReportNoSample', { value: route.esShardGroupLabel(group) }));
            return;
          }
          lines.push(route.$root.localizeMessage('esHealthReportSampledShard', { value: route.esShardGroupLabel(group) }));
          route.esAllocationLines(group.explanation).forEach(function(line) {
            lines.push('  ' + line);
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
