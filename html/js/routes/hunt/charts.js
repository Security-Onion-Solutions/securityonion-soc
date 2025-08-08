// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

export default {
  constructChartMetrics(data) {
    const records = [];
    const route = this;
    var other = 0;
    data.forEach(function(row, index) {
      var record = {
        value: row.value,
        keys: [row.keys.join(route.chartLabelFieldSeparator)],
      };
      if (records.length >= route.chartLabelOtherLimit) {
        other += row.value;
      } else {
        records.push(record);
      }
    });
    if (other > 0) {
      records.push({value: other, keys: [this.i18n.other]});
    }
    return records;
  },

  debounceChartResize(chart, size) {
    const MAX_RESIZE_METRIC_COUNT = 20;
    const MAX_RESIZE_METRIC_AGE = 1000; // milliseconds
    const MAX_RESIZE_METRIC_FLAPS = 1;

    if (!chart.options.responsive) return;

    const now = Date.now();

    // Get this chart's resize metric history, or create a new history
    var data = this.chartResizeTracker[chart];
    if (!data) {
      data = [];
      this.chartResizeTracker[chart] = data;
    }

    // Determine how many metrics are expired
    var pruneCount = 0;
    for (var idx = 0; idx < data.length; idx++) {
      var metric = data[idx];
      if (metric.time < now - MAX_RESIZE_METRIC_AGE) {
        pruneCount = idx + 1;
      } else {
        break
      }
    }

    // Remove expired metrics
    for (var idx = 0; idx < pruneCount; idx++) {
      data.shift();
    }

    var newResizeMetric = {
      size: size,
      time: now,
    }

    data.push(newResizeMetric);

    // Limit the number of metrics in history
    if (data.length > MAX_RESIZE_METRIC_COUNT) {
      data.shift();
    }

    // Review the metric history and determine if the chart size is flapping
    var flapCount = 0;
    var prevDirection = 0;
    for (var idx = 0; idx < data.length; idx++) {
      var prev = data[idx];
      if (idx < data.length - 1) {
        var next = data[idx + 1];
        var nextDirection = 0;
        if (next.size.width > prev.size.width) {
          nextDirection = 1;
        } else if (next.size.width < prev.size.width) {
          nextDirection = -1;
        }

        if (prevDirection != 0 && nextDirection != 0) {
          if (nextDirection != prevDirection) {
            flapCount++;
          }
        }
        if (nextDirection != 0) {
          prevDirection = nextDirection;
        }
      }
    }
    if (flapCount > MAX_RESIZE_METRIC_FLAPS) {
      chart.options.responsive = false;
    }
  },

  displayTable(group, groupIdx) {
    group.chart_type = "";
    this.groupBys[groupIdx] = group;
  },

  displayPieChart(group, groupIdx) {
    group.chart_type = "pie";
    group.chart_options = {};
    group.chart_data = {};
    this.setupPieChart(group.chart_options, group.chart_data, group.title);
    this.applyLegendOption(group, groupIdx);
    this.populateChart(group.chart_data, group.chart_metrics);
    this.groupBys[groupIdx] = group;
  },

  displayBarChart(group, groupIdx) {
    group.chart_type = "bar";
    group.chart_options = {};
    group.chart_data = {};
    this.setupBarChart(group.chart_options, group.chart_data, group.title, groupIdx);
    this.applyLegendOption(group, groupIdx);
    this.populateChart(group.chart_data, group.chart_metrics);
    this.groupBys[groupIdx] = group;
  },

  displaySankeyChart(group, groupIdx) {
    if (!this.isGroupSankeyCapable(group)) {
      return;
    }
    group.chart_type = "sankey";
    group.chart_options = {};
    group.chart_data = {};

    var flowMax = 0;
    var updateMaxMap = function(map, key, value) {
      var max = map[key];
      if (!max) {
        max = 0;
      }
      max = max + value;
      map[key] = max;
      flowMax = Math.max(flowMax, max);
    };

    var isRecursive = function(map, from, to, current, max) {
      if (current > max || from == to) {
        return true;
      }

      for (var i = 0; i < map.length; i++) {
        var item = map[i];
        if (item.from == to) {
          if (isRecursive(map, item.from, item.to, current + 1, max)) {
            return true;
          }
        }
      }
      return false;
    };

    var data = [];
    var maxFlowMap = {};
    group.data.forEach(function(item, index) {
      for (var idx = 0; idx < group.fields.length - 1; idx++) {
        var from = item[group.fields[idx]];
        var to = item[group.fields[idx+1]];
        var flow = { from: from, to: to, flow: item.count };
        data.push(flow);

        if (isRecursive(data, from, to, 0, group.fields.length)) {
          group.is_incomplete = true;
          data.pop();
        } else {
          updateMaxMap(maxFlowMap, from, item.count);
          updateMaxMap(maxFlowMap, to, item.count);
        }
      }
    });

    if (group.is_incomplete) {
      group.title += " " + this.i18n.chartTitleIncomplete;
    }
    this.setupSankeyChart(group.chart_options, group.chart_data, group.title);
    this.applyLegendOption(group, groupIdx);

    group.chart_data.datasets[0].data = data;
    group.chart_data.flowMax = flowMax;
    this.groupBys[groupIdx] = group;
  },

  isGroupSankeyCapable(group, groupIdx) {
    return group.fields != undefined && group.fields.length >= 2;
  },

  applyLegendOption(group, groupIdx) {
    const options = this.queryGroupByOptions[groupIdx];
    if (options.indexOf("legend") != -1) {
      group.chart_options.plugins.legend.display = true;
    } else if (options.indexOf("nolegend") != -1) {
      group.chart_options.plugins.legend.display = false;
    }
  },

  populateChart(chart, data) {
    chart.key++;
    chart.labels = [];
    chart.datasets[0].data = [];
    if (!data) return;
    const route = this;
    data.forEach(function(item, index) {
      chart.labels.push(route.$root.truncate(route.localizeValue(route.lookupSocId(item.keys[0])), route.chartLabelMaxLength));
      chart.datasets[0].data.push(item.value);
    });
  },

  setupCharts() {
    this.setupBarChart(this.topChartOptions, this.topChartData, this.i18n.chartTitleTop);
    this.setupTimelineChart(this.timelineChartOptions, this.timelineChartData, this.i18n.chartTitleTimeline);
    this.setupBarChart(this.bottomChartOptions, this.bottomChartData, this.i18n.chartTitleBottom);

    this.topChartData.key = 0;
    this.timelineChartData.key = 0;
    this.bottomChartData.key = 0;
  },

  setupBarChart(options, data, title, groupIdx) {
    var fontColor = this.$root.getColor("#888888", -40);
    var dataColor = this.$root.getColor("primary");
    var gridColor = this.$root.getColor("#888888", 65);
    options.onClick = this.handleChartClick(groupIdx);
    options.onResize = this.debounceChartResize;
    options.responsive = true;
    options.maintainAspectRatio = false;
    options.plugins = {
      legend: {
        display: false,
      },
      title: {
        display: true,
        text: title,
      }
    };
    options.scales = {
      y: {
        grid: {
          color: gridColor,
        },
        ticks: {
          beginAtZero: true,
          fontColor: fontColor,
          precision: 0,
        }
      },
      x: {
        gridLines: {
          color: gridColor,
        },
        ticks: {
          fontColor: fontColor,
        }
      },
    };

    data.labels = [];
    data.datasets = [{
      backgroundColor: dataColor,
      borderColor: dataColor,
      pointRadius: 3,
      fill: false,
      data: [],
      label: this.i18n.field_count,
    }];
  },

  setupTimelineChart(options, data, title) {
    this.setupBarChart(options, data, title);
    options.onClick = null;
    options.scales.x.type = 'timeseries';
  },

  setupPieChart(options, data, title) {
    options.onResize = this.debounceChartResize;
    options.responsive = true;
    options.maintainAspectRatio = false;
    options.plugins = {
      legend: {
        display: true,
        position: 'left',
      },
      title: {
        display: true,
        text: title,
      }
    };
    data.labels = [];
    data.datasets = [{
      backgroundColor: [
        'rgba(77, 201, 246, 1)',
        'rgba(246, 112, 25, 1)',
        'rgba(245, 55, 148, 1)',
        'rgba(83, 123, 196, 1)',
        'rgba(172, 194, 54, 1)',
        'rgba(22, 106, 143, 1)',
        'rgba(0, 169, 80, 1)',
        'rgba(88, 89, 91, 1)',
        'rgba(133, 73, 186, 1)',
        'rgba(235, 204, 52, 1)',
        'rgba(127, 127, 127, 1)',
      ],
      borderColor: 'rgba(255, 255, 255, 0.5)',
      data: [],
      label: this.i18n.field_count,
    }];
  },

  setupSankeyChart(options, data, title) {
    const route = this;
    options.onResize = this.debounceChartResize;
    options.responsive = true;
    options.maintainAspectRatio = false;
    options.plugins = {
      legend: {
        display: false,
      },
      title: {
        display: true,
        text: title,
      }
    };
    data.flowMax = 0; // This is a custom attribute used for color selection
    data.labels = [];
    data.datasets = [{
      data: [],
      label: this.i18n.field_count,
      color: this.$root.$vuetify && this.$root.$vuetify.theme.current.dark ? 'white' : 'black',
      colorFrom: c => route.getSankeyColor('from', 'out', c, data.flowMax),
      colorTo: c => route.getSankeyColor('to', 'in', c, data.flowMax),
      size: 'max',
    }];
  },

  getSankeyColor(tag, dir, source, max) {
    var color = 'steelblue';
    if (source && source.parsed && source.parsed._custom) {
      var value = source.parsed._custom[tag][dir] / (max > 0 ? max : 1);
      if (value > 0.90) {
        color = 'crimson';
      } else if (value > 0.80) {
        color = 'red';
      } else if (value > 0.70) {
        color = 'orangered';
      } else if (value > 0.60) {
        color = 'darkorange';
      } else if (value > 0.50) {
        color = 'orange';
      } else if (value > 0.40) {
        color = 'goldenrod';
      } else if (value > 0.30) {
        color = 'gold';
      } else if (value > 0.25) {
        color = 'yellow';
      } else if (value > 0.20) {
        color = 'yellowgreen';
      } else if (value > 0.15) {
        color = 'limegreen';
      } else if (value > 0.10) {
        color = 'green';
      } else if (value > 0.05) {
        color = 'aquamarine';
      } else if (value > 0.04) {
        color = 'cyan';
      } else if (value > 0.03) {
        color = 'darkturquoise';
      } else if (value > 0.02) {
        color = 'lightskyblue';
      } else if (value > 0.01) {
        color = 'royalblue';
      }
    }
    return color;
  },

  handleChartClick(groupIdx) {
    if (!groupIdx) {
      groupIdx = 0;
    }
    return (e, activeElement, chart) => {
      if (activeElement.length > 0) {
        var clickedValue = chart.data.labels[activeElement[0].index] + "";
        if (clickedValue && clickedValue.length > 0) {
          if (this.canQuery(clickedValue)) {
            var chartGroupByField = this.groupBys[groupIdx].fields[0];
            this.toggleQuickAction(e, {}, groupIdx, chartGroupByField, clickedValue);
          }
        }
        return true;
      }
      return false;
    };
  },
};