// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const gridRouteForMetrics = routes.find(r => r.name === 'grid');
if (gridRouteForMetrics && gridRouteForMetrics.component) {
  Object.assign(gridRouteForMetrics.component.methods, {
    initMetricsCharts() {
      var dashboard = { panels: [] };
      if (this.$root.parameters && this.$root.parameters.grid && this.$root.parameters.grid.metricsDashboard) {
        try {
          dashboard = typeof this.$root.parameters.grid.metricsDashboard === 'string' ?
                      JSON.parse(this.$root.parameters.grid.metricsDashboard) :
                      this.$root.parameters.grid.metricsDashboard;
        } catch (e) {
          console.error("Failed to parse metricsDashboard template:", e);
        }
      }

      const fontColor = this.$root.getColor("#888888", -40);
      const gridColor = this.$root.getColor("#888888", 65);
      const primaryColor = this.$root.getColor("primary");

      this.metricPanels = (dashboard.panels || []).map(panel => {
        const chartData = { key: 0, labels: [], datasets: [] };
        const chartOptions = {};

        const i18n = this.$root.i18n || {};
        const title = panel.titleKey ? (i18n[panel.titleKey] || panel.title) : (panel.title || panel.id);
        const labels = panel.labelKeys ? panel.labelKeys.map(k => i18n[k] || k) : (panel.labels || panel.keys);

        if (panel.type === 'line_chart') {
          window.socGraphing.setupTimelineChart(chartOptions, chartData, title, fontColor, gridColor, primaryColor, panel.units);
          chartOptions.onResize = this.debounceChartResize;
          if (panel.keys && panel.keys.length > 0) {
            chartData.datasets = panel.keys.map((k, idx) => ({
              label: labels ? labels[idx] : k,
              borderColor: panel.colors && panel.colors[idx] ? panel.colors[idx] : primaryColor,
              backgroundColor: panel.colors && panel.colors[idx] ? panel.colors[idx] : primaryColor,
              pointRadius: 2,
              fill: false,
              tension: 0.1,
              data: []
            }));
          }
        }

        return {
          ...panel,
          chartData,
          chartOptions,
          singleStatValue: 'N/A'
        };
      });
    },
    async loadHistoricalMetrics(isRefresh = false) {
      if (!isRefresh) {
        this.metricsLoading = true;
      }
      try {
        const range = this.metricsTimeRange || '1h';
        const rangeParam = `now-${range}:now`;
        
        const params = {
          nodeId: this.metricsNodeId,
          range: rangeParam,
          format: 'local',
          zone: 'UTC'
        };

        const fetchMetric = async (metricName) => {
          const res = await this.$root.papi.get('grid/metrics', { params: { ...params, metric: metricName } });
          return res.data;
        };

        // Gather all unique metric types from our active panel list
        const uniqueMetricTypes = [...new Set((this.metricPanels || []).map(p => p.metric))];
        
        // Fetch all of them in parallel
        const results = {};
        await Promise.all(uniqueMetricTypes.map(async (mType) => {
          try {
            results[mType] = await fetchMetric(mType);
          } catch (e) {
            console.error("Failed to fetch metric:", mType, e);
          }
        }));

        // Populate the panels dynamically!
        (this.metricPanels || []).forEach(panel => {
          const mData = results[panel.metric];
          if (panel.type === 'line_chart') {
            this.populateMetricsChart(panel.chartData, mData, panel.keys, panel.colors);
          } else if (panel.type === 'single_stat') {
            const series = mData ? mData[panel.key] : null;
            if (series && series.length > 0) {
              const latestVal = series[series.length - 1].value;
              panel.singleStatValue = typeof latestVal === 'number' ? Number(latestVal.toFixed(1)) : latestVal;
            } else {
              panel.singleStatValue = 'N/A';
            }
          }
        });
        
      } catch (error) {
        this.$root.showError(error);
      } finally {
        if (!isRefresh) {
          this.metricsLoading = false;
        }
      }
    },
    populateMetricsChart(chart, responseData, keys, colors) {
      chart.key++;
      const zone = this.zone || 'UTC';
      const primaryColor = this.$root.getColor ? this.$root.getColor("primary") : "#123456";
      const lineColors = (colors && colors.length > 0) ? colors : [primaryColor];

      const responseKeys = Object.keys(responseData || {}).sort();
      const hasMismatch = responseKeys.length > 0 && !responseKeys.every(k => keys.includes(k));

      if (hasMismatch) {
        chart.datasets = responseKeys.map((k, idx) => {
          const color = lineColors[idx % lineColors.length];
          return {
            label: k,
            borderColor: color,
            backgroundColor: color,
            pointRadius: 2,
            fill: false,
            tension: 0.1,
            data: responseData[k].map(item => ({
              x: new Date(moment.utc(item.timestamp).tz(zone).format('YYYY-MM-DDTHH:mm:ss')),
              y: item.value
            }))
          };
        });
      } else {
        keys.forEach((k, idx) => {
          const dataset = chart.datasets[idx];
          if (dataset) {
            dataset.data = (responseData && responseData[k]) ? responseData[k].map(item => ({
              x: new Date(moment.utc(item.timestamp).tz(zone).format('YYYY-MM-DDTHH:mm:ss')),
              y: item.value
            })) : [];
          }
        });
      }
    },
    debounceChartResize(chart, size) {
      window.socGraphing.debounceChartResize(chart, size, this.chartResizeTracker);
    },
    getMetricPanelCardHeight(panel) {
      const panelHeight = panel && panel.height;
      return (panelHeight ? (panelHeight + 60) : 310) + 'px';
    },
    setupMetricsAutoRefresh() {
      if (this.metricsRefreshInterval) {
        clearInterval(this.metricsRefreshInterval);
        this.metricsRefreshInterval = null;
      }

      if (!this.metricsAutoRefresh) {
        return;
      }

      this.metricsRefreshInterval = setInterval(() => {
        this.loadHistoricalMetrics(true);
      }, this.metricsAutoRefresh * 1000);
    },
  });
}
