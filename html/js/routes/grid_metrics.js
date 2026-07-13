// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const DEFAULT_DASHBOARD = {
  panels: [
    {
      id: "cpu",
      title: "CPU Usage",
      type: "line_chart",
      metric: "cpu",
      keys: ["cpu_used"],
      labels: ["CPU Usage"],
      width: 6,
      height: 250
    },
    {
      id: "memory",
      title: "Memory Usage",
      type: "line_chart",
      metric: "memory",
      keys: ["memory_used"],
      labels: ["Memory Usage"],
      width: 6,
      height: 250
    },
    {
      id: "load",
      title: "Load Average",
      type: "line_chart",
      metric: "load",
      keys: ["load1", "load5", "load15"],
      labels: ["Load 1m", "Load 5m", "Load 15m"],
      colors: ["#4dc9f6", "#f67019", "#f53794"],
      width: 6,
      height: 250
    },
    {
      id: "disk",
      title: "Disk Usage",
      type: "line_chart",
      metric: "disk",
      keys: ["disk_used_root", "disk_used_nsm"],
      labels: ["Root", "NSM"],
      colors: ["#4dc9f6", "#acc236"],
      width: 6,
      height: 250
    },
    {
      id: "net",
      title: "Network Traffic",
      type: "line_chart",
      metric: "net",
      keys: ["traffic_man_in", "traffic_man_out", "traffic_mon_in"],
      labels: ["Man In", "Man Out", "Mon In"],
      colors: ["#4dc9f6", "#f67019", "#00a950"],
      width: 6,
      height: 250
    },
    {
      id: "eps",
      title: "EPS",
      type: "line_chart",
      metric: "eps",
      keys: ["consumption_eps", "production_eps"],
      labels: ["Consumption EPS", "Production EPS"],
      colors: ["#4dc9f6", "#f67019"],
      width: 6,
      height: 250
    }
  ]
};

const gridRouteForMetrics = routes.find(r => r.name === 'grid');
if (gridRouteForMetrics && gridRouteForMetrics.component) {
  Object.assign(gridRouteForMetrics.component.methods, {
    initMetricsCharts() {
      var dashboard = DEFAULT_DASHBOARD;
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

        if (panel.type === 'line_chart') {
          window.socGraphing.setupTimelineChart(chartOptions, chartData, panel.title, fontColor, gridColor, primaryColor);
          chartOptions.onResize = this.debounceChartResize;
          if (panel.keys && panel.keys.length > 0) {
            chartData.datasets = panel.keys.map((k, idx) => ({
              label: panel.labels ? panel.labels[idx] : k,
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
        let rangeParam = '';
        if (this.metricsTimeRange === '1h') {
          rangeParam = 'now-1h:now';
        } else if (this.metricsTimeRange === '24h') {
          rangeParam = 'now-24h:now';
        } else if (this.metricsTimeRange === '7d') {
          rangeParam = 'now-7d:now';
        }
        
        const params = {
          nodeId: this.metricsNodeId,
          range: rangeParam,
          format: 'local',
          zone: this.zone
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
            this.populateMetricsChart(panel.chartData, mData, panel.keys);
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
    populateMetricsChart(chart, responseData, keys) {
      chart.key++;
      keys.forEach((k, idx) => {
        const dataset = chart.datasets[idx];
        if (dataset) {
          dataset.data = (responseData && responseData[k]) ? responseData[k].map(item => ({
            x: new Date(item.timestamp),
            y: item.value
          })) : [];
        }
      });
    },
    debounceChartResize(chart, size) {
      window.socGraphing.debounceChartResize(chart, size, this.chartResizeTracker);
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
