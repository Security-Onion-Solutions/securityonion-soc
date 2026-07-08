// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

const gridRouteForMetrics = routes.find(r => r.name === 'grid');
if (gridRouteForMetrics && gridRouteForMetrics.component) {
  Object.assign(gridRouteForMetrics.component.methods, {
    initMetricsCharts() {
      this.setupMetricsChart('cpu', this.i18n.metricsCpuUsage, [this.i18n.cpuUsageAbbr], [this.$root.getColor("primary")]);
      this.setupMetricsChart('memory', this.i18n.metricsMemUsage, [this.i18n.memUsageAbbr], [this.$root.getColor("primary")]);
      this.setupMetricsChart('load', this.i18n.loadAverage, [this.i18n.metricsLoad1, this.i18n.metricsLoad5, this.i18n.metricsLoad15], ["#4dc9f6", "#f67019", "#f53794"]);
      this.setupMetricsChart('disk', this.i18n.metricsDiskUsage, [this.i18n.metricsDiskRoot, this.i18n.metricsDiskNsm], ["#4dc9f6", "#acc236"]);
      this.setupMetricsChart('net', this.i18n.metricsNetTraffic, [this.i18n.metricsTrafficManIn, this.i18n.metricsTrafficManOut, this.i18n.metricsTrafficMonIn], ["#4dc9f6", "#f67019", "#00a950"]);
      this.setupMetricsChart('eps', this.i18n.eps, [this.i18n.metricsConsumptionEps, this.i18n.metricsProductionEps], ["#4dc9f6", "#f67019"]);
    },
    setupMetricsChart(chartKey, title, datasetLabels, colors) {
      const fontColor = this.$root.getColor("#888888", -40);
      const gridColor = this.$root.getColor("#888888", 65);
      const newOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: datasetLabels.length > 1,
            labels: { color: fontColor }
          },
          title: {
            display: true,
            text: title,
            color: fontColor,
          }
        },
        scales: {
          y: {
            grid: { color: gridColor },
            ticks: { color: fontColor }
          },
          x: {
            type: 'timeseries',
            grid: { color: gridColor },
            ticks: { color: fontColor }
          }
        }
      };

      const newData = {
        key: 0,
        labels: [],
        datasets: datasetLabels.map((lbl, idx) => ({
          label: lbl,
          data: [],
          borderColor: colors[idx] || this.$root.getColor("primary"),
          backgroundColor: colors[idx] || this.$root.getColor("primary"),
          pointRadius: 2,
          fill: false,
          tension: 0.1
        }))
      };

      if (chartKey === 'cpu') {
        this.chartCpuOptions = newOptions;
        this.chartCpuData = newData;
      } else if (chartKey === 'memory') {
        this.chartMemoryOptions = newOptions;
        this.chartMemoryData = newData;
      } else if (chartKey === 'load') {
        this.chartLoadOptions = newOptions;
        this.chartLoadData = newData;
      } else if (chartKey === 'disk') {
        this.chartDiskOptions = newOptions;
        this.chartDiskData = newData;
      } else if (chartKey === 'net') {
        this.chartNetOptions = newOptions;
        this.chartNetData = newData;
      } else if (chartKey === 'eps') {
        this.chartEpsOptions = newOptions;
        this.chartEpsData = newData;
      }
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

        const [cpuData, memData, loadData, diskData, netData, epsData] = await Promise.all([
          fetchMetric('cpu'),
          fetchMetric('memory'),
          fetchMetric('load'),
          fetchMetric('disk'),
          fetchMetric('net'),
          fetchMetric('eps')
        ]);

        this.populateMetricsChart(this.chartCpuData, cpuData, ['cpu_used']);
        this.populateMetricsChart(this.chartMemoryData, memData, ['memory_used']);
        this.populateMetricsChart(this.chartLoadData, loadData, ['load1', 'load5', 'load15']);
        this.populateMetricsChart(this.chartDiskData, diskData, ['disk_used_root', 'disk_used_nsm']);
        this.populateMetricsChart(this.chartNetData, netData, ['traffic_man_in', 'traffic_man_out', 'traffic_mon_in']);
        this.populateMetricsChart(this.chartEpsData, epsData, ['consumption_eps', 'production_eps']);
        
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
