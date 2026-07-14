// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

window.socGraphing = {
  debounceChartResize(chart, size, tracker) {
    const MAX_RESIZE_METRIC_COUNT = 20;
    const MAX_RESIZE_METRIC_AGE = 1000; // milliseconds
    const MAX_RESIZE_METRIC_FLAPS = 1;

    if (!chart || !chart.options || !chart.options.responsive) return;

    const now = Date.now();

    // Get this chart's resize metric history, or create a new history
    var data = tracker[chart];
    if (!data) {
      data = [];
      tracker[chart] = data;
    }

    // Determine how many metrics are expired
    var pruneCount = 0;
    for (var idx = 0; idx < data.length; idx++) {
      var metric = data[idx];
      if (metric.time < now - MAX_RESIZE_METRIC_AGE) {
        pruneCount = idx + 1;
      } else {
        break;
      }
    }

    // Remove expired metrics
    for (var idx = 0; idx < pruneCount; idx++) {
      data.shift();
    }

    var newResizeMetric = {
      size: size,
      time: now,
    };

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

  setupBarChart(options, data, title, fontColor, gridColor, dataColor) {
    options.responsive = true;
    options.maintainAspectRatio = false;
    options.layout = {
      padding: {
        bottom: 15
      }
    };
    options.plugins = {
      legend: {
        display: false,
      },
      title: {
        display: true,
        text: title,
        color: fontColor,
      }
    };
    options.scales = {
      y: {
        grid: {
          color: gridColor,
        },
        ticks: {
          beginAtZero: true,
          color: fontColor,
          precision: 0,
        }
      },
      x: {
        grid: {
          color: gridColor,
        },
        ticks: {
          color: fontColor,
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
      label: 'Count', // We can use a generic default, or set it caller-side if needed
    }];
  },

  setupTimelineChart(options, data, title, fontColor, gridColor, dataColor) {
    this.setupBarChart(options, data, title, fontColor, gridColor, dataColor);
    options.scales.x.type = 'timeseries';
  },

  setupPieChart(options, data, title, fontColor) {
    options.responsive = true;
    options.maintainAspectRatio = false;
    options.plugins = {
      legend: {
        display: true,
        position: 'left',
        labels: {
          color: fontColor,
        },
      },
      title: {
        display: true,
        text: title,
        color: fontColor,
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
      label: 'Count',
    }];
  },

  setupSankeyChart(options, data, title, fontColor, isDark, colorFromCallback, colorToCallback) {
    options.responsive = true;
    options.maintainAspectRatio = false;
    options.plugins = {
      legend: {
        display: false,
      },
      title: {
        display: true,
        text: title,
        color: fontColor,
      }
    };
    data.flowMax = 0;
    data.labels = [];
    data.datasets = [{
      data: [],
      label: 'Count',
      color: isDark ? 'white' : 'black',
      colorFrom: colorFromCallback,
      colorTo: colorToCallback,
      size: 'max',
    }];
  },

  populateChart(chart, data, chartLabelMaxLength, truncateFunc, localizeValueFunc, lookupSocIdFunc) {
    chart.key++;
    chart.labels = [];
    chart.datasets[0].data = [];
    if (!data) return;
    data.forEach(function (item) {
      var rawLabel = item.keys && item.keys.length > 0 ? item.keys[0] : '';
      var displayLabel = truncateFunc(localizeValueFunc(lookupSocIdFunc(rawLabel)), chartLabelMaxLength);
      chart.labels.push(displayLabel);
      chart.datasets[0].data.push(item.value);
    });
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
  }
};
