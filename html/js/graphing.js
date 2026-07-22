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

  getTranslation(key, defaultVal) {
    if (window.i18n && typeof window.i18n.getLocalizedTranslations === 'function') {
      const lang = (typeof navigator !== 'undefined' && navigator.language) ? navigator.language : 'en-US';
      const trans = window.i18n.getLocalizedTranslations(lang);
      if (trans && trans[key] !== undefined) {
        return trans[key];
      }
    }
    return defaultVal;
  },

  formatBytes(value) {
    const k = 1024;
    const sizes = [
      this.getTranslation('byteB', 'B'),
      this.getTranslation('byteKB', 'KB'),
      this.getTranslation('byteMB', 'MB'),
      this.getTranslation('byteGB', 'GB'),
      this.getTranslation('byteTB', 'TB'),
      this.getTranslation('bytePB', 'PB'),
      this.getTranslation('byteEB', 'EB'),
      this.getTranslation('byteZB', 'ZB'),
      this.getTranslation('byteYB', 'YB')
    ];
    if (value === 0) return '0 ' + sizes[0];
    const i = Math.floor(Math.log(Math.abs(value)) / Math.log(k));
    const formatted = parseFloat((value / Math.pow(k, i)).toFixed(1));
    return formatted + ' ' + (sizes[i] || '');
  },

  formatBits(value) {
    const k = 1000;
    const sizes = [
      this.getTranslation('bps', 'b/s'),
      this.getTranslation('kbps', 'Kb/s'),
      this.getTranslation('mbps', 'Mb/s'),
      this.getTranslation('gbps', 'Gb/s'),
      this.getTranslation('tbps', 'Tb/s'),
      this.getTranslation('pbps', 'Pb/s'),
      this.getTranslation('ebps', 'Eb/s'),
      this.getTranslation('zbps', 'Zb/s'),
      this.getTranslation('ybps', 'Yb/s')
    ];
    if (value === 0) return '0 ' + sizes[0];
    const i = Math.floor(Math.log(Math.abs(value)) / Math.log(k));
    const formatted = parseFloat((value / Math.pow(k, i)).toFixed(1));
    return formatted + ' ' + (sizes[i] || '');
  },

  formatPercent(value) {
    return parseFloat(value.toFixed(1)) + '%';
  },

  formatSeconds(value) {
    const absVal = Math.abs(value);
    if (absVal < 60) {
      return parseFloat(value.toFixed(1)) + this.getTranslation('sSeconds', 's');
    }
    if (absVal < 3600) {
      return parseFloat((value / 60).toFixed(1)) + this.getTranslation('mMinutes', 'm');
    }
    if (absVal < 86400) {
      return parseFloat((value / 3600).toFixed(1)) + this.getTranslation('hHours', 'h');
    }
    return parseFloat((value / 86400).toFixed(1)) + this.getTranslation('dDays', 'd');
  },

  formatDefaultNumber(value) {
    const absVal = Math.abs(value);
    if (absVal >= 1e12) {
      return parseFloat((value / 1e12).toFixed(1)) + this.getTranslation('tTrillion', 'T');
    }
    if (absVal >= 1e9) {
      return parseFloat((value / 1e9).toFixed(1)) + this.getTranslation('bBillion', 'B');
    }
    if (absVal >= 1e6) {
      return parseFloat((value / 1e6).toFixed(1)) + this.getTranslation('mMillion', 'M');
    }
    if (absVal >= 1e3) {
      return parseFloat((value / 1e3).toFixed(1)) + this.getTranslation('kThousand', 'K');
    }
    return value;
  },

  formatAxisValue(value, units) {
    if (typeof value !== 'number') return value;

    const self = window.socGraphing;
    if (units === 'byte' || units === 'bytes') {
      return self.formatBytes(value);
    }
    if (units === 'bit' || units === 'bits') {
      return self.formatBits(value * 1000000);
    }
    if (units === 'percent') {
      return self.formatPercent(value);
    }
    if (units === 'second' || units === 'seconds') {
      return self.formatSeconds(value);
    }

    return self.formatDefaultNumber(value);
  },

  setupBarChart(options, data, title, fontColor, gridColor, dataColor, units) {
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
      },
      tooltip: {
        mode: 'index',
        intersect: false,
        callbacks: {
          label: function (context) {
            let label = context.dataset.label || '';
            if (label) {
              label += ': ';
            }
            let val = context.raw;
            if (context.parsed && context.parsed.y !== undefined && context.parsed.y !== null) {
              val = context.parsed.y;
            } else if (val !== null && val !== undefined && typeof val === 'object' && val.y !== undefined) {
              val = val.y;
            }
            label += window.socGraphing.formatAxisValue(val, units);
            return label;
          }
        }
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
          callback: function (value, index, ticks) {
            return window.socGraphing.formatAxisValue(value, units);
          }
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

  setupTimelineChart(options, data, title, fontColor, gridColor, dataColor, units) {
    this.setupBarChart(options, data, title, fontColor, gridColor, dataColor, units);
    options.scales.x.type = 'timeseries';
    options.scales.x.time = {
      displayFormats: {
        millisecond: 'YYYY-MM-DD HH:mm:ss',
        second: 'YYYY-MM-DD HH:mm:ss',
        minute: 'YYYY-MM-DD HH:mm',
        hour: 'YYYY-MM-DD HH:mm',
        day: 'YYYY-MM-DD HH:mm',
        week: 'YYYY-MM-DD HH:mm',
        month: 'YYYY-MM-DD HH:mm',
        quarter: 'YYYY-MM-DD HH:mm',
        year: 'YYYY-MM-DD HH:mm'
      }
    };
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
