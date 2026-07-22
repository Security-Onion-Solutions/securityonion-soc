// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('./test_common.js');

window.i18n = global.i18n;

const graphing = window.socGraphing;

describe('graphing.js', () => {
  describe('getTranslation', () => {
    let originalGetLocalizedTranslations;

    beforeAll(() => {
      originalGetLocalizedTranslations = window.i18n.getLocalizedTranslations;
    });

    afterAll(() => {
      window.i18n.getLocalizedTranslations = originalGetLocalizedTranslations;
    });

    it('should return translation from window.i18n when key is found', () => {
      window.i18n.getLocalizedTranslations = jest.fn(() => ({
        testKey: 'Translated Value'
      }));

      const val = graphing.getTranslation('testKey', 'Default Value');
      expect(val).toBe('Translated Value');
    });

    it('should return defaultVal when key is not found', () => {
      window.i18n.getLocalizedTranslations = jest.fn(() => ({
        anotherKey: 'Translated Value'
      }));

      const val = graphing.getTranslation('testKey', 'Default Value');
      expect(val).toBe('Default Value');
    });

    it('should return defaultVal when window.i18n or function is not defined', () => {
      const origI18n = window.i18n;
      window.i18n = undefined;
      const val = graphing.getTranslation('testKey', 'Default Value');
      expect(val).toBe('Default Value');
      window.i18n = origI18n;
    });
  });

  describe('formatBytes', () => {
    it('should format bytes correctly', () => {
      expect(graphing.formatBytes(0)).toBe('0 B');
      expect(graphing.formatBytes(512)).toBe('512 B');
      expect(graphing.formatBytes(1024)).toBe('1 KB');
      expect(graphing.formatBytes(1024 * 1024)).toBe('1 MB');
      expect(graphing.formatBytes(1024 * 1024 * 1024 * 1.5)).toBe('1.5 GB');
      expect(graphing.formatBytes(1024 * 1024 * 1024 * 1024 * 2.34)).toBe('2.3 TB');
      expect(graphing.formatBytes(-1024 * 1024 * 15)).toBe('-15 MB');
    });
  });

  describe('formatBits', () => {
    it('should format bits correctly', () => {
      expect(graphing.formatBits(0)).toBe('0 b/s');
      expect(graphing.formatBits(500)).toBe('500 b/s');
      expect(graphing.formatBits(1000)).toBe('1 Kb/s');
      expect(graphing.formatBits(1000 * 1000)).toBe('1 Mb/s');
      expect(graphing.formatBits(1000 * 1000 * 1000 * 2.5)).toBe('2.5 Gb/s');
      expect(graphing.formatBits(-1000 * 1000 * 12)).toBe('-12 Mb/s');
    });
  });

  describe('formatPercent', () => {
    it('should format percentage correctly', () => {
      expect(graphing.formatPercent(0)).toBe('0%');
      expect(graphing.formatPercent(12.345)).toBe('12.3%');
      expect(graphing.formatPercent(99.99)).toBe('100%');
    });
  });

  describe('formatSeconds', () => {
    it('should format seconds correctly into human readable units', () => {
      expect(graphing.formatSeconds(0)).toBe('0s');
      expect(graphing.formatSeconds(45)).toBe('45s');
      expect(graphing.formatSeconds(125)).toBe('2.1m');
      expect(graphing.formatSeconds(7200)).toBe('2h');
      expect(graphing.formatSeconds(172800)).toBe('2d');
      expect(graphing.formatSeconds(-125)).toBe('-2.1m');
    });
  });

  describe('formatDefaultNumber', () => {
    it('should format standard numbers with appropriate SI prefixes', () => {
      expect(graphing.formatDefaultNumber(500)).toBe(500);
      expect(graphing.formatDefaultNumber(1500)).toBe('1.5k');
      expect(graphing.formatDefaultNumber(2500000)).toBe('2.5m');
      expect(graphing.formatDefaultNumber(3500000000)).toBe('3.5B');
      expect(graphing.formatDefaultNumber(4500000000000)).toBe('4.5T');
      expect(graphing.formatDefaultNumber(-1500)).toBe('-1.5k');
    });
  });

  describe('formatAxisValue', () => {
    it('should return value directly if not a number', () => {
      expect(graphing.formatAxisValue('not a number', 'bytes')).toBe('not a number');
      expect(graphing.formatAxisValue(null, 'bytes')).toBe(null);
    });

    it('should delegate to formatBytes for byte/bytes unit', () => {
      expect(graphing.formatAxisValue(2048, 'byte')).toBe('2 KB');
      expect(graphing.formatAxisValue(2048, 'bytes')).toBe('2 KB');
    });

    it('should delegate to formatBits for bit/bits unit (with 1000000 multiplier)', () => {
      expect(graphing.formatAxisValue(1.5, 'bit')).toBe('1.5 Mb/s');
      expect(graphing.formatAxisValue(1.5, 'bits')).toBe('1.5 Mb/s');
    });

    it('should delegate to formatPercent for percent unit', () => {
      expect(graphing.formatAxisValue(50.5, 'percent')).toBe('50.5%');
    });

    it('should delegate to formatSeconds for second/seconds unit', () => {
      expect(graphing.formatAxisValue(120, 'second')).toBe('2m');
      expect(graphing.formatAxisValue(120, 'seconds')).toBe('2m');
    });

    it('should delegate to formatDefaultNumber for unknown units or undefined units', () => {
      expect(graphing.formatAxisValue(1500, 'unknown')).toBe('1.5k');
      expect(graphing.formatAxisValue(1500)).toBe('1.5k');
    });
  });

  describe('setupBarChart', () => {
    it('should configure bar chart options and format axis values based on units', () => {
      const options = {};
      const data = {};
      graphing.setupBarChart(options, data, 'My Chart', '#fff', '#000', '#abc', 'bytes');

      expect(options.responsive).toBe(true);
      expect(options.maintainAspectRatio).toBe(false);
      expect(options.plugins.title.text).toBe('My Chart');
      expect(options.plugins.title.color).toBe('#fff');
      expect(options.plugins.tooltip.mode).toBe('nearest');
      expect(options.plugins.tooltip.intersect).toBe(false);
      expect(options.scales.y.grid.color).toBe('#000');
      expect(options.scales.y.ticks.color).toBe('#fff');

      expect(data.labels).toEqual([]);
      expect(data.datasets[0].backgroundColor).toBe('#abc');
      expect(data.datasets[0].borderColor).toBe('#abc');

      // Test the y axis tick callback
      const callback = options.scales.y.ticks.callback;
      expect(typeof callback).toBe('function');
      expect(callback(1024)).toBe('1 KB');

      // Test the tooltip label callback
      const labelCallback = options.plugins.tooltip.callbacks.label;
      expect(typeof labelCallback).toBe('function');

      // Test with parsed y
      const contextWithParsed = {
        dataset: { label: 'My Dataset' },
        parsed: { y: 2048 },
        raw: null
      };
      expect(labelCallback(contextWithParsed)).toBe('My Dataset: 2 KB');

      // Test with raw number
      const contextWithRawNum = {
        dataset: { label: 'My Dataset' },
        parsed: null,
        raw: 4096
      };
      expect(labelCallback(contextWithRawNum)).toBe('My Dataset: 4 KB');

      // Test with raw object
      const contextWithRawObj = {
        dataset: { label: 'My Dataset' },
        parsed: null,
        raw: { y: 1024 }
      };
      expect(labelCallback(contextWithRawObj)).toBe('My Dataset: 1 KB');

      // Test with no dataset label
      const contextNoLabel = {
        dataset: {},
        parsed: { y: 2048 }
      };
      expect(labelCallback(contextNoLabel)).toBe('2 KB');
    });
  });

  describe('setupTimelineChart', () => {
    it('should configure timeline chart options correctly', () => {
      const options = {};
      const data = {};
      graphing.setupTimelineChart(options, data, 'Timeline Chart', '#fff', '#000', '#abc', 'bytes');

      expect(options.responsive).toBe(true);
      expect(options.scales.x.type).toBe('timeseries');
      expect(options.scales.x.time.displayFormats.minute).toBe('YYYY-MM-DD HH:mm');

      // Test tick callback still works
      const callback = options.scales.y.ticks.callback;
      expect(callback(1024)).toBe('1 KB');
    });
  });

  describe('setupPieChart', () => {
    it('should configure pie chart options correctly', () => {
      const options = {};
      const data = {};
      graphing.setupPieChart(options, data, 'Pie Chart', '#fff');

      expect(options.responsive).toBe(true);
      expect(options.maintainAspectRatio).toBe(false);
      expect(options.plugins.legend.position).toBe('left');
      expect(options.plugins.legend.labels.color).toBe('#fff');
      expect(options.plugins.title.text).toBe('Pie Chart');

      expect(data.labels).toEqual([]);
      expect(data.datasets[0].backgroundColor).toContain('rgba(77, 201, 246, 1)');
      expect(data.datasets[0].data).toEqual([]);
    });
  });

  describe('setupSankeyChart', () => {
    it('should configure sankey chart options correctly', () => {
      const options = {};
      const data = {};
      const colorFromCb = jest.fn();
      const colorToCb = jest.fn();

      graphing.setupSankeyChart(options, data, 'Sankey Chart', '#fff', true, colorFromCb, colorToCb);

      expect(options.responsive).toBe(true);
      expect(options.maintainAspectRatio).toBe(false);
      expect(options.plugins.legend.display).toBe(false);
      expect(options.plugins.title.text).toBe('Sankey Chart');

      expect(data.flowMax).toBe(0);
      expect(data.labels).toEqual([]);
      expect(data.datasets[0].color).toBe('white');
      expect(data.datasets[0].colorFrom).toBe(colorFromCb);
      expect(data.datasets[0].colorTo).toBe(colorToCb);

      // test light mode color setting
      const lightData = {};
      graphing.setupSankeyChart(options, lightData, 'Sankey Chart', '#fff', false, colorFromCb, colorToCb);
      expect(lightData.datasets[0].color).toBe('black');
    });
  });

  describe('populateChart', () => {
    it('should populate chart data structure correctly with transformations', () => {
      const chart = {
        key: 0,
        labels: [],
        datasets: [{ data: [] }]
      };
      const data = [
        { keys: ['key1'], value: 10 },
        { keys: ['key2'], value: 20 }
      ];

      const truncateFunc = jest.fn((str) => str.substring(0, 5));
      const localizeValueFunc = jest.fn((str) => 'loc_' + str);
      const lookupSocIdFunc = jest.fn((str) => 'soc_' + str);

      graphing.populateChart(chart, data, 10, truncateFunc, localizeValueFunc, lookupSocIdFunc);

      expect(chart.key).toBe(1);
      expect(chart.labels).toEqual(['loc_s', 'loc_s']); // truncated to 5 chars ('loc_soc_key1' -> 'loc_s')
      expect(chart.datasets[0].data).toEqual([10, 20]);

      expect(lookupSocIdFunc).toHaveBeenCalledWith('key1');
      expect(lookupSocIdFunc).toHaveBeenCalledWith('key2');
      expect(localizeValueFunc).toHaveBeenCalledWith('soc_key1');
      expect(localizeValueFunc).toHaveBeenCalledWith('soc_key2');
      expect(truncateFunc).toHaveBeenCalledWith('loc_soc_key1', 10);
      expect(truncateFunc).toHaveBeenCalledWith('loc_soc_key2', 10);
    });

    it('should do nothing if data is empty or null', () => {
      const chart = {
        key: 0,
        labels: [],
        datasets: [{ data: [] }]
      };
      graphing.populateChart(chart, null, 10, jest.fn(), jest.fn(), jest.fn());
      expect(chart.key).toBe(1);
      expect(chart.labels).toEqual([]);
    });
  });

  describe('getSankeyColor', () => {
    it('should return steelblue when source has no custom properties', () => {
      expect(graphing.getSankeyColor('tag', 'dir', null, 100)).toBe('steelblue');
      expect(graphing.getSankeyColor('tag', 'dir', {}, 100)).toBe('steelblue');
      expect(graphing.getSankeyColor('tag', 'dir', { parsed: {} }, 100)).toBe('steelblue');
    });

    it('should map values correctly to distinct color gradients based on ratios', () => {
      const createSource = (val) => ({
        parsed: {
          _custom: {
            myTag: {
              myDir: val
            }
          }
        }
      });

      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(95), 100)).toBe('crimson');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(85), 100)).toBe('red');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(75), 100)).toBe('orangered');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(65), 100)).toBe('darkorange');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(55), 100)).toBe('orange');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(45), 100)).toBe('goldenrod');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(35), 100)).toBe('gold');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(28), 100)).toBe('yellow');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(23), 100)).toBe('yellowgreen');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(18), 100)).toBe('limegreen');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(13), 100)).toBe('green');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(8), 100)).toBe('aquamarine');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(4.5), 100)).toBe('cyan');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(3.5), 100)).toBe('darkturquoise');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(2.5), 100)).toBe('lightskyblue');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(1.5), 100)).toBe('royalblue');
      expect(graphing.getSankeyColor('myTag', 'myDir', createSource(0.5), 100)).toBe('steelblue');
    });

    it('should use 1 as max fallback if max <= 0 to avoid division by zero', () => {
      const source = {
        parsed: {
          _custom: {
            myTag: {
              myDir: 0.95
            }
          }
        }
      };
      expect(graphing.getSankeyColor('myTag', 'myDir', source, 0)).toBe('crimson');
    });
  });

  describe('debounceChartResize', () => {
    let originalDateNow;
    let time;

    beforeAll(() => {
      originalDateNow = Date.now;
      time = 10000;
      Date.now = jest.fn(() => time);
    });

    afterAll(() => {
      Date.now = originalDateNow;
    });

    it('should early exit if chart lacks options or responsive is false', () => {
      const chart = {};
      const tracker = {};
      graphing.debounceChartResize(chart, { width: 100 }, tracker);
      expect(tracker).toEqual({});
    });

    it('should track resize metrics and prune expired entries', () => {
      const chart = { options: { responsive: true } };
      const tracker = {};

      time = 10000;
      graphing.debounceChartResize(chart, { width: 100 }, tracker);

      // Verify history is created and holds first item
      expect(tracker[chart]).toHaveLength(1);
      expect(tracker[chart][0]).toEqual({ size: { width: 100 }, time: 10000 });

      // Add a second resize within age limit
      time = 10500;
      graphing.debounceChartResize(chart, { width: 110 }, tracker);
      expect(tracker[chart]).toHaveLength(2);

      // Add third resize with first resize now expired (> 1000ms from 10000 to 11100)
      time = 11100;
      graphing.debounceChartResize(chart, { width: 120 }, tracker);
      // Pruned first item (at 10000) but kept second (at 10500) and third (at 11100)
      expect(tracker[chart]).toHaveLength(2);
      expect(tracker[chart][0].time).toBe(10500);
      expect(tracker[chart][1].time).toBe(11100);
    });

    it('should cap the history length at 20', () => {
      const chart = { options: { responsive: true } };
      const tracker = {};

      // Keep time frozen so nothing expires
      time = 10000;
      for (let i = 0; i < 25; i++) {
        graphing.debounceChartResize(chart, { width: 100 + i }, tracker);
      }

      expect(tracker[chart]).toHaveLength(20);
      // First entries should have been shifted out
      expect(tracker[chart][0].size.width).toBe(105);
      expect(tracker[chart][19].size.width).toBe(124);
    });

    it('should flag flapping and set responsive to false if layout flaps too much', () => {
      const chart = { options: { responsive: true } };
      const tracker = {};

      time = 10000;
      // Sequence with multiple direction changes (flaps):
      // 100 -> 110 (up) -> 100 (down, flap 1) -> 110 (up, flap 2)
      graphing.debounceChartResize(chart, { width: 100 }, tracker);
      graphing.debounceChartResize(chart, { width: 110 }, tracker);
      graphing.debounceChartResize(chart, { width: 100 }, tracker);
      graphing.debounceChartResize(chart, { width: 110 }, tracker);

      expect(chart.options.responsive).toBe(false);
    });
  });
});
