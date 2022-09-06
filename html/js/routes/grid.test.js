// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./grid.js');

const comp = getComponent("grid");

test('updateStatus', () => {
  const status = { grid: { eps: 12 }};

  expect(comp.gridEps).toBe(0);
  comp.updateStatus(status);
  expect(comp.gridEps).toBe(12);
});

test('updateMetricsEnabled', () => {
	testUpdateMetricsEnabled(true, false, true);
	testUpdateMetricsEnabled(false, false, false);
	testUpdateMetricsEnabled(true, true, true);
});

function testUpdateMetricsEnabled(node1MetricsEnabled, node2MetricsEnabled, expectedMetricsEnabled) {
	const node1 = { metricsEnabled: node1MetricsEnabled };
	const node2 = { metricsEnabled: node2MetricsEnabled };
	comp.nodes = [node1, node2];

	comp.updateMetricsEnabled();

	expect(comp.metricsEnabled).toBe(expectedMetricsEnabled);

  const epsColumn = comp.headers.find(function(item) { 
    return item.text == comp.i18n.eps;
  });

  if (!expectedMetricsEnabled) {
		expect(epsColumn.align).toBe(' d-none');
	} else {
		expect(epsColumn.align).toBe('');
	}
}
