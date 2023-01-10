// Copyright 2020-2023 Security Onion Solutions. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
