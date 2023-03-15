// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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

test('colorNodeStatus', () => {
	expect(comp.colorNodeStatus("ok")).toBe("success");
  expect(comp.colorNodeStatus("fault")).toBe("error");
  expect(comp.colorNodeStatus("unknown")).toBe("warning");
});

test('iconNodeStatus', () => {
	expect(comp.iconNodeStatus("fault")).toBe("fa-triangle-exclamation");
  expect(comp.iconNodeStatus("ok")).toBe("fa-circle-check");
  expect(comp.iconNodeStatus("other")).toBe("fa-circle-question");
});

test('colorContainerStatus', () => {
	expect(comp.colorContainerStatus("running")).toBe("green");
  expect(comp.colorContainerStatus("broken")).toBe("error");
});

test('formatNode', () => {
	node = {
		processJson: '{"containers": [{ "Name": "a" },{ "Name": "c" },{ "Name": "b" }]}',
		role: 'standalone',
	}

	node = comp.formatNode(node);

	expect(node.containers).toStrictEqual([{"Name": "a"}, {"Name": "b"}, {"Name": "c"}]);
});

test('formatNode_MissingContainers', () => {
	node = {
		processJson: '{}',
		role: 'standalone',
	}

	node = comp.formatNode(node);

	expect(node.containers).toStrictEqual([]);
});

test('testConfirmDialog', () => {
	expect(comp.gridMemberTestConfirmDialog).toBe(false);
	expect(comp.selectedId).toBe(null);

	comp.showTestConfirm('t2');
	expect(comp.gridMemberTestConfirmDialog).toBe(true);
	expect(comp.selectedId).toBe('t2');

	comp.hideTestConfirm();
	expect(comp.gridMemberTestConfirmDialog).toBe(false);
	expect(comp.selectedId).toBe(null);
});

test('canTest', () => {
	const node = {};
	expect(comp.canTest(node)).toBe(false);

	node['keywords'] = "Foo Bar";
	expect(comp.canTest(node)).toBe(false);

	node['keywords'] = "Foo Sensor Bar";
	expect(comp.canTest(node)).toBe(true);
});

test('gridMemberTest', async () => {
	resetPapi();
	const mock = mockPapi("post");
	comp.selectedId = '123';
	await comp.gridMemberTest();
	expect(mock).toHaveBeenCalledWith('gridmembers/123/test');
});