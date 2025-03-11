// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js')
require('./jobs.js')

const comp = getComponent('jobs');

test('isKind', () => {
	comp.kind = '';
	expect(comp.isKind('pcap')).toBe(true);
	expect(comp.isKind('foo')).toBe(false);
	comp.kind = 'pcap';
	expect(comp.isKind('pcap')).toBe(true);
	expect(comp.isKind('foo')).toBe(false);
	comp.kind = 'foo';
	expect(comp.isKind('pcap')).toBe(false);
	expect(comp.isKind('foo')).toBe(true);
});

test('addJob', async () => {
	resetPapi();
	const mock = mockPapi('post', { data: 'addJobResponse' });
	comp.jobs = [];

	await comp.addJob('manager', 'importId', 'TCP', '1.1.1.1', '10000', '2.2.2.2', '20000', '2025/02/26 12:00:00 AM - 2025/02/28 11:59:59 PM');

	expect(mock).toHaveBeenCalledTimes(1);
	expect(mock).toHaveBeenCalledWith('job/', {
		nodeId: 'manager',
		filter: {
			importId: 'importId',
			protocol: 'tcp',
			srcIp: '1.1.1.1',
			srcPort: 10000,
			dstIp: '2.2.2.2',
			dstPort: 20000,
			beginTime: '2025-02-26 00:00:00.000 +00:00',
			endTime: '2025-02-28 23:59:59.000 +00:00',
		}
	});

	expect(comp.jobs).toEqual(['addJobResponse']);
});

test('addJob - minimal', async () => {
	resetPapi();
	const mock = mockPapi('post', { data: 'addJobResponse' });
	comp.jobs = [];

	await comp.addJob('manager');

	expect(mock).toHaveBeenCalledTimes(1);
	expect(mock).toHaveBeenCalledWith('job/', {
		nodeId: 'manager',
		filter: {
			importId: undefined,
			protocol: undefined,
			srcIp: undefined,
			srcPort: NaN,
			dstIp: undefined,
			dstPort: NaN,
		}
	});

	expect(comp.jobs).toEqual(['addJobResponse']);
});
