// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
