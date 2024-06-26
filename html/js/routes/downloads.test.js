// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

require('../test_common.js');
require('./downloads.js');

const comp = getComponent("downloads");

test('updateNode', () => {
    expect(comp.remoteAgentSupported).toBe(true);

    comp.remoteAgentSupported = true;
	comp.updateNode({ role: 'so-import'});
    expect(comp.remoteAgentSupported).toBe(false);

    comp.remoteAgentSupported = true;
	comp.updateNode({ role: 'so-eval'});
    expect(comp.remoteAgentSupported).toBe(false);

    comp.remoteAgentSupported = true;
	comp.updateNode({ role: 'so-standalone'});
    expect(comp.remoteAgentSupported).toBe(true);

    comp.remoteAgentSupported = true;
	comp.updateNode({ role: 'so-manager'});
    expect(comp.remoteAgentSupported).toBe(true);

    comp.remoteAgentSupported = true;
    comp.updateNode({ role: 'so-managersearch'});
    expect(comp.remoteAgentSupported).toBe(true);
});
