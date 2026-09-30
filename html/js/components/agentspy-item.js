// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-agentspy-item', 'pages/agentspy-item.html');

// Expanded work item detail, shared by both Agent Spy tables; `ctx` is the Agent Spy page.
components.push({
	name: "agentspy-item", component: {
		props: { item: { type: Object, required: true } },
		inject: { ctx: { from: 'agentSpyCtx' } },
		template: '#component-agentspy-item',
	}
});
