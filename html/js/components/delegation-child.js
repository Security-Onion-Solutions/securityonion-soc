// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-delegation-child', 'pages/delegation-child.html');

// Renders a delegated sub-agent's transcript (its reasoning and tool calls) for a
// delegate tool_use that has a childSession. Each tool call is rendered by
// `tool-use-card`; a tool call that is itself a delegation renders this component
// again via that card -- so delegations that delegate nest to any depth. Page
// state/helpers are reached through the injected `ctx` (the assistant page instance,
// provided as `delegationCtx`).
components.push({
	name: "delegation-child", component: {
		props: { toolUse: { type: Object, required: true } },
		inject: { ctx: { from: 'delegationCtx' } },
		template: '#component-delegation-child',
	}
});
