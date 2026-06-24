// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

loadPageTemplate('component-tool-use-card', 'pages/tool-use-card.html');

// Renders a single assistant tool call (parameters, approval, result, error). Used
// both for the orchestrator's top-level tool calls on the page and, with `nested`,
// for a delegated sub-agent's tool calls inside `delegation-child`. When the tool is
// itself a delegation it renders `delegation-child`, which renders more tool-use-cards
// -- so delegations that delegate nest to any depth through this mutual recursion.
// Page state/helpers are reached through the injected `ctx` (the assistant page
// instance, provided as `delegationCtx`).
components.push({
	name: "tool-use-card", component: {
		props: {
			toolUse: { type: Object, required: true },
			nested: { type: Boolean, default: false },
		},
		inject: { ctx: { from: 'delegationCtx' } },
		computed: {
			// The status to render (see ctx.displayStatus): an executing delegate whose
			// sub-agent awaits approval shows 'action_needed'. Computed so the derived
			// value (and its tree walk) is evaluated once per render and cached by Vue,
			// rather than recomputed at each of the template's status-icon/color/title uses.
			displayStatus() { return this.ctx.displayStatus(this.toolUse); },
		},
		template: '#component-tool-use-card',
	}
});
