// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	_ "embed"

	"github.com/security-onion-solutions/securityonion-soc/model"
)

//go:embed hunter.txt
var hunterPrompt string

//go:embed agent.txt
var agentPrompt string

func (ac *AssistantCoordinator) setupAgentic() {
	ac.srv.Config.ClientParams.AssistantParams.AvailableModels = []model.ModelParameters{
		{
			ID:                    "gemini-3.5-flash",
			DisplayName:           "Agent Gemini",
			Adapter:               "Gemini",
			ContextLimitSmall:     500000,
			ContextLimitLarge:     500000,
			CharsPerTokenEstimate: 4,
			IsAgentic:             true,
			IsOrchestrator:        true,
			AllowedTools:          []string{},
			CanDelegateTo:         []string{"gemini-3-flash-preview@Gemini"},
			Enabled:               true,
			AgentPrompt:           agentPrompt,
		}, {
			ID:                    "gemini-3-flash-preview",
			DisplayName:           "Hunter",
			Adapter:               "Gemini",
			ContextLimitSmall:     500000,
			ContextLimitLarge:     500000,
			CharsPerTokenEstimate: 4,
			IsAgentic:             true,
			AllowedTools:          []string{"query_events"},
			CanDelegateTo:         []string{},
			Enabled:               true,
			AgentPrompt:           hunterPrompt,
			AgentDescription:      "An agent specialized in querying and analyzing security event data to uncover insights, patterns, and potential threats. Hunter is adept at formulating complex queries, interpreting results, and providing actionable intelligence based on security event logs.",
		},
	}
}
