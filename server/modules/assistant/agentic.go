// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	_ "embed"
	"sort"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"

	"github.com/apex/log"
)

//go:embed hunter.txt
var hunterPrompt string

//go:embed agent.txt
var agentPrompt string

// setupAgentic defines the fixed set of agents the coordinator exposes when
// agentic mode is enabled. The agent set is hardcoded for now; only the
// agentName->model mapping (ac.agentMapping) is admin-configurable. A future
// release will make these agents editable. Each agent carries its system
// prompt and tool/delegation scope, but no model/adapter/context details: the
// executing model is resolved through ac.agentMapping at request time.
func (ac *AssistantCoordinator) setupAgentic() {
	ac.agents = map[string]model.AgentParameters{
		"Orchestrator": {
			Name:           "Orchestrator",
			IsOrchestrator: true,
			AllowedTools:   []string{},
			CanDelegateTo:  []string{"Hunter"},
			Prompt:         agentPrompt,
		},
		"Hunter": {
			Name:          "Hunter",
			AllowedTools:  []string{"query_events"},
			CanDelegateTo: []string{},
			Prompt:        hunterPrompt,
			Description:   "An agent specialized in querying and analyzing security event data to uncover insights, patterns, and potential threats. Hunter is adept at formulating complex queries, interpreting results, and providing actionable intelligence based on security event logs.",
		},
	}
}

// loadAgentMapping reads the admin-supplied agentName->model-DisplayName map
// from module config (the "agentMapping" key). Entries with non-string values
// are skipped with a warning. Returns an empty (non-nil) map when the key is
// absent or malformed.
func (ac *AssistantCoordinator) loadAgentMapping(config module.ModuleConfig) map[string]string {
	logger := log.FromContext(ac.srv.Context)
	mapping := map[string]string{}

	raw, ok := config["agentMapping"].(map[string]any)
	if !ok {
		if config["agentMapping"] != nil {
			logger.Warn("agentMapping config is not an object; no agent mappings loaded")
		}
		return mapping
	}

	for agentName, v := range raw {
		displayName, ok := v.(string)
		if !ok {
			logger.WithField("agent", agentName).Warn("agentMapping entry is not a string; skipping")
			continue
		}
		mapping[agentName] = displayName
	}

	return mapping
}

// validateAgentMappings drops any agent whose configured model mapping is
// missing or does not resolve to an enabled model. Policy is log-and-continue,
// mirroring validateModelSelectors: a misconfigured agent is removed from the
// fixed set rather than failing module init. Must run after
// validateModelSelectors so disabled models are already accounted for.
func (ac *AssistantCoordinator) validateAgentMappings() {
	logger := log.FromContext(ac.srv.Context)

	for name := range ac.agents {
		displayName, mapped := ac.agentMapping[name]
		if !mapped || displayName == "" {
			logger.WithField("agent", name).Error("agent has no configured model mapping; disabling agent")
			delete(ac.agents, name)
			continue
		}

		params := ac.resolveModel(displayName)
		if params == nil || !params.Enabled {
			logger.WithFields(log.Fields{
				"agent": name,
				"model": displayName,
			}).Error("agent maps to a model that is not configured or not enabled; disabling agent")
			delete(ac.agents, name)
		}
	}
}

// exposeAgents publishes the agentic flag, the validated agent set, and their
// agent->model mapping to the client parameters served at /connect/info/. The
// client uses the mapping to resolve each agent's executing model (e.g. for
// context-limit display). Agent prompts are not serialized
// (AgentParameters.Prompt is json:"-"). The list is sorted by name for a
// stable client-facing order, and the exposed mapping is limited to surviving
// agents so it stays consistent with AvailableAgents.
func (ac *AssistantCoordinator) exposeAgents() {
	names := make([]string, 0, len(ac.agents))
	for name := range ac.agents {
		names = append(names, name)
	}
	sort.Strings(names)

	agents := make([]model.AgentParameters, 0, len(names))
	mapping := make(map[string]string, len(names))
	for _, name := range names {
		agents = append(agents, ac.agents[name])
		mapping[name] = ac.agentMapping[name]
	}

	ac.srv.Config.ClientParams.AssistantParams.AvailableAgents = agents
	ac.srv.Config.ClientParams.AssistantParams.AgentMapping = mapping
}
