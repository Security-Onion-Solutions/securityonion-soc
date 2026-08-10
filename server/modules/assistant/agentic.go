// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"

	"github.com/apex/log"
)

// storedAgent is the JSON shape of a single agent as persisted in the
// "assistant.agents" config setting (one JSON object per line, matching the
// []{} uiElements convention). It carries the agent's model so this one setting
// drives both the agent definitions and the agent->model mapping.
//
// An entry whose name matches a system agent is an *override*: only the fields an
// admin may change are written, and everything omitted -- above all the built-in
// prompt, which is never sent to the browser and so cannot round-trip through the
// Agent Studio -- is restored from the system definition (see applyBuiltinDefaults).
// An entry with no matching system agent is an admin-created agent, defined
// entirely by what is stored here.
type storedAgent struct {
	Name string `json:"name"`
	// Enabled is a pointer so an absent field means "unchanged" (defaulting to
	// enabled) rather than "disabled", which is what a bare bool would decode to.
	Enabled        *bool `json:"enabled,omitempty"`
	IsOrchestrator bool  `json:"isOrchestrator"`
	// Model is a model selector ("id@adapter", or a bare id), the same form
	// agentMapping carries and resolveModel understands -- not a display name.
	Model         string   `json:"model"`
	AllowedSkills []string `json:"allowedSkills"`
	CanDelegateTo []string `json:"canDelegateTo"`
	Description   string   `json:"description"`
	// Persona is the admin-authored persona: an addendum to the built-in prompt for
	// a system agent, or the entire prompt for an admin-created one.
	Persona string `json:"persona"`
}

// reloadAgentConfiguration re-reads the agentic configuration from the config
// store and rebuilds the coordinator's in-memory agent set, mapping, delegate
// tools, and client-facing parameters. It is called once at startup and again on
// every relevant config setting change. Missing/empty settings leave the current
// (Init-time) values in place, so a store without these settings is harmless.
func (ac *AssistantCoordinator) reloadAgentConfiguration(ctx context.Context) {
	logger := log.FromContext(ctx)

	if ac.srv.Configstore == nil {
		return
	}

	settings, err := ac.srv.Configstore.GetSettings(ctx, true)
	if err != nil {
		logger.WithError(err).Error("unable to load settings for agentic configuration reload")
		return
	}

	byID := make(map[string]*model.Setting, len(settings))
	for _, s := range settings {
		if s != nil {
			byID[s.Id] = s
		}
	}

	// Scalar limits: only override when present and parseable.
	if s, ok := byID[ConfigSettingMaxDelegationDepth]; ok {
		if v, perr := parseIntSetting(s.Value); perr == nil {
			ac.maxDelegationDepth.Store(int64(v))
		} else if strings.TrimSpace(s.Value) != "" {
			logger.WithError(perr).WithField("setting", s.Id).Warn("invalid maxDelegationDepth; keeping previous value")
		}
	}
	if s, ok := byID[ConfigSettingMaxSubSessionTokens]; ok {
		if v, perr := parseIntSetting(s.Value); perr == nil {
			ac.maxSubSessionTokens.Store(int64(v))
		} else if strings.TrimSpace(s.Value) != "" {
			logger.WithError(perr).WithField("setting", s.Id).Warn("invalid maxSubSessionTokens; keeping previous value")
		}
	}

	// Agents: parse the structured value. A parse error keeps the current set.
	newAgents, newMapping, perr := parseAgentsSetting(byID[ConfigSettingAgents])
	if perr != nil {
		logger.WithError(perr).Error("unable to parse assistant.agents setting; keeping current agent set")
	}

	ac.agentMu.Lock()
	defer ac.agentMu.Unlock()

	if newAgents != nil {
		ac.applyBuiltinDefaults(newAgents)
		ac.restoreMissingBuiltins(newAgents, newMapping)
		ac.ensureEnabledOrchestrator(ctx, newAgents)
		ac.agents = newAgents
		ac.agentMapping = newMapping
	}

	// Rebuild derived state from the (possibly new) agent set.
	ac.DelegationLibrary = map[string]Tool{}
	ac.validateAgentMappings()
	ac.registerDelegateTools()
	ac.exposeAgents()
}

// applyBuiltinDefaults restores, from the system-provided set, the fields an admin
// may not change on an agent that names a built-in, and marks it as a system
// agent. A stored entry is therefore an override rather than a replacement. This
// is what keeps the embedded prompt intact: it is never sent to the browser
// (AgentParameters.Prompt is json:"-"), so a definition saved from the Agent Studio
// necessarily omits it, and a straight replacement would blank every system
// persona on the first save. Agents with no matching built-in are admin-created and
// are left exactly as stored.
func (ac *AssistantCoordinator) applyBuiltinDefaults(agents map[string]model.AgentParameters) {
	for name, agent := range agents {
		builtin, ok := ac.builtinAgents[name]
		if !ok {
			continue
		}

		// Not editable on a system agent: the built-in definition always wins.
		agent.IsSystem = true
		agent.Prompt = builtin.Prompt
		agent.IsOrchestrator = builtin.IsOrchestrator
		agent.Description = builtin.Description
		agent.AllowedSkills = builtin.AllowedSkills

		// Editable, but an omitted value falls back to the built-in.
		if agent.CanDelegateTo == nil {
			agent.CanDelegateTo = builtin.CanDelegateTo
		}

		agents[name] = agent
	}
}

// restoreMissingBuiltins re-adds any system agent the stored configuration does
// not mention, along with its startup model mapping. System agents can only be
// disabled, never deleted, so a setting written before a release introduced a new
// built-in must not hide it.
func (ac *AssistantCoordinator) restoreMissingBuiltins(agents map[string]model.AgentParameters, mapping map[string]string) {
	for name, builtin := range ac.builtinAgents {
		if _, ok := agents[name]; ok {
			continue
		}

		agents[name] = builtin

		if selector, ok := ac.builtinAgentMapping[name]; ok && mapping[name] == "" {
			mapping[name] = selector
		}
	}
}

// ensureEnabledOrchestrator guarantees at least one orchestrator stays enabled. A
// grid with none has no entry point for agentic chat, so a configuration that
// disables the last one is corrected here -- the system orchestrators are
// re-enabled and the problem logged -- rather than silently disabling the
// assistant. The Agent Studio refuses the same edit up front; this is the backstop
// for a hand-edited setting.
func (ac *AssistantCoordinator) ensureEnabledOrchestrator(ctx context.Context, agents map[string]model.AgentParameters) {
	for _, agent := range agents {
		if agent.IsOrchestrator && agent.Enabled {
			return
		}
	}

	restored := make([]string, 0, 1)
	for name, agent := range agents {
		if !agent.IsOrchestrator || !agent.IsSystem {
			continue
		}
		agent.Enabled = true
		agents[name] = agent
		restored = append(restored, name)
	}
	sort.Strings(restored)

	log.FromContext(ctx).WithField("reEnabled", restored).
		Error("configuration leaves no enabled orchestrator; re-enabling system orchestrators")
}

// parseAgentsSetting decodes the "assistant.agents" setting value into the agent
// set and the derived agent->model mapping. It accepts either newline-delimited
// JSON objects (the []{} uiElements convention) or a single JSON array. Returns
// (nil, nil, nil) when the setting is absent or empty, signaling the caller to
// keep the current agents.
func parseAgentsSetting(setting *model.Setting) (map[string]model.AgentParameters, map[string]string, error) {
	if setting == nil {
		return nil, nil, nil
	}

	value := strings.TrimSpace(setting.Value)
	if value == "" {
		return nil, nil, nil
	}

	var stored []storedAgent
	if strings.HasPrefix(value, "[") {
		if err := json.Unmarshal([]byte(value), &stored); err != nil {
			return nil, nil, fmt.Errorf("parsing agents array: %w", err)
		}
	} else {
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var sa storedAgent
			if err := json.Unmarshal([]byte(line), &sa); err != nil {
				return nil, nil, fmt.Errorf("parsing agent entry %q: %w", line, err)
			}
			stored = append(stored, sa)
		}
	}

	agents := make(map[string]model.AgentParameters, len(stored))
	mapping := make(map[string]string, len(stored))
	for _, sa := range stored {
		if strings.TrimSpace(sa.Name) == "" {
			continue
		}
		agents[sa.Name] = model.AgentParameters{
			Name:            sa.Name,
			IsOrchestrator:  sa.IsOrchestrator,
			CanDelegateTo:   sa.CanDelegateTo,
			AllowedSkills:   sa.AllowedSkills,
			Description:     sa.Description,
			PersonaAddendum: sa.Persona,
			// Absent means unchanged, which for a new entry means enabled.
			Enabled: sa.Enabled == nil || *sa.Enabled,
		}
		if strings.TrimSpace(sa.Model) != "" {
			mapping[sa.Name] = sa.Model
		}
	}

	if len(agents) == 0 {
		return nil, nil, nil
	}

	return agents, mapping, nil
}

// parseIntSetting parses a config setting value as an integer, tolerating a
// JSON-encoded number (e.g. a DB-stored value that round-tripped through JSONB).
func parseIntSetting(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty value")
	}
	if n, err := strconv.Atoi(value); err == nil {
		return n, nil
	}
	var n int
	if err := json.Unmarshal([]byte(value), &n); err == nil {
		return n, nil
	}
	return 0, fmt.Errorf("not an integer: %q", value)
}

//go:embed SOAgenticPrompts.bin
var allPrompts []byte

// setupAgentic defines the fixed set of agents the coordinator exposes when
// agentic mode is enabled. The agent set is hardcoded for now; only the
// agentName->model mapping (ac.agentMapping) is admin-configurable. A future
// release will make these agents editable. Each agent carries its system
// prompt and tool/delegation scope, but no model/adapter/context details: the
// executing model is resolved through ac.agentMapping at request time.
func (ac *AssistantCoordinator) setupAgentic() {
	prompts := ac.unzipAndUnmarshal(allPrompts)

	ac.agents = map[string]model.AgentParameters{
		"Orchestrator": {
			Name:           "Orchestrator",
			IsOrchestrator: true,
			AllowedSkills:  []string{},
			CanDelegateTo:  []string{"Investigator", "DetectionEngineer"},
			Prompt:         prompts["prompt_agent_orchestrator"],
		},
		"Investigator": {
			Name:          "Investigator",
			AllowedSkills: []string{"Hunt", "Playbooks", "Respond"},
			CanDelegateTo: []string{"DetectionEngineer"},
			Prompt:        prompts["prompt_agent_investigator"],
			Description: "Investigates alerts, explains events and records, and answers open questions about activity in event data. " +
				"Also acknowledges alerts, escalates to cases, and looks up cases. " +
				"Objectives must include all identifiers verbatim.",
		},
		"DetectionEngineer": {
			Name:          "DetectionEngineer",
			AllowedSkills: []string{"Detections", "Tuning", "Hunt"},
			CanDelegateTo: []string{},
			Prompt:        prompts["prompt_agent_engineer"],
			Description: "Manages detections and their overrides. " +
				"Handles: tuning noisy rules with overrides (suppressions, thresholds, custom filters); " +
				"creating detections or editing rule content; " +
				"coverage questions about which detections exist for a technique or behavior. " +
				"Objectives should include the detection public ID or rule UUID when known.",
		},
	}

	ac.SkillLibrary = map[string]model.Skill{
		"Hunt": {
			Name:             "Hunt",
			Tools:            []string{"query_events", "get_playbooks"},
			AdditionalPrompt: prompts["prompt_skill_hunt"],
		},
		"Playbooks": {
			Name:             "Playbooks",
			Tools:            []string{"get_playbooks"},
			AdditionalPrompt: prompts["prompt_skill_playbooks"],
		},
		"Respond": {
			Name:             "Respond",
			Tools:            []string{"ack_alerts", "escalate_alerts", "query_cases"},
			AdditionalPrompt: prompts["prompt_skill_respond"],
		},
		"Detections": {
			Name:             "Detections",
			Tools:            []string{"query_detections"},
			AdditionalPrompt: prompts["prompt_skill_detections"],
		},
		"Tuning": {
			Name:             "Tuning",
			Tools:            []string{"add_overrides", "create_detection", "toggle_detections", "update_detection_content", "update_overrides"},
			AdditionalPrompt: prompts["prompt_skill_tuning"],
		},
	}

	// Everything defined above ships with the product and starts enabled. Marking it
	// here keeps the definitions above free of two fields that never vary.
	for name, agent := range ac.agents {
		agent.IsSystem = true
		agent.Enabled = true
		ac.agents[name] = agent
	}

	// Snapshot the system-provided set before any config-driven reload can replace
	// it; reloads merge stored overrides on top of this (see applyBuiltinDefaults).
	ac.builtinAgents = make(map[string]model.AgentParameters, len(ac.agents))
	for name, agent := range ac.agents {
		ac.builtinAgents[name] = agent
	}
}

func (ac *AssistantCoordinator) unzipAndUnmarshal(data []byte) map[string]string {
	logger := log.FromContext(ac.srv.Context)
	prompts := map[string]string{}

	if len(data) != 0 {
		jsn := ac.decompressPrompt(data)

		err := json.Unmarshal([]byte(jsn), &prompts)
		if err != nil {
			logger.WithError(err).Warn("unzipped prompts are not valid JSON")
		} else {
			keys := make([]string, 0, len(prompts))
			for k := range prompts {
				keys = append(keys, k)
			}

			logger.WithField("loadedPrompts", keys).Info("loaded embedded prompts")
		}
	} else {
		logger.Warn("no embedded agentic prompts detected")
	}

	return prompts
}

// loadAgentMapping reads the admin-supplied agentName->model-selector map
// ("id@adapter" or bare id values) from module config (the "agentMapping"
// key). Entries with non-string values are skipped with a warning. Returns an
// empty (non-nil) map when the key is absent or malformed.
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
		modelSelector, ok := v.(string)
		if !ok {
			logger.WithField("agent", agentName).Warn("agentMapping entry is not a string; skipping")
			continue
		}

		mapping[agentName] = modelSelector
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

	for name, agent := range ac.agents {
		// A disabled agent never executes, so it needs no usable model. Keep it in the
		// set regardless of its mapping so the Agent Studio can still list and fix it.
		if !agent.Enabled {
			continue
		}

		modelSelector, mapped := ac.agentMapping[name]
		if !mapped || modelSelector == "" {
			logger.WithField("agent", name).Error("agent has no configured model mapping; disabling agent")
			delete(ac.agents, name)
			continue
		}

		params := ac.resolveModel(modelSelector)
		if params == nil || !params.Enabled {
			logger.WithFields(log.Fields{
				"agent": name,
				"model": modelSelector,
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
	ac.srv.Config.ClientParams.AssistantParams.AvailableSkills = ac.exposeSkills()
}

// exposeSkills returns the client-facing skill catalog (name and tools) built
// from the coordinator's SkillLibrary, sorted by name for a stable order. It
// backs the read-only Skills view in the Agent Studio. The skill's prompt
// guidance is intentionally not exposed (see model.SkillParameters).
func (ac *AssistantCoordinator) exposeSkills() []model.SkillParameters {
	names := make([]string, 0, len(ac.SkillLibrary))
	for name := range ac.SkillLibrary {
		names = append(names, name)
	}
	sort.Strings(names)

	skills := make([]model.SkillParameters, 0, len(names))
	for _, name := range names {
		skill := ac.SkillLibrary[name]
		skills = append(skills, model.SkillParameters{
			Name:  skill.Name,
			Tools: skill.Tools,
		})
	}

	return skills
}
