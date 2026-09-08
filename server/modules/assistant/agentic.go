// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/apex/log"
)

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

	newSkills, serr := parseSkillsSetting(byID[ConfigSettingSkills])
	if serr != nil {
		logger.WithError(serr).Error("unable to parse assistant.skills setting; keeping current skill set")
	}

	ac.agentMu.Lock()
	defer ac.agentMu.Unlock()

	if newSkills != nil {
		ac.applyBuiltinSkillDefaults(newSkills)
		ac.restoreMissingBuiltinSkills(newSkills)
		ac.SkillLibrary = newSkills
	}

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

// parseSkillsSetting decodes the "assistant.skills" setting. Returns (nil, nil)
// when absent or empty, signaling the caller to keep the current skills.
func parseSkillsSetting(setting *model.Setting) (map[string]model.Skill, error) {
	if setting == nil {
		return nil, nil
	}

	value := strings.TrimSpace(setting.Value)
	if value == "" {
		return nil, nil
	}

	var stored []model.StoredSkill
	if strings.HasPrefix(value, "[") {
		if err := json.Unmarshal([]byte(value), &stored); err != nil {
			return nil, fmt.Errorf("parsing skills array: %w", err)
		}
	} else {
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var ss model.StoredSkill
			if err := json.Unmarshal([]byte(line), &ss); err != nil {
				return nil, fmt.Errorf("parsing skill entry %q: %w", line, err)
			}
			stored = append(stored, ss)
		}
	}

	skills := make(map[string]model.Skill, len(stored))
	for _, ss := range stored {
		if strings.TrimSpace(ss.Name) == "" {
			continue
		}
		skills[ss.Name] = model.Skill{
			Name:            ss.Name,
			Tools:           ss.Tools,
			PersonaAddendum: ss.Persona,
			Enabled:         ss.Enabled == nil || *ss.Enabled,
		}
	}

	if len(skills) == 0 {
		return nil, nil
	}

	return skills, nil
}

// applyBuiltinSkillDefaults restores what an admin may not change on a system
// skill. Its tool set is fixed because the shipped guidance is written against it.
func (ac *AssistantCoordinator) applyBuiltinSkillDefaults(skills map[string]model.Skill) {
	for name, skill := range skills {
		builtin, ok := ac.builtinSkills[name]
		if !ok {
			continue
		}

		skill.IsSystem = true
		skill.AdditionalPrompt = builtin.AdditionalPrompt
		skill.Tools = builtin.Tools

		skills[name] = skill
	}
}

// restoreMissingBuiltinSkills re-adds any system skill the setting omits: they can
// be disabled but never deleted.
func (ac *AssistantCoordinator) restoreMissingBuiltinSkills(skills map[string]model.Skill) {
	for name, builtin := range ac.builtinSkills {
		if _, ok := skills[name]; ok {
			continue
		}
		skills[name] = builtin
	}
}

// applyBuiltinDefaults restores what an admin may not change on a system agent.
// Critically that includes the built-in prompt: it never reaches the browser, so a
// save from the Agent Studio omits it and a straight replacement would blank it.
func (ac *AssistantCoordinator) applyBuiltinDefaults(agents map[string]model.Agent) {
	for name, agent := range agents {
		builtin, ok := ac.builtinAgents[name]
		if !ok {
			continue
		}

		agent.IsSystem = true
		agent.Prompt = builtin.Prompt
		agent.IsOrchestrator = builtin.IsOrchestrator
		agent.Description = builtin.Description
		agent.AllowedSkills = builtin.AllowedSkills

		// Editable, so only fall back when omitted.
		if agent.CanDelegateTo == nil {
			agent.CanDelegateTo = builtin.CanDelegateTo
		}

		agents[name] = agent
	}
}

// restoreMissingBuiltins re-adds any system agent the setting omits, with its
// startup model mapping: they can be disabled but never deleted.
func (ac *AssistantCoordinator) restoreMissingBuiltins(agents map[string]model.Agent, mapping map[string]string) {
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

// ensureEnabledOrchestrator keeps at least one orchestrator enabled; a grid with
// none has no entry point for agentic chat. Backstop for a hand-edited setting.
func (ac *AssistantCoordinator) ensureEnabledOrchestrator(ctx context.Context, agents map[string]model.Agent) {
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
func parseAgentsSetting(setting *model.Setting) (map[string]model.Agent, map[string]string, error) {
	if setting == nil {
		return nil, nil, nil
	}

	value := strings.TrimSpace(setting.Value)
	if value == "" {
		return nil, nil, nil
	}

	var stored []model.StoredAgent
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
			var sa model.StoredAgent
			if err := json.Unmarshal([]byte(line), &sa); err != nil {
				return nil, nil, fmt.Errorf("parsing agent entry %q: %w", line, err)
			}
			stored = append(stored, sa)
		}
	}

	agents := make(map[string]model.Agent, len(stored))
	mapping := make(map[string]string, len(stored))
	for _, sa := range stored {
		if strings.TrimSpace(sa.Name) == "" {
			continue
		}
		agents[sa.Name] = model.Agent{
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

// setupAgentic defines the fixed set of chat-orchestration agents and the
// skill library the coordinator exposes when agentic mode is enabled.
func (ac *AssistantCoordinator) setupAgentic(prompts map[string]string) {
	ac.agents = map[string]model.Agent{
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
		"Reports": {
			Name:             "Reports",
			Tools:            []string{"query_reports", "update_custom_report"},
			AdditionalPrompt: prompts["prompt_skill_reports"],
		},
	}

	// Everything above ships with the product and starts enabled.
	for name, agent := range ac.agents {
		agent.IsSystem = true
		agent.Enabled = true
		ac.agents[name] = agent
	}
	for name, skill := range ac.SkillLibrary {
		skill.IsSystem = true
		skill.Enabled = true
		ac.SkillLibrary[name] = skill
	}

	// Snapshot before any reload can replace them; stored overrides merge onto these.
	ac.builtinAgents = make(map[string]model.Agent, len(ac.agents))
	for name, agent := range ac.agents {
		ac.builtinAgents[name] = agent
	}

	ac.builtinSkills = make(map[string]model.Skill, len(ac.SkillLibrary))
	for name, skill := range ac.SkillLibrary {
		ac.builtinSkills[name] = skill
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
// missing or does not resolve to an enabled model.
func (ac *AssistantCoordinator) validateAgentMappings() {
	logger := log.FromContext(ac.srv.Context)

	for name, agent := range ac.agents {
		// Never executes, so it needs no usable model; keep it listed so it can be fixed.
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
// context-limit display). Built-in prompts stay server-side: Agent.Prompt is
// json:"-". The list is sorted by name for a stable client-facing order, and the
// exposed mapping is limited to surviving agents so it stays consistent with
// AvailableAgents.
func (ac *AssistantCoordinator) exposeAgents() {
	names := make([]string, 0, len(ac.agents))
	for name := range ac.agents {
		names = append(names, name)
	}
	sort.Strings(names)

	agents := make([]model.Agent, 0, len(names))
	mapping := make(map[string]string, len(names))
	for _, name := range names {
		agents = append(agents, ac.agents[name])
		mapping[name] = ac.agentMapping[name]
	}

	ac.srv.Config.ClientParams.AssistantParams.AvailableAgents = agents
	ac.srv.Config.ClientParams.AssistantParams.AgentMapping = mapping
	ac.srv.Config.ClientParams.AssistantParams.AvailableSkills = ac.exposeSkills()
	ac.srv.Config.ClientParams.AssistantParams.AvailableTools = ac.exposeToolCatalog()
	ac.srv.Config.ClientParams.AssistantParams.MaxDelegationDepth = ac.getMaxDelegationDepth()
	ac.srv.Config.ClientParams.AssistantParams.MaxSubSessionTokens = ac.getMaxSubSessionTokens()

	ac.broadcastAgenticUpdate()
}

// broadcastAgenticUpdate pushes the recomputed parameters to connected browsers so an edit
// reaches every page and user without the hourly /info refresh. The whole block is sent.
func (ac *AssistantCoordinator) broadcastAgenticUpdate() {
	// Host is nil during Init, when nothing is connected yet.
	if ac.srv.Host == nil {
		return
	}

	ac.srv.Host.Broadcast(AgenticUpdateKind, "assistant", ac.srv.Config.ClientParams.AssistantParams)
}

// exposeSkills returns the skill catalog for the Agent Studio, sorted by name and
// including disabled skills so they can be re-enabled.
func (ac *AssistantCoordinator) exposeSkills() []model.Skill {
	names := make([]string, 0, len(ac.SkillLibrary))
	for name := range ac.SkillLibrary {
		names = append(names, name)
	}
	sort.Strings(names)

	skills := make([]model.Skill, 0, len(names))
	for _, name := range names {
		skills = append(skills, ac.SkillLibrary[name])
	}

	return skills
}

// exposeToolCatalog returns the tool names an admin-created skill may grant.
// Delegate tools are absent: they are granted through delegation, not skills.
func (ac *AssistantCoordinator) exposeToolCatalog() []string {
	tools := make([]string, 0, len(ac.FunctionLibrary))
	for name := range ac.FunctionLibrary {
		tools = append(tools, name)
	}
	sort.Strings(tools)

	return tools
}

// ErrSystemAgentImmutable is returned when a request tries to delete an agent or
// skill that ships with the product. They can be disabled, never removed.
var ErrSystemAgentImmutable = errors.New("ERROR_SYSTEM_AGENT_IMMUTABLE")

// ErrAgentNotFound is returned when a delete names something that is not stored.
var ErrAgentNotFound = errors.New("ERROR_AGENT_NOT_FOUND")

// ErrNameConflict is returned when a rename targets a name already in use, which
// would otherwise overwrite that entry.
var ErrNameConflict = errors.New("ERROR_NAME_CONFLICT")

// SaveAgent writes a single agent into the assistant.agents setting, leaving every
// other entry as stored. The read-modify-write happens here rather than in the
// browser so a page holding a stale list cannot revert someone else's edit.
func (ac *AssistantCoordinator) SaveAgent(ctx context.Context, originalName string, agent *model.StoredAgent) error {
	if agent == nil || strings.TrimSpace(agent.Name) == "" {
		return errors.New("ERROR_AGENT_NAME_REQUIRED")
	}

	renamed := originalName != "" && originalName != agent.Name

	return ac.updateStoredAgents(ctx, func(agents []model.StoredAgent) ([]model.StoredAgent, error) {
		if renamed && ac.agentNameTaken(agents, agent.Name) {
			return nil, ErrNameConflict
		}

		updated := upsertByName(agents, originalName, *agent, func(a model.StoredAgent) string { return a.Name })
		if renamed {
			updated = renameDelegateReferences(updated, originalName, agent.Name)
		}

		return updated, nil
	})
}

// agentNameTaken reports whether a name is already claimed by a stored entry or by
// a built-in, which may have no stored entry of its own yet.
func (ac *AssistantCoordinator) agentNameTaken(agents []model.StoredAgent, name string) bool {
	ac.agentMu.RLock()
	_, isBuiltin := ac.builtinAgents[name]
	ac.agentMu.RUnlock()

	if isBuiltin {
		return true
	}

	for _, a := range agents {
		if a.Name == name {
			return true
		}
	}

	return false
}

// renameDelegateReferences repoints every other agent's delegation at the new name
// so a rename does not leave a delegate that no longer resolves.
func renameDelegateReferences(agents []model.StoredAgent, oldName, newName string) []model.StoredAgent {
	for i := range agents {
		for j, target := range agents[i].CanDelegateTo {
			if target == oldName {
				agents[i].CanDelegateTo[j] = newName
			}
		}
	}

	return agents
}

// DeleteAgent removes an admin-created agent. System agents are refused.
func (ac *AssistantCoordinator) DeleteAgent(ctx context.Context, name string) error {
	ac.agentMu.RLock()
	_, isBuiltin := ac.builtinAgents[name]
	ac.agentMu.RUnlock()

	if isBuiltin {
		return ErrSystemAgentImmutable
	}

	return ac.updateStoredAgents(ctx, func(agents []model.StoredAgent) ([]model.StoredAgent, error) {
		remaining, removed := removeByName(agents, name, func(a model.StoredAgent) string { return a.Name })
		if !removed {
			return nil, ErrAgentNotFound
		}
		return remaining, nil
	})
}

// SaveSkill writes a single skill into the assistant.skills setting.
func (ac *AssistantCoordinator) SaveSkill(ctx context.Context, originalName string, skill *model.StoredSkill) error {
	if skill == nil || strings.TrimSpace(skill.Name) == "" {
		return errors.New("ERROR_SKILL_NAME_REQUIRED")
	}

	renamed := originalName != "" && originalName != skill.Name

	err := ac.updateStoredSkills(ctx, func(skills []model.StoredSkill) ([]model.StoredSkill, error) {
		if renamed && ac.skillNameTaken(skills, skill.Name) {
			return nil, ErrNameConflict
		}

		return upsertByName(skills, originalName, *skill, func(s model.StoredSkill) string { return s.Name }), nil
	})
	if err != nil || !renamed {
		return err
	}

	// A renamed skill would otherwise silently stop granting its tools to every
	// agent still holding the old name.
	return ac.updateStoredAgents(ctx, func(agents []model.StoredAgent) ([]model.StoredAgent, error) {
		return renameSkillReferences(agents, originalName, skill.Name), nil
	})
}

func (ac *AssistantCoordinator) skillNameTaken(skills []model.StoredSkill, name string) bool {
	ac.agentMu.RLock()
	_, isBuiltin := ac.builtinSkills[name]
	ac.agentMu.RUnlock()

	if isBuiltin {
		return true
	}

	for _, s := range skills {
		if s.Name == name {
			return true
		}
	}

	return false
}

func renameSkillReferences(agents []model.StoredAgent, oldName, newName string) []model.StoredAgent {
	for i := range agents {
		for j, granted := range agents[i].AllowedSkills {
			if granted == oldName {
				agents[i].AllowedSkills[j] = newName
			}
		}
	}

	return agents
}

// DeleteSkill removes an admin-created skill. System skills are refused.
func (ac *AssistantCoordinator) DeleteSkill(ctx context.Context, name string) error {
	ac.agentMu.RLock()
	_, isBuiltin := ac.builtinSkills[name]
	ac.agentMu.RUnlock()

	if isBuiltin {
		return ErrSystemAgentImmutable
	}

	return ac.updateStoredSkills(ctx, func(skills []model.StoredSkill) ([]model.StoredSkill, error) {
		remaining, removed := removeByName(skills, name, func(s model.StoredSkill) string { return s.Name })
		if !removed {
			return nil, ErrAgentNotFound
		}
		return remaining, nil
	})
}

// updateStoredAgents applies mutate to the stored agent list and writes it back.
// configWriteMu serializes the read-modify-write so two concurrent requests cannot
// each read the same list and overwrite one another.
func (ac *AssistantCoordinator) updateStoredAgents(ctx context.Context, mutate func([]model.StoredAgent) ([]model.StoredAgent, error)) error {
	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	var stored []model.StoredAgent
	if err := ac.readStoredSetting(ctx, ConfigSettingAgents, &stored); err != nil {
		return err
	}

	updated, err := mutate(stored)
	if err != nil {
		return err
	}

	return ac.writeStoredSetting(ctx, ConfigSettingAgents, len(updated), func(i int) any { return updated[i] })
}

func (ac *AssistantCoordinator) updateStoredSkills(ctx context.Context, mutate func([]model.StoredSkill) ([]model.StoredSkill, error)) error {
	ac.configWriteMu.Lock()
	defer ac.configWriteMu.Unlock()

	var stored []model.StoredSkill
	if err := ac.readStoredSetting(ctx, ConfigSettingSkills, &stored); err != nil {
		return err
	}

	updated, err := mutate(stored)
	if err != nil {
		return err
	}

	return ac.writeStoredSetting(ctx, ConfigSettingSkills, len(updated), func(i int) any { return updated[i] })
}

// readStoredSetting decodes a setting's current value into out, accepting both
// encodings the setting may hold: newline-delimited objects or a JSON array. An
// absent or empty setting leaves out empty.
func (ac *AssistantCoordinator) readStoredSetting(ctx context.Context, settingID string, out any) error {
	if ac.srv.Configstore == nil {
		return errors.New("ERROR_CONFIGSTORE_UNAVAILABLE")
	}

	settings, err := ac.srv.Configstore.GetSettings(ctx, true)
	if err != nil {
		return err
	}

	value := ""
	for _, s := range settings {
		if s != nil && s.Id == settingID {
			value = strings.TrimSpace(s.Value)
			break
		}
	}

	if value == "" {
		return nil
	}

	if strings.HasPrefix(value, "[") {
		return json.Unmarshal([]byte(value), out)
	}

	// Re-wrap the newline-delimited form as an array so one decode handles both.
	lines := []string{}
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}

	return json.Unmarshal([]byte("["+strings.Join(lines, ",")+"]"), out)
}

// writeStoredSetting serializes entries to the newline-delimited form and saves
// them, which fires the config callback that reloads and broadcasts the change.
func (ac *AssistantCoordinator) writeStoredSetting(ctx context.Context, settingID string, count int, at func(int) any) error {
	lines := make([]string, 0, count)
	for i := 0; i < count; i++ {
		encoded, err := json.Marshal(at(i))
		if err != nil {
			return err
		}
		lines = append(lines, string(encoded))
	}

	return ac.srv.Configstore.UpdateSetting(ctx, &model.Setting{
		Id:    settingID,
		Value: strings.Join(lines, "\n"),
	}, false)
}

// upsertByName replaces the entry currently named originalName -- which lets a
// rename land in place instead of orphaning the old entry -- or appends when there
// is nothing to replace. Callers reject a rename onto an existing name before
// getting here, so this never has to discard an entry.
func upsertByName[T any](entries []T, originalName string, entry T, nameOf func(T) string) []T {
	out := make([]T, 0, len(entries)+1)
	replaced := false

	for _, existing := range entries {
		if nameOf(existing) == originalName {
			out = append(out, entry)
			replaced = true
			continue
		}
		out = append(out, existing)
	}

	if !replaced {
		out = append(out, entry)
	}

	return out
}

func removeByName[T any](entries []T, name string, nameOf func(T) string) ([]T, bool) {
	remaining := make([]T, 0, len(entries))
	removed := false
	for _, entry := range entries {
		if nameOf(entry) == name {
			removed = true
			continue
		}
		remaining = append(remaining, entry)
	}

	return remaining, removed
}

// Compile-time check that the coordinator still satisfies the manager interface.
var _ server.AssistantManager = (*AssistantCoordinator)(nil)
