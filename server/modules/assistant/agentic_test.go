// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubEmbeddedSystemPrompt disables the embedded prompt so getPrompt() is a
// no-op, restoring the original when the test finishes.
func stubEmbeddedSystemPrompt(t *testing.T) {
	t.Helper()

	origPrompt := embeddedSystemPrompt
	t.Cleanup(func() {
		embeddedSystemPrompt = origPrompt
	})
	embeddedSystemPrompt = []byte{}
}

// agenticTestModels returns the models a normal (non-agentic) deployment's
// config would have populated.
func agenticTestModels() []model.ModelParameters {
	return []model.ModelParameters{
		{
			ID:          "classic-model",
			DisplayName: "Classic",
			Adapter:     "SOAI",
			Enabled:     true,
		},
	}
}

func newAgenticTestCoordinator() (*AssistantCoordinator, *server.Server) {
	srv := &server.Server{
		Context: context.Background(),
		Config: &config.ServerConfig{
			ClientParams: model.ClientParameters{
				AssistantParams: model.AssistantParameters{
					AvailableModels: agenticTestModels(),
				},
			},
		},
	}

	return NewAssistantCoordinator(srv), srv
}

func TestAssistantCoordinator_InitAgenticDisabled(t *testing.T) {
	stubEmbeddedSystemPrompt(t)

	for _, cfg := range []module.ModuleConfig{
		{"agentic": false},
		{}, // missing key defaults to false
	} {
		ac, srv := newAgenticTestCoordinator()

		err := ac.Init(cfg)
		assert.NoError(t, err)

		assert.False(t, ac.isAgentic)

		// The original config values shine through unchanged.
		assert.Equal(t, agenticTestModels(), srv.Config.ClientParams.AssistantParams.AvailableModels)

		// Nothing agent-related is set up or exposed.
		assert.Empty(t, ac.DelegationLibrary)
		assert.Empty(t, ac.agents)
		assert.False(t, srv.Config.ClientParams.AssistantParams.Agentic)
		assert.Empty(t, srv.Config.ClientParams.AssistantParams.AvailableAgents)

		// Memory defaults off, but the scan interval is set regardless so a
		// later enable can never tick at zero.
		assert.False(t, ac.memorySnapshot().useMemory)
		assert.Empty(t, ac.memoryAgents)
		assert.Equal(t, 300*time.Second, ac.memorySnapshot().scanInterval)
	}
}

func TestAssistantCoordinator_InitNonAgenticMemoryEnabled(t *testing.T) {
	stubEmbeddedSystemPrompt(t)

	ac, srv := newAgenticTestCoordinator()

	// Memory runs without agentic mode: the roles' models come from the
	// dedicated config keys, one by bare id to cover both selector forms.
	err := ac.Init(module.ModuleConfig{
		"agentic":        false,
		"useMemory":      true,
		"memoryModel":    "classic-model@SOAI",
		"embedModel":     "classic-model",
		"reconcileModel": "classic-model@SOAI",
	})
	assert.NoError(t, err)

	assert.False(t, ac.isAgentic)
	assert.True(t, ac.memorySnapshot().useMemory)

	// All three memory roles are defined and resolvable.
	assert.Len(t, ac.memoryAgents, 3)
	for _, name := range []string{"Memory", "Embed", "Reconcile"} {
		agentParams, modelParams, err := ac.resolveMemoryAgent(name)
		assert.NoError(t, err, "role %s should resolve", name)
		assert.Equal(t, name, agentParams.Name)
		assert.Equal(t, "classic-model", modelParams.ID)
		assert.Equal(t, "SOAI", modelParams.Adapter)
	}

	// Nothing agent-related is set up, exposed, or reachable from the chat
	// path: memory roles live outside ac.agents.
	assert.Empty(t, ac.agents)
	assert.Nil(t, ac.SkillLibrary)
	assert.Empty(t, ac.DelegationLibrary)
	assert.False(t, srv.Config.ClientParams.AssistantParams.Agentic)
	assert.Empty(t, srv.Config.ClientParams.AssistantParams.AvailableAgents)
	assert.Empty(t, srv.Config.ClientParams.AssistantParams.AgentMapping)

	agentParams, modelParams := ac.resolveSelector("Memory")
	assert.Nil(t, agentParams)
	assert.Nil(t, modelParams)
}

func TestAssistantCoordinator_InitNonAgenticMemoryUnmapped(t *testing.T) {
	stubEmbeddedSystemPrompt(t)

	testCases := []struct {
		name string
		cfg  module.ModuleConfig
	}{
		{
			name: "no model keys configured",
			cfg:  module.ModuleConfig{"useMemory": true},
		},
		{
			name: "model keys reference unknown models",
			cfg: module.ModuleConfig{
				"useMemory":      true,
				"memoryModel":    "no-such-model",
				"embedModel":     "classic-model@WrongAdapter",
				"reconcileModel": "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac, _ := newAgenticTestCoordinator()

			// Misconfiguration is log-and-continue: Init succeeds, the roles
			// are dropped, and each memory scan then fails to resolve them.
			err := ac.Init(tc.cfg)
			assert.NoError(t, err)

			assert.True(t, ac.memorySnapshot().useMemory)
			assert.Empty(t, ac.memoryAgents)

			_, _, err = ac.resolveMemoryAgent("Memory")
			assert.ErrorIs(t, err, ErrInvalidAgent)
		})
	}
}

func TestAssistantCoordinator_InitAgenticWithMemory(t *testing.T) {
	stubEmbeddedSystemPrompt(t)

	ac, srv := newAgenticTestCoordinator()

	// Agentic and memory together: the chat agents come from agentMapping
	// while the memory roles come from the dedicated keys, and the two sets
	// stay separate.
	err := ac.Init(module.ModuleConfig{
		"agentic":   true,
		"useMemory": true,
		"agentMapping": map[string]any{
			"Orchestrator":      "classic-model@SOAI",
			"Investigator":      "classic-model@SOAI",
			"DetectionEngineer": "classic-model@SOAI",
		},
		"memoryModel":    "classic-model@SOAI",
		"embedModel":     "classic-model@SOAI",
		"reconcileModel": "classic-model@SOAI",
	})
	assert.NoError(t, err)

	assert.True(t, ac.isAgentic)
	assert.True(t, ac.memorySnapshot().useMemory)

	assert.Len(t, ac.agents, 3)
	assert.Len(t, ac.memoryAgents, 3)

	// Memory roles are not chat agents: not exposed to clients, not
	// resolvable as agents, and no delegate tools registered for them.
	assert.Len(t, srv.Config.ClientParams.AssistantParams.AvailableAgents, 3)
	assert.NotContains(t, srv.Config.ClientParams.AssistantParams.AgentMapping, "Memory")

	for _, name := range []string{"Memory", "Embed", "Reconcile"} {
		_, _, err := ac.resolveAgent(name)
		assert.ErrorIs(t, err, ErrInvalidAgent, "role %s must not resolve as a chat agent", name)

		_, _, err = ac.resolveMemoryAgent(name)
		assert.NoError(t, err, "role %s should resolve as a memory role", name)

		_, ok := ac.DelegationLibrary[name]
		assert.False(t, ok)
	}
}

func TestAssistantCoordinator_InitAgenticEnabledMapsAgents(t *testing.T) {
	stubEmbeddedSystemPrompt(t)

	ac, srv := newAgenticTestCoordinator()

	// Map all hardcoded agents onto the deployment's configured model, one
	// of them by bare id to cover both selector forms through Init.
	err := ac.Init(module.ModuleConfig{
		"agentic": true,
		"agentMapping": map[string]any{
			"Orchestrator":      "classic-model@SOAI",
			"Investigator":      "classic-model",
			"DetectionEngineer": "classic-model@SOAI",
		},
	})
	assert.NoError(t, err)

	assert.True(t, ac.isAgentic)

	// Configured models are left in place; agents map onto them.
	assert.Equal(t, agenticTestModels(), srv.Config.ClientParams.AssistantParams.AvailableModels)

	// The hardcoded agents are defined and their mapping loaded.
	assert.Len(t, ac.agents, 3)
	assert.Equal(t, "classic-model@SOAI", ac.agentMapping["Orchestrator"])
	assert.Equal(t, "classic-model", ac.agentMapping["Investigator"])
	assert.Equal(t, "classic-model@SOAI", ac.agentMapping["DetectionEngineer"])

	// The agentic flag, agent list, and mapping are exposed to clients.
	assert.True(t, srv.Config.ClientParams.AssistantParams.Agentic)
	assert.Len(t, srv.Config.ClientParams.AssistantParams.AvailableAgents, 3)
	assert.Equal(t, map[string]string{
		"Orchestrator":      "classic-model@SOAI",
		"Investigator":      "classic-model",
		"DetectionEngineer": "classic-model@SOAI",
	}, srv.Config.ClientParams.AssistantParams.AgentMapping)

	// Delegation topology: hub-and-spoke plus the Investigator -> Engineer
	// handoff edge; the Engineer is terminal.
	assert.ElementsMatch(t, []string{"Investigator", "DetectionEngineer"}, ac.agents["Orchestrator"].CanDelegateTo)
	assert.Equal(t, []string{"DetectionEngineer"}, ac.agents["Investigator"].CanDelegateTo)
	assert.Empty(t, ac.agents["DetectionEngineer"].CanDelegateTo)

	// Skill wiring is a permission boundary: Tuning (the write skill) is
	// Engineer-only, and the Orchestrator holds no skills.
	assert.ElementsMatch(t, []string{"Hunt", "Playbooks", "Respond"}, ac.agents["Investigator"].AllowedSkills)
	assert.ElementsMatch(t, []string{"Detections", "Tuning", "Hunt"}, ac.agents["DetectionEngineer"].AllowedSkills)
	assert.Empty(t, ac.agents["Orchestrator"].AllowedSkills)

	// Delegate tools are registered under both the agent name and the
	// sanitized tool name.
	for _, key := range []string{
		"Investigator", "delegate_to_Investigator",
		"DetectionEngineer", "delegate_to_DetectionEngineer",
	} {
		_, ok := ac.DelegationLibrary[key]
		assert.True(t, ok, "missing delegate registration for %s", key)
	}
}

func TestAssistantCoordinator_InitAgenticEnabledDropsUnmappedAgents(t *testing.T) {
	stubEmbeddedSystemPrompt(t)

	ac, srv := newAgenticTestCoordinator()

	// Only the Investigator is mapped; the unmapped agents are dropped.
	err := ac.Init(module.ModuleConfig{
		"agentic": true,
		"agentMapping": map[string]any{
			"Investigator": "classic-model@SOAI",
		},
	})
	assert.NoError(t, err)

	assert.True(t, ac.isAgentic)

	// Only the validly-mapped agent survives.
	assert.Len(t, ac.agents, 1)
	_, hasInvestigator := ac.agents["Investigator"]
	assert.True(t, hasInvestigator)
	assert.Len(t, srv.Config.ClientParams.AssistantParams.AvailableAgents, 1)

	// The exposed mapping only includes the surviving agent.
	assert.Equal(t, map[string]string{"Investigator": "classic-model@SOAI"}, srv.Config.ClientParams.AssistantParams.AgentMapping)

	// No delegate tool is registered for the dropped DetectionEngineer, so
	// the Investigator's CanDelegateTo edge degrades to no tool rather than
	// a delegate targeting an agent that cannot run.
	_, ok := ac.DelegationLibrary["DetectionEngineer"]
	assert.False(t, ok)
	_, ok = ac.DelegationLibrary["delegate_to_DetectionEngineer"]
	assert.False(t, ok)
	_, ok = ac.DelegationLibrary["Investigator"]
	assert.True(t, ok)
}

func gzipString(t *testing.T, s string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	_, err := writer.Write([]byte(s))
	assert.NoError(t, err)
	assert.NoError(t, writer.Close())

	return buf.Bytes()
}

func TestAssistantCoordinator_UnzipAndUnmarshal(t *testing.T) {
	ac := NewAssistantCoordinator(&server.Server{
		Context: context.Background(),
		Config:  &config.ServerConfig{},
	})

	testCases := []struct {
		name     string
		data     []byte
		expected map[string]string
	}{
		{
			name: "valid gzipped JSON decodes to a map",
			data: gzipString(t, `{"prompt_agent_investigator": "You are an investigator.", "prompt_skill_hunt": "Query events."}`),
			expected: map[string]string{
				"prompt_agent_investigator": "You are an investigator.",
				"prompt_skill_hunt":         "Query events.",
			},
		},
		{
			name:     "nil input yields an empty map",
			data:     nil,
			expected: map[string]string{},
		},
		{
			name:     "empty input yields an empty map",
			data:     []byte{},
			expected: map[string]string{},
		},
		{
			name:     "non-gzip bytes yield an empty map",
			data:     []byte(`{"prompt_agent_investigator": "not compressed"}`),
			expected: map[string]string{},
		},
		{
			name:     "gzipped non-JSON yields an empty map",
			data:     gzipString(t, "not json"),
			expected: map[string]string{},
		},
		{
			name:     "gzipped JSON of the wrong shape yields an empty map",
			data:     gzipString(t, `["not", "an", "object"]`),
			expected: map[string]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			prompts := ac.unzipAndUnmarshal(tc.data)
			assert.NotNil(t, prompts)
			assert.Equal(t, tc.expected, prompts)
		})
	}
}

func TestParseAgentsSetting(t *testing.T) {
	t.Run("nil or empty setting keeps current agents", func(t *testing.T) {
		for _, s := range []*model.Setting{nil, {Id: ConfigSettingAgents, Value: ""}, {Id: ConfigSettingAgents, Value: "   \n  "}} {
			agents, mapping, err := parseAgentsSetting(s)
			assert.NoError(t, err)
			assert.Nil(t, agents)
			assert.Nil(t, mapping)
		}
	})

	t.Run("newline-delimited objects populate agents and mapping", func(t *testing.T) {
		value := `{"name":"Orchestrator","isOrchestrator":true,"model":"Sonnet","canDelegateTo":["Hunter"]}
{"name":"Hunter","model":"Opus","allowedSkills":["Hunt"],"description":"finds things","persona":"be a hunter"}`

		agents, mapping, err := parseAgentsSetting(&model.Setting{Id: ConfigSettingAgents, Value: value})
		require.NoError(t, err)
		require.Len(t, agents, 2)

		orch := agents["Orchestrator"]
		assert.True(t, orch.IsOrchestrator)
		assert.Equal(t, []string{"Hunter"}, orch.CanDelegateTo)

		hunter := agents["Hunter"]
		assert.Equal(t, []string{"Hunt"}, hunter.AllowedSkills)
		assert.Equal(t, "finds things", hunter.Description)
		assert.Equal(t, "be a hunter", hunter.PersonaAddendum)
		assert.Empty(t, hunter.Prompt)

		// The per-agent model drives the mapping.
		assert.Equal(t, map[string]string{"Orchestrator": "Sonnet", "Hunter": "Opus"}, mapping)
	})

	t.Run("json array form is also accepted", func(t *testing.T) {
		value := `[{"name":"A","model":"m1"},{"name":"B","model":"m2"}]`
		agents, mapping, err := parseAgentsSetting(&model.Setting{Id: ConfigSettingAgents, Value: value})
		require.NoError(t, err)
		assert.Len(t, agents, 2)
		assert.Equal(t, "m1", mapping["A"])
		assert.Equal(t, "m2", mapping["B"])
	})

	t.Run("entries without a name are skipped; agent without model has no mapping", func(t *testing.T) {
		value := `{"name":"","model":"x"}
{"name":"Solo"}`
		agents, mapping, err := parseAgentsSetting(&model.Setting{Id: ConfigSettingAgents, Value: value})
		require.NoError(t, err)
		require.Len(t, agents, 1)
		assert.Contains(t, agents, "Solo")
		assert.Empty(t, mapping)
	})

	t.Run("enabled defaults to true and is honored when present", func(t *testing.T) {
		value := `{"name":"Default","model":"m"}
{"name":"Off","model":"m","enabled":false}
{"name":"On","model":"m","enabled":true}`

		agents, _, err := parseAgentsSetting(&model.Setting{Id: ConfigSettingAgents, Value: value})
		require.NoError(t, err)
		require.Len(t, agents, 3)

		assert.True(t, agents["Default"].Enabled)
		assert.False(t, agents["Off"].Enabled)
		assert.True(t, agents["On"].Enabled)
	})

	t.Run("malformed json returns an error", func(t *testing.T) {
		_, _, err := parseAgentsSetting(&model.Setting{Id: ConfigSettingAgents, Value: `{"name":"X"`})
		assert.Error(t, err)
	})
}

func TestParseIntSetting(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"5", 5, false},
		{"  7 ", 7, false},
		{"0", 0, false},
		{"3", 3, false},
		{"", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := parseIntSetting(c.in)
		if c.wantErr {
			assert.Error(t, err, "input %q", c.in)
			continue
		}
		assert.NoError(t, err, "input %q", c.in)
		assert.Equal(t, c.want, got, "input %q", c.in)
	}
}

// builtinMergeCoordinator stands in for the shipped agents so the merge steps can
// be tested without the embedded prompt file.
func builtinMergeCoordinator() (*AssistantCoordinator, *memory.Handler) {
	ac, h := newSelectorLogCoordinator(nil)
	ac.builtinAgents = map[string]model.Agent{
		"Orchestrator": {
			Name:           "Orchestrator",
			IsOrchestrator: true,
			IsSystem:       true,
			Enabled:        true,
			Prompt:         "built-in orchestrator prompt",
			Description:    "routes work",
			AllowedSkills:  []string{},
			CanDelegateTo:  []string{"Hunter"},
		},
		"Hunter": {
			Name:          "Hunter",
			IsSystem:      true,
			Enabled:       true,
			Prompt:        "built-in hunter prompt",
			Description:   "hunts",
			AllowedSkills: []string{"Hunt"},
			CanDelegateTo: []string{},
		},
	}
	ac.builtinAgentMapping = map[string]string{"Orchestrator": "m1@a", "Hunter": "m2@a"}

	return ac, h
}

func TestApplyBuiltinDefaults(t *testing.T) {
	t.Run("a stored system agent keeps its built-in prompt and uneditable fields", func(t *testing.T) {
		ac, _ := builtinMergeCoordinator()

		// All the Agent Studio can save: it never received the prompt.
		agents := map[string]model.Agent{
			"Hunter": {Name: "Hunter", Enabled: false, PersonaAddendum: "also check DNS"},
		}

		ac.applyBuiltinDefaults(agents)

		hunter := agents["Hunter"]
		assert.True(t, hunter.IsSystem)
		assert.Equal(t, "built-in hunter prompt", hunter.Prompt, "built-in prompt must survive a save that omits it")
		assert.Equal(t, "hunts", hunter.Description)
		assert.Equal(t, []string{"Hunt"}, hunter.AllowedSkills)
		assert.Equal(t, []string{}, hunter.CanDelegateTo)

		assert.False(t, hunter.Enabled)
		assert.Equal(t, "also check DNS", hunter.PersonaAddendum)
		assert.Equal(t, "built-in hunter prompt\n\nalso check DNS", hunter.EffectivePrompt())
	})

	t.Run("stored delegation overrides the built-in", func(t *testing.T) {
		ac, _ := builtinMergeCoordinator()
		agents := map[string]model.Agent{
			"Orchestrator": {Name: "Orchestrator", Enabled: true, CanDelegateTo: []string{}},
		}

		ac.applyBuiltinDefaults(agents)

		assert.Equal(t, []string{}, agents["Orchestrator"].CanDelegateTo)
	})

	t.Run("an admin-created agent is left untouched", func(t *testing.T) {
		ac, _ := builtinMergeCoordinator()
		agents := map[string]model.Agent{
			"Custom": {Name: "Custom", Enabled: true, PersonaAddendum: "my own agent", Description: "mine"},
		}

		ac.applyBuiltinDefaults(agents)

		custom := agents["Custom"]
		assert.False(t, custom.IsSystem)
		assert.Empty(t, custom.Prompt)
		assert.Equal(t, "my own agent", custom.EffectivePrompt())
	})
}

func TestRestoreMissingBuiltins(t *testing.T) {
	t.Run("a built-in absent from the setting is restored with its mapping", func(t *testing.T) {
		ac, _ := builtinMergeCoordinator()
		agents := map[string]model.Agent{
			"Orchestrator": {Name: "Orchestrator", Enabled: true},
		}
		mapping := map[string]string{"Orchestrator": "custom@a"}

		ac.restoreMissingBuiltins(agents, mapping)

		require.Contains(t, agents, "Hunter", "a system agent may be disabled but never deleted")
		assert.Equal(t, "built-in hunter prompt", agents["Hunter"].Prompt)
		assert.Equal(t, "m2@a", mapping["Hunter"])
		// A built-in the setting mentions keeps its configured model.
		assert.Equal(t, "custom@a", mapping["Orchestrator"])
	})
}

func TestEnsureEnabledOrchestrator(t *testing.T) {
	t.Run("no change when an orchestrator is enabled", func(t *testing.T) {
		ac, h := builtinMergeCoordinator()
		agents := map[string]model.Agent{
			"Orchestrator": {Name: "Orchestrator", IsOrchestrator: true, IsSystem: true, Enabled: true},
			"Hunter":       {Name: "Hunter", IsSystem: true, Enabled: false},
		}

		ac.ensureEnabledOrchestrator(context.Background(), agents)

		assert.False(t, agents["Hunter"].Enabled)
		assert.Empty(t, logMessagesAt(h, log.ErrorLevel))
	})

	t.Run("disabling the last orchestrator is refused and logged", func(t *testing.T) {
		ac, h := builtinMergeCoordinator()
		ac.srv.Context = log.NewContext(context.Background(), &log.Logger{Handler: h, Level: log.DebugLevel})
		agents := map[string]model.Agent{
			"Orchestrator": {Name: "Orchestrator", IsOrchestrator: true, IsSystem: true, Enabled: false},
			"Hunter":       {Name: "Hunter", IsSystem: true, Enabled: true},
		}

		ac.ensureEnabledOrchestrator(ac.srv.Context, agents)

		assert.True(t, agents["Orchestrator"].Enabled, "a grid with no orchestrator has no entry point for agentic chat")

		errors := logMessagesAt(h, log.ErrorLevel)
		require.Len(t, errors, 1)
		assert.Contains(t, errors[0], "no enabled orchestrator")
	})

	t.Run("an admin-created orchestrator is not force-enabled", func(t *testing.T) {
		ac, h := builtinMergeCoordinator()
		ac.builtinAgents = map[string]model.Agent{}
		agents := map[string]model.Agent{
			"MyOrchestrator": {Name: "MyOrchestrator", IsOrchestrator: true, Enabled: false},
		}

		ac.ensureEnabledOrchestrator(log.NewContext(context.Background(), &log.Logger{Handler: h, Level: log.DebugLevel}), agents)

		// Only system orchestrators are restored; an admin may disable their own.
		assert.False(t, agents["MyOrchestrator"].Enabled)
		assert.Len(t, logMessagesAt(h, log.ErrorLevel), 1)
	})
}

func TestParseSkillsSetting(t *testing.T) {
	t.Run("nil or empty setting keeps current skills", func(t *testing.T) {
		for _, s := range []*model.Setting{nil, {Id: ConfigSettingSkills, Value: ""}, {Id: ConfigSettingSkills, Value: "  \n "}} {
			skills, err := parseSkillsSetting(s)
			assert.NoError(t, err)
			assert.Nil(t, skills)
		}
	})

	t.Run("newline-delimited objects populate the library", func(t *testing.T) {
		value := `{"name":"Hunt","persona":"prefer narrow queries"}
{"name":"Custom","tools":["query_events"],"enabled":false}`

		skills, err := parseSkillsSetting(&model.Setting{Id: ConfigSettingSkills, Value: value})
		require.NoError(t, err)
		require.Len(t, skills, 2)

		assert.Equal(t, "prefer narrow queries", skills["Hunt"].PersonaAddendum)
		assert.Empty(t, skills["Hunt"].AdditionalPrompt)
		assert.True(t, skills["Hunt"].Enabled, "an absent enabled flag means enabled")

		assert.Equal(t, []string{"query_events"}, skills["Custom"].Tools)
		assert.False(t, skills["Custom"].Enabled)
	})

	t.Run("json array form is accepted and unnamed entries are skipped", func(t *testing.T) {
		value := `[{"name":"A","tools":["t1"]},{"name":"","tools":["t2"]}]`
		skills, err := parseSkillsSetting(&model.Setting{Id: ConfigSettingSkills, Value: value})
		require.NoError(t, err)
		require.Len(t, skills, 1)
		assert.Contains(t, skills, "A")
	})

	t.Run("malformed json returns an error", func(t *testing.T) {
		_, err := parseSkillsSetting(&model.Setting{Id: ConfigSettingSkills, Value: `{"name":"X"`})
		assert.Error(t, err)
	})
}

func TestApplyBuiltinSkillDefaults(t *testing.T) {
	ac, _ := builtinMergeCoordinator()
	ac.builtinSkills = map[string]model.Skill{
		"Hunt": {
			Name:             "Hunt",
			Tools:            []string{"query_events", "get_playbooks"},
			AdditionalPrompt: "built-in hunt guidance",
			IsSystem:         true,
			Enabled:          true,
		},
	}

	t.Run("a stored system skill keeps its built-in guidance and tool set", func(t *testing.T) {
		// A save cannot carry the built-in guidance, nor widen a system skill's tools.
		skills := map[string]model.Skill{
			"Hunt": {Name: "Hunt", Tools: []string{"create_detection"}, Enabled: false, PersonaAddendum: "narrow queries"},
		}

		ac.applyBuiltinSkillDefaults(skills)

		hunt := skills["Hunt"]
		assert.True(t, hunt.IsSystem)
		assert.Equal(t, "built-in hunt guidance", hunt.AdditionalPrompt)
		assert.Equal(t, []string{"query_events", "get_playbooks"}, hunt.Tools, "a system skill's tool set is fixed")
		assert.False(t, hunt.Enabled)
		assert.Equal(t, "built-in hunt guidance\n\nnarrow queries", hunt.EffectiveGuidance())
	})

	t.Run("an admin-created skill keeps its own tools and guidance", func(t *testing.T) {
		skills := map[string]model.Skill{
			"Mine": {Name: "Mine", Tools: []string{"query_cases"}, Enabled: true, PersonaAddendum: "my guidance"},
		}

		ac.applyBuiltinSkillDefaults(skills)

		mine := skills["Mine"]
		assert.False(t, mine.IsSystem)
		assert.Equal(t, []string{"query_cases"}, mine.Tools)
		assert.Equal(t, "my guidance", mine.EffectiveGuidance())
	})

	t.Run("a built-in absent from the setting is restored", func(t *testing.T) {
		skills := map[string]model.Skill{"Mine": {Name: "Mine", Enabled: true}}

		ac.restoreMissingBuiltinSkills(skills)

		require.Contains(t, skills, "Hunt", "a system skill may be disabled but never deleted")
		assert.Equal(t, "built-in hunt guidance", skills["Hunt"].AdditionalPrompt)
	})
}

func TestBroadcastPayloadIsTheWholeAssistantBlock(t *testing.T) {
	ac, _ := builtinMergeCoordinator()
	params := &ac.srv.Config.ClientParams.AssistantParams
	params.AvailableAgents = []model.Agent{{Name: "Hunter", Prompt: "secret", Enabled: true}}
	params.AvailableSkills = []model.Skill{{Name: "Hunt", AdditionalPrompt: "also secret"}}
	params.MaxDelegationDepth = 3
	params.InvestigationPrompt = "carried too"

	raw, err := json.Marshal(*params)
	require.NoError(t, err)

	assert.Contains(t, string(raw), `"maxDelegationDepth":3`)
	assert.Contains(t, string(raw), "carried too")
	// Built-in prompts still cannot travel: both are json:"-".
	assert.NotContains(t, string(raw), "secret")
}

func TestExposeAgentsPublishesLimits(t *testing.T) {
	ac, _ := builtinMergeCoordinator()
	ac.maxDelegationDepth.Store(4)
	ac.maxSubSessionTokens.Store(9000)

	ac.exposeAgents()

	// Publishing them is what lets the Options dialog open without fetching every
	// setting just to read two numbers.
	params := ac.srv.Config.ClientParams.AssistantParams
	assert.Equal(t, 4, params.MaxDelegationDepth)
	assert.Equal(t, 9000, params.MaxSubSessionTokens)
}

func TestBroadcastAgenticUpdateWithoutHost(t *testing.T) {
	ac, _ := builtinMergeCoordinator()
	ac.srv.Host = nil

	// Init exposes agents before a Host exists; that must not panic.
	assert.NotPanics(t, ac.broadcastAgenticUpdate)
}

// fakeConfigstore records the last written value and serves a canned setting.
type fakeConfigstore struct {
	mu       sync.Mutex
	value    string
	settings []*model.Setting
	written  []string
	err      error
}

func (f *fakeConfigstore) GetSettings(ctx context.Context, includeDefault bool) ([]*model.Setting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.settings != nil {
		return f.settings, nil
	}
	return []*model.Setting{{Id: ConfigSettingAgents, Value: f.value}, {Id: ConfigSettingSkills, Value: f.value}}, nil
}

func (f *fakeConfigstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.written = append(f.written, setting.Value)
	f.value = setting.Value
	return nil
}

// Unused by these tests; present to satisfy server.Configstore.
func (f *fakeConfigstore) GetAuditHistory(ctx context.Context, settingID, nodeID string, limit, offset int, sort, order string) (*server.ConfigHistory, error) {
	return nil, nil
}

func (f *fakeConfigstore) GetAllAuditHistory(ctx context.Context, limit, offset int, sort, order string) (*server.ConfigHistory, error) {
	return nil, nil
}

func (f *fakeConfigstore) RevertSetting(ctx context.Context, settingID, nodeID string, timestamp time.Time, note string) error {
	return nil
}

func (f *fakeConfigstore) RevertAllSettings(ctx context.Context, timestamp time.Time, note string) (int, error) {
	return 0, nil
}

func (f *fakeConfigstore) GetRevertCount(ctx context.Context, timestamp time.Time) (int, error) {
	return 0, nil
}

func (f *fakeConfigstore) lastWritten() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.written) == 0 {
		return nil
	}
	return strings.Split(f.written[len(f.written)-1], "\n")
}

func configWriteCoordinator(stored string) (*AssistantCoordinator, *fakeConfigstore) {
	ac, _ := builtinMergeCoordinator()
	ac.builtinSkills = map[string]model.Skill{"Hunt": {Name: "Hunt", IsSystem: true, Enabled: true}}
	store := &fakeConfigstore{value: stored}
	ac.srv.Configstore = store

	return ac, store
}

func enabledPtr(v bool) *bool { return &v }

func TestSaveAgentMergesIntoStoredList(t *testing.T) {
	stored := `{"name":"Orchestrator","enabled":true,"model":"m1@a"}
{"name":"Hunter","enabled":true,"model":"m2@a","persona":"hunt well"}`
	ac, store := configWriteCoordinator(stored)

	err := ac.SaveAgent(context.Background(), "Hunter", &model.StoredAgent{
		Name: "Hunter", Enabled: enabledPtr(false), Model: "m3@a", Persona: "hunt better",
	})
	require.NoError(t, err)

	lines := store.lastWritten()
	require.Len(t, lines, 2)
	// The untouched agent is written back exactly as stored, which is the whole
	// point: a client editing Hunter cannot revert Orchestrator.
	assert.Contains(t, lines[0], `"name":"Orchestrator"`)
	assert.Contains(t, lines[0], `"model":"m1@a"`)
	assert.Contains(t, lines[1], `"model":"m3@a"`)
	assert.Contains(t, lines[1], `"persona":"hunt better"`)
}

func TestSaveAgentAppendsWhenNew(t *testing.T) {
	ac, store := configWriteCoordinator(`{"name":"Hunter","enabled":true}`)

	require.NoError(t, ac.SaveAgent(context.Background(), "Triage", &model.StoredAgent{Name: "Triage", Enabled: enabledPtr(true)}))

	lines := store.lastWritten()
	require.Len(t, lines, 2)
	assert.Contains(t, lines[1], `"name":"Triage"`)
}

func TestSaveAgentAcceptsArrayEncoding(t *testing.T) {
	ac, store := configWriteCoordinator(`[{"name":"Hunter","model":"m2@a"}]`)

	require.NoError(t, ac.SaveAgent(context.Background(), "Triage", &model.StoredAgent{Name: "Triage"}))

	// Read tolerates the array form; writes always use the newline-delimited form.
	lines := store.lastWritten()
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `"name":"Hunter"`)
}

func TestSaveAgentRequiresName(t *testing.T) {
	ac, store := configWriteCoordinator("")

	assert.Error(t, ac.SaveAgent(context.Background(), "  ", &model.StoredAgent{Name: "  "}))
	assert.Error(t, ac.SaveAgent(context.Background(), "x", nil))
	assert.Empty(t, store.written)
}

func TestDeleteAgent(t *testing.T) {
	stored := `{"name":"Orchestrator"}
{"name":"Custom"}`

	t.Run("removes an admin-created agent", func(t *testing.T) {
		ac, store := configWriteCoordinator(stored)

		require.NoError(t, ac.DeleteAgent(context.Background(), "Custom"))

		lines := store.lastWritten()
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], `"name":"Orchestrator"`)
	})

	t.Run("refuses a system agent", func(t *testing.T) {
		ac, store := configWriteCoordinator(stored)

		err := ac.DeleteAgent(context.Background(), "Orchestrator")

		assert.ErrorIs(t, err, ErrSystemAgentImmutable)
		assert.Empty(t, store.written, "a system agent can be disabled but never removed")
	})

	t.Run("reports an unknown agent", func(t *testing.T) {
		ac, store := configWriteCoordinator(stored)

		assert.ErrorIs(t, ac.DeleteAgent(context.Background(), "Nope"), ErrAgentNotFound)
		assert.Empty(t, store.written)
	})
}

func TestSaveAndDeleteSkill(t *testing.T) {
	stored := `{"name":"Hunt","enabled":true}
{"name":"Custom","enabled":true,"tools":["query_events"]}`

	t.Run("merges a skill without touching the others", func(t *testing.T) {
		ac, store := configWriteCoordinator(stored)

		require.NoError(t, ac.SaveSkill(context.Background(), "Hunt", &model.StoredSkill{Name: "Hunt", Enabled: enabledPtr(false), Persona: "be brief"}))

		lines := store.lastWritten()
		require.Len(t, lines, 2)
		assert.Contains(t, lines[0], `"persona":"be brief"`)
		assert.Contains(t, lines[1], `"tools":["query_events"]`)
	})

	t.Run("refuses to delete a system skill", func(t *testing.T) {
		ac, store := configWriteCoordinator(stored)

		assert.ErrorIs(t, ac.DeleteSkill(context.Background(), "Hunt"), ErrSystemAgentImmutable)
		assert.Empty(t, store.written)
	})

	t.Run("deletes an admin-created skill", func(t *testing.T) {
		ac, store := configWriteCoordinator(stored)

		require.NoError(t, ac.DeleteSkill(context.Background(), "Custom"))
		assert.Len(t, store.lastWritten(), 1)
	})

	t.Run("refuses a rename onto an existing skill", func(t *testing.T) {
		ac, store := configWriteCoordinator(stored)

		err := ac.SaveSkill(context.Background(), "Custom", &model.StoredSkill{Name: "Hunt"})

		assert.ErrorIs(t, err, ErrNameConflict)
		assert.Empty(t, store.written)
	})
}

func TestSaveSkillRenameUpdatesAgents(t *testing.T) {
	ac, store := configWriteCoordinator("")
	store.settings = []*model.Setting{
		{Id: ConfigSettingSkills, Value: `{"name":"Custom","tools":["query_events"]}`},
		{Id: ConfigSettingAgents, Value: `{"name":"Hunter","allowedSkills":["Custom","Hunt"]}`},
	}

	require.NoError(t, ac.SaveSkill(context.Background(), "Custom", &model.StoredSkill{Name: "Renamed", Tools: []string{"query_events"}}))

	// Both settings are written: an agent still naming the old skill would silently
	// lose its tools.
	require.Len(t, store.written, 2)
	assert.Contains(t, store.written[0], `"name":"Renamed"`)
	assert.Contains(t, store.written[1], `"allowedSkills":["Renamed","Hunt"]`)
}

func TestConcurrentSavesDoNotClobber(t *testing.T) {
	ac, store := configWriteCoordinator(`{"name":"A"}
{"name":"B"}`)

	// The point of moving the merge server-side: concurrent writers each read the
	// latest list under configWriteMu, so neither drops the other's change.
	var wg sync.WaitGroup
	for _, name := range []string{"A", "B"} {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			assert.NoError(t, ac.SaveAgent(context.Background(), n, &model.StoredAgent{Name: n, Persona: "set by " + n}))
		}(name)
	}
	wg.Wait()

	lines := store.lastWritten()
	require.Len(t, lines, 2)
	assert.Contains(t, strings.Join(lines, "\n"), "set by A")
	assert.Contains(t, strings.Join(lines, "\n"), "set by B")
}

func TestSaveAgentRename(t *testing.T) {
	t.Run("renaming replaces the entry rather than orphaning it", func(t *testing.T) {
		ac, store := configWriteCoordinator(`{"name":"Old","persona":"p"}
{"name":"Other"}`)

		require.NoError(t, ac.SaveAgent(context.Background(), "Old", &model.StoredAgent{Name: "New", Persona: "p"}))

		lines := store.lastWritten()
		require.Len(t, lines, 2)
		assert.Contains(t, lines[0], `"name":"New"`)
		assert.NotContains(t, strings.Join(lines, "\n"), `"name":"Old"`)
	})

	t.Run("renaming onto an existing name is refused", func(t *testing.T) {
		ac, store := configWriteCoordinator(`{"name":"Old"}
{"name":"Taken","persona":"keep me"}`)

		err := ac.SaveAgent(context.Background(), "Old", &model.StoredAgent{Name: "Taken", Persona: "fresh"})

		assert.ErrorIs(t, err, ErrNameConflict)
		assert.Empty(t, store.written, "the agent already using that name must not be overwritten")
	})

	t.Run("renaming onto a built-in name is refused even with nothing stored for it", func(t *testing.T) {
		ac, store := configWriteCoordinator(`{"name":"Custom"}`)

		err := ac.SaveAgent(context.Background(), "Custom", &model.StoredAgent{Name: "Orchestrator"})

		assert.ErrorIs(t, err, ErrNameConflict)
		assert.Empty(t, store.written)
	})

	t.Run("renaming repoints other agents' delegation", func(t *testing.T) {
		ac, store := configWriteCoordinator(`{"name":"Boss","canDelegateTo":["Old","Other"]}
{"name":"Old"}`)

		require.NoError(t, ac.SaveAgent(context.Background(), "Old", &model.StoredAgent{Name: "New"}))

		lines := store.lastWritten()
		require.Len(t, lines, 2)
		assert.Contains(t, lines[0], `"canDelegateTo":["New","Other"]`)
	})

	t.Run("saving without renaming keeps the name check out of the way", func(t *testing.T) {
		ac, store := configWriteCoordinator(`{"name":"Custom","persona":"old"}`)

		require.NoError(t, ac.SaveAgent(context.Background(), "Custom", &model.StoredAgent{Name: "Custom", Persona: "new"}))

		assert.Contains(t, store.lastWritten()[0], `"persona":"new"`)
	})
}
