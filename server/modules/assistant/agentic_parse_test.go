// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	ac.builtinAgents = map[string]model.AgentParameters{
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
		agents := map[string]model.AgentParameters{
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
		agents := map[string]model.AgentParameters{
			"Orchestrator": {Name: "Orchestrator", Enabled: true, CanDelegateTo: []string{}},
		}

		ac.applyBuiltinDefaults(agents)

		assert.Equal(t, []string{}, agents["Orchestrator"].CanDelegateTo)
	})

	t.Run("an admin-created agent is left untouched", func(t *testing.T) {
		ac, _ := builtinMergeCoordinator()
		agents := map[string]model.AgentParameters{
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
		agents := map[string]model.AgentParameters{
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
		agents := map[string]model.AgentParameters{
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
		agents := map[string]model.AgentParameters{
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
		ac.builtinAgents = map[string]model.AgentParameters{}
		agents := map[string]model.AgentParameters{
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
