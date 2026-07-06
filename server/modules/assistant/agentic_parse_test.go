// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"testing"

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
{"name":"Hunter","model":"Opus","allowedSkills":["Hunt"],"description":"finds things","prompt":"be a hunter"}`

		agents, mapping, err := parseAgentsSetting(&model.Setting{Id: ConfigSettingAgents, Value: value})
		require.NoError(t, err)
		require.Len(t, agents, 2)

		orch := agents["Orchestrator"]
		assert.True(t, orch.IsOrchestrator)
		assert.Equal(t, []string{"Hunter"}, orch.CanDelegateTo)

		hunter := agents["Hunter"]
		assert.Equal(t, []string{"Hunt"}, hunter.AllowedSkills)
		assert.Equal(t, "finds things", hunter.Description)
		assert.Equal(t, "be a hunter", hunter.Prompt)

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
