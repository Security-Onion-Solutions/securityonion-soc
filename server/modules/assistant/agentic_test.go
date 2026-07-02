// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"compress/gzip"
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/stretchr/testify/assert"
)

func TestAssistantCoordinator_InitAgenticToggle(t *testing.T) {
	// Disable the embedded prompt so getPrompt() is a no-op.
	origPrompt := embeddedSystemPrompt
	t.Cleanup(func() {
		embeddedSystemPrompt = origPrompt
	})
	embeddedSystemPrompt = []byte{}

	// The models a normal (non-agentic) deployment's config would have populated.
	configuredModels := func() []model.ModelParameters {
		return []model.ModelParameters{
			{
				ID:          "classic-model",
				DisplayName: "Classic",
				Adapter:     "SOAI",
				Enabled:     true,
			},
		}
	}

	newCoordinator := func() (*AssistantCoordinator, *server.Server) {
		srv := &server.Server{
			Context: context.Background(),
			Config: &config.ServerConfig{
				ClientParams: model.ClientParameters{
					AssistantParams: model.AssistantParameters{
						AvailableModels: configuredModels(),
					},
				},
			},
		}

		return NewAssistantCoordinator(srv), srv
	}

	t.Run("agentic disabled leaves configured models untouched", func(t *testing.T) {
		for _, cfg := range []module.ModuleConfig{
			{"agentic": false},
			{}, // missing key defaults to false
		} {
			ac, srv := newCoordinator()

			err := ac.Init(cfg)
			assert.NoError(t, err)

			assert.False(t, ac.isAgentic)

			// The original config values shine through unchanged.
			assert.Equal(t, configuredModels(), srv.Config.ClientParams.AssistantParams.AvailableModels)

			// Nothing agent-related is set up or exposed.
			assert.Empty(t, ac.DelegationLibrary)
			assert.Empty(t, ac.agents)
			assert.False(t, srv.Config.ClientParams.AssistantParams.Agentic)
			assert.Empty(t, srv.Config.ClientParams.AssistantParams.AvailableAgents)
		}
	})

	t.Run("agentic enabled maps agents onto configured models", func(t *testing.T) {
		ac, srv := newCoordinator()

		// Map both hardcoded agents onto the deployment's configured model.
		err := ac.Init(module.ModuleConfig{
			"agentic": true,
			"agentMapping": map[string]any{
				"Orchestrator": "Classic",
				"Hunter":       "Classic",
			},
		})
		assert.NoError(t, err)

		assert.True(t, ac.isAgentic)

		// Configured models are left in place; agents map onto them.
		assert.Equal(t, configuredModels(), srv.Config.ClientParams.AssistantParams.AvailableModels)

		// The hardcoded agents are defined and their mapping loaded.
		assert.Len(t, ac.agents, 2)
		assert.Equal(t, "Classic", ac.agentMapping["Orchestrator"])
		assert.Equal(t, "Classic", ac.agentMapping["Hunter"])

		// The agentic flag, agent list, and mapping are exposed to clients.
		assert.True(t, srv.Config.ClientParams.AssistantParams.Agentic)
		assert.Len(t, srv.Config.ClientParams.AssistantParams.AvailableAgents, 2)
		assert.Equal(t, map[string]string{
			"Orchestrator": "Classic",
			"Hunter":       "Classic",
		}, srv.Config.ClientParams.AssistantParams.AgentMapping)

		// Delegate tools are created for the agents.
		assert.NotEmpty(t, ac.DelegationLibrary)
	})

	t.Run("agentic enabled drops agents with no valid mapping", func(t *testing.T) {
		ac, srv := newCoordinator()

		// Only Hunter is mapped; Orchestrator and a bogus model mapping are dropped.
		err := ac.Init(module.ModuleConfig{
			"agentic": true,
			"agentMapping": map[string]any{
				"Hunter": "Classic",
			},
		})
		assert.NoError(t, err)

		assert.True(t, ac.isAgentic)

		// Only the validly-mapped agent survives.
		assert.Len(t, ac.agents, 1)
		_, hasHunter := ac.agents["Hunter"]
		assert.True(t, hasHunter)
		assert.Len(t, srv.Config.ClientParams.AssistantParams.AvailableAgents, 1)

		// The exposed mapping only includes the surviving agent.
		assert.Equal(t, map[string]string{"Hunter": "Classic"}, srv.Config.ClientParams.AssistantParams.AgentMapping)
	})
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
			data: gzipString(t, `{"prompt_agent_hunter": "You are a hunter.", "prompt_skill_hunt": "Query events."}`),
			expected: map[string]string{
				"prompt_agent_hunter": "You are a hunter.",
				"prompt_skill_hunt":   "Query events.",
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
			data:     []byte(`{"prompt_agent_hunter": "not compressed"}`),
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
