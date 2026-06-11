// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
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

			// No delegate tools are created.
			assert.Empty(t, ac.DelegationLibrary)
		}
	})

	t.Run("agentic enabled applies setupAgentic and creates delegates", func(t *testing.T) {
		ac, srv := newCoordinator()

		err := ac.Init(module.ModuleConfig{"agentic": true})
		assert.NoError(t, err)

		assert.True(t, ac.isAgentic)

		// AvailableModels is overwritten with the hardcoded agentic models; the
		// configured classic model is gone.
		models := srv.Config.ClientParams.AssistantParams.AvailableModels
		assert.Len(t, models, 2)

		byId := map[string]model.ModelParameters{}
		for _, m := range models {
			byId[m.ID] = m
		}
		assert.NotContains(t, byId, "classic-model")

		orchestrator, ok := byId["gemini-3.5-flash"]
		assert.True(t, ok)
		assert.Equal(t, "Agent Gemini", orchestrator.DisplayName)
		assert.Equal(t, "Gemini", orchestrator.Adapter)
		assert.True(t, orchestrator.Enabled)
		assert.True(t, orchestrator.IsAgentic)
		assert.True(t, orchestrator.IsOrchestrator)
		assert.Contains(t, orchestrator.CanDelegateTo, "gemini-3-flash-preview@Gemini")
		assert.NotEmpty(t, orchestrator.AgentPrompt)

		hunter, ok := byId["gemini-3-flash-preview"]
		assert.True(t, ok)
		assert.Equal(t, "Hunter", hunter.DisplayName)
		assert.Equal(t, "Gemini", hunter.Adapter)
		assert.True(t, hunter.Enabled)
		assert.True(t, hunter.IsAgentic)
		assert.False(t, hunter.IsOrchestrator)
		assert.Contains(t, hunter.AllowedTools, "query_events")
		assert.NotEmpty(t, hunter.AgentPrompt)
		assert.NotEmpty(t, hunter.AgentDescription)

		// Each enabled agentic model gets a delegate tool, registered under both
		// its model id and its tool name.
		assert.Len(t, ac.DelegationLibrary, 4)
		assert.Contains(t, ac.DelegationLibrary, "gemini-3.5-flash@Gemini")
		assert.Contains(t, ac.DelegationLibrary, "delegate_to_gemini-3.5-flash_at_Gemini")
		assert.Contains(t, ac.DelegationLibrary, "gemini-3-flash-preview@Gemini")
		assert.Contains(t, ac.DelegationLibrary, "delegate_to_gemini-3-flash-preview_at_Gemini")
	})
}
