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

	t.Run("agentic enabled replaces configured models", func(t *testing.T) {
		ac, srv := newCoordinator()

		err := ac.Init(module.ModuleConfig{"agentic": true})
		assert.NoError(t, err)

		assert.True(t, ac.isAgentic)

		// The configured models are replaced with the hardcoded agentic models.
		// The agentic model definitions are still in flux, so don't assert on
		// their specifics — just that the configured classic model is gone.
		models := srv.Config.ClientParams.AssistantParams.AvailableModels
		assert.NotEmpty(t, models)
		for _, m := range models {
			assert.NotEqual(t, "classic-model", m.ID)
		}

		// Delegate tools are created for the agentic models.
		assert.NotEmpty(t, ac.DelegationLibrary)
	})
}
