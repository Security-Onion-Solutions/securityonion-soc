// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"testing"
	"testing/synctest"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/execpool"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newExecPoolCoordinator(t *testing.T, maxConcurrent int) *AssistantCoordinator {
	t.Helper()

	ac := &AssistantCoordinator{
		srv: &server.Server{
			Context: context.Background(),
			Config: &config.ServerConfig{ClientParams: model.ClientParameters{AssistantParams: model.AssistantParameters{
				AvailableModels: []model.ModelParameters{{ID: "test-model", Adapter: "MyAdapter", Enabled: true}},
			}}},
		},
		isAgentic: true,
		agents: map[string]model.Agent{
			"Hunter":  {Name: "Hunter", Enabled: true, MaxConcurrentInstances: 1},
			"Analyst": {Name: "Analyst", Enabled: true},
		},
		agentMapping:                 map[string]string{"Hunter": "test-model@MyAdapter", "Analyst": "test-model@MyAdapter"},
		automationMaxConcurrentItems: maxConcurrent,
	}
	ac.execPool = ac.newExecPool()

	t.Cleanup(func() { require.NoError(t, ac.Stop()) })

	return ac
}

func TestAcquireTurnSlot(t *testing.T) {
	t.Run("agent at its limit is busy until released", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ac := newExecPoolCoordinator(t, 0)

			release, err := ac.AcquireTurnSlot(t.Context(), "s1", "Hunter")
			require.NoError(t, err)

			_, err = ac.AcquireTurnSlot(t.Context(), "s2", "Hunter")
			assert.ErrorIs(t, err, server.ErrAgentBusy)

			release()
			release()
			synctest.Wait()

			release, err = ac.AcquireTurnSlot(t.Context(), "s2", "Hunter")
			require.NoError(t, err)
			release()
		})
	})

	t.Run("a session already in a turn is refused", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ac := newExecPoolCoordinator(t, 0)

			release, err := ac.AcquireTurnSlot(t.Context(), "s1", "Analyst")
			require.NoError(t, err)
			defer release()

			_, err = ac.AcquireTurnSlot(t.Context(), "s1", "Analyst")
			assert.ErrorIs(t, err, server.ErrToolTurnBusy)
		})
	})

	t.Run("unlimited agent and models pass the global cap", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ac := newExecPoolCoordinator(t, 1)

			for _, session := range []string{"s1", "s2", "s3"} {
				release, err := ac.AcquireTurnSlot(t.Context(), session, "Analyst")
				require.NoError(t, err)
				defer release()
			}

			release, err := ac.AcquireTurnSlot(t.Context(), "s4", "test-model")
			require.NoError(t, err)
			defer release()

			synctest.Wait()

			stats := ac.execPool.Stats()
			assert.Equal(t, 4, stats.Running)
			assert.Equal(t, execpool.KeyStats{Running: 3}, stats.Keys["Analyst"])
			assert.Equal(t, execpool.KeyStats{Running: 1}, stats.Keys["test-model@MyAdapter"])
		})
	})

	t.Run("pool shutdown frees held slots", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ac := newExecPoolCoordinator(t, 0)

			_, err := ac.AcquireTurnSlot(t.Context(), "s1", "Hunter")
			require.NoError(t, err)

			require.NoError(t, ac.Stop())
			synctest.Wait()

			assert.Zero(t, ac.execPool.Stats().Running)
		})
	})

	t.Run("no pool never refuses", func(t *testing.T) {
		release, err := (&AssistantCoordinator{}).AcquireTurnSlot(t.Context(), "s1", "Hunter")
		require.NoError(t, err)
		release()
	})
}

func TestExecPoolKey(t *testing.T) {
	ac := newExecPoolCoordinator(t, 0)

	assert.Equal(t, "Hunter", ac.execPoolKey("Hunter"))
	assert.Equal(t, "test-model@MyAdapter", ac.execPoolKey("test-model"))
	assert.Equal(t, "test-model@MyAdapter", ac.execPoolKey("test-model@MyAdapter"))
	assert.Equal(t, "unknown", ac.execPoolKey("unknown"))

	ac.isAgentic = false
	assert.Equal(t, "test-model@MyAdapter", ac.execPoolKey("test-model"))
}
