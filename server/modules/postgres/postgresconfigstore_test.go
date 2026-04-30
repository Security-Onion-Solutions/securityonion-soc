// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package postgres

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocateSetting_GlobalRegular(t *testing.T) {
	loc, err := locateSetting(&model.Setting{Id: "soc.ai.provider"})
	require.NoError(t, err)
	assert.Equal(t, "global", loc.scope)
	assert.Equal(t, "", loc.minionId)
	assert.Equal(t, "", loc.roleName)
	assert.Equal(t, "soc.soc_soc", loc.pillarPath)
	assert.False(t, loc.isAdvanced)
}

func TestLocateSetting_GlobalAdvanced(t *testing.T) {
	loc, err := locateSetting(&model.Setting{Id: "soc.advanced"})
	require.NoError(t, err)
	assert.Equal(t, "global", loc.scope)
	assert.Equal(t, "soc.adv_soc", loc.pillarPath)
	assert.True(t, loc.isAdvanced)
}

func TestLocateSetting_MinionRegular(t *testing.T) {
	loc, err := locateSetting(&model.Setting{
		Id:     "soc.ai.provider",
		NodeId: "host1_sensor",
	})
	require.NoError(t, err)
	assert.Equal(t, "minion", loc.scope)
	assert.Equal(t, "host1_sensor", loc.minionId)
	assert.Equal(t, "minions.host1_sensor", loc.pillarPath)
	assert.False(t, loc.isAdvanced)
}

func TestLocateSetting_MinionAdvanced(t *testing.T) {
	loc, err := locateSetting(&model.Setting{
		Id:     "advanced",
		NodeId: "host1_sensor",
	})
	require.NoError(t, err)
	assert.Equal(t, "minion", loc.scope)
	assert.Equal(t, "host1_sensor", loc.minionId)
	assert.Equal(t, "minions.adv_host1_sensor", loc.pillarPath)
	assert.True(t, loc.isAdvanced)
}

func TestLocateSetting_EmptyId(t *testing.T) {
	_, err := locateSetting(&model.Setting{Id: ""})
	assert.Error(t, err)
}

func TestFlatten_NestedMap(t *testing.T) {
	out := make(map[string]overlayValue)
	flatten(map[string]interface{}{
		"soc": map[string]interface{}{
			"ai": map[string]interface{}{
				"provider": "openai",
			},
		},
	}, "", "", out)

	v, ok := out["soc.ai.provider"]
	require.True(t, ok)
	assert.Equal(t, "openai", v.value)
	assert.Equal(t, "", v.minionId)
}

func TestFlatten_MinionScoped(t *testing.T) {
	out := make(map[string]overlayValue)
	flatten(map[string]interface{}{
		"host": map[string]interface{}{
			"mainip": "10.0.0.1",
		},
	}, "", "host1_sensor", out)

	v, ok := out["host.mainip@host1_sensor"]
	require.True(t, ok)
	assert.Equal(t, "10.0.0.1", v.value)
	assert.Equal(t, "host1_sensor", v.minionId)
}

func TestFlatten_ArrayValue(t *testing.T) {
	out := make(map[string]overlayValue)
	flatten(map[string]interface{}{
		"firewall": map[string]interface{}{
			"hosts": []interface{}{"a", "b", "c"},
		},
	}, "", "", out)

	v, ok := out["firewall.hosts"]
	require.True(t, ok)
	// Saltstore convention: arrays are joined with newlines for display.
	assert.Contains(t, v.value, "a")
	assert.Contains(t, v.value, "b")
	assert.Contains(t, v.value, "c")
}

func TestNewPostgresConfigstore_Constructor(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	store := NewPostgresConfigstore(srv, nil, nil)
	assert.NotNil(t, store)
	assert.Equal(t, srv, store.server)
}

func TestPostgresConfigstore_GetSettings_Unauthorized(t *testing.T) {
	srv := server.NewFakeUnauthorizedServer()
	store := NewPostgresConfigstore(srv, nil, nil)
	_, err := store.GetSettings(context.Background(), false)
	assert.Error(t, err) // RBAC failure before any DB access
}

func TestScopePredicate(t *testing.T) {
	assert.Equal(t, "role_name IS NULL AND minion_id IS NULL",
		scopePredicate(&pillarLocator{scope: "global"}))
	assert.Equal(t, "role_name = $5 AND minion_id IS NULL",
		scopePredicate(&pillarLocator{scope: "role"}))
	assert.Equal(t, "minion_id = $5",
		scopePredicate(&pillarLocator{scope: "minion"}))
	assert.Equal(t, "false",
		scopePredicate(&pillarLocator{scope: "bogus"}))
}

func TestConflictTarget(t *testing.T) {
	assert.Equal(t, "(pillar_path) WHERE scope='global'",
		conflictTarget(&pillarLocator{scope: "global"}))
	assert.Equal(t, "(role_name, pillar_path) WHERE scope='role'",
		conflictTarget(&pillarLocator{scope: "role"}))
	assert.Equal(t, "(minion_id, pillar_path) WHERE scope='minion'",
		conflictTarget(&pillarLocator{scope: "minion"}))
}

func TestNullable(t *testing.T) {
	assert.Nil(t, nullable(""))
	assert.Equal(t, "abc", nullable("abc"))
}

func TestOverlayKey(t *testing.T) {
	assert.Equal(t, "soc.ai.provider", overlayKey("soc.ai.provider", ""))
	assert.Equal(t, "host.ip@m1_sensor", overlayKey("host.ip", "m1_sensor"))
}
