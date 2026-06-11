// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
)

func TestDelegateTool_Name(t *testing.T) {
	// Legacy id@adapter selectors must keep producing byte-identical tool names.
	tool := NewDelegateTool("sonnet@SOAI", "Hunter", "desc")
	assert.Equal(t, "delegate_to_sonnet_at_SOAI", tool.GetName())

	// Canonical DisplayName selectors are sanitized to provider-valid tool names.
	tool = NewDelegateTool("Agent Gemini", "Agent Gemini", "desc")
	assert.Equal(t, "delegate_to_Agent_Gemini", tool.GetName())

	tool = NewDelegateTool("Hunter (v2.0)", "Hunter (v2.0)", "desc")
	assert.Equal(t, "delegate_to_Hunter__v2_0_", tool.GetName())

	// Long names are truncated so the full tool name stays within 64 chars.
	tool = NewDelegateTool(strings.Repeat("x", 100), "Long", "desc")
	name := tool.GetName()
	assert.Equal(t, "delegate_to_"+strings.Repeat("x", 52), name)
	assert.Len(t, name, 64)

	// A name exactly at the limit is not truncated.
	tool = NewDelegateTool(strings.Repeat("y", 52), "AtLimit", "desc")
	assert.Equal(t, "delegate_to_"+strings.Repeat("y", 52), tool.GetName())

	// An empty selector yields just the prefix (documents current behavior;
	// registration never produces this since Selector() is never empty).
	tool = NewDelegateTool("", "Empty", "desc")
	assert.Equal(t, "delegate_to_", tool.GetName())
}

func TestDelegateTool_KickoffCarriesDisplayNameSelector(t *testing.T) {
	tool := NewDelegateTool("Hunter", "Hunter", "an event hunting agent")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
	result, err := tool.Execute(ctx, &server.Server{}, &model.ToolRequest{
		Params: json.RawMessage(`{"objective":"o","context":"c","expected_output":"e"}`),
	})
	assert.NoError(t, err)

	kickoff, ok := result.Result.(model.DelegationKickoff)
	assert.True(t, ok)
	assert.Equal(t, "Hunter", kickoff.ChildModel)
	assert.Equal(t, "Hunter", kickoff.AgentName)
}

func TestDelegateTool_ExecuteReturnsKickoff(t *testing.T) {
	tool := NewDelegateTool("sonnet@SOAI", "Hunter", "an event hunting agent")

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")
	req := &model.ToolRequest{
		SessionId: "parent-1",
		ToolUseId: "tooluse-1",
		Params:    json.RawMessage(`{"objective":"find DNS beacons","context":"prior findings","expected_output":"a ranked list","constraints":"none"}`),
		Model:     "AgentClaude@SOAI",
	}

	// Execute must NOT contact the LLM; it only returns a kickoff marker.
	result, err := tool.Execute(ctx, &server.Server{}, req)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, tool.GetName(), result.ToolName)
	assert.Equal(t, "test-user", result.OnBehalfOfUser)

	kickoff, ok := result.Result.(model.DelegationKickoff)
	assert.True(t, ok, "result should carry a DelegationKickoff marker")
	assert.NotEmpty(t, kickoff.ChildSessionId)
	assert.Equal(t, "sonnet@SOAI", kickoff.ChildModel)
	assert.Equal(t, "Hunter", kickoff.AgentName)
	assert.Contains(t, kickoff.Objective, "find DNS beacons")
	assert.Contains(t, kickoff.Objective, "prior findings")
	assert.Contains(t, kickoff.Objective, "a ranked list")
}

func TestDelegateTool_ExecuteBadParams(t *testing.T) {
	tool := NewDelegateTool("sonnet@SOAI", "Hunter", "desc")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	_, err := tool.Execute(ctx, &server.Server{}, &model.ToolRequest{
		Params: json.RawMessage(`{bad json`),
	})
	assert.Error(t, err)
}
