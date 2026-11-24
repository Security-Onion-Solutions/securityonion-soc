// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toolConfigFor is the tool config an adapter receives when the tool is offered.
func toolConfigFor(tool Tool) json.RawMessage {
	return mustMarshal(model.ToolConfig{
		Tools: []*model.ToolSpec{{Spec: model.ToolDefinition{
			Name:        tool.GetName(),
			Description: tool.GetDescription(),
			InputSchema: tool.GetSchema(),
		}}},
	})
}

func TestListDestinationsTool_Registration(t *testing.T) {
	tool := &ListDestinationsTool{}
	assert.Equal(t, "list_destinations", tool.GetName())
	assert.Contains(t, knownTools, "list_destinations")
	assert.NotEmpty(t, tool.GetDescription())

	schema := tool.GetSchema()
	require.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.NotNil(t, schema.Json.Properties)
	assert.Empty(t, schema.Json.Properties)
	assert.Empty(t, schema.Json.Required)
}

func runListDestinations(t *testing.T, ctx context.Context, authorized bool, licensed bool, notifier server.Notifier) (*model.ToolResponse, error) {
	defer licensing.Shutdown()
	if licensed {
		licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")
	}
	srv := &server.Server{
		Config:   &config.ServerConfig{DeveloperEnabled: authorized},
		Notifier: notifier,
	}
	return (&ListDestinationsTool{}).Execute(ctx, srv, &model.ToolRequest{Params: json.RawMessage(`{}`)})
}

func TestListDestinationsTool_Failures(t *testing.T) {
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

	_, err := runListDestinations(t, ctx, false, true, server.NewFakeNotifier())
	assert.EqualError(t, err, "ERROR_PERMISSION_DENIED")

	_, err = runListDestinations(t, ctx, true, false, server.NewFakeNotifier())
	assert.EqualError(t, err, "ERROR_ASSISTANT_NOTIFICATIONS_UNLICENSED")

	_, err = runListDestinations(t, ctx, true, true, nil)
	assert.EqualError(t, err, "ERROR_ASSISTANT_NOTIFIER_UNAVAILABLE")
}

// permissionAuthorizer grants only the listed operation/target pairs.
type permissionAuthorizer map[string]bool

func (a permissionAuthorizer) CheckContextOperationAuthorized(ctx context.Context, operation string, target string) error {
	if a[target+"/"+operation] {
		return nil
	}
	return model.NewUnauthorized("test-user-id", operation, target)
}

func (a permissionAuthorizer) CheckUserOperationAuthorized(userId string, operation string, target string) error {
	return a.CheckContextOperationAuthorized(context.Background(), operation, target)
}

func TestListDestinationsTool_RequiresConfigRead(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")
	tool := &ListDestinationsTool{}
	req := &model.ToolRequest{Params: json.RawMessage(`{}`)}

	sender := &server.Server{Authorizer: permissionAuthorizer{"notifications/write": true}, Notifier: server.NewFakeNotifier()}
	_, err := tool.Execute(ctx, sender, req)
	assert.EqualError(t, err, "ERROR_PERMISSION_DENIED")

	admin := &server.Server{Authorizer: permissionAuthorizer{"config/read": true}, Notifier: server.NewFakeNotifier()}
	_, err = tool.Execute(ctx, admin, req)
	assert.NoError(t, err)
}

func TestListDestinationsTool_Result(t *testing.T) {
	notifier := server.NewFakeNotifier()
	notifier.Destinations = map[string]model.DestinationConfig{
		"soc-bell": {Type: "soc", Enabled: true},
		"mail": {ID: "mail", Name: "Mail", Type: "smtp", Enabled: true, Severities: []string{"high", "critical"},
			Params: map[string]any{"host": "smtp.example.com", "password": "smtp-secret"}},
		"ir-slack": {Name: "IR Slack", Type: "slack_webhook", Enabled: false, ScheduleIDs: []string{"after-hours"},
			Params: map[string]any{"webhookUrl": "https://hooks.slack.com/services/SLACKSECRET"}},
		"hook": {Name: "Hook", Type: "generic_webhook", Enabled: true,
			Params: map[string]any{"webhookUrl": "https://example.com/hook", "headers": map[string]any{"Authorization": "Bearer HEADERSECRET"}}},
		"matrix": {Name: "Matrix", Type: "matrix_hookshot_webhook", Enabled: true,
			Params: map[string]any{"webhookUrl": "https://matrix.example.com/_matrix/hookshot/MATRIXSECRET"}},
	}

	// Automated runs act as SYSTEM_ID; the tool works there too.
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, server.SYSTEM_ID)
	resp, err := runListDestinations(t, ctx, true, true, notifier)
	require.NoError(t, err)

	raw, err := json.Marshal(resp.Result)
	require.NoError(t, err)
	for _, secret := range []string{"smtp-secret", "SLACKSECRET", "HEADERSECRET", "MATRIXSECRET", "smtp.example.com", "params"} {
		assert.NotContains(t, string(raw), secret)
	}

	var decoded struct {
		Destinations []map[string]any `json:"destinations"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))

	ids := []string{}
	for _, dest := range decoded.Destinations {
		ids = append(ids, dest["id"].(string))
		keys := []string{}
		for key := range dest {
			keys = append(keys, key)
		}
		assert.ElementsMatch(t, []string{"id", "name", "type", "enabled", "severities", "scheduleIds"}, keys)
		assert.NotNil(t, dest["severities"])
		assert.NotNil(t, dest["scheduleIds"])
	}
	assert.Equal(t, []string{"hook", "ir-slack", "mail", "matrix", "soc-bell"}, ids)

	irSlack := decoded.Destinations[1]
	assert.Equal(t, false, irSlack["enabled"])
	assert.Equal(t, []any{"after-hours"}, irSlack["scheduleIds"])
	assert.Equal(t, []any{}, irSlack["severities"])
	assert.Equal(t, []any{"high", "critical"}, decoded.Destinations[2]["severities"])
}

func TestListDestinationsTool_EmptyMap(t *testing.T) {
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")
	resp, err := runListDestinations(t, ctx, true, true, server.NewFakeNotifier())
	require.NoError(t, err)

	raw, err := json.Marshal(resp.Result)
	require.NoError(t, err)
	assert.JSONEq(t, `{"destinations": []}`, string(raw))
}
