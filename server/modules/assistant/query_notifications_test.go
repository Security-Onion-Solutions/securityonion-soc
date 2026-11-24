// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/module"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestQueryNotificationsTool_GetName(t *testing.T) {
	assert.Equal(t, "query_notifications", (&QueryNotificationsTool{}).GetName())
	assert.Contains(t, knownTools, "query_notifications")
}

func TestQueryNotificationsTool_GetDescription(t *testing.T) {
	assert.NotEmpty(t, (&QueryNotificationsTool{}).GetDescription())
}

func TestQueryNotificationsTool_GetSchema(t *testing.T) {
	schema := (&QueryNotificationsTool{}).GetSchema()

	require.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Len(t, schema.Json.Properties, 2)
	assert.Equal(t, "string", schema.Json.Properties["filter"].Type)
	assert.Equal(t, "integer", schema.Json.Properties["limit"].Type)
	assert.Empty(t, schema.Json.Required)

	for _, filter := range []string{"active", model.NotificationFilterUnread, model.NotificationFilterDismissed, model.NotificationFilterAll} {
		assert.Contains(t, schema.Json.Properties["filter"].Description, filter)
	}

	assert.Equal(t, 10, schema.Json.Properties["limit"].Default)
	assert.Contains(t, schema.Json.Properties["limit"].Description, "at most 50.")

	configured := newQueryNotificationsTool(map[string]any{"defaultLimit": float64(3), "maxLimit": float64(5)}).GetSchema()
	assert.Equal(t, 3, configured.Json.Properties["limit"].Default)
	assert.Contains(t, configured.Json.Properties["limit"].Description, "at most 5.")
}

func TestNewQueryNotificationsTool_Settings(t *testing.T) {
	defaults := &queryNotificationsLimits{defaultLimit: 10, maxLimit: 50, summaryLength: 1000, valueLength: 200, maxEntries: 25}

	testCases := []struct {
		name     string
		cfg      map[string]any
		expected *queryNotificationsLimits
	}{
		{"nil", nil, defaults},
		{"empty", map[string]any{}, defaults},
		{
			"all set",
			map[string]any{"defaultLimit": float64(20), "maxLimit": float64(100), "summaryMaxLength": float64(2000), "fieldValueMaxLength": float64(300), "maxEntries": float64(40)},
			&queryNotificationsLimits{defaultLimit: 20, maxLimit: 100, summaryLength: 2000, valueLength: 300, maxEntries: 40},
		},
		{
			"below 1 uses the default",
			map[string]any{"defaultLimit": float64(0), "maxLimit": float64(-1), "summaryMaxLength": float64(0), "fieldValueMaxLength": float64(-5), "maxEntries": float64(0)},
			defaults,
		},
		{
			"default above max is capped",
			map[string]any{"defaultLimit": float64(80), "maxLimit": float64(30)},
			&queryNotificationsLimits{defaultLimit: 30, maxLimit: 30, summaryLength: 1000, valueLength: 200, maxEntries: 25},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, newQueryNotificationsTool(tc.cfg).limits)
		})
	}

	assert.Equal(t, defaults, (&QueryNotificationsTool{}).getLimits())
}

func TestAssistantCoordinator_InitQueryNotificationsSettings(t *testing.T) {
	stubEmbeddedSystemPrompt(t)
	ac, _ := newAgenticTestCoordinator()

	require.NoError(t, ac.Init(module.ModuleConfig{
		"tools": map[string]any{"queryNotifications": map[string]any{"maxLimit": float64(20)}},
	}))

	tool, ok := ac.FunctionLibrary["query_notifications"].(*QueryNotificationsTool)
	require.True(t, ok)
	assert.Equal(t, 20, tool.getLimits().maxLimit)
	assert.Equal(t, 10, tool.getLimits().defaultLimit)
	assert.Same(t, knownTools["send_notification"], ac.FunctionLibrary["send_notification"])
	// The shared registry keeps its unconfigured instance.
	assert.Nil(t, knownTools["query_notifications"].(*QueryNotificationsTool).limits)
}

func TestQueryNotificationsTool_Execute_ConfiguredLimits(t *testing.T) {
	tool := newQueryNotificationsTool(map[string]any{
		"defaultLimit":        float64(3),
		"maxLimit":            float64(5),
		"summaryMaxLength":    float64(4),
		"fieldValueMaxLength": float64(2),
		"maxEntries":          float64(2),
	})

	runQueryNotificationsWith(t, tool, `{}`, "", 3, nil)
	res := runQueryNotificationsWith(t, tool, `{"limit": 6}`, "", 5, nil)
	assert.Contains(t, res.Note, "6 is above the maximum, so 5 was used")

	record := &model.NotificationRecord{
		ID:          "n1",
		Summary:     "abcdef",
		Fields:      map[string]string{"a": "xyz", "b": "ok", "c": "dropped"},
		Links:       map[string]string{"a": "/#/one", "b": "/#/two", "c": "/#/three"},
		Attachments: []model.Attachment{{Filename: "1.pdf"}, {Filename: "2.pdf"}, {Filename: "3.pdf"}},
	}
	res = runQueryNotificationsWith(t, tool, `{}`, "", 3, &model.NotificationListResponse{Notifications: []*model.NotificationRecord{record}, Count: 1})
	require.Len(t, res.Notifications, 1)

	entry := res.Notifications[0]
	assert.Equal(t, "abcd…", entry.Summary)
	assert.Equal(t, map[string]string{"a": "xy…", "b": "ok"}, entry.Fields)
	assert.Equal(t, 1, entry.FieldsOmitted)
	assert.Equal(t, map[string]string{"a": "/#/one", "b": "/#/two"}, entry.Links)
	assert.Equal(t, 1, entry.LinksOmitted)
	assert.Equal(t, []string{"1.pdf", "2.pdf"}, entry.Attachments)
	assert.Equal(t, 1, entry.AttachmentsOmitted)
}

func newQueryNotificationsServer(authorized bool, store server.Notificationstore) *server.Server {
	srv := &server.Server{
		Config: &config.ServerConfig{
			DeveloperEnabled: authorized,
		},
	}
	if store != nil {
		srv.Notificationstore = store
	}
	return srv
}

func queryNotificationsContext() context.Context {
	return context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")
}

func TestQueryNotificationsTool_Execute_Failures(t *testing.T) {
	testCases := []struct {
		name          string
		params        string
		unauthorized  bool
		unlicensed    bool
		nilStore      bool
		expectedError string
	}{
		{
			name:          "no permission",
			params:        `{}`,
			unauthorized:  true,
			expectedError: "ERROR_PERMISSION_DENIED",
		},
		{
			name:          "unlicensed",
			params:        `{}`,
			unlicensed:    true,
			expectedError: "ERROR_ASSISTANT_NOTIFICATIONS_UNLICENSED",
		},
		{
			name:          "nil store",
			params:        `{}`,
			nilStore:      true,
			expectedError: "ERROR_ASSISTANT_NOTIFIER_UNAVAILABLE",
		},
		{
			name:          "malformed params",
			params:        `{bad`,
			expectedError: "ERROR_ASSISTANT_UNMARSHAL_PARAMS",
		},
		{
			name:          "wrong limit type",
			params:        `{"limit": "ten"}`,
			expectedError: "ERROR_ASSISTANT_UNMARSHAL_PARAMS",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer licensing.Shutdown()
			if !tc.unlicensed {
				licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")
			}

			// No expectations: any store call fails the test.
			var store server.Notificationstore
			if !tc.nilStore {
				store = servermock.NewMockNotificationstore(gomock.NewController(t))
			}

			tool := &QueryNotificationsTool{}
			result, err := tool.Execute(queryNotificationsContext(), newQueryNotificationsServer(!tc.unauthorized, store), &model.ToolRequest{Params: json.RawMessage(tc.params)})

			assert.EqualError(t, err, tc.expectedError)
			assert.Nil(t, result)
		})
	}
}

func TestQueryNotificationsTool_Execute_StoreError(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	store := servermock.NewMockNotificationstore(gomock.NewController(t))
	store.EXPECT().GetNotifications(gomock.Any(), "", DEFAULT_QUERY_NOTIFICATIONS_LIMIT).Return(nil, errors.New("dial tcp db.internal:5432: connection refused"))

	tool := &QueryNotificationsTool{}
	result, err := tool.Execute(queryNotificationsContext(), newQueryNotificationsServer(true, store), &model.ToolRequest{Params: json.RawMessage(`{}`)})

	assert.EqualError(t, err, "ERROR_NOTIFICATION_QUERY_FAILED")
	assert.Nil(t, result)
}

func runQueryNotifications(t *testing.T, params string, expectedFilter string, expectedLimit int, list *model.NotificationListResponse) *queryNotificationsResult {
	return runQueryNotificationsWith(t, &QueryNotificationsTool{}, params, expectedFilter, expectedLimit, list)
}

func runQueryNotificationsWith(t *testing.T, tool *QueryNotificationsTool, params string, expectedFilter string, expectedLimit int, list *model.NotificationListResponse) *queryNotificationsResult {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	if list == nil {
		list = &model.NotificationListResponse{Notifications: []*model.NotificationRecord{}}
	}

	store := servermock.NewMockNotificationstore(gomock.NewController(t))
	store.EXPECT().GetNotifications(gomock.Any(), expectedFilter, expectedLimit).Return(list, nil)

	result, err := tool.Execute(queryNotificationsContext(), newQueryNotificationsServer(true, store), &model.ToolRequest{Params: json.RawMessage(params)})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "query_notifications", result.ToolName)
	assert.Equal(t, "test-user-id", result.OnBehalfOfUser)

	res, ok := result.Result.(*queryNotificationsResult)
	require.True(t, ok)
	return res
}

func TestQueryNotificationsTool_Execute_Inputs(t *testing.T) {
	testCases := []struct {
		name           string
		params         string
		expectedFilter string
		expectedLimit  int
		noteContains   string
	}{
		{"empty object", `{}`, "", 10, ""},
		{"null", `null`, "", 10, ""},
		{"active", `{"filter": "active"}`, "", 10, ""},
		{"empty filter", `{"filter": ""}`, "", 10, ""},
		{"unread", `{"filter": "unread"}`, model.NotificationFilterUnread, 10, ""},
		{"dismissed", `{"filter": "dismissed"}`, model.NotificationFilterDismissed, 10, ""},
		{"all", `{"filter": "all"}`, model.NotificationFilterAll, 10, ""},
		{"capitalized", `{"filter": "Unread"}`, model.NotificationFilterUnread, 10, ""},
		{"padded", `{"filter": " unread "}`, model.NotificationFilterUnread, 10, ""},
		{"unknown filter", `{"filter": "starred"}`, "", 10, `"starred" was not recognized`},
		{"zero limit", `{"limit": 0}`, "", 10, ""},
		{"negative limit", `{"limit": -5}`, "", 10, ""},
		{"limit 1", `{"limit": 1}`, "", 1, ""},
		{"limit 50", `{"limit": 50}`, "", 50, ""},
		{"limit 51", `{"limit": 51}`, "", 50, "51 is above the maximum"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := runQueryNotifications(t, tc.params, tc.expectedFilter, tc.expectedLimit, nil)
			if tc.noteContains == "" {
				assert.Empty(t, res.Note)
			} else {
				assert.Contains(t, res.Note, tc.noteContains)
			}
		})
	}
}

func TestQueryNotificationsTool_Execute_EmptyInbox(t *testing.T) {
	res := runQueryNotifications(t, `{}`, "", 10, nil)

	raw, err := json.Marshal(res)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"notifications":[]`)
	assert.Contains(t, string(raw), `"count":0`)
	assert.NotContains(t, string(raw), `"note"`)
}

func TestQueryNotificationsTool_Execute_Shaping(t *testing.T) {
	created := time.Date(2026, 11, 17, 1, 12, 44, 0, time.FixedZone("EST", -5*3600))
	readAt := created.Add(time.Hour)

	manyFields := map[string]string{}
	for i := 0; i < 199; i++ {
		manyFields[fmt.Sprintf("f%03d", i)] = "v"
	}
	longKey := "a" + strings.Repeat("k", 999)
	manyFields[longKey] = "v"

	records := []*model.NotificationRecord{
		{
			ID:          "n1",
			Source:      model.SourceDetection,
			Title:       "ET SCAN Potential SSH Scan",
			Summary:     strings.Repeat("é", 1000),
			Severity:    model.NotificationSeverityHigh,
			Fields:      map[string]string{"exact": strings.Repeat("ü", 200), "long": strings.Repeat("x", 10000)},
			Links:       map[string]string{"View": "/#/alerts?q=" + strings.Repeat("y", 300)},
			Attachments: []model.Attachment{{Filename: "alert-report.pdf", ContentType: "application/pdf", Data: []byte("binary")}},
			SilenceKey:  "detection:secret",
			CreatedAt:   created,
			Recipients:  []string{"user-a"},
			IsRead:      true,
			ReadAt:      &readAt,
			IsDismissed: false,
			Audience:    model.NotificationAudienceYou,
		},
		{
			ID:        "n2",
			Summary:   strings.Repeat("é", 1001),
			Fields:    manyFields,
			CreatedAt: created,
			Audience:  model.NotificationAudienceEveryone,
		},
		{
			ID:         "n3",
			CreatedAt:  created,
			Recipients: []string{"other-user"},
			Audience:   model.NotificationAudienceOthers,
		},
	}

	res := runQueryNotifications(t, `{}`, "", 10, &model.NotificationListResponse{Notifications: records, Count: 3, Truncated: true})

	now, err := time.Parse(time.RFC3339, res.Now)
	require.NoError(t, err)
	assert.Equal(t, time.UTC, now.Location())
	assert.True(t, strings.HasSuffix(res.Now, "Z"))
	assert.Equal(t, 3, res.Count)
	assert.True(t, res.Truncated)
	require.Len(t, res.Notifications, 3)

	first := res.Notifications[0]
	assert.Equal(t, "2026-11-17T06:12:44Z", first.Created)
	assert.Equal(t, strings.Repeat("é", 1000), first.Summary)
	assert.Equal(t, strings.Repeat("ü", 200), first.Fields["exact"])
	assert.Equal(t, strings.Repeat("x", 200)+"…", first.Fields["long"])
	assert.Equal(t, "/#/alerts?q="+strings.Repeat("y", 300), first.Links["View"])
	assert.Equal(t, []string{"alert-report.pdf"}, first.Attachments)
	assert.True(t, first.Read)
	assert.False(t, first.Dismissed)
	assert.Equal(t, model.NotificationAudienceYou, first.To)

	second := res.Notifications[1]
	assert.Equal(t, strings.Repeat("é", 1000)+"…", second.Summary)
	assert.Len(t, second.Fields, 25)
	assert.Equal(t, 175, second.FieldsOmitted)
	assert.Equal(t, "v", second.Fields["a"+strings.Repeat("k", 99)+"…"])
	assert.Equal(t, model.NotificationAudienceEveryone, second.To)

	assert.Equal(t, model.NotificationAudienceOthers, res.Notifications[2].To)

	raw, err := json.Marshal(res)
	require.NoError(t, err)
	for _, absent := range []string{"recipients", "user-a", "other-user", "silenceKey", "detection:secret", "readAt", "dismissedAt", "binary", "YmluYXJ5", "audience"} {
		assert.NotContains(t, string(raw), absent)
	}
}
