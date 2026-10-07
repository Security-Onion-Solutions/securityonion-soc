// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestSendNotificationTool_GetName(t *testing.T) {
	tool := &SendNotificationTool{}
	assert.Equal(t, "send_notification", tool.GetName())

	// The init() registration is what puts the tool in the catalog; buildToolConfig
	// silently drops names it can't find, so losing it wouldn't fail anywhere else.
	assert.Contains(t, knownTools, "send_notification")
}

func TestSendNotificationTool_GetDescription(t *testing.T) {
	assert.NotEmpty(t, (&SendNotificationTool{}).GetDescription())
}

func TestSendNotificationTool_GetSchema(t *testing.T) {
	schema := (&SendNotificationTool{}).GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Equal(t, "string", schema.Json.Properties["title"].Type)
	assert.Equal(t, "string", schema.Json.Properties["summary"].Type)
	assert.Equal(t, "string", schema.Json.Properties["severity"].Type)
	assert.Equal(t, "object", schema.Json.Properties["fields"].Type)
	assert.Equal(t, "object", schema.Json.Properties["links"].Type)

	assert.Equal(t, "string", schema.Json.Properties["approvalMessage"].Type)
	assert.Equal(t, "boolean", schema.Json.Properties["share_chat"].Type)
	assert.Equal(t, false, schema.Json.Properties["share_chat"].Default)

	assert.ElementsMatch(t, []string{"title", "summary"}, schema.Json.Required)
	assert.Equal(t, model.NotificationSeverityInfo, schema.Json.Properties["severity"].Default)

	// ToolSchemaProperty has no enum field, so the description is the only thing keeping
	// the advertised values in sync with the model constants.
	severities := []string{
		model.NotificationSeverityInfo,
		model.NotificationSeverityLow,
		model.NotificationSeverityMedium,
		model.NotificationSeverityHigh,
		model.NotificationSeverityCritical,
	}
	for _, severity := range severities {
		assert.Contains(t, schema.Json.Properties["severity"].Description, severity)
	}
}

func TestSendNotificationTool_Execute(t *testing.T) {
	testCases := []struct {
		name             string
		params           string
		unauthorized     bool
		unlicensed       bool
		nilNotifier      bool
		sendErr          error
		expectedError    string
		expectedSeverity string
		expectedFields   map[string]string
		expectedLinks    map[string]string
		resultContains   []string
	}{
		{
			name:             "minimal notification",
			params:           `{"title": "SSH scan", "summary": "Inbound SSH scan from 10.0.0.5."}`,
			expectedSeverity: model.NotificationSeverityInfo,
			resultContains:   []string{"SSH scan", "submitted"},
		},
		{
			name:   "mixed value types are coerced",
			params: `{"title": "T", "summary": "S", "fields": {"count": 5, "host": "ws1", "confirmed": true, "ctx": {"a": 1}, "skipped": null}, "links": {"View alert": "/#/alerts?q=_id:abc"}}`,
			expectedFields: map[string]string{
				"count":     "5",
				"host":      "ws1",
				"confirmed": "true",
				"ctx":       `{"a":1}`,
			},
			expectedLinks:    map[string]string{"View alert": "/#/alerts?q=_id:abc"},
			expectedSeverity: model.NotificationSeverityInfo,
		},
		{
			name:             "large numbers avoid exponent notation",
			params:           `{"title": "T", "summary": "S", "fields": {"events": 1000000}}`,
			expectedFields:   map[string]string{"events": "1000000"},
			expectedSeverity: model.NotificationSeverityInfo,
		},
		{
			name:             "severity is trimmed and lowercased",
			params:           `{"title": "T", "summary": "S", "severity": "  HIGH "}`,
			expectedSeverity: model.NotificationSeverityHigh,
		},
		{
			name:             "unrecognized severity falls back with a note",
			params:           `{"title": "T", "summary": "S", "severity": "warning"}`,
			expectedSeverity: model.NotificationSeverityInfo,
			resultContains:   []string{"warning", "not recognized"},
		},
		{
			name:          "whitespace title is rejected",
			params:        `{"title": "   ", "summary": "S"}`,
			expectedError: "ERROR_ASSISTANT_NOTIFICATION_TITLE_REQUIRED",
		},
		{
			name:          "missing summary is rejected",
			params:        `{"title": "T"}`,
			expectedError: "ERROR_ASSISTANT_NOTIFICATION_SUMMARY_REQUIRED",
		},
		{
			name:          "malformed JSON parameters",
			params:        `{"title": "missing closing brace"`,
			expectedError: "ERROR_ASSISTANT_UNMARSHAL_PARAMS",
		},
		{
			name:          "unauthorized user",
			params:        `{"title": "T", "summary": "S"}`,
			unauthorized:  true,
			expectedError: "ERROR_PERMISSION_DENIED",
		},
		{
			name:          "unlicensed grid",
			params:        `{"title": "T", "summary": "S"}`,
			unlicensed:    true,
			expectedError: "ERROR_ASSISTANT_NOTIFICATIONS_UNLICENSED",
		},
		{
			name:          "notifier unavailable",
			params:        `{"title": "T", "summary": "S"}`,
			nilNotifier:   true,
			expectedError: "ERROR_ASSISTANT_NOTIFIER_UNAVAILABLE",
		},
		{
			name:          "notifier error is surfaced",
			params:        `{"title": "T", "summary": "S"}`,
			sendErr:       assert.AnError,
			expectedError: assert.AnError.Error(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer licensing.Shutdown()
			if !tc.unlicensed {
				licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")
			}

			fakeNotifier := server.NewFakeNotifier()
			fakeNotifier.Err = tc.sendErr

			mockServer := &server.Server{
				Config: &config.ServerConfig{
					DeveloperEnabled: !tc.unauthorized,
				},
			}
			if !tc.nilNotifier {
				mockServer.Notifier = fakeNotifier
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			tool := &SendNotificationTool{}
			result, err := tool.Execute(ctx, mockServer, &model.ToolRequest{Params: json.RawMessage(tc.params)})

			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
				if tc.sendErr == nil {
					assert.Empty(t, fakeNotifier.InputPayloads)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "send_notification", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.NotZero(t, result.TimeToExecute)

			args, ok := result.Parameters.(*sendNotificationArgs)
			assert.True(t, ok)
			assert.NotNil(t, args)

			assert.Len(t, fakeNotifier.InputPayloads, 1)
			payload := fakeNotifier.InputPayloads[0]
			assert.Equal(t, model.SourceAgentAI, payload.Source)
			assert.Equal(t, tc.expectedSeverity, payload.Severity)
			assert.NotEmpty(t, payload.ID)
			assert.False(t, payload.Timestamp.IsZero())
			assert.Equal(t, tc.expectedFields, payload.Fields)
			assert.Equal(t, tc.expectedLinks, payload.Links)

			// No destinations are passed, so the notifier resolves its configured defaults.
			assert.Empty(t, fakeNotifier.InputDestinations[0])

			for _, expected := range tc.resultContains {
				assert.Contains(t, result.Result, expected)
			}
		})
	}
}

func TestSendNotificationTool_Execute_TrimsAndPropagatesContext(t *testing.T) {
	defer licensing.Shutdown()
	licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

	fakeNotifier := server.NewFakeNotifier()
	mockServer := &server.Server{
		Notifier: fakeNotifier,
		Config:   &config.ServerConfig{DeveloperEnabled: true},
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	tool := &SendNotificationTool{}
	params := `{"title": "  Beaconing detected  ", "summary": "  ws1 contacted evil.example every 60s.  "}`
	_, err := tool.Execute(ctx, mockServer, &model.ToolRequest{Params: json.RawMessage(params)})

	assert.NoError(t, err)
	assert.Len(t, fakeNotifier.InputPayloads, 1)
	assert.Equal(t, "Beaconing detected", fakeNotifier.InputPayloads[0].Title)
	assert.Equal(t, "ws1 contacted evil.example every 60s.", fakeNotifier.InputPayloads[0].Summary)

	assert.Len(t, fakeNotifier.InputContexts, 1)
	assert.Equal(t, "test-user-123", fakeNotifier.InputContexts[0].Value(web.ContextKeyRequestorId))
}

// sessionTreeStore serves GetSessions from sessions keyed by id, honoring the
// descendants option the way the elastic store does: root first, then sub-sessions.
func sessionTreeStore(ctrl *gomock.Controller, sessions []*model.AssistantSession, getErr error) *servermock.MockAssistantstore {
	store := servermock.NewMockAssistantstore(ctrl)
	store.EXPECT().GetSessions(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, opts ...model.GetSessionsOpt) ([]*model.AssistantSession, error) {
			if getErr != nil {
				return nil, getErr
			}

			o := &model.GetSessionsOpts{}
			for _, opt := range opts {
				opt(o)
			}

			var out []*model.AssistantSession
			for _, id := range o.SessionIds() {
				for _, s := range sessions {
					if s.SessionId == id {
						out = append(out, s)
					}
				}
			}
			if o.Descendants() {
				for i := 0; i < len(out); i++ {
					for _, s := range sessions {
						if s.ParentSessionId == out[i].SessionId {
							out = append(out, s)
						}
					}
				}
			}

			return out, nil
		}).AnyTimes()

	return store
}

func TestSendNotificationTool_Execute_SharesAndLinksChat(t *testing.T) {
	tree := func(rootTags ...string) []*model.AssistantSession {
		return []*model.AssistantSession{
			{SessionId: "root", Tags: rootTags},
			{SessionId: "child", ParentSessionId: "root", Tags: rootTags},
			{SessionId: "grand", ParentSessionId: "child", Tags: rootTags},
		}
	}
	triageTree := []*model.AssistantSession{
		{SessionId: "root", Type: alertTriageKindName, EntityId: "abc-123"},
		{SessionId: "child", ParentSessionId: "root"},
	}
	alertLink := map[string]string{alertLinkLabel: triageAlertLink("abc-123")}

	testCases := []struct {
		name          string
		sessionId     string
		params        string
		sessions      []*model.AssistantSession
		getErr        error
		toggleErr     error
		expectToggle  []string
		expectedLinks map[string]string
		sharedNote    bool
	}{
		{
			name:          "top-level chat is shared with its sub-sessions and linked",
			sessionId:     "root",
			params:        `{"title": "T", "summary": "S", "share_chat": true}`,
			sessions:      tree(),
			expectToggle:  []string{"root", "child", "grand"},
			expectedLinks: map[string]string{chatLinkLabel: "/#/assistant/root"},
			sharedNote:    true,
		},
		{
			name:          "sub-agent session resolves to its top-level chat",
			sessionId:     "grand",
			params:        `{"title": "T", "summary": "S", "share_chat": true}`,
			sessions:      tree(),
			expectToggle:  []string{"root", "child", "grand"},
			expectedLinks: map[string]string{chatLinkLabel: "/#/assistant/root"},
			sharedNote:    true,
		},
		{
			name:          "already shared chat is not re-tagged",
			sessionId:     "child",
			params:        `{"title": "T", "summary": "S", "share_chat": true}`,
			sessions:      tree(model.SessionTagShared),
			expectedLinks: map[string]string{chatLinkLabel: "/#/assistant/root"},
		},
		{
			name:         "model cannot replace the chat link but keeps its own",
			sessionId:    "root",
			params:       `{"title": "T", "summary": "S", "share_chat": true, "links": {"💬": "https://evil.example", "View alert": "/#/alerts?q=_id:abc"}}`,
			sessions:     tree(),
			expectToggle: []string{"root", "child", "grand"},
			expectedLinks: map[string]string{
				chatLinkLabel: "/#/assistant/root",
				"View alert":  "/#/alerts?q=_id:abc",
			},
			sharedNote: true,
		},
		{
			name:          "share failure still sends the notification",
			sessionId:     "root",
			params:        `{"title": "T", "summary": "S", "share_chat": true}`,
			sessions:      tree(),
			toggleErr:     assert.AnError,
			expectToggle:  []string{"root", "child", "grand"},
			expectedLinks: map[string]string{chatLinkLabel: "/#/assistant/root"},
		},
		{
			name:          "lookup failure falls back to the given session",
			sessionId:     "child",
			params:        `{"title": "T", "summary": "S", "share_chat": true}`,
			getErr:        assert.AnError,
			expectedLinks: map[string]string{chatLinkLabel: "/#/assistant/child"},
		},
		{
			name:      "chat stays private and unlinked unless share_chat is set",
			sessionId: "root",
			params:    `{"title": "T", "summary": "S", "links": {"View alert": "/#/alerts?q=_id:abc"}}`,
			sessions:  tree(),
			expectedLinks: map[string]string{
				"View alert": "/#/alerts?q=_id:abc",
			},
		},
		{
			name:          "alert triage links the alert instead of the chat",
			sessionId:     "root",
			params:        `{"title": "T", "summary": "S"}`,
			sessions:      triageTree,
			expectedLinks: alertLink,
		},
		{
			name:          "alert triage still shares the chat when asked",
			sessionId:     "child",
			params:        `{"title": "T", "summary": "S", "share_chat": true}`,
			sessions:      triageTree,
			expectToggle:  []string{"root", "child"},
			expectedLinks: alertLink,
			sharedNote:    true,
		},
		{
			name:          "model cannot replace the alert link",
			sessionId:     "root",
			params:        `{"title": "T", "summary": "S", "links": {"🔔": "https://evil.example"}}`,
			sessions:      triageTree,
			expectedLinks: alertLink,
		},
		{
			name:      "alert triage drops model links to the same alert but keeps others",
			sessionId: "root",
			params:    `{"title": "T", "summary": "S", "links": {"View alert": "/#/alerts?q=_id:abc-123", "Encoded": "/#/hunt?q=_id%3A%22abc-123%22", "Rule": "/#/detections?q=rule"}}`,
			sessions:  triageTree,
			expectedLinks: map[string]string{
				alertLinkLabel: alertLink[alertLinkLabel],
				"Rule":         "/#/detections?q=rule",
			},
		},
		{
			name:   "no session means no share and no link",
			params: `{"title": "T", "summary": "S", "share_chat": true}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer licensing.Shutdown()
			licensing.Test(licensing.FEAT_NTF, 0, 0, "", "")

			ctrl := gomock.NewController(t)
			fakeNotifier := server.NewFakeNotifier()
			mockServer := &server.Server{
				Notifier: fakeNotifier,
				Config:   &config.ServerConfig{DeveloperEnabled: true},
			}

			if tc.sessionId != "" {
				store := sessionTreeStore(ctrl, tc.sessions, tc.getErr)
				if tc.expectToggle != nil {
					store.EXPECT().ToggleSessionsTag(gomock.Any(), tc.expectToggle, model.SessionTagShared, true).Return(tc.toggleErr)
				}
				mockServer.Assistantstore = store
			} else {
				mockServer.Assistantstore = servermock.NewMockAssistantstore(ctrl)
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			tool := &SendNotificationTool{}
			result, err := tool.Execute(ctx, mockServer, &model.ToolRequest{SessionId: tc.sessionId, Params: json.RawMessage(tc.params)})

			assert.NoError(t, err)
			assert.Len(t, fakeNotifier.InputPayloads, 1)
			assert.Equal(t, tc.expectedLinks, fakeNotifier.InputPayloads[0].Links)
			if tc.sharedNote {
				assert.Contains(t, result.Result, "now shared")
			} else {
				assert.NotContains(t, result.Result, "now shared")
			}
		})
	}
}

func TestTriageAlertLink(t *testing.T) {
	testCases := []struct {
		name    string
		alertId string
	}{
		{name: "plain id", alertId: "WKhCuTw4GPvrQA-9ksmn"},
		{name: "id needing escapes", alertId: "a&b=c d#e"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			link := triageAlertLink(tc.alertId)

			path, rawQuery, found := strings.Cut(link, "?")
			assert.True(t, found)
			assert.Equal(t, "/#/alerts", path)

			query, err := url.ParseQuery(rawQuery)
			assert.NoError(t, err)
			assert.Equal(t, url.Values{
				"q":      {`_id:"` + tc.alertId + `"`},
				"tab":    {"investigation"},
				"expand": {tc.alertId},
				"rt":     {"30"},
				"rtu":    {"days"},
			}, query)
		})
	}
}

func TestNormalizeNotificationSeverity(t *testing.T) {
	testCases := []struct {
		input        string
		expected     string
		expectedNote bool
	}{
		{input: "", expected: model.NotificationSeverityInfo},
		{input: "info", expected: model.NotificationSeverityInfo},
		{input: "low", expected: model.NotificationSeverityLow},
		{input: "Medium", expected: model.NotificationSeverityMedium},
		{input: " HIGH ", expected: model.NotificationSeverityHigh},
		{input: "CRITICAL", expected: model.NotificationSeverityCritical},
		{input: "warning", expected: model.NotificationSeverityInfo, expectedNote: true},
		{input: "p1", expected: model.NotificationSeverityInfo, expectedNote: true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			severity, note := normalizeNotificationSeverity(tc.input)
			assert.Equal(t, tc.expected, severity)
			if tc.expectedNote {
				assert.Contains(t, note, tc.input)
			} else {
				assert.Empty(t, note)
			}
		})
	}
}

func TestStringifyValues(t *testing.T) {
	testCases := []struct {
		name     string
		input    map[string]any
		expected map[string]string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "only unusable entries",
			input:    map[string]any{"": "dropped", "  ": "dropped", "nil": nil},
			expected: nil,
		},
		{
			name: "scalars",
			input: map[string]any{
				"str":   "text",
				"true":  true,
				"false": false,
				"int":   float64(42),
				"big":   float64(1000000),
				"frac":  float64(1.5),
				"neg":   float64(-7),
			},
			expected: map[string]string{
				"str":   "text",
				"true":  "true",
				"false": "false",
				"int":   "42",
				"big":   "1000000",
				"frac":  "1.5",
				"neg":   "-7",
			},
		},
		{
			name: "nested values are encoded as JSON",
			input: map[string]any{
				"obj":  map[string]any{"a": float64(1)},
				"list": []any{"x", float64(2)},
			},
			expected: map[string]string{
				"obj":  `{"a":1}`,
				"list": `["x",2]`,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, stringifyValues(tc.input))
		})
	}
}
