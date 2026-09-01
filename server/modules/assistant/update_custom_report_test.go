// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

const validReportTemplate = "{{- /* query.alerts.oql = tags:alert */ -}}\nMy Report\n===\nTotal: {{ .Results.alerts.TotalEvents }}"

const reportIDPrefix = "sensoroni.files.templates.reports."

type updateErrorConfigstore struct {
	*server.MemConfigStore
	err error
}

func (u *updateErrorConfigstore) UpdateSetting(ctx context.Context, setting *model.Setting, remove bool) error {
	return u.err
}

func newReportSettings() []*model.Setting {
	return []*model.Setting{
		{Id: reportIDPrefix + "custom.generic_report1__md", File: true, Title: "Custom Report 1", Default: validReportTemplate},
		{Id: reportIDPrefix + "custom.generic_report2__md", File: true, Title: "Custom Report 2"},
		{Id: reportIDPrefix + "custom.generic_report3__md", File: true, Title: "Custom Report 3"},
		{Id: reportIDPrefix + "standard.case_report__md", File: true, Title: "Case Report Template", Default: "Case body"},
	}
}

func settingByIDSuffix(settings []*model.Setting, suffix string) *model.Setting {
	for _, s := range settings {
		if strings.HasSuffix(s.Id, suffix) {
			return s
		}
	}
	return nil
}

func TestUpdateCustomReportTool_Metadata(t *testing.T) {
	tool := &UpdateCustomReportTool{}

	assert.Equal(t, "update_custom_report", tool.GetName())
	assert.NotEmpty(t, tool.GetDescription())

	schema := tool.GetSchema()
	assert.NotNil(t, schema.Json)
	assert.Contains(t, schema.Json.Properties, "content")
	assert.Contains(t, schema.Json.Properties, "filename")
	assert.Contains(t, schema.Json.Required, "content")
}

func TestUpdateCustomReportTool_Execute(t *testing.T) {
	testCases := []struct {
		name          string
		params        string
		settings      func() []*model.Setting
		configstore   server.Configstore
		nilStore      bool
		noAdmin       bool
		unauthorized  bool
		expectedError bool
		assertResult  func(t *testing.T, result *model.ToolResponse, store *server.MemConfigStore)
	}{
		{
			name:   "author into next free slot",
			params: `{"content": "` + jsonEscape(validReportTemplate) + `"}`,
			assertResult: func(t *testing.T, result *model.ToolResponse, store *server.MemConfigStore) {
				msg := result.Result.(string)
				assert.Contains(t, msg, "Created")
				assert.Contains(t, msg, "generic_report2.md")
				assert.Contains(t, msg, "sync was started")

				settings, _ := store.GetSettings(context.Background(), false)
				assert.Equal(t, validReportTemplate, settingByIDSuffix(settings, "generic_report2__md").Value)
			},
		},
		{
			name:   "update named slot",
			params: `{"content": "` + jsonEscape(validReportTemplate) + `", "filename": "generic_report3.md"}`,
			assertResult: func(t *testing.T, result *model.ToolResponse, store *server.MemConfigStore) {
				msg := result.Result.(string)
				assert.Contains(t, msg, "Updated")
				assert.Contains(t, msg, "generic_report3.md")

				settings, _ := store.GetSettings(context.Background(), false)
				assert.Equal(t, validReportTemplate, settingByIDSuffix(settings, "generic_report3__md").Value)
			},
		},
		{
			name:   "clear a slot with content",
			params: `{"content": "", "filename": "generic_report2.md"}`,
			settings: func() []*model.Setting {
				s := newReportSettings()
				s[1].Value = validReportTemplate
				return s
			},
			assertResult: func(t *testing.T, result *model.ToolResponse, store *server.MemConfigStore) {
				msg := result.Result.(string)
				assert.Contains(t, msg, "Cleared")
				assert.Contains(t, msg, "generic_report2.md")

				// Cleared with remove=true, so the override is dropped rather than saved as empty;
				// the mem store discards the whole entry where the real store reverts to the default.
				settings, _ := store.GetSettings(context.Background(), false)
				assert.Nil(t, settingByIDSuffix(settings, "generic_report2__md"))
			},
		},
		{
			name:          "clear the shipped example slot",
			params:        `{"content": "", "filename": "generic_report1.md"}`,
			expectedError: true,
		},
		{
			name:   "clear an already empty slot",
			params: `{"content": "", "filename": "generic_report2.md"}`,
			assertResult: func(t *testing.T, result *model.ToolResponse, store *server.MemConfigStore) {
				assert.Contains(t, result.Result.(string), "no saved content to clear")
			},
		},
		{
			name:    "author without admin store reports not deployed",
			params:  `{"content": "` + jsonEscape(validReportTemplate) + `"}`,
			noAdmin: true,
			assertResult: func(t *testing.T, result *model.ToolResponse, store *server.MemConfigStore) {
				assert.Contains(t, result.Result.(string), "Synchronize the grid")
			},
		},
		{
			name:          "clear without filename",
			params:        `{"content": ""}`,
			expectedError: true,
		},
		{
			name:          "invalid filename",
			params:        `{"content": "` + jsonEscape(validReportTemplate) + `", "filename": "nope.md"}`,
			expectedError: true,
		},
		{
			name:   "all slots in use",
			params: `{"content": "` + jsonEscape(validReportTemplate) + `"}`,
			settings: func() []*model.Setting {
				s := newReportSettings()
				s[1].Value = validReportTemplate
				s[2].Value = validReportTemplate
				return s
			},
			expectedError: true,
		},
		{
			name:          "invalid template",
			params:        `{"content": "Just a title\n===\nno query directive"}`,
			expectedError: true,
		},
		{
			name:          "invalid params",
			params:        `{invalid json}`,
			expectedError: true,
		},
		{
			name:          "nil config store",
			params:        `{"content": "` + jsonEscape(validReportTemplate) + `"}`,
			nilStore:      true,
			expectedError: true,
		},
		{
			name:          "get settings error",
			params:        `{"content": "` + jsonEscape(validReportTemplate) + `"}`,
			configstore:   &errorConfigstore{err: errors.New("read boom")},
			expectedError: true,
		},
		{
			name:          "update setting error",
			params:        `{"content": "` + jsonEscape(validReportTemplate) + `"}`,
			configstore:   &updateErrorConfigstore{MemConfigStore: server.NewMemConfigStore(newReportSettings()), err: errors.New("write boom")},
			expectedError: true,
		},
		{
			name:          "unauthorized",
			params:        `{"content": "` + jsonEscape(validReportTemplate) + `"}`,
			unauthorized:  true,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			build := tc.settings
			if build == nil {
				build = newReportSettings
			}

			var cs server.Configstore
			var admin server.AdminConfigstore
			var memStore *server.MemConfigStore

			switch {
			case tc.nilStore:
				cs = nil
			case tc.configstore != nil:
				cs = tc.configstore
			default:
				memStore = server.NewMemConfigStore(build())
				cs = memStore
				if !tc.noAdmin {
					admin = memStore
				}
			}

			mockServer := &server.Server{
				Configstore:      cs,
				AdminConfigstore: admin,
				Config: &config.ServerConfig{
					DeveloperEnabled: !tc.unauthorized,
				},
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			tool := &UpdateCustomReportTool{}
			result, err := tool.Execute(ctx, mockServer, &model.ToolRequest{Params: json.RawMessage(tc.params)})

			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "update_custom_report", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)

			if tc.assertResult != nil {
				tc.assertResult(t, result, memStore)
			}
		})
	}
}

func TestCustomReportSlots(t *testing.T) {
	slots := []reportSlot{
		{Filename: "case_report.md", Kind: "standard"},
		{Filename: "generic_report3.md", Kind: "custom", Slot: 3},
		{Filename: "generic_report1.md", Kind: "custom", Slot: 1},
		{Filename: "generic_report2.md", Kind: "custom", Slot: 2},
	}

	custom := customReportSlots(slots)

	assert.Len(t, custom, 3)
	assert.Equal(t, 1, custom[0].Slot)
	assert.Equal(t, 2, custom[1].Slot)
	assert.Equal(t, 3, custom[2].Slot)
}

func TestFindCustomSlotByName(t *testing.T) {
	custom := []reportSlot{
		{Filename: "generic_report1.md", Kind: "custom", Slot: 1},
		{Filename: "generic_report2.md", Kind: "custom", Slot: 2},
	}

	found, err := findCustomSlotByName(custom, "generic_report2.md")
	assert.NoError(t, err)
	assert.Equal(t, 2, found.Slot)

	_, err = findCustomSlotByName(custom, "nope.md")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "generic_report1.md")
	assert.Contains(t, err.Error(), "generic_report2.md")
}

func TestSelectReportSlot(t *testing.T) {
	withContent := &model.Setting{Value: "content"}
	empty := &model.Setting{}

	slots := []reportSlot{
		{Filename: "generic_report1.md", Kind: "custom", Slot: 1, Setting: withContent},
		{Filename: "generic_report2.md", Kind: "custom", Slot: 2, Setting: withContent},
		{Filename: "generic_report3.md", Kind: "custom", Slot: 3, Setting: empty},
	}

	t.Run("named slot", func(t *testing.T) {
		slot, updating, err := selectReportSlot(slots, "generic_report2.md")
		assert.NoError(t, err)
		assert.True(t, updating)
		assert.Equal(t, 2, slot.Slot)
	})

	t.Run("named invalid slot", func(t *testing.T) {
		_, _, err := selectReportSlot(slots, "nope.md")
		assert.Error(t, err)
	})

	t.Run("lowest free slot", func(t *testing.T) {
		slot, updating, err := selectReportSlot(slots, "")
		assert.NoError(t, err)
		assert.False(t, updating)
		assert.Equal(t, 3, slot.Slot)
	})

	t.Run("slot 1 is reserved even if empty", func(t *testing.T) {
		reserved := []reportSlot{
			{Filename: "generic_report1.md", Kind: "custom", Slot: 1, Setting: empty},
			{Filename: "generic_report2.md", Kind: "custom", Slot: 2, Setting: withContent},
		}
		_, _, err := selectReportSlot(reserved, "")
		assert.Error(t, err)
	})

	t.Run("all slots in use", func(t *testing.T) {
		full := []reportSlot{
			{Filename: "generic_report2.md", Kind: "custom", Slot: 2, Setting: withContent},
		}
		_, _, err := selectReportSlot(full, "")
		assert.Error(t, err)
	})
}

func TestDeployNoteFor(t *testing.T) {
	assert.Contains(t, deployNoteFor(true), "sync was started")
	assert.Contains(t, deployNoteFor(false), "Synchronize the grid")
}

func TestValidateReportTemplate(t *testing.T) {
	testCases := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "valid template",
			content: validReportTemplate,
		},
		{
			name:    "multiple directives on their own lines",
			content: "{{- /* query.alerts.oql = tags:alert */ -}}\n{{- /* query.alerts.metricLimit = 50 */ -}}\nMy Report\n===\nTotal: {{ .Results.alerts.TotalEvents }}",
		},
		{
			name:    "directive below the title block",
			content: "My Report\n===\n{{- /* query.alerts.oql = tags:alert */ -}}\nTotal: 5",
			wantErr: "below the title block",
		},
		{
			name:    "empty content",
			content: "   ",
			wantErr: "empty",
		},
		{
			name:    "unparsable template",
			content: "{{- /* query.alerts.oql = tags:alert */ -}}\n{{ .Unclosed ",
			wantErr: "text/template",
		},
		{
			name:    "no query directive",
			content: "My Report\n===\nTotal: 5",
			wantErr: "must define at least one",
		},
		{
			name:    "bare directive renders as text",
			content: "/* query.alerts.oql = tags:alert */\nMy Report\n===\nTotal: 5",
			wantErr: "template comment",
		},
		{
			name:    "two directives on one line",
			content: "{{- /* query.alerts.oql = tags:alert */ -}} {{- /* query.alerts.metricLimit = 50 */ -}}\nMy Report\n===\nTotal: 5",
			wantErr: "more than one query directive",
		},
		{
			name:    "emoji in body",
			content: "{{- /* query.alerts.oql = tags:alert */ -}}\nMy Report\n===\n\U0001F4CB Alerts: 5",
			wantErr: "non-ASCII",
		},
		{
			name:    "em dash in body",
			content: "{{- /* query.alerts.oql = tags:alert */ -}}\nMy Report\n===\nAlerts — recent",
			wantErr: "non-ASCII",
		},
		{
			name:    "groupby with a colon",
			content: "{{- /* query.alerts.oql = tags:alert | groupby:source.ip */ -}}\nMy Report\n===\nTotal: 5",
			wantErr: "separated by a space",
		},
		{
			name:    "sortby with a colon",
			content: "{{- /* query.alerts.oql = tags:alert | sortby:@timestamp */ -}}\nMy Report\n===\nTotal: 5",
			wantErr: "separated by a space",
		},
		{
			name:    "space separated groupby is allowed",
			content: "{{- /* query.alerts.oql = tags:alert | groupby source.ip destination.ip */ -}}\nMy Report\n===\nTotal: 5",
		},
		{
			name:    "colons elsewhere in the query are allowed",
			content: "{{- /* query.alerts.oql = tags:alert AND source.ip:1.2.3.4 | groupby rule.name */ -}}\nMy Report\n===\nTotal: 5",
		},
		{
			name:    "non-ASCII inside a directive is allowed",
			content: "{{- /* query.alerts.oql = message:été */ -}}\nMy Report\n===\nTotal: 5",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReportTemplate(tc.content)

			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
