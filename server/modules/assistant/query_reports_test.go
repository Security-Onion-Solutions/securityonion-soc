// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestQueryReportsTool_Metadata(t *testing.T) {
	tool := &QueryReportsTool{}

	assert.Equal(t, "query_reports", tool.GetName())
	assert.NotEmpty(t, tool.GetDescription())

	schema := tool.GetSchema()
	assert.NotNil(t, schema.Json)
	assert.Contains(t, schema.Json.Properties, "filename")
}

type errorConfigstore struct {
	server.Configstore
	err error
}

func (e *errorConfigstore) GetSettings(ctx context.Context, advanced bool) ([]*model.Setting, error) {
	return nil, e.err
}

func TestQueryReportsTool_Execute(t *testing.T) {
	reportSettings := []*model.Setting{
		{Id: "sensoroni.files.templates.reports.custom.generic_report1__md", File: true, Title: "Custom Report 1", Default: "Example Report\n===\nbody"},
		{Id: "sensoroni.files.templates.reports.custom.generic_report2__md", File: true, Title: "Custom Report 2", Value: ""},
		{Id: "sensoroni.files.templates.reports.standard.case_report__md", File: true, Title: "Case Report Template", Default: "Case body"},
		{Id: "sensoroni.some.other.setting", File: false},
	}

	testCases := []struct {
		name          string
		params        string
		settings      []*model.Setting
		configstore   server.Configstore
		nilStore      bool
		unauthorized  bool
		expectedError bool
		assertResult  func(t *testing.T, result any)
	}{
		{
			name:     "list all reports",
			params:   `{}`,
			settings: reportSettings,
			assertResult: func(t *testing.T, result any) {
				reports, ok := result.([]reportSummary)
				assert.True(t, ok)
				assert.Len(t, reports, 3)

				assert.Equal(t, "generic_report1.md", reports[0].Filename)
				assert.Equal(t, "Custom Report 1", reports[0].Title)
				assert.Equal(t, "custom", reports[0].Type)
				assert.False(t, reports[0].Empty)

				assert.Equal(t, "generic_report2.md", reports[1].Filename)
				assert.Equal(t, "custom", reports[1].Type)
				assert.True(t, reports[1].Empty)

				assert.Equal(t, "case_report.md", reports[2].Filename)
				assert.Equal(t, "standard", reports[2].Type)
				assert.False(t, reports[2].Empty)
			},
		},
		{
			name:     "get specific report content",
			params:   `{"filename": "generic_report1.md"}`,
			settings: reportSettings,
			assertResult: func(t *testing.T, result any) {
				detail, ok := result.(reportDetail)
				assert.True(t, ok)
				assert.Equal(t, "generic_report1.md", detail.Filename)
				assert.Equal(t, "Custom Report 1", detail.Title)
				assert.Equal(t, "custom", detail.Type)
				assert.False(t, detail.Empty)
				assert.Equal(t, "Example Report\n===\nbody", detail.Content)
			},
		},
		{
			name:     "get empty slot content",
			params:   `{"filename": "generic_report2.md"}`,
			settings: reportSettings,
			assertResult: func(t *testing.T, result any) {
				detail, ok := result.(reportDetail)
				assert.True(t, ok)
				assert.True(t, detail.Empty)
				assert.Equal(t, "", detail.Content)
			},
		},
		{
			name:     "report not found",
			params:   `{"filename": "does_not_exist.md"}`,
			settings: reportSettings,
			assertResult: func(t *testing.T, result any) {
				msg, ok := result.(string)
				assert.True(t, ok)
				assert.Contains(t, msg, "not found")
			},
		},
		{
			name:     "no reports found",
			params:   `{}`,
			settings: []*model.Setting{{Id: "sensoroni.some.other.setting", File: false}},
			assertResult: func(t *testing.T, result any) {
				msg, ok := result.(string)
				assert.True(t, ok)
				assert.Equal(t, "No reports found", msg)
			},
		},
		{
			name:          "invalid params",
			params:        `{invalid json}`,
			settings:      reportSettings,
			expectedError: true,
		},
		{
			name:          "nil config store",
			params:        `{}`,
			nilStore:      true,
			expectedError: true,
		},
		{
			name:          "config store error",
			params:        `{}`,
			configstore:   &errorConfigstore{err: errors.New("boom")},
			expectedError: true,
		},
		{
			name:          "unauthorized",
			params:        `{}`,
			settings:      reportSettings,
			unauthorized:  true,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cs server.Configstore
			switch {
			case tc.nilStore:
				cs = nil
			case tc.configstore != nil:
				cs = tc.configstore
			default:
				cs = server.NewMemConfigStore(tc.settings)
			}

			mockServer := &server.Server{
				Configstore: cs,
				Config: &config.ServerConfig{
					DeveloperEnabled: !tc.unauthorized,
				},
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			tool := &QueryReportsTool{}
			result, err := tool.Execute(ctx, mockServer, &model.ToolRequest{Params: json.RawMessage(tc.params)})

			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "query_reports", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)

			if tc.assertResult != nil {
				tc.assertResult(t, result.Result)
			}
		})
	}
}
