// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

func TestQueryCasesTool_Execute(t *testing.T) {
	testCases := []struct {
		name           string
		params         string
		auxData        string
		mockResults    *model.EventSearchResults
		mockError      error
		expectedResult any
		expectedError  bool
	}{
		{
			name:    "basic case query",
			params:  `{"oql_query": "so_case.title:malware AND _index:\"*:so-case\" AND so_kind:case", "limit": 10}`,
			auxData: ``,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-case-index",
						Id:     "case-1",
						Payload: map[string]any{
							"@timestamp":          "2024-01-01T00:00:00Z",
							"so_case.title":       "Malware Investigation",
							"so_case.description": "Investigating suspicious malware activity",
							"so_case.status":      "open",
							"so_case.priority":    "high",
							"so_case.severity":    3,
							"so_case.assigneeId":  "analyst1",
							"so_case.userId":      "user1",
						},
					},
					{
						Source: "so-case-index",
						Id:     "case-2",
						Payload: map[string]any{
							"@timestamp":          "2024-01-01T00:01:00Z",
							"so_case.title":       "Malware Detection Follow-up",
							"so_case.description": "Follow-up investigation for malware detection",
							"so_case.status":      "in-progress",
							"so_case.priority":    "medium",
							"so_case.severity":    2,
							"so_case.assigneeId":  "analyst2",
							"so_case.userId":      "user2",
						},
					},
				},
				TotalEvents: 2,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: QueryCasesResult{
				QueryResults: []map[string]any{
					{
						"payload": map[string]any{
							"_id":                 "case-1",
							"@timestamp":          "2024-01-01T00:00:00Z",
							"so_case.title":       "Malware Investigation",
							"so_case.description": "Investigating suspicious malware activity",
							"so_case.status":      "open",
							"so_case.priority":    "high",
							"so_case.severity":    3,
							"so_case.assigneeId":  "analyst1",
							"so_case.userId":      "user1",
						},
					},
					{
						"payload": map[string]any{
							"_id":                 "case-2",
							"@timestamp":          "2024-01-01T00:01:00Z",
							"so_case.title":       "Malware Detection Follow-up",
							"so_case.description": "Follow-up investigation for malware detection",
							"so_case.status":      "in-progress",
							"so_case.priority":    "medium",
							"so_case.severity":    2,
							"so_case.assigneeId":  "analyst2",
							"so_case.userId":      "user2",
						},
					},
				},
				RecentCases: []map[string]any{},
			},
		},
		{
			name:    "query with recent cases in auxData",
			params:  `{"oql_query": "so_case.category:phishing AND _index:\"*:so-case\" AND so_kind:case", "limit": 5}`,
			auxData: `[{"case_id": "recent-1", "title": "Recent Phishing Case", "status": "closed"}]`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-case-index",
						Id:     "case-3",
						Payload: map[string]any{
							"@timestamp":       "2024-01-01T00:00:00Z",
							"so_case.title":    "Phishing Email Investigation",
							"so_case.category": "phishing",
							"so_case.status":   "open",
							"so_case.priority": "high",
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: QueryCasesResult{
				QueryResults: []map[string]any{
					{
						"payload": map[string]any{
							"_id":              "case-3",
							"@timestamp":       "2024-01-01T00:00:00Z",
							"so_case.title":    "Phishing Email Investigation",
							"so_case.category": "phishing",
							"so_case.status":   "open",
							"so_case.priority": "high",
						},
					},
				},
				RecentCases: []map[string]any{
					{"case_id": "recent-1", "title": "Recent Phishing Case", "status": "closed"},
				},
			},
		},
		{
			name:    "query with time range",
			params:  `{"oql_query": "so_case.status:closed AND _index:\"*:so-case\" AND so_kind:case", "range_start": "-7d", "range_end": "now", "limit": 20}`,
			auxData: ``,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-case-index",
						Id:     "case-4",
						Payload: map[string]any{
							"@timestamp":           "2024-01-01T00:00:00Z",
							"so_case.title":        "Closed Investigation",
							"so_case.status":       "closed",
							"so_case.completeTime": "2024-01-01T12:00:00Z",
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: QueryCasesResult{
				QueryResults: []map[string]any{
					{
						"payload": map[string]any{
							"_id":                  "case-4",
							"@timestamp":           "2024-01-01T00:00:00Z",
							"so_case.title":        "Closed Investigation",
							"so_case.status":       "closed",
							"so_case.completeTime": "2024-01-01T12:00:00Z",
						},
					},
				},
				RecentCases: []map[string]any{},
			},
		},
		{
			name:    "query with absolute time range",
			params:  `{"oql_query": "so_case.priority:critical AND _index:\"*:so-case\" AND so_kind:case", "range_start": "2024/01/01 10:00:00 AM", "range_end": "2024/01/01 11:00:00 AM", "limit": 15}`,
			auxData: ``,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-case-index",
						Id:     "case-5",
						Payload: map[string]any{
							"@timestamp":       "2024-01-01T10:00:00Z",
							"so_case.title":    "Critical Security Incident",
							"so_case.priority": "critical",
							"so_case.severity": 4,
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: QueryCasesResult{
				QueryResults: []map[string]any{
					{
						"payload": map[string]any{
							"_id":              "case-5",
							"@timestamp":       "2024-01-01T10:00:00Z",
							"so_case.title":    "Critical Security Incident",
							"so_case.priority": "critical",
							"so_case.severity": 4,
						},
					},
				},
				RecentCases: []map[string]any{},
			},
		},
		{
			name:    "query with legacy query field",
			params:  `{"query": "so_case.tags:incident AND _index:\"*:so-case\" AND so_kind:case", "limit": 12}`,
			auxData: `[]`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-case-index",
						Id:     "case-6",
						Payload: map[string]any{
							"@timestamp":    "2024-01-01T00:00:00Z",
							"so_case.title": "Security Incident Response",
							"so_case.tags":  []string{"incident", "response"},
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: QueryCasesResult{
				QueryResults: []map[string]any{
					{
						"payload": map[string]any{
							"_id":           "case-6",
							"@timestamp":    "2024-01-01T00:00:00Z",
							"so_case.title": "Security Incident Response",
							"so_case.tags":  []string{"incident", "response"},
						},
					},
				},
				RecentCases: []map[string]any{},
			},
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"oql_query": "invalid json}`,
			auxData:       `[]`,
			expectedError: true,
		},
		{
			name:    "invalid auxData JSON",
			params:  `{"oql_query": "so_case.title:test AND _index:\"*:so-case\" AND so_kind:case", "limit": 10}`,
			auxData: `invalid json`,
			mockResults: &model.EventSearchResults{
				Events:  []*model.EventRecord{},
				Metrics: make(map[string][]*model.EventMetric),
			},
			expectedError: true,
		},
		{
			name:          "eventstore error",
			params:        `{"oql_query": "so_case.title:test AND _index:\"*:so-case\" AND so_kind:case", "limit": 10}`,
			auxData:       `[]`,
			mockError:     assert.AnError,
			expectedError: true,
		},
		{
			name:    "no cases found",
			params:  `{"oql_query": "so_case.title:nonexistent AND _index:\"*:so-case\" AND so_kind:case", "limit": 10}`,
			auxData: `[]`,
			mockResults: &model.EventSearchResults{
				Events:  []*model.EventRecord{},
				Metrics: make(map[string][]*model.EventMetric),
			},
			expectedResult: "No cases found",
		},
		{
			name:    "case with all so_case fields",
			params:  `{"oql_query": "so_case.template:incident AND _index:\"*:so-case\" AND so_kind:case", "limit": 5}`,
			auxData: `[]`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-case-index",
						Id:     "case-7",
						Payload: map[string]any{
							"@timestamp":           "2024-01-01T00:00:00Z",
							"so_case.assigneeId":   "analyst3",
							"so_case.category":     "malware",
							"so_case.completeTime": "2024-01-02T00:00:00Z",
							"so_case.createTime":   "2024-01-01T00:00:00Z",
							"so_case.description":  "Comprehensive incident investigation",
							"so_case.pap":          2,
							"so_case.priority":     "high",
							"so_case.severity":     3,
							"so_case.startTime":    "2024-01-01T01:00:00Z",
							"so_case.status":       "closed",
							"so_case.tags":         []string{"incident", "malware", "investigation"},
							"so_case.template":     "incident",
							"so_case.title":        "Comprehensive Incident Case",
							"so_case.tlp":          "amber",
							"so_case.userId":       "user3",
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: QueryCasesResult{
				QueryResults: []map[string]any{
					{
						"payload": map[string]any{
							"_id":                  "case-7",
							"@timestamp":           "2024-01-01T00:00:00Z",
							"so_case.assigneeId":   "analyst3",
							"so_case.category":     "malware",
							"so_case.completeTime": "2024-01-02T00:00:00Z",
							"so_case.createTime":   "2024-01-01T00:00:00Z",
							"so_case.description":  "Comprehensive incident investigation",
							"so_case.pap":          2,
							"so_case.priority":     "high",
							"so_case.severity":     3,
							"so_case.startTime":    "2024-01-01T01:00:00Z",
							"so_case.status":       "closed",
							"so_case.tags":         []string{"incident", "malware", "investigation"},
							"so_case.template":     "incident",
							"so_case.title":        "Comprehensive Incident Case",
							"so_case.tlp":          "amber",
							"so_case.userId":       "user3",
						},
					},
				},
				RecentCases: []map[string]any{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock eventstore
			mockEventstore := server.NewFakeEventstore()
			if tc.mockResults != nil {
				mockEventstore.SearchResults = []*model.EventSearchResults{tc.mockResults}
			}
			if tc.mockError != nil {
				mockEventstore.Err = tc.mockError
			}

			// Create mock server
			mockServer := &server.Server{
				Eventstore: mockEventstore,
			}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create tool and execute
			tool := &QueryCasesTool{}
			result, err := tool.Execute(ctx, mockServer, &model.ToolRequest{Params: json.RawMessage(tc.params), AuxData: json.RawMessage(tc.auxData)})

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "query_cases", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)

			// Verify search criteria was populated correctly
			if !tc.expectedError && tc.mockError == nil {
				assert.Len(t, mockEventstore.InputSearchCriterias, 1)
				criteria := mockEventstore.InputSearchCriterias[0]
				assert.NotNil(t, criteria)
				assert.Contains(t, criteria.RawQuery, "NOT metadata.raw_index:")
			}

			// Assert result content
			if tc.expectedResult != nil {
				if resultStr, ok := tc.expectedResult.(string); ok {
					// Handle string results (like "No cases found")
					assert.Equal(t, resultStr, result.Result)
				} else {
					// Handle QueryCasesResult
					assert.Equal(t, tc.expectedResult, result.Result)
				}
			} else {
				assert.Nil(t, result.Result)
			}
		})
	}
}

func TestFilterCases(t *testing.T) {
	testCases := []struct {
		name         string
		events       []*model.EventRecord
		extraFields  []string
		expectedLen  int
		validateFunc func(t *testing.T, result []map[string]any)
	}{
		{
			name: "basic case with default fields",
			events: []*model.EventRecord{
				{
					Id:     "test-case-1",
					Source: "so-case-index",
					Payload: map[string]any{
						"@timestamp":          "2024-01-01T00:00:00Z",
						"so_case.title":       "Test Case",
						"so_case.description": "Test case description",
						"so_case.status":      "open",
						"so_case.priority":    "medium",
						"so_case.severity":    2,
						"so_case.assigneeId":  "analyst1",
						"so_case.userId":      "user1",
						"ignored_field":       "this should not appear",
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-case-1", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "Test Case", payload["so_case.title"])
				assert.Equal(t, "Test case description", payload["so_case.description"])
				assert.Equal(t, "open", payload["so_case.status"])
				assert.Equal(t, "medium", payload["so_case.priority"])
				assert.Equal(t, 2, payload["so_case.severity"])
				assert.Equal(t, "analyst1", payload["so_case.assigneeId"])
				assert.Equal(t, "user1", payload["so_case.userId"])
				assert.NotContains(t, payload, "ignored_field")
			},
		},
		{
			name: "case with all so_case fields",
			events: []*model.EventRecord{
				{
					Id:     "test-case-2",
					Source: "so-case-index",
					Payload: map[string]any{
						"@timestamp":           "2024-01-01T00:00:00Z",
						"so_case.assigneeId":   "analyst2",
						"so_case.category":     "phishing",
						"so_case.completeTime": "2024-01-02T00:00:00Z",
						"so_case.createTime":   "2024-01-01T00:00:00Z",
						"so_case.description":  "Phishing investigation case",
						"so_case.pap":          1,
						"so_case.priority":     "high",
						"so_case.severity":     3,
						"so_case.startTime":    "2024-01-01T01:00:00Z",
						"so_case.status":       "in-progress",
						"so_case.tags":         []string{"phishing", "email"},
						"so_case.template":     "phishing",
						"so_case.title":        "Phishing Email Case",
						"so_case.tlp":          "green",
						"so_case.userId":       "user2",
						"extra_field":          "should not appear",
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-case-2", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "analyst2", payload["so_case.assigneeId"])
				assert.Equal(t, "phishing", payload["so_case.category"])
				assert.Equal(t, "2024-01-02T00:00:00Z", payload["so_case.completeTime"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["so_case.createTime"])
				assert.Equal(t, "Phishing investigation case", payload["so_case.description"])
				assert.Equal(t, 1, payload["so_case.pap"])
				assert.Equal(t, "high", payload["so_case.priority"])
				assert.Equal(t, 3, payload["so_case.severity"])
				assert.Equal(t, "2024-01-01T01:00:00Z", payload["so_case.startTime"])
				assert.Equal(t, "in-progress", payload["so_case.status"])
				assert.Equal(t, []string{"phishing", "email"}, payload["so_case.tags"])
				assert.Equal(t, "phishing", payload["so_case.template"])
				assert.Equal(t, "Phishing Email Case", payload["so_case.title"])
				assert.Equal(t, "green", payload["so_case.tlp"])
				assert.Equal(t, "user2", payload["so_case.userId"])
				assert.NotContains(t, payload, "extra_field")
			},
		},
		{
			name: "case with extra fields",
			events: []*model.EventRecord{
				{
					Id:     "test-case-3",
					Source: "so-case-index",
					Payload: map[string]any{
						"@timestamp":     "2024-01-01T00:00:00Z",
						"so_case.title":  "Custom Case",
						"so_case.status": "open",
						"custom_field1":  "custom_value1",
						"custom_field2":  "custom_value2",
						"ignored_field":  "ignored",
					},
				},
			},
			extraFields: []string{"custom_field1", "custom_field2"},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-case-3", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "Custom Case", payload["so_case.title"])
				assert.Equal(t, "open", payload["so_case.status"])
				assert.Equal(t, "custom_value1", payload["custom_field1"])
				assert.Equal(t, "custom_value2", payload["custom_field2"])
				assert.NotContains(t, payload, "ignored_field")
			},
		},
		{
			name: "multiple cases",
			events: []*model.EventRecord{
				{
					Id:     "test-case-4",
					Source: "so-case-index",
					Payload: map[string]any{
						"@timestamp":       "2024-01-01T00:00:00Z",
						"so_case.title":    "First Case",
						"so_case.status":   "open",
						"so_case.priority": "high",
					},
				},
				{
					Id:     "test-case-5",
					Source: "so-case-index",
					Payload: map[string]any{
						"@timestamp":       "2024-01-01T00:01:00Z",
						"so_case.title":    "Second Case",
						"so_case.status":   "closed",
						"so_case.priority": "low",
					},
				},
			},
			expectedLen: 2,
			validateFunc: func(t *testing.T, result []map[string]any) {
				assert.Equal(t, "test-case-4", result[0]["payload"].(map[string]any)["_id"])
				assert.Equal(t, "test-case-5", result[1]["payload"].(map[string]any)["_id"])
				assert.Equal(t, "First Case", result[0]["payload"].(map[string]any)["so_case.title"])
				assert.Equal(t, "Second Case", result[1]["payload"].(map[string]any)["so_case.title"])
				assert.Equal(t, "open", result[0]["payload"].(map[string]any)["so_case.status"])
				assert.Equal(t, "closed", result[1]["payload"].(map[string]any)["so_case.status"])
			},
		},
		{
			name: "missing fields",
			events: []*model.EventRecord{
				{
					Id:     "test-case-6",
					Source: "so-case-index",
					Payload: map[string]any{
						"@timestamp":     "2024-01-01T00:00:00Z",
						"so_case.title":  "Minimal Case",
						"so_case.status": "open",
						// Missing many default fields
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-case-6", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "Minimal Case", payload["so_case.title"])
				assert.Equal(t, "open", payload["so_case.status"])
				// Missing fields should not be present
				assert.NotContains(t, payload, "so_case.description")
				assert.NotContains(t, payload, "so_case.priority")
				assert.NotContains(t, payload, "so_case.assigneeId")
			},
		},
		{
			name: "nil field values are excluded",
			events: []*model.EventRecord{
				{
					Id:     "test-case-7",
					Source: "so-case-index",
					Payload: map[string]any{
						"@timestamp":          "2024-01-01T00:00:00Z",
						"so_case.title":       "Case with Nil Fields",
						"so_case.status":      "open",
						"so_case.description": nil,
						"so_case.assigneeId":  nil,
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-case-7", payload["_id"])
				assert.Equal(t, "Case with Nil Fields", payload["so_case.title"])
				assert.Equal(t, "open", payload["so_case.status"])
				// Nil fields should not be included
				assert.NotContains(t, payload, "so_case.description")
				assert.NotContains(t, payload, "so_case.assigneeId")
			},
		},
		{
			name:        "empty cases list",
			events:      []*model.EventRecord{},
			expectedLen: 0,
			validateFunc: func(t *testing.T, result []map[string]any) {
				assert.Empty(t, result)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := filterCases(tc.events, tc.extraFields...)

			assert.Len(t, result, tc.expectedLen)

			if tc.validateFunc != nil {
				tc.validateFunc(t, result)
			}
		})
	}
}
