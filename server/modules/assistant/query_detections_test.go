// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestQueryDetectionsTool_Execute(t *testing.T) {
	testCases := []struct {
		name           string
		params         string
		mockResults    *model.EventSearchResults
		mockError      error
		expectedResult any
		expectedError  bool
	}{
		{
			name:   "basic detection query",
			params: `{"oql_query": "so_detection.title:malware AND _index:\"*:so-detection\" AND so_kind:detection", "limit": 10}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-detection-index",
						Id:     "detection-1",
						Payload: map[string]any{
							"@timestamp":               "2024-01-01T00:00:00Z",
							"so_detection.id":          "gQKCepgBAWAm-kn2lYs2",
							"so_detection.createTime":  "2024-11-14T15:03:22Z",
							"so_detection.userId":      "dcbe6004-f6e0-4579-9f98-9576201ffb29",
							"so_detection.publicId":    "923421c7-9b1e-45d4-80cc-e21d060c8723",
							"so_detection.title":       "Security Onion - Grid Node Login Failure (SSH)",
							"so_detection.severity":    "high",
							"so_detection.author":      "Security Onion Solutions",
							"so_detection.category":    "ps_script",
							"so_detection.description": "Detects when a user fails to login to a grid node via SSH. Review associated logs for username and source IP.",
							"so_detection.isEnabled":   true,
							"so_detection.isCommunity": true,
							"so_detection.engine":      "sigma",
							"so_detection.language":    "sigma",
							"so_detection.ruleset":     "__custom__",
							"so_detection.license":     "DRL",
						},
					},
					{
						Source: "so-detection-index",
						Id:     "detection-2",
						Payload: map[string]any{
							"@timestamp":               "2024-01-01T00:01:00Z",
							"so_detection.id":          "hRLDepgBAWAm-kn2mZt3",
							"so_detection.title":       "CobaltStrike Named Pipe",
							"so_detection.severity":    "critical",
							"so_detection.author":      "Community Contributor",
							"so_detection.category":    "malware",
							"so_detection.description": "Detects CobaltStrike named pipe usage",
							"so_detection.isEnabled":   false,
							"so_detection.isCommunity": false,
							"so_detection.language":    "suricata",
							"so_detection.product":     "windows",
							"so_detection.service":     "sshd",
						},
					},
				},
				TotalEvents: 2,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{
					"payload": map[string]any{
						"_id":                      "detection-1",
						"@timestamp":               "2024-01-01T00:00:00Z",
						"so_detection.id":          "gQKCepgBAWAm-kn2lYs2",
						"so_detection.createTime":  "2024-11-14T15:03:22Z",
						"so_detection.userId":      "dcbe6004-f6e0-4579-9f98-9576201ffb29",
						"so_detection.publicId":    "923421c7-9b1e-45d4-80cc-e21d060c8723",
						"so_detection.title":       "Security Onion - Grid Node Login Failure (SSH)",
						"so_detection.severity":    "high",
						"so_detection.author":      "Security Onion Solutions",
						"so_detection.category":    "ps_script",
						"so_detection.description": "Detects when a user fails to login to a grid node via SSH. Review associated logs for username and source IP.",
						"so_detection.isEnabled":   true,
						"so_detection.isCommunity": true,
						"so_detection.engine":      "sigma",
						"so_detection.language":    "sigma",
						"so_detection.ruleset":     "__custom__",
						"so_detection.license":     "DRL",
					},
				},
				{
					"payload": map[string]any{
						"_id":                      "detection-2",
						"@timestamp":               "2024-01-01T00:01:00Z",
						"so_detection.id":          "hRLDepgBAWAm-kn2mZt3",
						"so_detection.title":       "CobaltStrike Named Pipe",
						"so_detection.severity":    "critical",
						"so_detection.author":      "Community Contributor",
						"so_detection.category":    "malware",
						"so_detection.description": "Detects CobaltStrike named pipe usage",
						"so_detection.isEnabled":   false,
						"so_detection.isCommunity": false,
						"so_detection.language":    "suricata",
						"so_detection.product":     "windows",
						"so_detection.service":     "sshd",
					},
				},
			},
		},
		{
			name:   "query with relative time range",
			params: `{"oql_query": "so_detection.language:sigma AND _index:\"*:so-detection\" AND so_kind:detection", "range_start": "-999d", "range_end": "now", "limit": 5}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-detection-index",
						Id:     "detection-3",
						Payload: map[string]any{
							"@timestamp":            "2024-01-01T00:00:00Z",
							"so_detection.id":       "sigma-detection-1",
							"so_detection.title":    "Sigma Detection Rule",
							"so_detection.language": "sigma",
							"so_detection.severity": "medium",
							"so_detection.author":   "Sigma Community",
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{
					"payload": map[string]any{
						"_id":                   "detection-3",
						"@timestamp":            "2024-01-01T00:00:00Z",
						"so_detection.id":       "sigma-detection-1",
						"so_detection.title":    "Sigma Detection Rule",
						"so_detection.language": "sigma",
						"so_detection.severity": "medium",
						"so_detection.author":   "Sigma Community",
					},
				},
			},
		},
		{
			name:   "query with absolute time range",
			params: `{"oql_query": "so_detection.severity:critical AND _index:\"*:so-detection\" AND so_kind:detection", "range_start": "2024/01/01 10:00:00 AM", "range_end": "2024/01/01 11:00:00 AM", "limit": 15}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-detection-index",
						Id:     "detection-4",
						Payload: map[string]any{
							"@timestamp":            "2024-01-01T10:00:00Z",
							"so_detection.id":       "critical-detection-1",
							"so_detection.title":    "Critical Security Detection",
							"so_detection.severity": "critical",
							"so_detection.category": "malware",
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{
					"payload": map[string]any{
						"_id":                   "detection-4",
						"@timestamp":            "2024-01-01T10:00:00Z",
						"so_detection.id":       "critical-detection-1",
						"so_detection.title":    "Critical Security Detection",
						"so_detection.severity": "critical",
						"so_detection.category": "malware",
					},
				},
			},
		},
		{
			name:   "query with legacy query field",
			params: `{"query": "so_detection.engine:suricata AND _index:\"*:so-detection\" AND so_kind:detection", "limit": 12}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-detection-index",
						Id:     "detection-5",
						Payload: map[string]any{
							"@timestamp":            "2024-01-01T00:00:00Z",
							"so_detection.id":       "suricata-detection-1",
							"so_detection.title":    "Suricata Network Detection",
							"so_detection.engine":   "suricata",
							"so_detection.language": "suricata",
							"so_detection.category": "network",
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{
					"payload": map[string]any{
						"_id":                   "detection-5",
						"@timestamp":            "2024-01-01T00:00:00Z",
						"so_detection.id":       "suricata-detection-1",
						"so_detection.title":    "Suricata Network Detection",
						"so_detection.engine":   "suricata",
						"so_detection.language": "suricata",
						"so_detection.category": "network",
					},
				},
			},
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"oql_query": "invalid json}`,
			expectedError: true,
		},
		{
			name:          "eventstore error",
			params:        `{"oql_query": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "limit": 10}`,
			mockError:     assert.AnError,
			expectedError: true,
		},
		{
			name:   "no detections found",
			params: `{"oql_query": "so_detection.title:nonexistent AND _index:\"*:so-detection\" AND so_kind:detection", "limit": 10}`,
			mockResults: &model.EventSearchResults{
				Events:  []*model.EventRecord{},
				Metrics: make(map[string][]*model.EventMetric),
			},
			expectedResult: "No detections found",
		},
		{
			name:   "detection with all so_detection fields",
			params: `{"oql_query": "so_detection.ruleset:community AND _index:\"*:so-detection\" AND so_kind:detection", "limit": 5}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-detection-index",
						Id:     "detection-6",
						Payload: map[string]any{
							"@timestamp":                 "2024-01-01T00:00:00Z",
							"so_detection.id":            "comprehensive-detection-1",
							"so_detection.createTime":    "2024-11-14T15:03:22Z",
							"so_detection.userId":        "user-123",
							"so_detection.publicId":      "public-123",
							"so_detection.title":         "Comprehensive Detection Rule",
							"so_detection.severity":      "high",
							"so_detection.author":        "Security Team",
							"so_detection.category":      "endpoint",
							"so_detection.description":   "Comprehensive detection for testing",
							"so_detection.content":       "title: Test Rule\nid: test-123\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\\\test.exe'\n  condition: selection",
							"so_detection.isEnabled":     true,
							"so_detection.isCommunity":   false,
							"so_detection.engine":        "sigma",
							"so_detection.language":      "sigma",
							"so_detection.overrides":     []string{"override1", "override2"},
							"so_detection.tags":          []string{"test", "endpoint", "process"},
							"so_detection.ruleset":       "community",
							"so_detection.license":       "MIT",
							"so_detection.sourceCreated": "2024-01-01T00:00:00Z",
							"so_detection.sourceUpdated": "2024-01-01T12:00:00Z",
							"so_detection.product":       "windows",
							"so_detection.service":       "winlogbeat",
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{
					"payload": map[string]any{
						"_id":                        "detection-6",
						"@timestamp":                 "2024-01-01T00:00:00Z",
						"so_detection.id":            "comprehensive-detection-1",
						"so_detection.createTime":    "2024-11-14T15:03:22Z",
						"so_detection.userId":        "user-123",
						"so_detection.publicId":      "public-123",
						"so_detection.title":         "Comprehensive Detection Rule",
						"so_detection.severity":      "high",
						"so_detection.author":        "Security Team",
						"so_detection.category":      "endpoint",
						"so_detection.description":   "Comprehensive detection for testing",
						"so_detection.content":       "title: Test Rule\nid: test-123\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\\\test.exe'\n  condition: selection",
						"so_detection.isEnabled":     true,
						"so_detection.isCommunity":   false,
						"so_detection.engine":        "sigma",
						"so_detection.language":      "sigma",
						"so_detection.overrides":     []string{"override1", "override2"},
						"so_detection.tags":          []string{"test", "endpoint", "process"},
						"so_detection.ruleset":       "community",
						"so_detection.license":       "MIT",
						"so_detection.sourceCreated": "2024-01-01T00:00:00Z",
						"so_detection.sourceUpdated": "2024-01-01T12:00:00Z",
						"so_detection.product":       "windows",
						"so_detection.service":       "winlogbeat",
					},
				},
			},
		},
		{
			name:   "detection with custom limit",
			params: `{"oql_query": "so_detection.language:yara AND _index:\"*:so-detection\" AND so_kind:detection", "limit": 50}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "so-detection-index",
						Id:     "detection-7",
						Payload: map[string]any{
							"@timestamp":            "2024-01-01T00:00:00Z",
							"so_detection.id":       "yara-detection-1",
							"so_detection.title":    "YARA Malware Detection",
							"so_detection.language": "yara",
							"so_detection.severity": "medium",
							"so_detection.category": "malware",
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{
					"payload": map[string]any{
						"_id":                   "detection-7",
						"@timestamp":            "2024-01-01T00:00:00Z",
						"so_detection.id":       "yara-detection-1",
						"so_detection.title":    "YARA Malware Detection",
						"so_detection.language": "yara",
						"so_detection.severity": "medium",
						"so_detection.category": "malware",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mock detectionstore
			mockDetectionstore := mock.NewMockDetectionstore(ctrl)
			if tc.mockResults != nil || tc.mockError != nil {
				mockDetectionstore.EXPECT().
					QueryWithRange(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, query, rangeStart, rangeEnd, rangeFormat string, limit int) (*model.EventSearchResults, error) {
						// Verify the query contains the metadata filter
						if !assert.Contains(t, query, `NOT metadata.raw_index:"logs-soc-so"`) {
							t.Errorf("Query should contain metadata filter, got: %s", query)
						}
						if tc.mockError != nil {
							return nil, tc.mockError
						}
						return tc.mockResults, nil
					}).
					Times(1)
			}

			// Create mock server with proper authorization
			mockServer := server.NewFakeAuthorizedServer(map[string][]string{
				"test-user-id": {"detections/read"},
			})
			mockServer.Detectionstore = mockDetectionstore

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create tool and execute
			tool := &QueryDetectionsTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params, "")

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "query_detections", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)

			// Assert result content
			if tc.expectedResult != nil {
				if resultStr, ok := tc.expectedResult.(string); ok {
					// Handle string results (like "No detections found")
					assert.Equal(t, resultStr, result.Result)
				} else {
					// Handle detection results
					assert.Equal(t, tc.expectedResult, result.Result)
				}
			} else {
				assert.Nil(t, result.Result)
			}
		})
	}
}

func TestFilterDetections(t *testing.T) {
	testCases := []struct {
		name         string
		events       []*model.EventRecord
		extraFields  []string
		expectedLen  int
		validateFunc func(t *testing.T, result []map[string]any)
	}{
		{
			name: "basic detection with default fields",
			events: []*model.EventRecord{
				{
					Id:     "test-detection-1",
					Source: "so-detection-index",
					Payload: map[string]any{
						"@timestamp":               "2024-01-01T00:00:00Z",
						"so_detection.id":          "detection-id-1",
						"so_detection.title":       "Test Detection Rule",
						"so_detection.severity":    "high",
						"so_detection.author":      "Security Team",
						"so_detection.category":    "malware",
						"so_detection.description": "Test detection description",
						"so_detection.isEnabled":   true,
						"so_detection.language":    "sigma",
						"ignored_field":            "this should not appear",
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-detection-1", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "detection-id-1", payload["so_detection.id"])
				assert.Equal(t, "Test Detection Rule", payload["so_detection.title"])
				assert.Equal(t, "high", payload["so_detection.severity"])
				assert.Equal(t, "Security Team", payload["so_detection.author"])
				assert.Equal(t, "malware", payload["so_detection.category"])
				assert.Equal(t, "Test detection description", payload["so_detection.description"])
				assert.Equal(t, true, payload["so_detection.isEnabled"])
				assert.Equal(t, "sigma", payload["so_detection.language"])
				assert.NotContains(t, payload, "ignored_field")
			},
		},
		{
			name: "detection with all so_detection fields",
			events: []*model.EventRecord{
				{
					Id:     "test-detection-2",
					Source: "so-detection-index",
					Payload: map[string]any{
						"@timestamp":                 "2024-01-01T00:00:00Z",
						"so_detection.id":            "detection-id-2",
						"so_detection.createTime":    "2024-11-14T15:03:22Z",
						"so_detection.userId":        "user-456",
						"so_detection.publicId":      "public-456",
						"so_detection.title":         "Comprehensive Detection",
						"so_detection.severity":      "critical",
						"so_detection.author":        "Advanced Team",
						"so_detection.category":      "network",
						"so_detection.description":   "Advanced network detection",
						"so_detection.content":       "rule content here",
						"so_detection.isEnabled":     false,
						"so_detection.isCommunity":   true,
						"so_detection.engine":        "suricata",
						"so_detection.language":      "suricata",
						"so_detection.overrides":     []string{"override1"},
						"so_detection.tags":          []string{"network", "ids"},
						"so_detection.ruleset":       "community",
						"so_detection.license":       "GPL",
						"so_detection.sourceCreated": "2024-01-01T00:00:00Z",
						"so_detection.sourceUpdated": "2024-01-01T12:00:00Z",
						"so_detection.product":       "linux",
						"so_detection.service":       "suricata",
						"extra_field":                "should not appear",
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-detection-2", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "detection-id-2", payload["so_detection.id"])
				assert.Equal(t, "2024-11-14T15:03:22Z", payload["so_detection.createTime"])
				assert.Equal(t, "user-456", payload["so_detection.userId"])
				assert.Equal(t, "public-456", payload["so_detection.publicId"])
				assert.Equal(t, "Comprehensive Detection", payload["so_detection.title"])
				assert.Equal(t, "critical", payload["so_detection.severity"])
				assert.Equal(t, "Advanced Team", payload["so_detection.author"])
				assert.Equal(t, "network", payload["so_detection.category"])
				assert.Equal(t, "Advanced network detection", payload["so_detection.description"])
				assert.Equal(t, "rule content here", payload["so_detection.content"])
				assert.Equal(t, false, payload["so_detection.isEnabled"])
				assert.Equal(t, true, payload["so_detection.isCommunity"])
				assert.Equal(t, "suricata", payload["so_detection.engine"])
				assert.Equal(t, "suricata", payload["so_detection.language"])
				assert.Equal(t, []string{"override1"}, payload["so_detection.overrides"])
				assert.Equal(t, []string{"network", "ids"}, payload["so_detection.tags"])
				assert.Equal(t, "community", payload["so_detection.ruleset"])
				assert.Equal(t, "GPL", payload["so_detection.license"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["so_detection.sourceCreated"])
				assert.Equal(t, "2024-01-01T12:00:00Z", payload["so_detection.sourceUpdated"])
				assert.Equal(t, "linux", payload["so_detection.product"])
				assert.Equal(t, "suricata", payload["so_detection.service"])
				assert.NotContains(t, payload, "extra_field")
			},
		},
		{
			name: "detection with extra fields",
			events: []*model.EventRecord{
				{
					Id:     "test-detection-3",
					Source: "so-detection-index",
					Payload: map[string]any{
						"@timestamp":            "2024-01-01T00:00:00Z",
						"so_detection.id":       "detection-id-3",
						"so_detection.title":    "Custom Detection",
						"so_detection.severity": "medium",
						"custom_field1":         "custom_value1",
						"custom_field2":         "custom_value2",
						"ignored_field":         "ignored",
					},
				},
			},
			extraFields: []string{"custom_field1", "custom_field2"},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-detection-3", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "detection-id-3", payload["so_detection.id"])
				assert.Equal(t, "Custom Detection", payload["so_detection.title"])
				assert.Equal(t, "medium", payload["so_detection.severity"])
				assert.Equal(t, "custom_value1", payload["custom_field1"])
				assert.Equal(t, "custom_value2", payload["custom_field2"])
				assert.NotContains(t, payload, "ignored_field")
			},
		},
		{
			name: "multiple detections",
			events: []*model.EventRecord{
				{
					Id:     "test-detection-4",
					Source: "so-detection-index",
					Payload: map[string]any{
						"@timestamp":            "2024-01-01T00:00:00Z",
						"so_detection.id":       "detection-id-4",
						"so_detection.title":    "First Detection",
						"so_detection.severity": "high",
						"so_detection.language": "sigma",
					},
				},
				{
					Id:     "test-detection-5",
					Source: "so-detection-index",
					Payload: map[string]any{
						"@timestamp":            "2024-01-01T00:01:00Z",
						"so_detection.id":       "detection-id-5",
						"so_detection.title":    "Second Detection",
						"so_detection.severity": "low",
						"so_detection.language": "yara",
					},
				},
			},
			expectedLen: 2,
			validateFunc: func(t *testing.T, result []map[string]any) {
				assert.Equal(t, "test-detection-4", result[0]["payload"].(map[string]any)["_id"])
				assert.Equal(t, "test-detection-5", result[1]["payload"].(map[string]any)["_id"])
				assert.Equal(t, "First Detection", result[0]["payload"].(map[string]any)["so_detection.title"])
				assert.Equal(t, "Second Detection", result[1]["payload"].(map[string]any)["so_detection.title"])
				assert.Equal(t, "high", result[0]["payload"].(map[string]any)["so_detection.severity"])
				assert.Equal(t, "low", result[1]["payload"].(map[string]any)["so_detection.severity"])
				assert.Equal(t, "sigma", result[0]["payload"].(map[string]any)["so_detection.language"])
				assert.Equal(t, "yara", result[1]["payload"].(map[string]any)["so_detection.language"])
			},
		},
		{
			name: "missing fields",
			events: []*model.EventRecord{
				{
					Id:     "test-detection-6",
					Source: "so-detection-index",
					Payload: map[string]any{
						"@timestamp":            "2024-01-01T00:00:00Z",
						"so_detection.id":       "detection-id-6",
						"so_detection.title":    "Minimal Detection",
						"so_detection.severity": "medium",
						// Missing many default fields
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-detection-6", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "detection-id-6", payload["so_detection.id"])
				assert.Equal(t, "Minimal Detection", payload["so_detection.title"])
				assert.Equal(t, "medium", payload["so_detection.severity"])
				// Missing fields should not be present
				assert.NotContains(t, payload, "so_detection.description")
				assert.NotContains(t, payload, "so_detection.author")
			},
		},
		{
			name: "nil field values are excluded",
			events: []*model.EventRecord{
				{
					Id:     "test-detection-7",
					Source: "so-detection-index",
					Payload: map[string]any{
						"@timestamp":               "2024-01-01T00:00:00Z",
						"so_detection.id":          "detection-id-7",
						"so_detection.title":       "Detection with Nil Fields",
						"so_detection.severity":    "low",
						"so_detection.description": nil,
						"so_detection.author":      nil,
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-detection-7", payload["_id"])
				assert.Equal(t, "Detection with Nil Fields", payload["so_detection.title"])
				assert.Equal(t, "low", payload["so_detection.severity"])
				// Nil fields should not be included
				assert.NotContains(t, payload, "so_detection.description")
				assert.NotContains(t, payload, "so_detection.author")
			},
		},
		{
			name: "suricata detection with network fields",
			events: []*model.EventRecord{
				{
					Id:     "test-detection-9",
					Source: "so-detection-index",
					Payload: map[string]any{
						"@timestamp":            "2024-01-01T00:00:00Z",
						"so_detection.id":       "suricata-detection-1",
						"so_detection.title":    "Suricata Network Rule",
						"so_detection.language": "suricata",
						"so_detection.engine":   "suricata",
						"so_detection.severity": "medium",
						"so_detection.category": "network",
						"so_detection.product":  "linux",
						"so_detection.service":  "suricata",
						"so_detection.tags":     []string{"network", "intrusion"},
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-detection-9", payload["_id"])
				assert.Equal(t, "Suricata Network Rule", payload["so_detection.title"])
				assert.Equal(t, "suricata", payload["so_detection.language"])
				assert.Equal(t, "suricata", payload["so_detection.engine"])
				assert.Equal(t, "medium", payload["so_detection.severity"])
				assert.Equal(t, "network", payload["so_detection.category"])
				assert.Equal(t, "linux", payload["so_detection.product"])
				assert.Equal(t, "suricata", payload["so_detection.service"])
				assert.Equal(t, []string{"network", "intrusion"}, payload["so_detection.tags"])
			},
		},
		{
			name:        "empty detections list",
			events:      []*model.EventRecord{},
			expectedLen: 0,
			validateFunc: func(t *testing.T, result []map[string]any) {
				assert.Empty(t, result)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := filterDetections(tc.events, tc.extraFields...)

			assert.Len(t, result, tc.expectedLen)

			if tc.validateFunc != nil {
				tc.validateFunc(t, result)
			}
		})
	}
}

func TestQueryDetectionsTool_GetName(t *testing.T) {
	tool := &QueryDetectionsTool{}
	assert.Equal(t, "query_detections", tool.GetName())
}

func TestQueryDetectionsTool_GetDescription(t *testing.T) {
	tool := &QueryDetectionsTool{}
	desc := tool.GetDescription()
	assert.NotEmpty(t, desc)
}

func TestQueryDetectionsTool_GetSchema(t *testing.T) {
	tool := &QueryDetectionsTool{}
	schema := tool.GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Contains(t, schema.Json.Required, "oql_query")

	// Check that all expected properties are present
	expectedProperties := []string{"oql_query", "range_start", "range_end", "range_format", "limit"}
	for _, prop := range expectedProperties {
		assert.Contains(t, schema.Json.Properties, prop)
	}

	// Check oql_query property
	oqlQuery := schema.Json.Properties["oql_query"]
	assert.Equal(t, "string", oqlQuery.Type)

	// Check limit property
	limit := schema.Json.Properties["limit"]
	assert.Equal(t, "integer", limit.Type)
	assert.Equal(t, 100, limit.Default)
}
