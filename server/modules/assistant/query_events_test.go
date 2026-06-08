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

func TestQueryEventsTool_Execute(t *testing.T) {
	testCases := []struct {
		name           string
		params         string
		mockResults    *model.EventSearchResults
		mockError      error
		expectedResult any
		expectedError  bool
	}{
		{
			name:   "basic query without groupby",
			params: `{"oql_query": "tags:alert", "limit": 10}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{Source: "test-index", Id: "alert-1", Payload: map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "tags": []string{"alert"}}},
					{Source: "test-index", Id: "alert-2", Payload: map[string]any{"@timestamp": "2024-01-01T00:01:00Z", "tags": []string{"alert"}}},
				},
				TotalEvents: 2,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{"payload": map[string]any{"_id": "alert-1", "@timestamp": "2024-01-01T00:00:00Z", "tags": []string{"alert"}}},
				{"payload": map[string]any{"_id": "alert-2", "@timestamp": "2024-01-01T00:01:00Z", "tags": []string{"alert"}}},
			},
		},
		{
			name:   "query with groupby field",
			params: `{"oql_query": "tags:alert", "groupby_field": "rule.name", "limit": 5}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{},
				Metrics: map[string][]*model.EventMetric{
					"groupby_rule.name": {
						{Keys: []any{[]any{"ET SCAN Port 0 Traffic"}}, Value: 25},
						{Keys: []any{[]any{"ET MALWARE Suspicious"}}, Value: 15},
					},
				},
				TotalEvents: 40,
			},
			expectedResult: []map[string]any{
				{"rule.name": "ET SCAN Port 0 Traffic", "count": 25},
				{"rule.name": "ET MALWARE Suspicious", "count": 15},
			},
		},
		{
			name:   "query with relative time range",
			params: `{"oql_query": "tags:dns", "start_time": "-1h", "end_time": "now", "limit": 20}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{Source: "dns-index", Id: "dns-1", Payload: map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "dns.query.name": "example.com"}},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{"payload": map[string]any{"_id": "dns-1", "@timestamp": "2024-01-01T00:00:00Z", "dns.query.name": "example.com"}},
			},
		},
		{
			name:   "query with absolute time range",
			params: `{"oql_query": "tags:dns", "start_time": "2024-01-01 00:00:00", "end_time": "2024/01/01 01:00:00", "limit": 20}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{Source: "dns-index", Id: "dns-1", Payload: map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "dns.query.name": "example.com"}},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{"payload": map[string]any{"_id": "dns-1", "@timestamp": "2024-01-01T00:00:00Z", "dns.query.name": "example.com"}},
			},
		},
		{
			name:   "query with legacy query field",
			params: `{"query": "tags:conn", "limit": 15}`,
			mockResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{Source: "conn-index", Id: "conn-1", Payload: map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "source.ip": "192.168.1.1", "destination.ip": "192.168.1.2"}},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedResult: []map[string]any{
				{"payload": map[string]any{"_id": "conn-1", "@timestamp": "2024-01-01T00:00:00Z", "source.ip": "192.168.1.1", "destination.ip": "192.168.1.2"}},
			},
		},
		{
			name:   "groupby with no matching metrics",
			params: `{"oql_query": "tags:alert", "groupby_field": "nonexistent.field", "limit": 5}`,
			mockResults: &model.EventSearchResults{
				Events:  []*model.EventRecord{},
				Metrics: make(map[string][]*model.EventMetric),
			},
			expectedResult: make(map[string][]*model.EventMetric),
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"oql_query": "invalid json}`,
			expectedError: true,
		},
		{
			name:          "eventstore error",
			params:        `{"oql_query": "tags:alert", "limit": 10}`,
			mockError:     assert.AnError,
			expectedError: true,
		},
		{
			name:   "no events found",
			params: `{"oql_query": "tags:alert", "limit": 10}`,
			mockResults: &model.EventSearchResults{
				Events:  []*model.EventRecord{},
				Metrics: make(map[string][]*model.EventMetric),
			},
			expectedResult: "No events found",
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
			tool := &QueryEventsTool{}
			result, err := tool.Execute(ctx, mockServer, &model.ToolRequest{Params: json.RawMessage(tc.params)})

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "query_events", result.ToolName)
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
				assert.Equal(t, tc.expectedResult, result.Result)
			} else {
				assert.Nil(t, result.Result)
			}
		})
	}
}

func TestFilterEvents(t *testing.T) {
	testCases := []struct {
		name         string
		events       []*model.EventRecord
		extraFields  []string
		expectedLen  int
		validateFunc func(t *testing.T, result []map[string]any)
	}{
		{
			name: "basic event with default fields",
			events: []*model.EventRecord{
				{
					Id:     "test-id-1",
					Source: "test-index",
					Payload: map[string]any{
						"@timestamp":     "2024-01-01T00:00:00Z",
						"source.ip":      "192.168.1.1",
						"destination.ip": "10.0.0.1",
						"tags":           []string{"alert", "malware"},
						"rule.name":      "ET MALWARE Suspicious",
						"ignored_field":  "this should not appear",
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				assert.Equal(t, "test-id-1", result[0]["payload"].(map[string]any)["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", result[0]["payload"].(map[string]any)["@timestamp"])
				assert.Equal(t, "192.168.1.1", result[0]["payload"].(map[string]any)["source.ip"])
				assert.Equal(t, "10.0.0.1", result[0]["payload"].(map[string]any)["destination.ip"])
				assert.Equal(t, []string{"alert", "malware"}, result[0]["payload"].(map[string]any)["tags"])
				assert.Equal(t, "ET MALWARE Suspicious", result[0]["payload"].(map[string]any)["rule.name"])
				assert.NotContains(t, result[0]["payload"].(map[string]any), "ignored_field")
			},
		},
		{
			name: "nested fields",
			events: []*model.EventRecord{
				{
					Id:     "test-id-2",
					Source: "test-index",
					Payload: map[string]any{
						"@timestamp": "2024-01-01T00:00:00Z",
						"destination": map[string]any{
							"ip":   "10.0.0.1",
							"port": 443,
							"geo": map[string]any{
								"country_name": "United States",
							},
						},
						"source": map[string]any{
							"ip": "192.168.1.1",
							"geo": map[string]any{
								"country_name": "Canada",
							},
						},
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-id-2", payload["_id"])

				// Check nested destination fields
				dest := payload["destination"].(map[string]any)
				assert.Equal(t, "10.0.0.1", dest["ip"])
				assert.Equal(t, 443, dest["port"])
				destGeo := dest["geo"].(map[string]any)
				assert.Equal(t, "United States", destGeo["country_name"])

				// Check nested source fields
				src := payload["source"].(map[string]any)
				assert.Equal(t, "192.168.1.1", src["ip"])
				srcGeo := src["geo"].(map[string]any)
				assert.Equal(t, "Canada", srcGeo["country_name"])
			},
		},
		{
			name: "event with extra fields",
			events: []*model.EventRecord{
				{
					Id:     "test-id-3",
					Source: "test-index",
					Payload: map[string]any{
						"@timestamp": "2024-01-01T00:00:00Z",
						"custom": map[string]any{
							"field1": "value1",
							"field2": "value2",
						},
						"ignored_field": "ignored",
					},
				},
			},
			extraFields: []string{"custom.field1", "custom.field2"},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-id-3", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])

				// Check extra fields are included
				custom := payload["custom"].(map[string]any)
				assert.Equal(t, "value1", custom["field1"])
				assert.Equal(t, "value2", custom["field2"])

				// Check ignored field is not included
				assert.NotContains(t, payload, "ignored_field")
			},
		},
		{
			name: "multiple events",
			events: []*model.EventRecord{
				{
					Id:     "test-id-4",
					Source: "test-index",
					Payload: map[string]any{
						"@timestamp": "2024-01-01T00:00:00Z",
						"source.ip":  "192.168.1.1",
						"tags":       []string{"conn"},
					},
				},
				{
					Id:     "test-id-5",
					Source: "test-index",
					Payload: map[string]any{
						"@timestamp": "2024-01-01T00:01:00Z",
						"source.ip":  "192.168.1.2",
						"tags":       []string{"dns"},
					},
				},
			},
			expectedLen: 2,
			validateFunc: func(t *testing.T, result []map[string]any) {
				assert.Equal(t, "test-id-4", result[0]["payload"].(map[string]any)["_id"])
				assert.Equal(t, "test-id-5", result[1]["payload"].(map[string]any)["_id"])
				assert.Equal(t, "192.168.1.1", result[0]["payload"].(map[string]any)["source.ip"])
				assert.Equal(t, "192.168.1.2", result[1]["payload"].(map[string]any)["source.ip"])
			},
		},
		{
			name: "missing fields",
			events: []*model.EventRecord{
				{
					Id:     "test-id-6",
					Source: "test-index",
					Payload: map[string]any{
						"@timestamp": "2024-01-01T00:00:00Z",
						"source.ip":  "192.168.1.1",
						// Missing many default fields
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-id-6", payload["_id"])
				assert.Equal(t, "2024-01-01T00:00:00Z", payload["@timestamp"])
				assert.Equal(t, "192.168.1.1", payload["source.ip"])
				// Missing fields should not be present
				assert.NotContains(t, payload, "destination.ip")
				assert.NotContains(t, payload, "rule.name")
			},
		},
		{
			name: "nil field values are excluded",
			events: []*model.EventRecord{
				{
					Id:     "test-id-7",
					Source: "test-index",
					Payload: map[string]any{
						"@timestamp":     "2024-01-01T00:00:00Z",
						"source.ip":      "192.168.1.1",
						"destination.ip": nil,
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-id-7", payload["_id"])
				assert.Equal(t, "192.168.1.1", payload["source.ip"])
				// Nil field should not be included
				assert.NotContains(t, payload, "destination.ip")
			},
		},
		{
			name: "dns event with multiple field formats",
			events: []*model.EventRecord{
				{
					Id:     "test-id-8",
					Source: "dns-index",
					Payload: map[string]any{
						"@timestamp": "2024-01-01T00:00:00Z",
						"tags":       []string{"dns"},
						"dns": map[string]any{
							"query": map[string]any{
								"name": "example.com",
							},
							"query_name": "alternative.com",
						},
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				// Both dns field formats should be present
				dns := payload["dns"].(map[string]any)
				assert.Equal(t, "alternative.com", dns["query_name"])
				query := dns["query"].(map[string]any)
				assert.Equal(t, "example.com", query["name"])
			},
		},
		{
			name: "comprehensive security event",
			events: []*model.EventRecord{
				{
					Id:     "test-id-9",
					Source: "alert-index",
					Payload: map[string]any{
						"@timestamp": "2024-01-01T00:00:00Z",
						"tags":       []string{"alert", "ids"},
						"source": map[string]any{
							"ip":   "192.168.1.100",
							"port": 45678,
						},
						"destination": map[string]any{
							"ip":   "10.0.0.1",
							"port": 443,
						},
						"network": map[string]any{
							"protocol":     "TLS",
							"transport":    "tcp",
							"community_id": "1:abc123",
						},
						"rule": map[string]any{
							"name":     "ET MALWARE Suspicious Connection",
							"category": "Malware",
							"uuid":     "abc-123-def",
						},
						"event": map[string]any{
							"severity":       2,
							"severity_label": "high",
						},
						"log": map[string]any{
							"id": map[string]any{
								"uid": "uid123",
							},
						},
						"observer": map[string]any{
							"name": "sensor1",
						},
						"some": map[string]any{
							"random": map[string]any{
								"field": "not included",
							},
						},
					},
				},
			},
			expectedLen: 1,
			validateFunc: func(t *testing.T, result []map[string]any) {
				payload := result[0]["payload"].(map[string]any)
				assert.Equal(t, "test-id-9", payload["_id"])
				assert.Equal(t, []string{"alert", "ids"}, payload["tags"])

				// Check nested source fields
				source := payload["source"].(map[string]any)
				assert.Equal(t, "192.168.1.100", source["ip"])
				assert.Equal(t, 45678, source["port"])

				// Check nested destination fields
				destination := payload["destination"].(map[string]any)
				assert.Equal(t, "10.0.0.1", destination["ip"])
				assert.Equal(t, 443, destination["port"])

				// Check nested network fields
				network := payload["network"].(map[string]any)
				assert.Equal(t, "TLS", network["protocol"])
				assert.Equal(t, "tcp", network["transport"])
				assert.Equal(t, "1:abc123", network["community_id"])

				// Check nested rule fields
				rule := payload["rule"].(map[string]any)
				assert.Equal(t, "ET MALWARE Suspicious Connection", rule["name"])
				assert.Equal(t, "Malware", rule["category"])
				assert.Equal(t, "abc-123-def", rule["uuid"])

				// Check event fields
				event := payload["event"].(map[string]any)
				assert.Equal(t, 2, event["severity"])
				assert.Equal(t, "high", event["severity_label"])

				// Check log ID and observer
				log := payload["log"].(map[string]any)
				logID := log["id"].(map[string]any)
				assert.Equal(t, "uid123", logID["uid"])

				observer := payload["observer"].(map[string]any)
				assert.Equal(t, "sensor1", observer["name"])

				// Verify random field is not included
				assert.NotContains(t, payload, "some")
			},
		},
		{
			name:        "empty events list",
			events:      []*model.EventRecord{},
			expectedLen: 0,
			validateFunc: func(t *testing.T, result []map[string]any) {
				assert.Empty(t, result)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := filterEvents(tc.events, tc.extraFields...)

			assert.Len(t, result, tc.expectedLen)

			if tc.validateFunc != nil {
				tc.validateFunc(t, result)
			}
		})
	}
}
