// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
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
				{"payload": map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "tags": []string{"alert"}}},
				{"payload": map[string]any{"@timestamp": "2024-01-01T00:01:00Z", "tags": []string{"alert"}}},
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
				{"payload": map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "dns.query.name": "example.com"}},
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
				{"payload": map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "dns.query.name": "example.com"}},
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
				{"payload": map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "source.ip": "192.168.1.1", "destination.ip": "192.168.1.2"}},
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
			result, err := tool.Execute(ctx, mockServer, tc.params)

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
