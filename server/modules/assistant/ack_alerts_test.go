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

func TestAckAlertsTool_GetName(t *testing.T) {
	tool := &AckAlertsTool{}
	assert.Equal(t, "ack_alerts", tool.GetName())
}

func TestAckAlertsTool_GetDescription(t *testing.T) {
	desc := (&AckAlertsTool{}).GetDescription()
	assert.NotEmpty(t, desc)
}

func TestAckAlertsTool_GetSchema(t *testing.T) {
	schema := (&AckAlertsTool{}).GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Contains(t, schema.Json.Properties, "search_filter")
	assert.Equal(t, "string", schema.Json.Properties["search_filter"].Type)
	assert.Contains(t, schema.Json.Properties, "event_filter")
	assert.Equal(t, "object", schema.Json.Properties["event_filter"].Type)
	assert.Contains(t, schema.Json.Properties, "date_range")
	assert.Contains(t, schema.Json.Properties, "date_range_format")
	assert.Contains(t, schema.Json.Properties, "timezone")
	assert.Contains(t, schema.Json.Required, "search_filter")
}

func TestAckAlertsTool_Execute(t *testing.T) {
	testCases := []struct {
		name                    string
		params                  string
		mockResults             *model.EventUpdateResults
		mockError               error
		expectedResult          string
		expectedError           bool
		expectedEventFilter     map[string]any
		expectedDateRange       string
		expectedDateRangeFormat string
		expectedTimezone        string
	}{
		{
			name:   "successful acknowledgment with search filter",
			params: `{"search_filter": "soc_id:alert-123"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			expectedResult: "1 eligible alert were successfully acknowledged",
		},
		{
			name:   "no alert modified",
			params: `{"search_filter": "soc_id:nonexistent-alert"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 0,
			},
			expectedResult: "No alert was modified",
		},
		{
			name:   "multiple alerts acknowledged",
			params: `{"search_filter": "rule.uuid:xyz"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 5,
			},
			expectedResult: "5 eligible alerts were successfully acknowledged",
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"search_filter": "missing closing brace"`,
			expectedError: true,
		},
		{
			name:          "eventstore error",
			params:        `{"search_filter": "soc_id:alert-789"}`,
			mockError:     assert.AnError,
			expectedError: true,
		},
		{
			name:   "search filter with wildcards",
			params: `{"search_filter": "rule.name:*phishing*"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 3,
			},
			expectedResult: "3 eligible alerts were successfully acknowledged",
		},
		{
			name:   "with event filter",
			params: `{"search_filter": "soc_id:alert-123", "event_filter": {"rule.uuid": "test-uuid"}}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			expectedResult:      "1 eligible alert were successfully acknowledged",
			expectedEventFilter: map[string]any{"rule.uuid": "test-uuid"},
		},
		{
			name:          "with date range but no date_range_format",
			params:        `{"search_filter": "soc_id:alert-123", "date_range": "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM"}`,
			expectedError: true,
		},
		{
			name:   "with date range and date_range_format",
			params: `{"search_filter": "soc_id:alert-123", "date_range": "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM", "date_range_format": "2006/01/02 3:04:05 PM"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 2,
			},
			expectedResult:          "2 eligible alerts were successfully acknowledged",
			expectedDateRange:       "2024/12/03 02:31:35 PM - 2024/12/04 02:31:35 PM",
			expectedDateRangeFormat: "2006/01/02 3:04:05 PM",
		},
		{
			name:   "with timezone",
			params: `{"search_filter": "soc_id:alert-123", "timezone": "America/New_York"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			expectedResult:   "1 eligible alert were successfully acknowledged",
			expectedTimezone: "America/New_York",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock eventstore
			mockEventstore := server.NewFakeEventstore()
			if tc.mockResults != nil {
				mockEventstore.UpdateResults = []*model.EventUpdateResults{tc.mockResults}
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
			tool := &AckAlertsTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params)

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "ack_alerts", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.NotZero(t, result.TimeToExecute)

			// Verify acknowledge criteria was populated correctly
			if !tc.expectedError && tc.mockError == nil {
				assert.Len(t, mockEventstore.InputAckCriterias, 1)
				criteria := mockEventstore.InputAckCriterias[0]
				assert.NotNil(t, criteria)
				assert.True(t, criteria.Acknowledge)

				// Verify the search filter wraps the user's filter with base criteria
				assert.Contains(t, criteria.SearchFilter, "tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true")

				// Verify event filter
				assert.NotNil(t, criteria.EventFilter)

				// Verify expected event filter if specified
				if tc.expectedEventFilter != nil {
					for key, expectedValue := range tc.expectedEventFilter {
						assert.Equal(t, expectedValue, criteria.EventFilter[key])
					}
				} else {
					// Default event filter should have tags:alert
					assert.Equal(t, "alert", criteria.EventFilter["tags"])
				}

				// Verify date range fields if specified
				if tc.expectedDateRange != "" {
					assert.Equal(t, tc.expectedDateRange, criteria.DateRange)
				}

				if tc.expectedDateRangeFormat != "" {
					assert.Equal(t, tc.expectedDateRangeFormat, criteria.DateRangeFormat)
				}

				if tc.expectedTimezone != "" {
					assert.Equal(t, tc.expectedTimezone, criteria.Timezone)
				}
			}

			// Assert result content
			if tc.expectedResult != "" {
				assert.Equal(t, tc.expectedResult, result.Result)
			}

			// Verify parameters were captured
			if !tc.expectedError {
				assert.NotNil(t, result.Parameters)
				args, ok := result.Parameters.(*ackAlertArgs)
				assert.True(t, ok)
				assert.NotNil(t, args)
			}
		})
	}
}

func TestAckAlertsTool_Execute_VerifyContextPropagation(t *testing.T) {
	// This test verifies that the context is properly passed to the eventstore
	mockEventstore := server.NewFakeEventstore()
	mockEventstore.UpdateResults = []*model.EventUpdateResults{
		{
			UpdatedCount: 1,
		},
	}

	mockServer := &server.Server{
		Eventstore: mockEventstore,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	tool := &AckAlertsTool{}
	_, err := tool.Execute(ctx, mockServer, `{"search_filter": "soc_id:test-alert"}`)

	assert.NoError(t, err)
	assert.Len(t, mockEventstore.InputContexts, 1)

	// Verify the context contains the user ID
	contextUserId := mockEventstore.InputContexts[0].Value(web.ContextKeyRequestorId)
	assert.Equal(t, "test-user-123", contextUserId)
}

func TestAckAlertTool_Execute_EmptySearchFilter(t *testing.T) {
	// Test with empty string search_filter
	mockEventstore := server.NewFakeEventstore()
	mockEventstore.UpdateResults = []*model.EventUpdateResults{
		{
			UpdatedCount: 0,
		},
	}

	mockServer := &server.Server{
		Eventstore: mockEventstore,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	tool := &AckAlertsTool{}
	result, err := tool.Execute(ctx, mockServer, `{"search_filter": ""}`)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "No alert was modified", result.Result)

	// Verify empty string was still passed to eventstore
	assert.Len(t, mockEventstore.InputAckCriterias, 1)
	criteria := mockEventstore.InputAckCriterias[0]
	assert.Equal(t, "(tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true) AND ()", criteria.SearchFilter)
}

func TestAckAlertsTool_Execute_ComplexQuery(t *testing.T) {
	// Test with a complex search filter and multiple parameters
	mockEventstore := server.NewFakeEventstore()
	mockEventstore.UpdateResults = []*model.EventUpdateResults{
		{
			UpdatedCount: 10,
		},
	}

	mockServer := &server.Server{
		Eventstore: mockEventstore,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	tool := &AckAlertsTool{}
	params := `{
		"search_filter": "rule.name:*phishing* AND event.severity:high",
		"event_filter": {"source.ip": "192.168.1.1", "destination.port": 443},
		"date_range": "2024/12/01 12:00:00 PM - 2024/12/07 12:00:00 PM",
		"date_range_format": "2006/01/02 3:04:05 PM",
		"timezone": "America/New_York"
	}`
	result, err := tool.Execute(ctx, mockServer, params)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "10 eligible alerts were successfully acknowledged", result.Result)

	// Verify all criteria fields were populated correctly
	assert.Len(t, mockEventstore.InputAckCriterias, 1)
	criteria := mockEventstore.InputAckCriterias[0]
	assert.True(t, criteria.Acknowledge)
	assert.Equal(t, "(tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true) AND (rule.name:*phishing* AND event.severity:high)", criteria.SearchFilter)
	assert.Equal(t, "192.168.1.1", criteria.EventFilter["source.ip"])
	assert.Equal(t, float64(443), criteria.EventFilter["destination.port"])
	assert.Equal(t, "2024/12/01 12:00:00 PM - 2024/12/07 12:00:00 PM", criteria.DateRange)
	assert.Equal(t, "2006/01/02 3:04:05 PM", criteria.DateRangeFormat)
	assert.Equal(t, "America/New_York", criteria.Timezone)
}
