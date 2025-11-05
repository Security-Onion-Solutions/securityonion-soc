// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestEscalateAlertsTool_GetName(t *testing.T) {
	tool := &EscalateAlertsTool{}
	assert.Equal(t, "escalate_alerts", tool.GetName())
}

func TestEscalateAlertsTool_GetDescription(t *testing.T) {
	desc := (&EscalateAlertsTool{}).GetDescription()
	assert.NotEmpty(t, desc)
}

func TestEscalateAlertsTool_GetSchema(t *testing.T) {
	schema := (&EscalateAlertsTool{}).GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Contains(t, schema.Json.Properties, "search_filter")
	assert.Equal(t, "string", schema.Json.Properties["search_filter"].Type)
	assert.Contains(t, schema.Json.Properties, "case_title")
	assert.Equal(t, "string", schema.Json.Properties["case_title"].Type)
	assert.Contains(t, schema.Json.Properties, "case_id")
	assert.Equal(t, "string", schema.Json.Properties["case_id"].Type)
	assert.Contains(t, schema.Json.Properties, "range_start")
	assert.Equal(t, "string", schema.Json.Properties["range_start"].Type)
	assert.Contains(t, schema.Json.Properties, "range_end")
	assert.Equal(t, "string", schema.Json.Properties["range_end"].Type)
	assert.Contains(t, schema.Json.Properties, "range_format")
	assert.Equal(t, "string", schema.Json.Properties["range_format"].Type)
	assert.Contains(t, schema.Json.Required, "search_filter")
}

func TestEscalateAlertsTool_Execute(t *testing.T) {
	testCases := []struct {
		name              string
		params            string
		mockSearchResults *model.EventSearchResults
		mockUpdateResults *model.EventUpdateResults
		mockCase          *model.Case
		mockError         error
		expectedResult    string
		expectedError     bool
		expectDateRange   bool
	}{
		{
			name:   "successful escalation with search filter",
			params: `{"search_filter": "soc_id:alert-123", "case_title": "Test Alert Case"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-123",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:00:00Z",
							"rule.name":  "Test Rule",
						},
					},
				},
			},
			mockUpdateResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			mockCase: &model.Case{
				Auditable: model.Auditable{
					Id: "case-123",
				},
				Title: "Test Alert Case",
			},
			expectedResult: `Successfully added 1 alert to case "Test Alert Case" (Id: case-123)`,
		},
		{
			name:   "no alerts found",
			params: `{"search_filter": "soc_id:nonexistent-alert", "case_title": "Empty Case"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{},
			},
			expectedResult: "No alerts found with that query. No case was created.",
		},
		{
			name:   "multiple alerts escalated",
			params: `{"search_filter": "rule.uuid:xyz", "case_title": "Multiple Alerts Case"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-1",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:00:00Z",
						},
					},
					{
						Id: "alert-2",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:01:00Z",
						},
					},
					{
						Id: "alert-3",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:02:00Z",
						},
					},
				},
			},
			mockUpdateResults: &model.EventUpdateResults{
				UpdatedCount: 3,
			},
			mockCase: &model.Case{
				Auditable: model.Auditable{
					Id: "case-456",
				},
				Title: "Multiple Alerts Case",
			},
			expectedResult: `Successfully added 3 alerts to case "Multiple Alerts Case" (Id: case-456)`,
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"search_filter": "missing closing brace"`,
			expectedError: true,
		},
		{
			name:   "eventstore error",
			params: `{"search_filter": "soc_id:alert-789", "case_title": "Error Case"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-789",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:00:00Z",
						},
					},
				},
			},
			mockError:     assert.AnError,
			expectedError: true,
		},
		{
			name:   "with range_start only (treated as relative)",
			params: `{"search_filter": "soc_id:alert-123", "case_title": "Test Case", "range_start": "-2h"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-123",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:00:00Z",
						},
					},
				},
			},
			mockUpdateResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			mockCase: &model.Case{
				Auditable: model.Auditable{
					Id: "case-123",
				},
				Title: "Test Case",
			},
			expectedResult:  `Successfully added 1 alert to case "Test Case" (Id: case-123)`,
			expectDateRange: true,
		},
		{
			name:   "with range_start, range_end and range_format",
			params: `{"search_filter": "soc_id:alert-123", "case_title": "Date Range Case", "range_start": "2024/12/03 02:31:35 PM", "range_end": "2024/12/04 02:31:35 PM", "range_format": "2006/01/02 3:04:05 PM"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-123",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:00:00Z",
						},
					},
					{
						Id: "alert-124",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:01:00Z",
						},
					},
				},
			},
			mockUpdateResults: &model.EventUpdateResults{
				UpdatedCount: 2,
			},
			mockCase: &model.Case{
				Auditable: model.Auditable{
					Id: "case-789",
				},
				Title: "Date Range Case",
			},
			expectedResult:  `Successfully added 2 alerts to case "Date Range Case" (Id: case-789)`,
			expectDateRange: true,
		},
		{
			name:   "with relative date range",
			params: `{"search_filter": "soc_id:alert-123", "case_title": "Relative Date Case", "range_start": "-1h", "range_end": "now"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-123",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:00:00Z",
						},
					},
				},
			},
			mockUpdateResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			mockCase: &model.Case{
				Auditable: model.Auditable{
					Id: "case-999",
				},
				Title: "Relative Date Case",
			},
			expectedResult:  `Successfully added 1 alert to case "Relative Date Case" (Id: case-999)`,
			expectDateRange: true,
		},
		{
			name:   "successful escalation with case_id",
			params: `{"search_filter": "soc_id:alert-456", "case_id": "existing-case-123"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-456",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:00:00Z",
							"rule.name":  "Existing Case Rule",
						},
					},
				},
			},
			mockUpdateResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			mockCase: &model.Case{
				Auditable: model.Auditable{
					Id: "existing-case-123",
				},
				Title: "Existing Case Title",
			},
			expectedResult: `Successfully added 1 alert to case "Existing Case Title" (Id: existing-case-123)`,
		},
		{
			name:   "multiple alerts escalated to existing case",
			params: `{"search_filter": "rule.uuid:existing-rule", "case_id": "existing-case-456"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-10",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T11:00:00Z",
						},
					},
					{
						Id: "alert-11",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T11:01:00Z",
						},
					},
				},
			},
			mockUpdateResults: &model.EventUpdateResults{
				UpdatedCount: 2,
			},
			mockCase: &model.Case{
				Auditable: model.Auditable{
					Id: "existing-case-456",
				},
				Title: "Multi Alert Existing Case",
			},
			expectedResult: `Successfully added 2 alerts to case "Multi Alert Existing Case" (Id: existing-case-456)`,
		},
		{
			name:   "case_id with date range",
			params: `{"search_filter": "soc_id:alert-789", "case_id": "existing-case-789", "range_start": "-3h", "range_end": "now"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-789",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T12:00:00Z",
						},
					},
				},
			},
			mockUpdateResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			mockCase: &model.Case{
				Auditable: model.Auditable{
					Id: "existing-case-789",
				},
				Title: "Date Range Existing Case",
			},
			expectedResult:  `Successfully added 1 alert to case "Date Range Existing Case" (Id: existing-case-789)`,
			expectDateRange: true,
		},
		{
			name:   "case_id not found error",
			params: `{"search_filter": "soc_id:alert-999", "case_id": "nonexistent-case"}`,
			mockSearchResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Id: "alert-999",
						Payload: map[string]interface{}{
							"@timestamp": "2024-12-04T10:00:00Z",
						},
					},
				},
			},
			mockError:     assert.AnError,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mock eventstore
			mockEventstore := server.NewFakeEventstore()
			if tc.mockSearchResults != nil {
				mockEventstore.SearchResults = []*model.EventSearchResults{tc.mockSearchResults}
			}
			if tc.mockUpdateResults != nil {
				mockEventstore.UpdateResults = []*model.EventUpdateResults{tc.mockUpdateResults}
			}
			if tc.mockError != nil {
				mockEventstore.Err = tc.mockError
			}

			// Create mock casestore
			mockCasestore := mock.NewMockCasestore(ctrl)

			// Only set up casestore expectations if we expect to create a case
			if !tc.expectedError && tc.mockSearchResults != nil && len(tc.mockSearchResults.Events) > 0 {
				// Parse params to determine if we're using case_id or case_title
				var args escalateAlertArgs
				json.Unmarshal([]byte(tc.params), &args)

				if args.CaseId != "" {
					// Expect GetCase call for existing case
					mockCasestore.EXPECT().
						GetCase(gomock.Any(), args.CaseId).
						Return(tc.mockCase, tc.mockError).
						Times(1)
				} else {
					// Expect Create call for new case
					mockCasestore.EXPECT().
						Create(gomock.Any(), gomock.Any()).
						Return(tc.mockCase, nil).
						Times(1)
				}

				// Expect CreateRelatedEvents call (only if GetCase/Create succeeds)
				if tc.mockError == nil {
					mockCasestore.EXPECT().
						CreateRelatedEvents(gomock.Any(), gomock.Any()).
						DoAndReturn(func(ctx context.Context, events []*model.RelatedEvent) (int, map[string]error, error) {
							return len(events), nil, nil
						}).
						Times(1)
				}
			}

			// Create mock server
			mockServer := &server.Server{
				Eventstore: mockEventstore,
				Casestore:  mockCasestore,
			}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create tool and execute
			tool := &EscalateAlertsTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params, "")

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "escalate_alerts", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.NotZero(t, result.TimeToExecute)

			// Verify search criteria was populated correctly
			if !tc.expectedError && tc.mockError == nil {
				assert.Len(t, mockEventstore.InputSearchCriterias, 1)
				searchCrit := mockEventstore.InputSearchCriterias[0]
				assert.NotNil(t, searchCrit)

				// Verify the search filter wraps the user's filter with base criteria
				assert.Contains(t, searchCrit.ParsedQuery.String(), "tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true")

				// Verify acknowledge criteria was populated correctly if alerts were found
				if tc.mockSearchResults != nil && len(tc.mockSearchResults.Events) > 0 {
					assert.Len(t, mockEventstore.InputAckCriterias, 1)
					ackCrit := mockEventstore.InputAckCriterias[0]
					assert.NotNil(t, ackCrit)
					assert.True(t, ackCrit.Acknowledge)
					assert.True(t, ackCrit.Escalate)
					assert.NotNil(t, ackCrit.EventFilter)
					assert.Equal(t, "alert", ackCrit.EventFilter["tags"])
				}

				// Verify date range fields were parsed correctly if specified
				// Note: The date range parameters are used to set BeginTime and EndTime
				if tc.expectDateRange {
					// Just verify that BeginTime and EndTime were set (not zero)
					assert.False(t, searchCrit.BeginTime.IsZero())
					assert.False(t, searchCrit.EndTime.IsZero())
				}
			}

			// Assert result content
			if tc.expectedResult != "" {
				assert.Equal(t, tc.expectedResult, result.Result)
			}

			// Verify parameters were captured
			if !tc.expectedError {
				assert.NotNil(t, result.Parameters)
				args, ok := result.Parameters.(*escalateAlertArgs)
				assert.True(t, ok)
				assert.NotNil(t, args)
			}
		})
	}
}

func TestEscalateAlertsTool_Execute_VerifyContextPropagation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// This test verifies that the context is properly passed to the eventstore and casestore
	mockEventstore := server.NewFakeEventstore()
	mockEventstore.SearchResults = []*model.EventSearchResults{
		{
			Events: []*model.EventRecord{
				{
					Id: "test-alert",
					Payload: map[string]interface{}{
						"@timestamp": "2024-12-04T10:00:00Z",
					},
				},
			},
		},
	}
	mockEventstore.UpdateResults = []*model.EventUpdateResults{
		{
			UpdatedCount: 1,
		},
	}

	mockCasestore := mock.NewMockCasestore(ctrl)
	mockCasestore.EXPECT().
		Create(gomock.Any(), gomock.Any()).
		Return(&model.Case{Auditable: model.Auditable{Id: "case-123"}, Title: "Test Case"}, nil).
		Times(1)
	mockCasestore.EXPECT().
		CreateRelatedEvents(gomock.Any(), gomock.Any()).
		Return(1, nil, nil).
		Times(1)

	mockServer := &server.Server{
		Eventstore: mockEventstore,
		Casestore:  mockCasestore,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	tool := &EscalateAlertsTool{}
	_, err := tool.Execute(ctx, mockServer, `{"search_filter": "soc_id:test-alert", "case_title": "Test Case"}`, "")

	assert.NoError(t, err)
	assert.Len(t, mockEventstore.InputContexts, 2) // Once for Search, once for Acknowledge

	// Verify the context contains the user ID
	contextUserId := mockEventstore.InputContexts[0].Value(web.ContextKeyRequestorId)
	assert.Equal(t, "test-user-123", contextUserId)
}

func TestEscalateAlertsTool_Execute_EmptySearchFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Test with empty string search_filter - this should result in an error
	// because the empty filter creates an invalid query during Populate
	mockEventstore := server.NewFakeEventstore()
	mockEventstore.SearchResults = []*model.EventSearchResults{
		{
			Events: []*model.EventRecord{},
		},
	}

	mockCasestore := mock.NewMockCasestore(ctrl)

	mockServer := &server.Server{
		Eventstore: mockEventstore,
		Casestore:  mockCasestore,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	tool := &EscalateAlertsTool{}
	result, err := tool.Execute(ctx, mockServer, `{"search_filter": "", "case_title": "Empty Filter Case"}`, "")

	// Empty search filter results in an error during query parsing
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestEscalateAlertsTool_Execute_ComplexQuery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Test with a complex search filter and multiple parameters
	mockEventstore := server.NewFakeEventstore()
	mockEventstore.SearchResults = []*model.EventSearchResults{
		{
			Events: []*model.EventRecord{
				{Id: "alert-1", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:00:00Z"}},
				{Id: "alert-2", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:01:00Z"}},
				{Id: "alert-3", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:02:00Z"}},
				{Id: "alert-4", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:03:00Z"}},
				{Id: "alert-5", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:04:00Z"}},
				{Id: "alert-6", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:05:00Z"}},
				{Id: "alert-7", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:06:00Z"}},
				{Id: "alert-8", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:07:00Z"}},
				{Id: "alert-9", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:08:00Z"}},
				{Id: "alert-10", Payload: map[string]interface{}{"@timestamp": "2024-12-04T10:09:00Z"}},
			},
		},
	}
	mockEventstore.UpdateResults = []*model.EventUpdateResults{
		{
			UpdatedCount: 10,
		},
	}

	mockCasestore := mock.NewMockCasestore(ctrl)
	mockCasestore.EXPECT().
		Create(gomock.Any(), gomock.Any()).
		Return(&model.Case{Auditable: model.Auditable{Id: "case-complex"}, Title: "Complex Phishing Case"}, nil).
		Times(1)
	mockCasestore.EXPECT().
		CreateRelatedEvents(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, events []*model.RelatedEvent) (int, map[string]error, error) {
			assert.Len(t, events, 10)
			return 10, nil, nil
		}).
		Times(1)

	mockServer := &server.Server{
		Eventstore: mockEventstore,
		Casestore:  mockCasestore,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	tool := &EscalateAlertsTool{}
	params := `{
		"search_filter": "rule.name:*phishing* AND event.severity:high",
		"case_title": "Complex Phishing Case",
		"range_start": "2024/12/01 12:00:00 PM",
		"range_end": "2024/12/07 12:00:00 PM",
		"range_format": "2006/01/02 3:04:05 PM"
	}`
	result, err := tool.Execute(ctx, mockServer, params, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, `Successfully added 10 alerts to case "Complex Phishing Case" (Id: case-complex)`, result.Result)

	// Verify all search criteria fields were populated correctly
	assert.Len(t, mockEventstore.InputSearchCriterias, 1)
	searchCrit := mockEventstore.InputSearchCriterias[0]
	assert.Contains(t, searchCrit.ParsedQuery.String(), "tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true")
	assert.Contains(t, searchCrit.ParsedQuery.String(), "rule.name:*phishing* AND event.severity:high")
	// Verify date range was parsed correctly
	assert.False(t, searchCrit.BeginTime.IsZero())
	assert.False(t, searchCrit.EndTime.IsZero())

	// Verify acknowledge criteria
	assert.Len(t, mockEventstore.InputAckCriterias, 1)
	ackCrit := mockEventstore.InputAckCriterias[0]
	assert.True(t, ackCrit.Acknowledge)
	assert.True(t, ackCrit.Escalate)
	assert.Equal(t, "alert", ackCrit.EventFilter["tags"])
}

func TestEscalateAlertsTool_Execute_NoAlertsEscalated(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Test when alerts are found but none get escalated (UpdatedCount = 0)
	mockEventstore := server.NewFakeEventstore()
	mockEventstore.SearchResults = []*model.EventSearchResults{
		{
			Events: []*model.EventRecord{
				{
					Id: "alert-123",
					Payload: map[string]interface{}{
						"@timestamp": "2024-12-04T10:00:00Z",
					},
				},
			},
		},
	}
	mockEventstore.UpdateResults = []*model.EventUpdateResults{
		{
			UpdatedCount: 0,
		},
	}

	mockCasestore := mock.NewMockCasestore(ctrl)
	mockCasestore.EXPECT().
		Create(gomock.Any(), gomock.Any()).
		Return(&model.Case{Auditable: model.Auditable{Id: "case-123"}, Title: "Test Case"}, nil).
		Times(1)
	mockCasestore.EXPECT().
		CreateRelatedEvents(gomock.Any(), gomock.Any()).
		Return(1, nil, nil).
		Times(1)

	mockServer := &server.Server{
		Eventstore: mockEventstore,
		Casestore:  mockCasestore,
	}

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user")

	tool := &EscalateAlertsTool{}
	result, err := tool.Execute(ctx, mockServer, `{"search_filter": "soc_id:alert-123", "case_title": "Test Case"}`, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "No case was created", result.Result)
}
