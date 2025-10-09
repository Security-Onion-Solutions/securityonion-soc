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

func TestAckAlertTool_GetName(t *testing.T) {
	tool := &AckAlertTool{}
	assert.Equal(t, "ack_alert", tool.GetName())
}

func TestAckAlertTool_GetDescription(t *testing.T) {
	desc := (&AckAlertTool{}).GetDescription()
	assert.NotEmpty(t, desc)
}

func TestAckAlertTool_GetSchema(t *testing.T) {
	schema := (&AckAlertTool{}).GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Contains(t, schema.Json.Properties, "alert_id")
	assert.Equal(t, "string", schema.Json.Properties["alert_id"].Type)
	assert.Contains(t, schema.Json.Required, "alert_id")
}

func TestAckAlertTool_Execute(t *testing.T) {
	testCases := []struct {
		name           string
		params         string
		mockResults    *model.EventUpdateResults
		mockError      error
		expectedResult string
		expectedError  bool
	}{
		{
			name:   "successful acknowledgment",
			params: `{"alert_id": "alert-123"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			expectedResult: "Success",
		},
		{
			name:   "no alert modified",
			params: `{"alert_id": "nonexistent-alert"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 0,
			},
			expectedResult: "No alert was modified",
		},
		{
			name:   "multiple alerts acknowledged",
			params: `{"alert_id": "alert-456"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 5,
			},
			expectedResult: "Success",
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"alert_id": "missing closing brace"`,
			expectedError: true,
		},
		{
			name:   "missing required alert_id field",
			params: `{}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 0,
			},
			expectedResult: "No alert was modified",
		},
		{
			name:          "eventstore error",
			params:        `{"alert_id": "alert-789"}`,
			mockError:     assert.AnError,
			expectedError: true,
		},
		{
			name:   "alert with special characters in ID",
			params: `{"alert_id": "alert-with-special-chars-!@#$%"}`,
			mockResults: &model.EventUpdateResults{
				UpdatedCount: 1,
			},
			expectedResult: "Success",
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
			tool := &AckAlertTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params)

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "ack_alert", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.NotZero(t, result.TimeToExecute)

			// Verify acknowledge criteria was populated correctly
			if !tc.expectedError && tc.mockError == nil {
				assert.Len(t, mockEventstore.InputAckCriterias, 1)
				criteria := mockEventstore.InputAckCriterias[0]
				assert.NotNil(t, criteria)
				assert.True(t, criteria.Acknowledge)
				assert.Equal(t, "tags:alert AND NOT event.acknowledged:true AND NOT event.escalated:true", criteria.SearchFilter)
				assert.NotNil(t, criteria.EventFilter)

				// Verify the alert_id was passed correctly in the event filter
				if tc.params != `{}` { // Skip for missing alert_id test case
					expectedAlertId := ""
					switch tc.name {
					case "successful acknowledgment":
						expectedAlertId = "alert-123"
					case "no alert modified":
						expectedAlertId = "nonexistent-alert"
					case "multiple alerts acknowledged":
						expectedAlertId = "alert-456"
					case "alert with special characters in ID":
						expectedAlertId = "alert-with-special-chars-!@#$%"
					}
					if expectedAlertId != "" {
						assert.Equal(t, expectedAlertId, criteria.EventFilter["soc_id"])
					}
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

func TestAckAlertTool_Execute_VerifyContextPropagation(t *testing.T) {
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

	tool := &AckAlertTool{}
	_, err := tool.Execute(ctx, mockServer, `{"alert_id": "test-alert"}`)

	assert.NoError(t, err)
	assert.Len(t, mockEventstore.InputContexts, 1)

	// Verify the context contains the user ID
	contextUserId := mockEventstore.InputContexts[0].Value(web.ContextKeyRequestorId)
	assert.Equal(t, "test-user-123", contextUserId)
}

func TestAckAlertTool_Execute_EmptyAlertId(t *testing.T) {
	// Test with empty string alert_id
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

	tool := &AckAlertTool{}
	result, err := tool.Execute(ctx, mockServer, `{"alert_id": ""}`)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "No alert was modified", result.Result)

	// Verify empty string was still passed to eventstore
	assert.Len(t, mockEventstore.InputAckCriterias, 1)
	criteria := mockEventstore.InputAckCriterias[0]
	assert.Equal(t, "", criteria.EventFilter["soc_id"])
}
