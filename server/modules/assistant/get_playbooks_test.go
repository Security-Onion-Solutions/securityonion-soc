// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetPlaybooksTool_Execute(t *testing.T) {
	testCases := []struct {
		name                   string
		params                 string
		mockEventResults       *model.EventSearchResults
		mockEventError         error
		mockDetection          *model.Detection
		mockDetectionError     error
		mockPlaybooks          []*model.Playbook
		mockPlaybookError      error
		mockExecuteSearchError error
		expectedResult         any
		expectedError          bool
	}{
		{
			name:   "successful playbook questions retrieval",
			params: `{"alert_id": "alert-123"}`,
			mockEventResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "test-index",
						Id:     "alert-123",
						Payload: map[string]any{
							"@timestamp": "2024-01-01T00:00:00Z",
							"rule.uuid":  "test-rule-uuid",
							"tags":       []string{"alert"},
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			mockDetection: &model.Detection{
				PublicID: "test-rule-uuid",
				Category: "malware",
				Engine:   model.EngineNameSuricata,
			},
			mockPlaybooks: []*model.Playbook{
				{
					Name:        "Malware Investigation",
					Description: "Standard malware investigation playbook",
					Questions: []*model.Question{
						{
							Question: "Was this file executed?",
							Context:  "Check process execution logs",
							Range:    nil,
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-123",
									Payload: map[string]any{
										"@timestamp":   "2024-01-01T00:01:00Z",
										"process.name": "malware.exe",
										"process.pid":  1234,
									},
								},
							},
						},
						{
							Question: "What network connections were made?",
							Context:  "Check network logs for connections",
							Range:    nil,
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-123",
									Payload: map[string]any{
										"@timestamp":       "2024-01-01T00:02:00Z",
										"destination.ip":   "192.168.1.100",
										"destination.port": 80,
									},
								},
							},
						},
					},
				},
			},
			expectedResult: []*SimplePlaybook{
				{
					Name:        "Malware Investigation",
					Description: "Standard malware investigation playbook",
					Questions: []*SimpleQuestion{
						{
							Question: "Was this file executed?",
							Context:  "Check process execution logs",
							Range:    nil,
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":          "alert-123",
										"@timestamp":   "2024-01-01T00:01:00Z",
										"process.name": "malware.exe",
									},
								},
							},
						},
						{
							Question: "What network connections were made?",
							Context:  "Check network logs for connections",
							Range:    nil,
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":              "alert-123",
										"@timestamp":       "2024-01-01T00:02:00Z",
										"destination.ip":   "192.168.1.100",
										"destination.port": 80,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:   "successful playbook questions retrieval with specific playbook index",
			params: `{"alert_id": "alert-456", "playbook_index": 0}`,
			mockEventResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "test-index",
						Id:     "alert-456",
						Payload: map[string]any{
							"@timestamp": "2024-01-01T00:00:00Z",
							"rule.uuid":  "test-rule-uuid-2",
							"tags":       []string{"alert"},
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			mockDetection: &model.Detection{
				PublicID: "test-rule-uuid-2",
				Category: "scan",
				Engine:   model.EngineNameSuricata,
			},
			mockPlaybooks: []*model.Playbook{
				{
					Name:        "Network Scan Investigation",
					Description: "Investigation playbook for network scans",
					Questions: []*model.Question{
						{
							Question: "What hosts were scanned?",
							Context:  "Check for scan patterns",
							Range:    nil,
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-456",
									Payload: map[string]any{
										"@timestamp":     "2024-01-01T00:01:00Z",
										"destination.ip": "192.168.1.1",
										"source.ip":      "10.0.0.1",
									},
								},
							},
						},
					},
				},
				{
					Name:        "Generic Scan Playbook",
					Description: "Generic playbook for scan alerts",
					Questions: []*model.Question{
						{
							Question:     "Generic scan question",
							Context:      "Generic context",
							Range:        nil,
							QueryResults: []*model.EventRecord{},
						},
					},
				},
			},
			expectedResult: []*SimplePlaybook{
				{
					Name:        "Network Scan Investigation",
					Description: "Investigation playbook for network scans",
					Questions: []*SimpleQuestion{
						{
							Question: "What hosts were scanned?",
							Context:  "Check for scan patterns",
							Range:    nil,
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":            "alert-456",
										"@timestamp":     "2024-01-01T00:01:00Z",
										"destination.ip": "192.168.1.1",
										"source.ip":      "10.0.0.1",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"alert_id": "invalid json}`,
			expectedError: true,
		},
		{
			name:   "alert not found",
			params: `{"alert_id": "nonexistent-alert"}`,
			mockEventResults: &model.EventSearchResults{
				Events:      []*model.EventRecord{},
				TotalEvents: 0,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedError: true,
		},
		{
			name:           "event search error",
			params:         `{"alert_id": "alert-error"}`,
			mockEventError: assert.AnError,
			expectedError:  true,
		},
		{
			name:   "event without rule.uuid",
			params: `{"alert_id": "alert-no-uuid"}`,
			mockEventResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "test-index",
						Id:     "alert-no-uuid",
						Payload: map[string]any{
							"@timestamp": "2024-01-01T00:00:00Z",
							"tags":       []string{"alert"},
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			expectedError: true,
		},
		{
			name:   "detection not found",
			params: `{"alert_id": "alert-det-not-found"}`,
			mockEventResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "test-index",
						Id:     "alert-det-not-found",
						Payload: map[string]any{
							"@timestamp": "2024-01-01T00:00:00Z",
							"rule.uuid":  "nonexistent-rule-uuid",
							"tags":       []string{"alert"},
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			mockDetectionError: assert.AnError,
			expectedError:      true,
		},
		{
			name:   "no playbooks found for detection",
			params: `{"alert_id": "alert-no-playbooks"}`,
			mockEventResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "test-index",
						Id:     "alert-no-playbooks",
						Payload: map[string]any{
							"@timestamp": "2024-01-01T00:00:00Z",
							"rule.uuid":  "rule-no-playbooks",
							"tags":       []string{"alert"},
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			mockDetection: &model.Detection{
				PublicID: "rule-no-playbooks",
				Category: "unknown",
				Engine:   model.EngineNameSuricata,
			},
			mockPlaybooks:     []*model.Playbook{},
			mockPlaybookError: assert.AnError,
			expectedError:     true,
		},
		{
			name:   "extract details error",
			params: `{"alert_id": "alert-extract-error"}`,
			mockEventResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "test-index",
						Id:     "alert-extract-error",
						Payload: map[string]any{
							"@timestamp": "2024-01-01T00:00:00Z",
							"rule.uuid":  "test-rule-uuid-extract-error",
							"tags":       []string{"alert"},
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			mockDetection: &model.Detection{
				PublicID: "test-rule-uuid-extract-error",
				Category: "test",
				Engine:   model.EngineNameSuricata,
			},
			mockPlaybooks: []*model.Playbook{
				{
					Name:        "Test Playbook",
					Description: "Test playbook for extract details error",
					Questions:   []*model.Question{},
				},
			},
			expectedResult: []*SimplePlaybook{
				{
					Name:        "Test Playbook",
					Description: "Test playbook for extract details error",
					Questions:   []*SimpleQuestion{},
				},
			},
		},
		{
			name:   "invalid playbook index",
			params: `{"alert_id": "alert-invalid-index", "playbook_index": 5}`,
			mockEventResults: &model.EventSearchResults{
				Events: []*model.EventRecord{
					{
						Source: "test-index",
						Id:     "alert-invalid-index",
						Payload: map[string]any{
							"@timestamp": "2024-01-01T00:00:00Z",
							"rule.uuid":  "test-rule-uuid-3",
							"tags":       []string{"alert"},
						},
					},
				},
				TotalEvents: 1,
				Metrics:     make(map[string][]*model.EventMetric),
			},
			mockDetection: &model.Detection{
				PublicID: "test-rule-uuid-3",
				Category: "test",
				Engine:   model.EngineNameSuricata,
			},
			mockPlaybooks: []*model.Playbook{
				{
					Name:        "Single Playbook",
					Description: "Only one playbook available",
					Questions:   []*model.Question{},
				},
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock controller
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mock stores
			mockEventstore := server.NewFakeEventstore()
			mockDetectionstore := mock.NewMockDetectionstore(ctrl)
			mockPlaybookstore := mock.NewMockPlaybookstore(ctrl)
			mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

			// Setup eventstore mock
			if tc.mockEventResults != nil {
				mockEventstore.SearchResults = []*model.EventSearchResults{tc.mockEventResults}
			}
			if tc.mockEventError != nil {
				mockEventstore.Err = tc.mockEventError
			}

			// Setup detection store expectations
			if tc.mockEventResults != nil && len(tc.mockEventResults.Events) > 0 {
				if ruleUuid, ok := tc.mockEventResults.Events[0].Payload["rule.uuid"].(string); ok {
					if tc.mockDetection != nil {
						mockDetectionstore.EXPECT().GetDetectionByPublicId(gomock.Any(), ruleUuid).Return(tc.mockDetection, tc.mockDetectionError)
						// Setup ExtractDetails expectation for cases with Suricata engine
						if tc.mockDetectionError == nil && tc.mockDetection.Engine == model.EngineNameSuricata {
							if tc.name == "extract details error" {
								// Test error case in ExtractDetails
								mockDetectionEngine.EXPECT().ExtractDetails(tc.mockDetection).Return(assert.AnError).AnyTimes()
							} else {
								// Normal success case
								mockDetectionEngine.EXPECT().ExtractDetails(tc.mockDetection).Return(nil).AnyTimes()
							}
						}
					} else {
						mockDetectionstore.EXPECT().GetDetectionByPublicId(gomock.Any(), ruleUuid).Return(nil, tc.mockDetectionError)
					}
				}
			}

			// Setup playbook store expectations
			if tc.mockDetection != nil && tc.mockDetectionError == nil {
				if tc.mockPlaybooks != nil || tc.mockPlaybookError != nil {
					mockPlaybookstore.EXPECT().GetPlaybooksForDetection(gomock.Any(), tc.mockDetection.PublicID, tc.mockDetection.Category, tc.mockDetection.Engine).Return(tc.mockPlaybooks, tc.mockPlaybookError)
				}

				// Only expect ExecutePlaybookSearches if we have playbooks and no error, and the function won't return early
				if tc.mockPlaybooks != nil && tc.mockPlaybookError == nil && !tc.expectedError {
					mockPlaybookstore.EXPECT().ExecutePlaybookSearches(gomock.Any(), gomock.Any(), gomock.Any()).Return(tc.mockExecuteSearchError)
				}
			}

			// Create mock server
			mockServer := &server.Server{
				Eventstore:       mockEventstore,
				Detectionstore:   mockDetectionstore,
				Playbookstore:    mockPlaybookstore,
				DetectionEngines: sync.Map{},
			}

			// Store the Suricata detection engine for tests that use it
			if tc.mockDetection != nil && tc.mockDetection.Engine == model.EngineNameSuricata {
				mockServer.DetectionEngines.Store(model.EngineNameSuricata, mockDetectionEngine)
			}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create tool and execute
			tool := &GetPlaybooksTool{}
			result, err := tool.Execute(ctx, mockServer, &model.ToolRequest{Params: json.RawMessage(tc.params)})

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "get_playbooks", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.True(t, result.TimeToExecute > 0)

			// Verify search criteria was populated correctly for successful cases
			if !tc.expectedError && tc.mockEventError == nil && tc.mockEventResults != nil {
				assert.Len(t, mockEventstore.InputSearchCriterias, 1)
				criteria := mockEventstore.InputSearchCriterias[0]
				assert.NotNil(t, criteria)
				// The alert ID should be in the query
				var expectedAlertId string
				if len(tc.mockEventResults.Events) > 0 {
					expectedAlertId = tc.mockEventResults.Events[0].Id
				}
				if expectedAlertId != "" {
					assert.Contains(t, criteria.RawQuery, expectedAlertId)
				}
			}

			// Assert result content
			if tc.expectedResult != nil {
				assert.Equal(t, tc.expectedResult, result.Result)
			}
		})
	}
}

func TestSimplifyPlaybooks(t *testing.T) {
	testCases := []struct {
		name           string
		inputPlaybooks []*model.Playbook
		expectedResult []*SimplePlaybook
		description    string
	}{
		{
			name:           "empty playbooks slice",
			inputPlaybooks: []*model.Playbook{},
			expectedResult: []*SimplePlaybook{},
			description:    "Should return empty slice for empty input",
		},
		{
			name:           "nil playbooks slice",
			inputPlaybooks: nil,
			expectedResult: []*SimplePlaybook{},
			description:    "Should return empty slice for nil input",
		},
		{
			name: "playbook with questions having query results",
			inputPlaybooks: []*model.Playbook{
				{
					Name:        "Malware Investigation",
					Description: "Investigation playbook for malware alerts",
					Questions: []*model.Question{
						{
							Question: "Was this file executed?",
							Context:  "Check process execution logs",
							Range:    nil,
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-1",
									Payload: map[string]any{
										"@timestamp":   "2024-01-01T00:01:00Z",
										"process.name": "malware.exe",
										"process.pid":  1234,
									},
								},
							},
						},
						{
							Question: "What network connections were made?",
							Context:  "Check network logs",
							Range:    stringPtr("±1h"),
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-2",
									Payload: map[string]any{
										"@timestamp":       "2024-01-01T00:02:00Z",
										"destination.ip":   "192.168.1.100",
										"destination.port": 80,
									},
								},
							},
						},
					},
				},
			},
			expectedResult: []*SimplePlaybook{
				{
					Name:        "Malware Investigation",
					Description: "Investigation playbook for malware alerts",
					Questions: []*SimpleQuestion{
						{
							Question: "Was this file executed?",
							Context:  "Check process execution logs",
							Range:    nil,
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":          "alert-1",
										"@timestamp":   "2024-01-01T00:01:00Z",
										"process.name": "malware.exe",
									},
								},
							},
						},
						{
							Question: "What network connections were made?",
							Context:  "Check network logs",
							Range:    stringPtr("±1h"),
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":              "alert-2",
										"@timestamp":       "2024-01-01T00:02:00Z",
										"destination.ip":   "192.168.1.100",
										"destination.port": 80,
									},
								},
							},
						},
					},
				},
			},
			description: "Should convert playbook with questions that have query results",
		},
		{
			name: "playbook with questions without query results",
			inputPlaybooks: []*model.Playbook{
				{
					Name:        "Empty Investigation",
					Description: "Investigation playbook with no results",
					Questions: []*model.Question{
						{
							Question:     "Was this file executed?",
							Context:      "Check process execution logs",
							Range:        nil,
							QueryResults: []*model.EventRecord{}, // Empty results
						},
						{
							Question:     "What network connections were made?",
							Context:      "Check network logs",
							Range:        stringPtr("±1h"),
							QueryResults: nil, // Nil results
						},
					},
				},
			},
			expectedResult: []*SimplePlaybook{
				{
					Name:        "Empty Investigation",
					Description: "Investigation playbook with no results",
					Questions:   []*SimpleQuestion{}, // No questions should be included
				},
			},
			description: "Should filter out questions without query results",
		},
		{
			name: "mixed playbooks with and without results",
			inputPlaybooks: []*model.Playbook{
				{
					Name:        "Mixed Results Playbook",
					Description: "Some questions have results, others don't",
					Questions: []*model.Question{
						{
							Question: "Question with results",
							Context:  "Has query results",
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-1",
									Payload: map[string]any{
										"@timestamp": "2024-01-01T00:01:00Z",
										"source.ip":  "10.0.0.1",
									},
								},
							},
						},
						{
							Question:     "Question without results",
							Context:      "No query results",
							QueryResults: []*model.EventRecord{}, // Empty
						},
						{
							Question: "Another question with results",
							Context:  "Also has query results",
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-1",
									Payload: map[string]any{
										"@timestamp":     "2024-01-01T00:02:00Z",
										"destination.ip": "192.168.1.1",
									},
								},
							},
						},
					},
				},
			},
			expectedResult: []*SimplePlaybook{
				{
					Name:        "Mixed Results Playbook",
					Description: "Some questions have results, others don't",
					Questions: []*SimpleQuestion{
						{
							Question: "Question with results",
							Context:  "Has query results",
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":        "alert-1",
										"@timestamp": "2024-01-01T00:01:00Z",
										"source.ip":  "10.0.0.1",
									},
								},
							},
						},
						{
							Question: "Another question with results",
							Context:  "Also has query results",
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":            "alert-1",
										"@timestamp":     "2024-01-01T00:02:00Z",
										"destination.ip": "192.168.1.1",
									},
								},
							},
						},
					},
				},
			},
			description: "Should only include questions with query results",
		},
		{
			name: "playbook with QueryFields preserves custom fields",
			inputPlaybooks: []*model.Playbook{
				{
					Name:        "Custom Field Investigation",
					Description: "Investigation playbook with custom fields specified",
					Questions: []*model.Question{
						{
							Question:    "What custom fields are present?",
							Context:     "Check for custom fields not in default list",
							Range:       nil,
							QueryFields: []string{"custom.field.one", "custom.field.two", "process.pid"},
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-3",
									Payload: map[string]any{
										"@timestamp":       "2024-01-01T00:03:00Z",
										"custom.field.one": "value1",
										"custom.field.two": "value2",
										"process.pid":      5678,
										"process.name":     "test.exe",
										"unwanted.field":   "should be filtered",
									},
								},
							},
						},
					},
				},
			},
			expectedResult: []*SimplePlaybook{
				{
					Name:        "Custom Field Investigation",
					Description: "Investigation playbook with custom fields specified",
					Questions: []*SimpleQuestion{
						{
							Question: "What custom fields are present?",
							Context:  "Check for custom fields not in default list",
							Range:    nil,
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":              "alert-3",
										"@timestamp":       "2024-01-01T00:03:00Z",
										"custom.field.one": "value1",
										"custom.field.two": "value2",
										"process.pid":      5678,
										"process.name":     "test.exe",
									},
								},
							},
						},
					},
				},
			},
			description: "Should preserve fields specified in QueryFields even if not in default list",
		},
		{
			name: "multiple playbooks",
			inputPlaybooks: []*model.Playbook{
				{
					Name:        "First Playbook",
					Description: "First investigation playbook",
					Questions: []*model.Question{
						{
							Question: "First question",
							Context:  "First context",
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-1",
									Payload: map[string]any{
										"@timestamp": "2024-01-01T00:01:00Z",
										"event.id":   "event-1",
									},
								},
							},
						},
					},
				},
				{
					Name:        "Second Playbook",
					Description: "Second investigation playbook",
					Questions: []*model.Question{
						{
							Question: "Second question",
							Context:  "Second context",
							QueryResults: []*model.EventRecord{
								{
									Id: "alert-2",
									Payload: map[string]any{
										"@timestamp": "2024-01-01T00:02:00Z",
										"event.id":   "event-2",
									},
								},
							},
						},
					},
				},
			},
			expectedResult: []*SimplePlaybook{
				{
					Name:        "First Playbook",
					Description: "First investigation playbook",
					Questions: []*SimpleQuestion{
						{
							Question: "First question",
							Context:  "First context",
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":        "alert-1",
										"@timestamp": "2024-01-01T00:01:00Z",
									},
								},
							},
						},
					},
				},
				{
					Name:        "Second Playbook",
					Description: "Second investigation playbook",
					Questions: []*SimpleQuestion{
						{
							Question: "Second question",
							Context:  "Second context",
							QueryResults: []map[string]any{
								{
									"payload": map[string]any{
										"_id":        "alert-2",
										"@timestamp": "2024-01-01T00:02:00Z",
									},
								},
							},
						},
					},
				},
			},
			description: "Should handle multiple playbooks correctly",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := simplifyPlaybooks(tc.inputPlaybooks)

			assert.Equal(t, tc.expectedResult, result, tc.description)

			// Additional assertions to verify structure
			assert.Len(t, result, len(tc.expectedResult), "Should return correct number of playbooks")

			for i, expectedPlaybook := range tc.expectedResult {
				if i < len(result) {
					actualPlaybook := result[i]
					assert.Equal(t, expectedPlaybook.Name, actualPlaybook.Name, "Playbook name should match")
					assert.Equal(t, expectedPlaybook.Description, actualPlaybook.Description, "Playbook description should match")
					assert.Len(t, actualPlaybook.Questions, len(expectedPlaybook.Questions), "Should have correct number of questions")

					for j, expectedQuestion := range expectedPlaybook.Questions {
						if j < len(actualPlaybook.Questions) {
							actualQuestion := actualPlaybook.Questions[j]
							assert.Equal(t, expectedQuestion.Question, actualQuestion.Question, "Question text should match")
							assert.Equal(t, expectedQuestion.Context, actualQuestion.Context, "Question context should match")
							assert.Equal(t, expectedQuestion.Range, actualQuestion.Range, "Question range should match")
							// QueryResults comparison is handled by the main assertion
						}
					}
				}
			}
		})
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
