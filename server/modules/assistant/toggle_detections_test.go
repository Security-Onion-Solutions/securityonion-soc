// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestToggleDetectionsTool_Execute(t *testing.T) {
	testCases := []struct {
		name               string
		params             string
		mockQueryResults   []interface{}
		mockQueryError     error
		mockBulkStats      *model.BulkUpdateStats
		mockBulkError      error
		expectedResult     string
		expectedError      bool
		expectedEnable     bool
		expectedDetections int
		setupEngines       bool
		syncError          error
		syncErrorMap       map[string]string
	}{
		{
			name:   "enable detections successfully",
			params: `{"search_filter": "so_detection.title:malware AND _index:\"*:so-detection\" AND so_kind:detection", "enable": true}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-1"},
					PublicID:  "PUB001",
					Title:     "Malware Detection 1",
					IsEnabled: false,
				},
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-2"},
					PublicID:  "PUB002",
					Title:     "Malware Detection 2",
					IsEnabled: false,
				},
			},
			mockBulkStats: &model.BulkUpdateStats{
				Updated:        2,
				Audited:        2,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 100000000, // 100ms in nanoseconds
				NeedToSync:     []*model.Detection{},
			},
			expectedResult:     "Successfully Enabled 2 detections. Enabled=2, Audited=2, Filtered=0, Errors=map[], UpdateDuration=100ms, SyncDuration=",
			expectedEnable:     true,
			expectedDetections: 2,
		},
		{
			name:   "disable detections successfully",
			params: `{"search_filter": "so_detection.severity:high AND _index:\"*:so-detection\" AND so_kind:detection", "enable": false}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-3"},
					PublicID:  "PUB003",
					Title:     "High Severity Detection",
					IsEnabled: true,
				},
			},
			mockBulkStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 50000000, // 50ms in nanoseconds
				NeedToSync:     []*model.Detection{},
			},
			expectedResult:     "Successfully Disabled 1 detections. Disabled=1, Audited=1, Filtered=0, Errors=map[], UpdateDuration=50ms, SyncDuration=",
			expectedEnable:     false,
			expectedDetections: 1,
		},
		{
			name:   "toggle with time range",
			params: `{"search_filter": "so_detection.language:sigma AND _index:\"*:so-detection\" AND so_kind:detection", "enable": true, "range_start": "-999d", "range_end": "now"}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-4"},
					PublicID:  "PUB004",
					Title:     "Sigma Detection",
					IsEnabled: false,
				},
			},
			mockBulkStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 75000000, // 75ms in nanoseconds
				NeedToSync:     []*model.Detection{},
			},
			expectedResult:     "Successfully Enabled 1 detections. Enabled=1, Audited=1, Filtered=0, Errors=map[], UpdateDuration=75ms, SyncDuration=",
			expectedEnable:     true,
			expectedDetections: 1,
		},
		{
			name:   "toggle with absolute time range",
			params: `{"search_filter": "so_detection.engine:suricata AND _index:\"*:so-detection\" AND so_kind:detection", "enable": false, "range_start": "2024/01/01 10:00:00 AM", "range_end": "2024/01/01 11:00:00 AM", "range_format": "2006/01/02 3:04:05 PM"}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-5"},
					PublicID:  "PUB005",
					Title:     "Suricata Detection",
					IsEnabled: true,
				},
			},
			mockBulkStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 60000000, // 60ms in nanoseconds
				NeedToSync:     []*model.Detection{},
			},
			expectedResult:     "Successfully Disabled 1 detections. Disabled=1, Audited=1, Filtered=0, Errors=map[], UpdateDuration=60ms, SyncDuration=",
			expectedEnable:     false,
			expectedDetections: 1,
		},
		{
			name:             "no detections found",
			params:           `{"search_filter": "so_detection.title:nonexistent AND _index:\"*:so-detection\" AND so_kind:detection", "enable": true}`,
			mockQueryResults: []interface{}{},
			expectedResult:   "No detections found",
		},
		{
			name:   "toggle with errors in bulk update",
			params: `{"search_filter": "so_detection.title:problematic AND _index:\"*:so-detection\" AND so_kind:detection", "enable": true}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-6"},
					PublicID:  "PUB006",
					Title:     "Problematic Detection",
					IsEnabled: false,
				},
			},
			mockBulkStats: &model.BulkUpdateStats{
				Updated:  0,
				Audited:  0,
				Filtered: 0,
				ErrMap: map[string]string{
					"PUB006": "unsupported engine",
				},
				UpdateDuration: 25000000, // 25ms in nanoseconds
				NeedToSync:     []*model.Detection{},
			},
			expectedResult:     "Successfully Enabled 0 detections. Enabled=0, Audited=0, Filtered=0, Errors=map[PUB006:unsupported engine], UpdateDuration=25ms, SyncDuration=",
			expectedEnable:     true,
			expectedDetections: 1,
		},
		{
			name:   "toggle with filtered detections",
			params: `{"search_filter": "so_detection.title:filtered AND _index:\"*:so-detection\" AND so_kind:detection", "enable": true}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-7"},
					PublicID:  "PUB007",
					Title:     "Filtered Detection",
					IsEnabled: false,
				},
			},
			mockBulkStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       1,
				ErrMap:         map[string]string{},
				UpdateDuration: 80000000, // 80ms in nanoseconds
				NeedToSync:     []*model.Detection{},
			},
			expectedResult:     "Successfully Enabled 1 detections. Enabled=1, Audited=1, Filtered=1, Errors=map[], UpdateDuration=80ms, SyncDuration=",
			expectedEnable:     true,
			expectedDetections: 1,
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"search_filter": "invalid json}`,
			expectedError: true,
		},
		{
			name:          "invalid enable parameter",
			params:        `{"search_filter": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "maybe"}`,
			expectedError: true,
		},
		{
			name:           "query error",
			params:         `{"search_filter": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "enable": true}`,
			mockQueryError: assert.AnError,
			expectedError:  true,
		},
		{
			name:   "bulk update error",
			params: `{"search_filter": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "enable": true}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-8"},
					PublicID:  "PUB008",
					Title:     "Test Detection",
					IsEnabled: false,
				},
			},
			mockBulkError:      assert.AnError,
			expectedError:      true,
			expectedDetections: 1,
		},
		{
			name:   "sync detections successfully",
			params: `{"search_filter": "so_detection.title:sync AND _index:\"*:so-detection\" AND so_kind:detection", "enable": true}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-sync"},
					PublicID:  "PUB-SYNC",
					Title:     "Sync Detection",
					IsEnabled: false,
					Engine:    model.EngineNameSuricata,
				},
			},
			mockBulkStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 30000000, // 30ms in nanoseconds
				NeedToSync: []*model.Detection{
					{
						Auditable: model.Auditable{Id: "detection-sync"},
						PublicID:  "PUB-SYNC",
						Title:     "Sync Detection",
						IsEnabled: true,
						Engine:    model.EngineNameSuricata,
					},
				},
			},
			expectedResult:     "Successfully Enabled 1 detections. Enabled=1, Audited=1, Filtered=0, Errors=map[], UpdateDuration=30ms, SyncDuration=",
			expectedEnable:     true,
			expectedDetections: 1,
			setupEngines:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mock detection store
			mockDetectionstore := mock.NewMockDetectionstore(ctrl)

			// Setup QueryWithRange expectations
			if tc.mockQueryResults != nil || tc.mockQueryError != nil {
				mockDetectionstore.EXPECT().
					QueryWithRange(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, query, rangeStart, rangeEnd, rangeFormat string, limit int) (*model.EventSearchResults, error) {
						// Verify the query contains the metadata filter
						if !strings.Contains(query, `NOT metadata.raw_index:"logs-soc-so"`) {
							t.Errorf("Query should contain metadata filter, got: %s", query)
						}
						if tc.mockQueryError != nil {
							return nil, tc.mockQueryError
						}
						// Return EventSearchResults with empty Events slice
						return &model.EventSearchResults{Events: []*model.EventRecord{}}, nil
					}).
					Times(1)

				// Setup ConvertEventsToDetections expectations
				if tc.mockQueryError == nil {
					mockDetectionstore.EXPECT().
						ConvertEventsToDetections(gomock.Any(), gomock.Any()).
						DoAndReturn(func(ctx context.Context, detectEvents *model.EventSearchResults) ([]*model.Detection, error) {
							// Convert []interface{} to []*model.Detection
							detections := make([]*model.Detection, len(tc.mockQueryResults))
							for i, obj := range tc.mockQueryResults {
								detections[i] = obj.(*model.Detection)
							}
							return detections, nil
						}).
						Times(1)
				}
			}

			// Setup BulkUpdateDetections expectations
			if tc.expectedDetections > 0 && tc.mockBulkError == nil && !tc.expectedError {
				mockDetectionstore.EXPECT().
					BulkUpdateDetections(gomock.Any(), tc.expectedEnable, gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, newStatus bool, detects []*model.Detection, logger interface{}) (*model.BulkUpdateStats, error) {
						// Verify the correct number of detections
						if len(detects) != tc.expectedDetections {
							t.Errorf("Expected %d detections, got %d", tc.expectedDetections, len(detects))
						}
						if tc.mockBulkError != nil {
							return nil, tc.mockBulkError
						}
						return tc.mockBulkStats, nil
					}).
					Times(1)
			} else if tc.mockBulkError != nil {
				mockDetectionstore.EXPECT().
					BulkUpdateDetections(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, tc.mockBulkError).
					Times(1)
			}

			// Create mock server with proper authorization
			mockServer := server.NewFakeAuthorizedServer(map[string][]string{
				"test-user-id": {"detections/write"},
			})
			mockServer.Detectionstore = mockDetectionstore
			mockServer.DetectionEngines = sync.Map{}

			// Setup detection engines if needed for sync testing
			if tc.setupEngines {
				mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)
				mockDetectionEngine.EXPECT().
					SyncLocalDetections(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, detections []*model.Detection) (map[string]string, error) {
						if tc.syncError != nil {
							return nil, tc.syncError
						}
						if tc.syncErrorMap != nil {
							return tc.syncErrorMap, nil
						}
						return map[string]string{}, nil
					}).
					AnyTimes()
				mockServer.DetectionEngines.Store(model.EngineNameSuricata, mockDetectionEngine)
			}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create tool and execute
			tool := &ToggleDetectionsTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params, "")

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "toggle_detections", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.True(t, result.TimeToExecute > 0)

			// Assert result content - check if result contains expected parts since sync duration varies
			if tc.expectedResult != "" {
				resultStr := result.Result.(string)
				if strings.Contains(tc.expectedResult, "SyncDuration=") {
					// For results with sync duration, check that it starts correctly and contains expected parts
					assert.True(t, strings.HasPrefix(resultStr, strings.Split(tc.expectedResult, "SyncDuration=")[0]))
					assert.Contains(t, resultStr, "SyncDuration=")
				} else {
					assert.Equal(t, tc.expectedResult, resultStr)
				}
			}
		})
	}
}

func TestToggleDetectionsTool_GetName(t *testing.T) {
	tool := &ToggleDetectionsTool{}
	assert.Equal(t, "toggle_detections", tool.GetName())
}

func TestToggleDetectionsTool_GetDescription(t *testing.T) {
	tool := &ToggleDetectionsTool{}
	desc := tool.GetDescription()
	assert.NotEmpty(t, desc)
}

func TestToggleDetectionsTool_GetSchema(t *testing.T) {
	tool := &ToggleDetectionsTool{}
	schema := tool.GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Contains(t, schema.Json.Required, "search_filter")

	// Check that all expected properties are present
	expectedProperties := []string{"search_filter", "enable", "range_start", "range_end", "range_format"}
	for _, prop := range expectedProperties {
		assert.Contains(t, schema.Json.Properties, prop)
	}

	// Check search_filter property
	searchFilter := schema.Json.Properties["search_filter"]
	assert.Equal(t, "string", searchFilter.Type)

	// Check enable property
	enable := schema.Json.Properties["enable"]
	assert.Equal(t, "boolean", enable.Type)

	// Check range properties
	rangeStart := schema.Json.Properties["range_start"]
	assert.Equal(t, "string", rangeStart.Type)

	rangeEnd := schema.Json.Properties["range_end"]
	assert.Equal(t, "string", rangeEnd.Type)

	rangeFormat := schema.Json.Properties["range_format"]
	assert.Equal(t, "string", rangeFormat.Type)
}

func TestToggleDetectionsTool_QueryFiltering(t *testing.T) {
	testCases := []struct {
		name          string
		searchFilter  string
		expectedQuery string
	}{
		{
			name:          "basic query with metadata filter added",
			searchFilter:  "so_detection.title:malware",
			expectedQuery: `(so_detection.title:malware) AND NOT metadata.raw_index:"logs-soc-so"`,
		},
		{
			name:          "query already has metadata filter",
			searchFilter:  `so_detection.title:malware AND NOT metadata.raw_index:"logs-soc-so"`,
			expectedQuery: `so_detection.title:malware AND NOT metadata.raw_index:"logs-soc-so"`,
		},
		{
			name:          "empty search filter",
			searchFilter:  "",
			expectedQuery: `NOT metadata.raw_index:"logs-soc-so"`,
		},
		{
			name:          "complex query with metadata filter added",
			searchFilter:  `so_detection.severity:high AND so_detection.engine:suricata`,
			expectedQuery: `(so_detection.severity:high AND so_detection.engine:suricata) AND NOT metadata.raw_index:"logs-soc-so"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mock detection store
			mockDetectionstore := mock.NewMockDetectionstore(ctrl)
			mockDetectionstore.EXPECT().
				QueryWithRange(gomock.Any(), tc.expectedQuery, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(&model.EventSearchResults{Events: []*model.EventRecord{}}, nil).
				Times(1)

			mockDetectionstore.EXPECT().
				ConvertEventsToDetections(gomock.Any(), gomock.Any()).
				Return([]*model.Detection{}, nil).
				Times(1)

			// Create mock server with proper authorization
			mockServer := server.NewFakeAuthorizedServer(map[string][]string{
				"test-user-id": {"detections/write"},
			})
			mockServer.Detectionstore = mockDetectionstore
			mockServer.DetectionEngines = sync.Map{}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create parameters - properly escape quotes in JSON
			escapedFilter := strings.ReplaceAll(tc.searchFilter, `"`, `\"`)
			params := `{"search_filter": "` + escapedFilter + `", "enable": true}`

			// Create tool and execute
			tool := &ToggleDetectionsTool{}
			result, err := tool.Execute(ctx, mockServer, params, "")

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "No detections found", result.Result)
		})
	}
}

func TestToggleDetectionsTool_Authorization(t *testing.T) {
	testCases := []struct {
		name        string
		permissions []string
		expectError bool
	}{
		{
			name:        "authorized user with write permissions",
			permissions: []string{"detections/write"},
			expectError: false,
		},
		{
			name:        "unauthorized user without write permissions",
			permissions: []string{"detections/read"},
			expectError: true,
		},
		{
			name:        "unauthorized user with no permissions",
			permissions: []string{},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mock detection store
			mockDetectionstore := mock.NewMockDetectionstore(ctrl)

			if !tc.expectError {
				// Setup expectations for authorized case
				mockDetectionstore.EXPECT().
					QueryWithRange(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&model.EventSearchResults{Events: []*model.EventRecord{}}, nil).
					Times(1)

				mockDetectionstore.EXPECT().
					ConvertEventsToDetections(gomock.Any(), gomock.Any()).
					Return([]*model.Detection{
						{
							Auditable: model.Auditable{Id: "detection-1"},
							PublicID:  "PUB001",
							Title:     "Test Detection",
							IsEnabled: false,
						},
					}, nil).
					Times(1)

				mockDetectionstore.EXPECT().
					BulkUpdateDetections(gomock.Any(), true, gomock.Any(), gomock.Any()).
					Return(&model.BulkUpdateStats{
						Updated:        1,
						Audited:        1,
						Filtered:       0,
						ErrMap:         map[string]string{},
						UpdateDuration: 50000000,
						NeedToSync:     []*model.Detection{},
					}, nil).
					Times(1)
			}

			// Create mock server with specific permissions
			var mockServer *server.Server
			if tc.expectError {
				// For unauthorized tests, use an unauthorized server
				mockServer = server.NewFakeUnauthorizedServer()
			} else {
				// For authorized tests, use an authorized server
				mockServer = server.NewFakeAuthorizedServer(map[string][]string{
					"test-user-id": tc.permissions,
				})
			}
			mockServer.Detectionstore = mockDetectionstore
			mockServer.DetectionEngines = sync.Map{}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create parameters
			params := `{"search_filter": "so_detection.title:test", "enable": true}`

			// Create tool and execute
			tool := &ToggleDetectionsTool{}
			result, err := tool.Execute(ctx, mockServer, params, "")

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}
