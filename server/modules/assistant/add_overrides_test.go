// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAddOverridesTool_GetName(t *testing.T) {
	tool := &AddOverridesTool{}
	assert.Equal(t, "add_overrides", tool.GetName())
}

func TestAddOverridesTool_GetDescription(t *testing.T) {
	tool := &AddOverridesTool{}
	description := tool.GetDescription()
	assert.Contains(t, description, "Add one or more new overrides to existing detection(s)")
	assert.Contains(t, description, "_index:\"*:so-detection\" AND so_kind:detection")
	assert.Contains(t, description, "999 days ago")
	assert.Contains(t, description, "Suricata:")
	assert.Contains(t, description, "Sigma:")
	assert.Contains(t, description, "YARA does not have overrides")
}

func TestAddOverridesTool_GetSchema(t *testing.T) {
	tool := &AddOverridesTool{}
	schema := tool.GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Contains(t, schema.Json.Required, "search_filter")

	// Check that all expected properties are present
	expectedProperties := []string{"search_filter", "overrides", "range_start", "range_end", "range_format", "limit"}
	for _, prop := range expectedProperties {
		assert.Contains(t, schema.Json.Properties, prop)
	}

	// Check search_filter property
	searchFilter := schema.Json.Properties["search_filter"]
	assert.Equal(t, "string", searchFilter.Type)
	assert.Contains(t, searchFilter.Description, "so_detection.id")
	assert.Contains(t, searchFilter.Description, "so_detection.title")
	assert.Contains(t, searchFilter.Description, "so_detection.severity")
	assert.Contains(t, searchFilter.Description, "so_detection.isEnabled")

	// Check overrides property
	overrides := schema.Json.Properties["overrides"]
	assert.Equal(t, "array", overrides.Type)
	assert.Contains(t, overrides.Description, "new overrides to add")

	// Check range properties
	rangeStart := schema.Json.Properties["range_start"]
	assert.Equal(t, "string", rangeStart.Type)
	assert.Contains(t, rangeStart.Description, "start time")

	rangeEnd := schema.Json.Properties["range_end"]
	assert.Equal(t, "string", rangeEnd.Type)
	assert.Contains(t, rangeEnd.Description, "end time")

	rangeFormat := schema.Json.Properties["range_format"]
	assert.Equal(t, "string", rangeFormat.Type)
	assert.Contains(t, rangeFormat.Description, "format")

	// Check limit property
	limit := schema.Json.Properties["limit"]
	assert.Equal(t, "integer", limit.Type)
	assert.Contains(t, limit.Description, "maximum number")
}

func TestAddOverridesTool_Execute(t *testing.T) {
	testCases := []struct {
		name                    string
		params                  string
		mockQueryResults        []interface{}
		mockQueryError          error
		mockBulkAddStats        *model.BulkUpdateStats
		mockBulkAddError        error
		mockSyncError           error
		mockSyncErrorMap        map[string]string
		expectedResult          string
		expectedError           bool
		expectedOverridesCount  int
		expectedDetectionsCount int
	}{
		{
			name:   "successfully add suricata threshold override",
			params: `{"search_filter": "so_detection.title:malware AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": [{"note":"","seconds":60,"isEnabled":true,"count":10,"type":"threshold","track":"by_src","thresholdType":"both"}]}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-1"},
					PublicID:  "PUB001",
					Title:     "Malware Detection 1",
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
					Overrides: []*model.Override{},
				},
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-2"},
					PublicID:  "PUB002",
					Title:     "Malware Detection 2",
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
					Overrides: []*model.Override{},
				},
			},
			mockBulkAddStats: &model.BulkUpdateStats{
				Updated:        2,
				Audited:        2,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 100 * time.Millisecond,
				NeedToSync: []*model.Detection{
					{
						Auditable: model.Auditable{Id: "detection-1"},
						PublicID:  "PUB001",
						Engine:    model.EngineNameSuricata,
					},
					{
						Auditable: model.Auditable{Id: "detection-2"},
						PublicID:  "PUB002",
						Engine:    model.EngineNameSuricata,
					},
				},
			},
			expectedResult:          "Successfully added 1 override to 2 detections. Updated=2, Audited=2, Errors=map[], UpdateDuration=100ms, SyncDuration=",
			expectedOverridesCount:  1,
			expectedDetectionsCount: 2,
		},
		{
			name:   "successfully add multiple suricata overrides",
			params: `{"search_filter": "so_detection.engine:suricata AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": [{"note":"Threshold override","seconds":60,"isEnabled":true,"count":10,"type":"threshold","track":"by_src","thresholdType":"both"},{"note":"Modify override","regex":"rev:1;","isEnabled":true,"type":"modify","value":"rev:2;"}]}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-1"},
					PublicID:  "PUB001",
					Title:     "Suricata Detection",
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
					Overrides: []*model.Override{},
				},
			},
			mockBulkAddStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 75 * time.Millisecond,
				NeedToSync: []*model.Detection{
					{
						Auditable: model.Auditable{Id: "detection-1"},
						PublicID:  "PUB001",
						Engine:    model.EngineNameSuricata,
					},
				},
			},
			expectedResult:          "Successfully added 2 overrides to 1 detections. Updated=1, Audited=1, Errors=map[], UpdateDuration=75ms, SyncDuration=",
			expectedOverridesCount:  2,
			expectedDetectionsCount: 1,
		},
		{
			name:   "successfully add sigma custom filter override",
			params: `{"search_filter": "so_detection.language:sigma AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": [{"note":"Custom filter","isEnabled":true,"type":"customFilter","customFilter":"sofilter:\n  user.name: test_user"}]}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-1"},
					PublicID:  "PUB001",
					Title:     "Sigma Detection",
					Engine:    model.EngineNameElastAlert,
					Language:  model.SigLangSigma,
					Overrides: []*model.Override{},
				},
			},
			mockBulkAddStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 50 * time.Millisecond,
				NeedToSync: []*model.Detection{
					{
						Auditable: model.Auditable{Id: "detection-1"},
						PublicID:  "PUB001",
						Engine:    model.EngineNameElastAlert,
					},
				},
			},
			expectedResult:          "Successfully added 1 override to 1 detections. Updated=1, Audited=1, Errors=map[], UpdateDuration=50ms, SyncDuration=",
			expectedOverridesCount:  1,
			expectedDetectionsCount: 1,
		},
		{
			name:             "no detections found",
			params:           `{"search_filter": "so_detection.title:nonexistent AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": [{"note":"","seconds":60,"isEnabled":true,"count":10,"type":"threshold","track":"by_src","thresholdType":"both"}]}`,
			mockQueryResults: []interface{}{},
			expectedResult:   "No detections found",
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"search_filter": "invalid json}`,
			expectedError: true,
		},
		{
			name:          "invalid overrides JSON",
			params:        `{"search_filter": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": "invalid json"}`,
			expectedError: true,
		},
		{
			name:           "query error",
			params:         `{"search_filter": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": [{"note":"","seconds":60,"isEnabled":true,"count":10,"type":"threshold","track":"by_src","thresholdType":"both"}]}`,
			mockQueryError: assert.AnError,
			expectedError:  true,
		},
		{
			name:   "bulk add overrides error",
			params: `{"search_filter": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": [{"note":"","seconds":60,"isEnabled":true,"count":10,"type":"threshold","track":"by_src","thresholdType":"both"}]}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-1"},
					PublicID:  "PUB001",
					Title:     "Test Detection",
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
				},
			},
			mockBulkAddStats: &model.BulkUpdateStats{
				Updated:        0,
				Audited:        0,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 25 * time.Millisecond,
				NeedToSync:     []*model.Detection{},
			},
			mockBulkAddError:        assert.AnError,
			expectedError:           true,
			expectedOverridesCount:  1,
			expectedDetectionsCount: 1,
		},
		{
			name:   "sync error during detection sync",
			params: `{"search_filter": "so_detection.title:sync AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": [{"note":"","seconds":60,"isEnabled":true,"count":10,"type":"threshold","track":"by_src","thresholdType":"both"}]}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-sync"},
					PublicID:  "PUB-SYNC",
					Title:     "Sync Detection",
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
				},
			},
			mockBulkAddStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 30 * time.Millisecond,
				NeedToSync: []*model.Detection{
					{
						Auditable: model.Auditable{Id: "detection-sync"},
						PublicID:  "PUB-SYNC",
						Engine:    model.EngineNameSuricata,
					},
				},
			},
			mockSyncError:           assert.AnError,
			expectedError:           true,
			expectedOverridesCount:  1,
			expectedDetectionsCount: 1,
		},
		{
			name:   "sync error map during detection sync",
			params: `{"search_filter": "so_detection.title:sync AND _index:\"*:so-detection\" AND so_kind:detection", "overrides": [{"note":"","seconds":60,"isEnabled":true,"count":10,"type":"threshold","track":"by_src","thresholdType":"both"}]}`,
			mockQueryResults: []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-sync"},
					PublicID:  "PUB-SYNC",
					Title:     "Sync Detection",
					Engine:    model.EngineNameSuricata,
					Language:  model.SigLangSuricata,
				},
			},
			mockBulkAddStats: &model.BulkUpdateStats{
				Updated:        1,
				Audited:        1,
				Filtered:       0,
				ErrMap:         map[string]string{},
				UpdateDuration: 30 * time.Millisecond,
				NeedToSync: []*model.Detection{
					{
						Auditable: model.Auditable{Id: "detection-sync"},
						PublicID:  "PUB-SYNC",
						Engine:    model.EngineNameSuricata,
					},
				},
			},
			mockSyncErrorMap: map[string]string{
				"PUB-SYNC": "sync failed",
			},
			expectedError:           true,
			expectedOverridesCount:  1,
			expectedDetectionsCount: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockDetectionstore := mock.NewMockDetectionstore(ctrl)
			mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

			// Set up mock expectations
			if tc.mockQueryResults != nil || tc.mockQueryError != nil {
				mockDetectionstore.EXPECT().
					QueryWithRange(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, query, rangeStart, rangeEnd, rangeFormat string, limit int) (*model.EventSearchResults, error) {
						// Verify query contains metadata filter
						assert.Contains(t, query, "NOT metadata.raw_index:")
						if tc.mockQueryError != nil {
							return nil, tc.mockQueryError
						}
						return &model.EventSearchResults{Events: []*model.EventRecord{}}, nil
					})

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
						})
				}
			}

			if tc.mockBulkAddStats != nil || tc.mockBulkAddError != nil {
				mockDetectionstore.EXPECT().
					BulkAddOverrides(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, newOverrides []*model.Override, detects []*model.Detection, logger interface{}) (*model.BulkUpdateStats, error) {
						if tc.expectedOverridesCount > 0 {
							assert.Len(t, newOverrides, tc.expectedOverridesCount)
						}
						if tc.expectedDetectionsCount > 0 {
							assert.Len(t, detects, tc.expectedDetectionsCount)
						}
						if tc.mockBulkAddError != nil {
							return nil, tc.mockBulkAddError
						}
						return tc.mockBulkAddStats, nil
					})
			}

			// Set up sync expectations
			if tc.mockBulkAddStats != nil && len(tc.mockBulkAddStats.NeedToSync) > 0 {
				if tc.mockSyncError != nil {
					mockDetectionEngine.EXPECT().
						SyncLocalDetections(gomock.Any(), gomock.Any()).
						Return(nil, tc.mockSyncError)
				} else if tc.mockSyncErrorMap != nil {
					mockDetectionEngine.EXPECT().
						SyncLocalDetections(gomock.Any(), gomock.Any()).
						Return(tc.mockSyncErrorMap, nil)
				} else {
					mockDetectionEngine.EXPECT().
						SyncLocalDetections(gomock.Any(), gomock.Any()).
						Return(map[string]string{}, nil)
				}
			}

			// Create mock server with proper authorization
			mockServer := server.NewFakeAuthorizedServer(map[string][]string{
				"test-user-id": {"detections/write"},
			})
			mockServer.Detectionstore = mockDetectionstore

			// Add DetectionEngines with mock engine
			// The engine must be loaded for any test that returns detections from the query
			mockServer.DetectionEngines = sync.Map{}
			if len(tc.mockQueryResults) > 0 {
				mockServer.DetectionEngines.Store(model.EngineNameSuricata, mockDetectionEngine)
				mockServer.DetectionEngines.Store(model.EngineNameElastAlert, mockDetectionEngine)
			}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create tool and execute
			tool := &AddOverridesTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params, "")

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "add_overrides", result.ToolName)
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
