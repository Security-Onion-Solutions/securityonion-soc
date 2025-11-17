// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"strings"
	"testing"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
)

// FakeDetectionstore implements the Detectionstore interface for testing
type FakeDetectionstore struct {
	QueryWithRangeResults []interface{}
	QueryWithRangeError   error
	QueryWithRangeCalled  bool
	QueryWithRangeQuery   string

	BulkUpdateStats         *model.BulkUpdateStats
	BulkUpdateError         error
	BulkUpdateCalled        bool
	BulkUpdateEnable        bool
	BulkUpdateDetectionList []*model.Detection
}

func (f *FakeDetectionstore) QueryWithRange(ctx context.Context, query, rangeStart, rangeEnd, rangeFormat string) ([]interface{}, error) {
	f.QueryWithRangeCalled = true
	f.QueryWithRangeQuery = query
	if f.QueryWithRangeError != nil {
		return nil, f.QueryWithRangeError
	}
	return f.QueryWithRangeResults, nil
}

func (f *FakeDetectionstore) BulkUpdateDetections(ctx context.Context, newStatus bool, detects []*model.Detection, logger log.Interface) (*model.BulkUpdateStats, error) {
	f.BulkUpdateCalled = true
	f.BulkUpdateEnable = newStatus
	f.BulkUpdateDetectionList = detects
	if f.BulkUpdateError != nil {
		return nil, f.BulkUpdateError
	}
	return f.BulkUpdateStats, nil
}

// Stub implementations for other required methods (not used in toggle_detections)
func (f *FakeDetectionstore) Query(ctx context.Context, query string, max int) ([]interface{}, error) {
	return nil, nil
}
func (f *FakeDetectionstore) CreateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
	return nil, nil
}
func (f *FakeDetectionstore) GetDetection(ctx context.Context, detectId string) (*model.Detection, error) {
	return nil, nil
}
func (f *FakeDetectionstore) GetDetectionByPublicId(ctx context.Context, publicId string) (*model.Detection, error) {
	return nil, nil
}
func (f *FakeDetectionstore) UpdateDetection(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
	return nil, nil
}
func (f *FakeDetectionstore) DeleteDetection(ctx context.Context, detectID string) (*model.Detection, error) {
	return nil, nil
}
func (f *FakeDetectionstore) GetAllDetections(ctx context.Context, opts ...model.GetAllOption) (map[string]*model.Detection, error) {
	return nil, nil
}
func (f *FakeDetectionstore) GetDetectionHistory(ctx context.Context, detectID string) ([]interface{}, error) {
	return nil, nil
}
func (f *FakeDetectionstore) CreateComment(ctx context.Context, newComment *model.DetectionComment) (*model.DetectionComment, error) {
	return nil, nil
}
func (f *FakeDetectionstore) GetComment(ctx context.Context, commentId string) (*model.DetectionComment, error) {
	return nil, nil
}
func (f *FakeDetectionstore) GetComments(ctx context.Context, detectionId string) ([]*model.DetectionComment, error) {
	return nil, nil
}
func (f *FakeDetectionstore) UpdateComment(ctx context.Context, comment *model.DetectionComment) (*model.DetectionComment, error) {
	return nil, nil
}
func (f *FakeDetectionstore) DeleteComment(ctx context.Context, id string) error {
	return nil
}
func (f *FakeDetectionstore) DoesTemplateExist(ctx context.Context, tmpl string) (bool, error) {
	return false, nil
}
func (f *FakeDetectionstore) BuildBulkIndexer(ctx context.Context, logger log.Interface) (esutil.BulkIndexer, error) {
	// Return a mock that satisfies the esutil.BulkIndexer interface
	return &mockBulkIndexer{}, nil
}

// mockBulkIndexer is a simple mock for the esutil.BulkIndexer interface
type mockBulkIndexer struct{}

func (m *mockBulkIndexer) Add(ctx context.Context, item esutil.BulkIndexerItem) error {
	return nil
}

func (m *mockBulkIndexer) Close(ctx context.Context) error {
	return nil
}

func (m *mockBulkIndexer) Stats() esutil.BulkIndexerStats {
	return esutil.BulkIndexerStats{}
}
func (f *FakeDetectionstore) ConvertObjectToDocument(ctx context.Context, kind string, obj interface{}, auditable *model.Auditable, isEdit bool, auditDocId *string, op *string) ([]byte, string, error) {
	return nil, "", nil
}

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
	}{
		{
			name:   "enable detections successfully",
			params: `{"search_filter": "so_detection.title:malware AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "true"}`,
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
			},
			expectedResult:     "Enabled=2, Audited=2, Filtered=0, Errs=map[], Duration=100ms",
			expectedEnable:     true,
			expectedDetections: 2,
		},
		{
			name:   "disable detections successfully",
			params: `{"search_filter": "so_detection.severity:high AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "false"}`,
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
			},
			expectedResult:     "Disabled=1, Audited=1, Filtered=0, Errs=map[], Duration=50ms",
			expectedEnable:     false,
			expectedDetections: 1,
		},
		{
			name:   "toggle with time range",
			params: `{"search_filter": "so_detection.language:sigma AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "true", "range_start": "-999d", "range_end": "now"}`,
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
			},
			expectedResult:     "Enabled=1, Audited=1, Filtered=0, Errs=map[], Duration=75ms",
			expectedEnable:     true,
			expectedDetections: 1,
		},
		{
			name:   "toggle with absolute time range",
			params: `{"search_filter": "so_detection.engine:suricata AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "false", "range_start": "2024/01/01 10:00:00 AM", "range_end": "2024/01/01 11:00:00 AM", "range_format": "2006/01/02 3:04:05 PM"}`,
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
			},
			expectedResult:     "Disabled=1, Audited=1, Filtered=0, Errs=map[], Duration=60ms",
			expectedEnable:     false,
			expectedDetections: 1,
		},
		{
			name:             "no detections found",
			params:           `{"search_filter": "so_detection.title:nonexistent AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "true"}`,
			mockQueryResults: []interface{}{},
			expectedResult:   "No detections found",
		},
		{
			name:   "toggle with errors in bulk update",
			params: `{"search_filter": "so_detection.title:problematic AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "true"}`,
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
			},
			expectedResult:     "Enabled=0, Audited=0, Filtered=0, Errs=map[PUB006:unsupported engine], Duration=25ms",
			expectedEnable:     true,
			expectedDetections: 1,
		},
		{
			name:   "toggle with filtered detections",
			params: `{"search_filter": "so_detection.title:filtered AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "true"}`,
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
			},
			expectedResult:     "Enabled=1, Audited=1, Filtered=1, Errs=map[], Duration=80ms",
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
			params:         `{"search_filter": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "true"}`,
			mockQueryError: assert.AnError,
			expectedError:  true,
		},
		{
			name:   "bulk update error",
			params: `{"search_filter": "so_detection.title:test AND _index:\"*:so-detection\" AND so_kind:detection", "enable": "true"}`,
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock detection store
			mockDetectionstore := &FakeDetectionstore{}
			if tc.mockQueryResults != nil {
				mockDetectionstore.QueryWithRangeResults = tc.mockQueryResults
			}
			if tc.mockQueryError != nil {
				mockDetectionstore.QueryWithRangeError = tc.mockQueryError
			}
			if tc.mockBulkStats != nil {
				mockDetectionstore.BulkUpdateStats = tc.mockBulkStats
			}
			if tc.mockBulkError != nil {
				mockDetectionstore.BulkUpdateError = tc.mockBulkError
			}

			// Create mock server with proper authorization
			mockServer := server.NewFakeAuthorizedServer(map[string][]string{
				"test-user-id": {"detections/write"},
			})
			mockServer.Detectionstore = mockDetectionstore

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

			// Verify query was called with correct parameters
			if tc.mockQueryResults != nil || tc.mockQueryError != nil {
				assert.True(t, mockDetectionstore.QueryWithRangeCalled)
				assert.Contains(t, mockDetectionstore.QueryWithRangeQuery, "NOT metadata.raw_index:")
			}

			// Verify bulk update was called with correct parameters
			if tc.expectedDetections > 0 && tc.mockBulkError == nil {
				assert.True(t, mockDetectionstore.BulkUpdateCalled)
				assert.Equal(t, tc.expectedEnable, mockDetectionstore.BulkUpdateEnable)
				assert.Len(t, mockDetectionstore.BulkUpdateDetectionList, tc.expectedDetections)
			}

			// Assert result content
			if tc.expectedResult != "" {
				assert.Equal(t, tc.expectedResult, result.Result)
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
	description := tool.GetDescription()
	assert.Contains(t, description, "Enable or disable detections in Security Onion")
	assert.Contains(t, description, "_index:\"*:so-detection\" AND so_kind:detection")
	assert.Contains(t, description, "999 days ago")
	assert.Contains(t, description, "wildcards")
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
	assert.Contains(t, searchFilter.Description, "so_detection.id")
	assert.Contains(t, searchFilter.Description, "so_detection.title")
	assert.Contains(t, searchFilter.Description, "so_detection.severity")
	assert.Contains(t, searchFilter.Description, "so_detection.isEnabled")

	// Check enable property
	enable := schema.Json.Properties["enable"]
	assert.Equal(t, "string", enable.Type)
	assert.Contains(t, enable.Description, "true")
	assert.Contains(t, enable.Description, "false")

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
			// Create mock detection store
			mockDetectionstore := &FakeDetectionstore{}
			mockDetectionstore.QueryWithRangeResults = []interface{}{} // No results to avoid bulk update

			// Create mock server with proper authorization
			mockServer := server.NewFakeAuthorizedServer(map[string][]string{
				"test-user-id": {"detections/write"},
			})
			mockServer.Detectionstore = mockDetectionstore

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create parameters - properly escape quotes in JSON
			escapedFilter := strings.ReplaceAll(tc.searchFilter, `"`, `\"`)
			params := `{"search_filter": "` + escapedFilter + `", "enable": "true"}`

			// Create tool and execute
			tool := &ToggleDetectionsTool{}
			result, err := tool.Execute(ctx, mockServer, params, "")

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "No detections found", result.Result)

			// Verify the query was modified correctly
			assert.True(t, mockDetectionstore.QueryWithRangeCalled)
			assert.Equal(t, tc.expectedQuery, mockDetectionstore.QueryWithRangeQuery)
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
			// Create mock detection store
			mockDetectionstore := &FakeDetectionstore{}
			mockDetectionstore.QueryWithRangeResults = []interface{}{
				&model.Detection{
					Auditable: model.Auditable{Id: "detection-1"},
					PublicID:  "PUB001",
					Title:     "Test Detection",
					IsEnabled: false,
				},
			}
			// Add mock bulk update stats for successful cases
			if !tc.expectError {
				mockDetectionstore.BulkUpdateStats = &model.BulkUpdateStats{
					Updated:        1,
					Audited:        1,
					Filtered:       0,
					ErrMap:         map[string]string{},
					UpdateDuration: 50000000, // 50ms in nanoseconds
				}
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

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Create parameters
			params := `{"search_filter": "so_detection.title:test", "enable": "true"}`

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
