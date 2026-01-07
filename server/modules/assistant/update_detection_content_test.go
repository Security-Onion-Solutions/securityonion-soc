// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestUpdateDetectionContentTool_GetName(t *testing.T) {
	tool := &UpdateDetectionContentTool{}
	assert.Equal(t, "update_detection_content", tool.GetName())
}

func TestUpdateDetectionContentTool_GetDescription(t *testing.T) {
	desc := (&UpdateDetectionContentTool{}).GetDescription()
	assert.NotEmpty(t, desc)
}

func TestUpdateDetectionContentTool_GetSchema(t *testing.T) {
	schema := (&UpdateDetectionContentTool{}).GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)

	// Check required properties
	assert.Contains(t, schema.Json.Properties, "soc_id")
	assert.Equal(t, "string", schema.Json.Properties["soc_id"].Type)

	assert.Contains(t, schema.Json.Properties, "public_id")
	assert.Equal(t, "string", schema.Json.Properties["public_id"].Type)

	assert.Contains(t, schema.Json.Properties, "content")
	assert.Equal(t, "string", schema.Json.Properties["content"].Type)
}

func TestUpdateDetectionContentTool_Execute(t *testing.T) {
	testCases := []struct {
		name                  string
		params                string
		mockDetection         *model.Detection
		mockUpdatedDetection  *model.Detection
		mockGetDetectionError error
		mockValidateError     error
		mockEngineError       error
		mockRuleValidateError error
		mockExtractError      error
		mockApplyFiltersError error
		mockUpdateError       error
		mockSyncError         error
		mockSyncErrMap        map[string]string
		mockMergeAuxError     error
		expectedError         bool
		usePublicId           bool
	}{
		{
			name:   "successful update with soc_id",
			params: `{"soc_id": "gQKCepgBAWAm-kn2lYs2", "content": "title: Updated Test Rule\nid: 12345\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '.exe'\n  condition: selection"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "gQKCepgBAWAm-kn2lYs2",
				},
				PublicID: "test-detection-public-id",
				Title:    "Original Test Rule",
				Content:  "title: Original Test Rule\nid: 12345\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '.exe'\n  condition: selection",
				Engine:   model.EngineNameElastAlert,
				Language: model.SigLangSigma,
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "gQKCepgBAWAm-kn2lYs2",
				},
				PublicID: "test-detection-public-id",
				Title:    "Updated Test Rule",
				Content:  "title: Updated Test Rule\nid: 12345\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '.exe'\n  condition: selection",
				Engine:   model.EngineNameElastAlert,
				Language: model.SigLangSigma,
			},
		},
		{
			name:   "successful update with public_id",
			params: `{"public_id": "dcbe6004-f6e0-4579-9f98-9576201ffb29", "content": "alert tcp any any -> any any (msg:\"Updated Test Rule\"; sid:1000001; rev:2;)"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "hRLDepgBAWAm-kn2mZt3",
				},
				PublicID: "dcbe6004-f6e0-4579-9f98-9576201ffb29",
				Title:    "Original Suricata Rule",
				Content:  "alert tcp any any -> any any (msg:\"Original Test Rule\"; sid:1000001; rev:1;)",
				Engine:   model.EngineNameSuricata,
				Language: model.SigLangSuricata,
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "hRLDepgBAWAm-kn2mZt3",
				},
				PublicID: "dcbe6004-f6e0-4579-9f98-9576201ffb29",
				Title:    "Updated Suricata Rule",
				Content:  "alert tcp any any -> any any (msg:\"Updated Test Rule\"; sid:1000001; rev:2;)",
				Engine:   model.EngineNameSuricata,
				Language: model.SigLangSuricata,
			},
			usePublicId: true,
		},
		{
			name:   "successful yara detection update",
			params: `{"soc_id": "yara-detection-id", "content": "rule UpdatedTestRule {\n  meta:\n    description = \"Updated YARA rule\"\n  strings:\n    $test = \"updated_malware\"\n  condition:\n    $test\n}"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "yara-detection-id",
				},
				PublicID: "yara-public-id",
				Title:    "OriginalTestRule",
				Content:  "rule OriginalTestRule {\n  meta:\n    description = \"Original YARA rule\"\n  strings:\n    $test = \"malware\"\n  condition:\n    $test\n}",
				Engine:   model.EngineNameStrelka,
				Language: model.SigLangYara,
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "yara-detection-id",
				},
				PublicID: "yara-public-id",
				Title:    "UpdatedTestRule",
				Content:  "rule UpdatedTestRule {\n  meta:\n    description = \"Updated YARA rule\"\n  strings:\n    $test = \"updated_malware\"\n  condition:\n    $test\n}",
				Engine:   model.EngineNameStrelka,
				Language: model.SigLangYara,
			},
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"soc_id": "test-id", "content": "missing closing brace"`,
			expectedError: true,
		},
		{
			name:                  "detection not found by soc_id",
			params:                `{"soc_id": "nonexistent-id", "content": "title: Test"}`,
			mockGetDetectionError: errors.New("detection not found"),
			expectedError:         true,
		},
		{
			name:                  "detection not found by public_id",
			params:                `{"public_id": "nonexistent-public-id", "content": "title: Test"}`,
			mockGetDetectionError: errors.New("detection not found"),
			expectedError:         true,
			usePublicId:           true,
		},
		{
			name:   "detection validation error",
			params: `{"soc_id": "test-id", "content": "invalid content"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   "invalid-engine", // This will cause validation to fail
			},
			mockValidateError: errors.New("invalid detection"),
			expectedError:     true,
		},
		{
			name:   "unsupported engine",
			params: `{"soc_id": "test-id", "content": "title: Test"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   model.EngineNameElastAlert,
			},
			mockEngineError: errors.New("engine not found"),
			expectedError:   true,
		},
		{
			name:   "rule validation error",
			params: `{"soc_id": "test-id", "content": "invalid rule syntax"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   model.EngineNameElastAlert,
			},
			mockRuleValidateError: errors.New("invalid rule syntax"),
			expectedError:         true,
		},
		{
			name:   "extract details error",
			params: `{"soc_id": "test-id", "content": "title: Test"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   model.EngineNameElastAlert,
			},
			mockExtractError: errors.New("failed to extract details"),
			expectedError:    true,
		},
		{
			name:   "apply filters error",
			params: `{"soc_id": "test-id", "content": "title: Test"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   model.EngineNameElastAlert,
			},
			mockApplyFiltersError: errors.New("failed to apply filters"),
			expectedError:         true,
		},
		{
			name:   "update detection error",
			params: `{"soc_id": "test-id", "content": "title: Test"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   model.EngineNameElastAlert,
			},
			mockUpdateError: errors.New("failed to update detection"),
			expectedError:   true,
		},
		{
			name:   "sync local detections error",
			params: `{"soc_id": "test-id", "content": "title: Test"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   model.EngineNameElastAlert,
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "title: Test",
				Engine:   model.EngineNameElastAlert,
			},
			mockSyncError: errors.New("failed to sync"),
			expectedError: true,
		},
		{
			name:   "sync local detections error map",
			params: `{"soc_id": "test-id", "content": "title: Test"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   model.EngineNameElastAlert,
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "title: Test",
				Engine:   model.EngineNameElastAlert,
			},
			mockSyncErrMap: map[string]string{"test-id": "sync failed"},
			expectedError:  true,
		},
		{
			name:   "merge auxiliary data error (non-fatal)",
			params: `{"soc_id": "test-id", "content": "title: Test"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "original content",
				Engine:   model.EngineNameElastAlert,
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "test-id",
				},
				PublicID: "test-public-id",
				Title:    "Test Rule",
				Content:  "title: Test",
				Engine:   model.EngineNameElastAlert,
			},
			mockMergeAuxError: errors.New("failed to merge auxiliary data"),
			expectedError:     false, // This error is logged but not fatal
		},
		{
			name:   "community detection cannot be updated",
			params: `{"soc_id": "community-detection-id", "content": "title: Updated Community Rule"}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{
					Id: "community-detection-id",
				},
				PublicID:    "community-public-id",
				Title:       "Community Rule",
				Content:     "original community content",
				Engine:      model.EngineNameElastAlert,
				IsCommunity: true, // This should trigger the error
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mock stores
			mockDetectionstore := mock.NewMockDetectionstore(ctrl)
			mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

			// Create mock server
			mockServer := &server.Server{
				Detectionstore: mockDetectionstore,
				Config: &config.ServerConfig{
					DeveloperEnabled: true,
				},
			}

			// Set up detection engine expectations if not expecting engine error
			if tc.mockEngineError == nil && tc.mockDetection != nil {
				mockServer.DetectionEngines.Store(tc.mockDetection.Engine, mockDetectionEngine)
			}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Set up mock expectations based on test case
			// Always set up GetDetection or GetDetectionByPublicId expectations unless it's just a JSON parsing error
			if tc.params != `{"soc_id": "test-id", "content": "missing closing brace"` {
				if tc.mockGetDetectionError != nil {
					if tc.usePublicId {
						mockDetectionstore.EXPECT().GetDetectionByPublicId(ctx, gomock.Any()).Return(nil, tc.mockGetDetectionError)
					} else {
						mockDetectionstore.EXPECT().GetDetection(ctx, gomock.Any()).Return(nil, tc.mockGetDetectionError)
					}
				} else if tc.mockDetection != nil {
					if tc.usePublicId {
						mockDetectionstore.EXPECT().GetDetectionByPublicId(ctx, gomock.Any()).Return(tc.mockDetection, nil)
					} else {
						mockDetectionstore.EXPECT().GetDetection(ctx, gomock.Any()).Return(tc.mockDetection, nil)
					}

					// Set up subsequent expectations based on error type
					// Skip all engine expectations for community detection error since it returns early
					if tc.name == "community detection cannot be updated" {
						// Don't set up any engine expectations since the function returns early with community error
					} else if tc.mockValidateError != nil {
						// Detection.Validate() is called on the detection object itself, so we can't mock it directly
						// This would require the detection to have invalid fields
						// For this test case, we need to set up the engine but not expect any calls since validation fails early
						if tc.mockEngineError == nil {
							// Don't set up any engine expectations since validation fails before engine calls
						}
					} else if tc.mockEngineError != nil {
						// For unsupported engine test, don't set up any engine expectations
					} else if tc.mockRuleValidateError != nil {
						mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("", tc.mockRuleValidateError)
					} else if tc.mockExtractError != nil {
						mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
						mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(tc.mockExtractError)
					} else if tc.mockApplyFiltersError != nil {
						mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
						mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
						mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, tc.mockApplyFiltersError)
					} else if tc.mockUpdateError != nil {
						mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
						mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
						mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
						mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).Return(nil, tc.mockUpdateError)
					} else if tc.mockSyncError != nil {
						mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
						mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
						mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
						mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).Return(tc.mockUpdatedDetection, nil)
						mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(nil, tc.mockSyncError)
					} else if tc.mockSyncErrMap != nil {
						mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
						mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
						mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
						mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).Return(tc.mockUpdatedDetection, nil)
						mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(tc.mockSyncErrMap, nil)
					} else {
						// Successful case
						mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
						mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
						mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
						mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
							// Verify that content was updated and Kind/Operation were cleared
							assert.Equal(t, "", detect.Kind)
							assert.Equal(t, "", detect.Operation)
							return tc.mockUpdatedDetection, nil
						})
						mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)

						if tc.mockMergeAuxError != nil {
							mockDetectionEngine.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(tc.mockMergeAuxError)
						} else {
							mockDetectionEngine.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)
						}
					}
				}
			}

			// Create tool and execute
			tool := &UpdateDetectionContentTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params, "")

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "update_detection_content", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.NotZero(t, result.TimeToExecute)

			// Verify result content
			if tc.mockUpdatedDetection != nil {
				assert.Equal(t, tc.mockUpdatedDetection, result.Result)
			}

			// Verify parameters were captured
			assert.NotNil(t, result.Parameters)
			args, ok := result.Parameters.(*updateDetectionContentArgs)
			assert.True(t, ok)
			assert.NotNil(t, args)
		})
	}
}

func TestUpdateDetectionContentTool_Execute_VerifyContextPropagation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

	mockServer := &server.Server{
		Detectionstore: mockDetectionstore,
		Config: &config.ServerConfig{
			DeveloperEnabled: true,
		},
	}
	mockServer.DetectionEngines.Store(model.EngineNameElastAlert, mockDetectionEngine)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	mockDetection := &model.Detection{
		Auditable: model.Auditable{
			Id: "test-detection-id",
		},
		PublicID: "test-public-id",
		Title:    "Test Rule",
		Content:  "original content",
		Engine:   model.EngineNameElastAlert,
	}

	mockUpdatedDetection := &model.Detection{
		Auditable: model.Auditable{
			Id: "test-detection-id",
		},
		PublicID: "test-public-id",
		Title:    "Updated Test Rule",
		Content:  "title: Updated Test Rule",
		Engine:   model.EngineNameElastAlert,
	}

	// Set up expectations
	mockDetectionstore.EXPECT().GetDetection(ctx, "test-detection-id").Return(mockDetection, nil)
	mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
	mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
	mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
	mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).Return(mockUpdatedDetection, nil)
	mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)
	mockDetectionEngine.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)

	tool := &UpdateDetectionContentTool{}
	_, err := tool.Execute(ctx, mockServer, `{"soc_id": "test-detection-id", "content": "title: Updated Test Rule"}`, "")

	assert.NoError(t, err)
}

func TestUpdateDetectionContentTool_Execute_ContentUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

	mockServer := &server.Server{
		Detectionstore: mockDetectionstore,
		Config: &config.ServerConfig{
			DeveloperEnabled: true,
		},
	}
	mockServer.DetectionEngines.Store(model.EngineNameElastAlert, mockDetectionEngine)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

	originalContent := "title: Original Rule\nid: test-123\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\\\original.exe'\n  condition: selection"
	updatedContent := "title: Updated Rule\nid: test-123\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\\\updated.exe'\n  condition: selection"

	mockDetection := &model.Detection{
		Auditable: model.Auditable{
			Id:        "test-detection-id",
			Kind:      "original-kind",
			Operation: "original-operation",
		},
		PublicID: "test-public-id",
		Title:    "Original Rule",
		Content:  originalContent,
		Engine:   model.EngineNameElastAlert,
	}

	mockUpdatedDetection := &model.Detection{
		Auditable: model.Auditable{
			Id:        "test-detection-id",
			Kind:      "", // Should be cleared
			Operation: "", // Should be cleared
		},
		PublicID: "test-public-id",
		Title:    "Updated Rule",
		Content:  updatedContent,
		Engine:   model.EngineNameElastAlert,
	}

	// Set up expectations
	mockDetectionstore.EXPECT().GetDetection(ctx, "test-detection-id").Return(mockDetection, nil)
	mockDetectionEngine.EXPECT().ValidateRule(updatedContent).Return("validated", nil)
	mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).DoAndReturn(func(detect *model.Detection) error {
		// Verify content was updated before ExtractDetails is called
		assert.Equal(t, updatedContent, detect.Content)
		return nil
	})
	mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
	mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
		// Verify that content was updated and Kind/Operation were cleared
		assert.Equal(t, updatedContent, detect.Content)
		assert.Equal(t, "", detect.Kind)
		assert.Equal(t, "", detect.Operation)
		return mockUpdatedDetection, nil
	})
	mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)
	mockDetectionEngine.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)

	tool := &UpdateDetectionContentTool{}
	// Use fmt.Sprintf with %q to properly escape the JSON content
	params := fmt.Sprintf(`{"soc_id": "test-detection-id", "content": %q}`, updatedContent)
	result, err := tool.Execute(ctx, mockServer, params, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, mockUpdatedDetection, result.Result)
}

func TestUpdateDetectionContentTool_Execute_TimeToExecute(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

	mockServer := &server.Server{
		Detectionstore: mockDetectionstore,
		Config: &config.ServerConfig{
			DeveloperEnabled: true,
		},
	}
	mockServer.DetectionEngines.Store(model.EngineNameElastAlert, mockDetectionEngine)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

	mockDetection := &model.Detection{
		Auditable: model.Auditable{
			Id: "test-detection-id",
		},
		PublicID: "test-public-id",
		Title:    "Test Rule",
		Content:  "original content",
		Engine:   model.EngineNameElastAlert,
	}

	mockUpdatedDetection := &model.Detection{
		Auditable: model.Auditable{
			Id: "test-detection-id",
		},
		PublicID: "test-public-id",
		Title:    "Updated Test Rule",
		Content:  "title: Updated Test Rule",
		Engine:   model.EngineNameElastAlert,
	}

	// Set up expectations
	mockDetectionstore.EXPECT().GetDetection(ctx, "test-detection-id").Return(mockDetection, nil)
	mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
	mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
	mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
	mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).Return(mockUpdatedDetection, nil)
	mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)
	mockDetectionEngine.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)

	tool := &UpdateDetectionContentTool{}
	result, err := tool.Execute(ctx, mockServer, `{"soc_id": "test-detection-id", "content": "title: Updated Test Rule"}`, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotZero(t, result.TimeToExecute)
}
