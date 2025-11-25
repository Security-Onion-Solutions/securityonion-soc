// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestUpdateOverridesTool_GetName(t *testing.T) {
	tool := &UpdateOverridesTool{}
	assert.Equal(t, "update_overrides", tool.GetName())
}

func TestUpdateOverridesTool_GetDescription(t *testing.T) {
	desc := (&UpdateOverridesTool{}).GetDescription()
	assert.NotEmpty(t, desc)
}

func TestUpdateOverridesTool_GetSchema(t *testing.T) {
	schema := (&UpdateOverridesTool{}).GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)

	// Check required properties
	assert.Contains(t, schema.Json.Properties, "soc_id")
	assert.Contains(t, schema.Json.Properties, "public_id")
	assert.Contains(t, schema.Json.Properties, "overrides")
}

func TestUpdateOverridesTool_Execute(t *testing.T) {
	// Helper function to create string pointers
	strPtr := func(s string) *string { return &s }
	intPtr := func(i int) *int { return &i }

	testCases := []struct {
		name                  string
		params                string
		mockDetection         *model.Detection
		mockUpdatedDetection  *model.Detection
		mockGetDetectionError error
		mockEngineError       error
		mockUpdateError       error
		mockSyncError         error
		expectedError         bool
		usePublicId           bool
	}{
		{
			name:   "successful update with suricata threshold override",
			params: `{"soc_id": "test-id", "overrides": [{"note":"","isEnabled":true,"type":"threshold","thresholdType":"both","track":"by_src","count":10,"seconds":60}]}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				PublicID:  "test-public-id",
				Title:     "Test Suricata Rule",
				Engine:    model.EngineNameSuricata,
				Language:  model.SigLangSuricata,
				Overrides: []*model.Override{},
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				PublicID:  "test-public-id",
				Title:     "Test Suricata Rule",
				Engine:    model.EngineNameSuricata,
				Language:  model.SigLangSuricata,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeThreshold,
						IsEnabled: true,
						Note:      "",
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						OverrideParameters: model.OverrideParameters{
							ThresholdType: strPtr("both"),
							Track:         strPtr("by_src"),
							Count:         intPtr(10),
							Seconds:       intPtr(60),
						},
					},
				},
			},
		},
		{
			name:   "successful update with sigma custom filter override",
			params: `{"public_id": "test-public-id", "overrides": [{"note":"Custom filter","isEnabled":true,"type":"customFilter","customFilter":"sofilter:\n  user.name: test_user"}]}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				PublicID:  "test-public-id",
				Title:     "Test Sigma Rule",
				Engine:    model.EngineNameElastAlert,
				Language:  model.SigLangSigma,
				Overrides: []*model.Override{},
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				PublicID:  "test-public-id",
				Title:     "Test Sigma Rule",
				Engine:    model.EngineNameElastAlert,
				Language:  model.SigLangSigma,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeCustomFilter,
						IsEnabled: true,
						Note:      "Custom filter",
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						OverrideParameters: model.OverrideParameters{
							CustomFilter: strPtr("sofilter:\n  user.name: test_user"),
						},
					},
				},
			},
			usePublicId: true,
		},
		{
			name:   "multiple overrides update",
			params: `{"soc_id": "test-id", "overrides": [{"note":"First","isEnabled":true,"type":"threshold","thresholdType":"limit","track":"by_src","count":5,"seconds":30},{"note":"Second","isEnabled":false,"type":"modify","regex":"sid:1000001;","value":"sid:1000002;"}]}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				PublicID:  "test-public-id",
				Engine:    model.EngineNameSuricata,
				Overrides: []*model.Override{},
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				PublicID:  "test-public-id",
				Engine:    model.EngineNameSuricata,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeThreshold,
						IsEnabled: true,
						Note:      "First",
						OverrideParameters: model.OverrideParameters{
							ThresholdType: strPtr("limit"),
							Track:         strPtr("by_src"),
							Count:         intPtr(5),
							Seconds:       intPtr(30),
						},
					},
					{
						Type:      model.OverrideTypeModify,
						IsEnabled: false,
						Note:      "Second",
						OverrideParameters: model.OverrideParameters{
							Regex: strPtr("sid:1000001;"),
							Value: strPtr("sid:1000002;"),
						},
					},
				},
			},
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"soc_id": "test-id", "overrides": "invalid json"}`,
			expectedError: true,
		},
		{
			name:                  "detection not found",
			params:                `{"soc_id": "nonexistent-id", "overrides": []}`,
			mockGetDetectionError: errors.New("detection not found"),
			expectedError:         true,
		},
		{
			name:   "validation error - missing required parameters",
			params: `{"soc_id": "test-id", "overrides": [{"type":"threshold","isEnabled":true,"track":"by_src"}]}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				PublicID:  "test-public-id",
				Engine:    model.EngineNameSuricata,
			},
			expectedError: true,
		},
		{
			name:   "unsupported engine",
			params: `{"soc_id": "test-id", "overrides": []}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				Engine:    model.EngineNameSuricata,
			},
			mockEngineError: errors.New("engine not found"),
			expectedError:   true,
		},
		{
			name:   "update detection error",
			params: `{"soc_id": "test-id", "overrides": []}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				Engine:    model.EngineNameSuricata,
			},
			mockUpdateError: errors.New("failed to update detection"),
			expectedError:   true,
		},
		{
			name:   "sync error",
			params: `{"soc_id": "test-id", "overrides": []}`,
			mockDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				Engine:    model.EngineNameSuricata,
			},
			mockUpdatedDetection: &model.Detection{
				Auditable: model.Auditable{Id: "test-id"},
				Engine:    model.EngineNameSuricata,
				Overrides: []*model.Override{},
			},
			mockSyncError: errors.New("failed to sync"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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

			if tc.mockEngineError == nil && tc.mockDetection != nil {
				mockServer.DetectionEngines.Store(tc.mockDetection.Engine, mockDetectionEngine)
			}

			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Set up mock expectations
			if tc.params != `{"soc_id": "test-id", "overrides": "invalid json"}` {
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

					if tc.name == "validation error - missing required parameters" {
						// Don't set up engine expectations since validation fails early
					} else if tc.mockEngineError != nil {
						// Don't set up engine expectations for unsupported engine
					} else if tc.mockUpdateError != nil {
						mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).Return(nil, tc.mockUpdateError)
					} else if tc.mockSyncError != nil {
						mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).Return(tc.mockUpdatedDetection, nil)
						mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(nil, tc.mockSyncError)
					} else {
						// Successful case
						mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
							assert.Equal(t, "", detect.Kind)
							assert.Equal(t, "", detect.Operation)
							return tc.mockUpdatedDetection, nil
						})
						mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)
						mockDetectionEngine.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)
					}
				}
			}

			tool := &UpdateOverridesTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params, "")

			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "update_overrides", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.NotZero(t, result.TimeToExecute)

			if tc.mockUpdatedDetection != nil {
				assert.Equal(t, tc.mockUpdatedDetection, result.Result)
			}

			assert.NotNil(t, result.Parameters)
			args, ok := result.Parameters.(*updateOverridesArgs)
			assert.True(t, ok)
			assert.NotNil(t, args)
		})
	}
}

func TestUpdateOverridesTool_Execute_TimestampHandling(t *testing.T) {
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
	mockServer.DetectionEngines.Store(model.EngineNameSuricata, mockDetectionEngine)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

	strPtr := func(s string) *string { return &s }
	intPtr := func(i int) *int { return &i }

	existingTime := time.Now().Add(-time.Hour)
	mockDetection := &model.Detection{
		Auditable: model.Auditable{Id: "test-id"},
		PublicID:  "test-public-id",
		Engine:    model.EngineNameSuricata,
		Overrides: []*model.Override{
			{
				Type:      model.OverrideTypeThreshold,
				IsEnabled: true,
				CreatedAt: existingTime,
				UpdatedAt: existingTime,
				OverrideParameters: model.OverrideParameters{
					ThresholdType: strPtr("limit"),
					Track:         strPtr("by_src"),
					Count:         intPtr(5),
					Seconds:       intPtr(30),
				},
			},
		},
	}

	mockUpdatedDetection := &model.Detection{
		Auditable: model.Auditable{Id: "test-id"},
		PublicID:  "test-public-id",
		Engine:    model.EngineNameSuricata,
		Overrides: []*model.Override{
			{
				Type:      model.OverrideTypeThreshold,
				IsEnabled: true,
				CreatedAt: existingTime,
				UpdatedAt: time.Now(),
				OverrideParameters: model.OverrideParameters{
					ThresholdType: strPtr("both"),
					Track:         strPtr("by_dst"),
					Count:         intPtr(10),
					Seconds:       intPtr(60),
				},
			},
		},
	}

	mockDetectionstore.EXPECT().GetDetection(ctx, "test-id").Return(mockDetection, nil)
	mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
		if len(detect.Overrides) > 0 {
			override := detect.Overrides[0]
			// CreatedAt should be preserved, UpdatedAt should be updated
			assert.Equal(t, existingTime.Unix(), override.CreatedAt.Unix())
			assert.True(t, override.UpdatedAt.After(existingTime))
		}
		return mockUpdatedDetection, nil
	})
	mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)
	mockDetectionEngine.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)

	tool := &UpdateOverridesTool{}
	params := fmt.Sprintf(`{"soc_id": "test-id", "overrides": [{"isEnabled":true,"type":"threshold","thresholdType":"both","track":"by_dst","count":10,"seconds":60,"createdAt":"%s","updatedAt":"%s"}]}`,
		existingTime.Format(time.RFC3339), existingTime.Format(time.RFC3339))
	result, err := tool.Execute(ctx, mockServer, params, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, mockUpdatedDetection, result.Result)
}

func TestUpdateOverridesTool_Execute_EmptyOverrides(t *testing.T) {
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
	mockServer.DetectionEngines.Store(model.EngineNameSuricata, mockDetectionEngine)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

	strPtr := func(s string) *string { return &s }
	intPtr := func(i int) *int { return &i }

	mockDetection := &model.Detection{
		Auditable: model.Auditable{Id: "test-id"},
		PublicID:  "test-public-id",
		Engine:    model.EngineNameSuricata,
		Overrides: []*model.Override{
			{
				Type:      model.OverrideTypeThreshold,
				IsEnabled: true,
				CreatedAt: time.Now().Add(-time.Hour),
				UpdatedAt: time.Now().Add(-time.Hour),
				OverrideParameters: model.OverrideParameters{
					ThresholdType: strPtr("limit"),
					Track:         strPtr("by_src"),
					Count:         intPtr(5),
					Seconds:       intPtr(30),
				},
			},
		},
	}

	mockUpdatedDetection := &model.Detection{
		Auditable: model.Auditable{Id: "test-id"},
		PublicID:  "test-public-id",
		Engine:    model.EngineNameSuricata,
		Overrides: []*model.Override{}, // All overrides removed
	}

	mockDetectionstore.EXPECT().GetDetection(ctx, "test-id").Return(mockDetection, nil)
	mockDetectionstore.EXPECT().UpdateDetection(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
		assert.Len(t, detect.Overrides, 0)
		return mockUpdatedDetection, nil
	})
	mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)
	mockDetectionEngine.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)

	tool := &UpdateOverridesTool{}
	result, err := tool.Execute(ctx, mockServer, `{"soc_id": "test-id", "overrides": []}`, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, mockUpdatedDetection, result.Result)
}
