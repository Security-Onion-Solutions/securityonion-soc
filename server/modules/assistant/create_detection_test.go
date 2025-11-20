// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestCreateDetectionTool_GetName(t *testing.T) {
	tool := &CreateDetectionTool{}
	assert.Equal(t, "create_detection", tool.GetName())
}

func TestCreateDetectionTool_GetDescription(t *testing.T) {
	desc := (&CreateDetectionTool{}).GetDescription()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Create a new detection")
}

func TestCreateDetectionTool_GetSchema(t *testing.T) {
	schema := (&CreateDetectionTool{}).GetSchema()

	assert.NotNil(t, schema.Json)
	assert.Equal(t, "object", schema.Json.Type)
	assert.Contains(t, schema.Json.Properties, "language")
	assert.Equal(t, "string", schema.Json.Properties["language"].Type)
	assert.Contains(t, schema.Json.Properties["language"].Description, "sigma")
	assert.Contains(t, schema.Json.Properties["language"].Description, "suricata")
	assert.Contains(t, schema.Json.Properties["language"].Description, "yara")

	assert.Contains(t, schema.Json.Properties, "license")
	assert.Equal(t, "string", schema.Json.Properties["license"].Type)

	assert.Contains(t, schema.Json.Properties, "content")
	assert.Equal(t, "string", schema.Json.Properties["content"].Type)

	assert.Contains(t, schema.Json.Required, "search_filter")
}

func TestCreateDetectionTool_Execute(t *testing.T) {
	testCases := []struct {
		name               string
		params             string
		mockDetection      *model.Detection
		mockUser           *model.User
		mockDetectionError error
		mockUserError      error
		mockEngineError    error
		mockValidateError  error
		mockExtractError   error
		mockApplyError     error
		mockSyncError      error
		mockSyncErrMap     map[string]string
		expectedError      bool
		expectedEngine     model.EngineName
		expectedLanguage   model.SigLanguage
		expectedRuleset    string
	}{
		{
			name:   "successful sigma detection creation",
			params: `{"language": "sigma", "license": "DRL", "content": "title: Test Rule\nid: 12345\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '.exe'\n  condition: selection"}`,
			mockDetection: &model.Detection{
				PublicID: "test-detection-id",
				Title:    "Test Rule",
				Content:  "title: Test Rule\nid: 12345\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '.exe'\n  condition: selection",
			},
			mockUser: &model.User{
				Id:        "test-user-id",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
			},
			expectedEngine:   model.EngineNameElastAlert,
			expectedLanguage: model.SigLangSigma,
			expectedRuleset:  detections.RULESET_CUSTOM,
		},
		{
			name:   "successful suricata detection creation",
			params: `{"language": "suricata", "license": "DRL", "content": "alert tcp any any -> any any (msg:\"Test Rule\"; sid:1000001; rev:1;)"}`,
			mockDetection: &model.Detection{
				PublicID: "test-detection-id-2",
				Title:    "Test Suricata Rule",
				Content:  "alert tcp any any -> any any (msg:\"Test Rule\"; sid:1000001; rev:1;)",
			},
			mockUser: &model.User{
				Id:        "test-user-id",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
			},
			expectedEngine:   model.EngineNameSuricata,
			expectedLanguage: model.SigLangSuricata,
			expectedRuleset:  detections.RULESET_CUSTOM,
		},
		{
			name:   "successful yara detection creation",
			params: `{"language": "yara", "license": "DRL", "content": "rule TestRule {\n  meta:\n    description = \"Test YARA rule\"\n  strings:\n    $test = \"malware\"\n  condition:\n    $test\n}"}`,
			mockDetection: &model.Detection{
				PublicID: "test-detection-id-3",
				Title:    "TestRule",
				Content:  "rule TestRule {\n  meta:\n    description = \"Test YARA rule\"\n  strings:\n    $test = \"malware\"\n  condition:\n    $test\n}",
			},
			mockUser: &model.User{
				Id:        "test-user-id",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
			},
			expectedEngine:   model.EngineNameStrelka,
			expectedLanguage: model.SigLangYara,
			expectedRuleset:  detections.RULESET_CUSTOM,
		},
		{
			name:          "invalid JSON parameters",
			params:        `{"language": "sigma", "license": "DRL", "content": "missing closing brace"`,
			expectedError: true,
		},
		{
			name:             "unsupported engine",
			params:           `{"language": "sigma", "license": "DRL", "content": "title: Test"}`,
			mockEngineError:  errors.New("engine not found"),
			expectedError:    true,
			expectedEngine:   model.EngineNameElastAlert,
			expectedLanguage: model.SigLangSigma,
		},
		{
			name:              "rule validation error",
			params:            `{"language": "sigma", "license": "DRL", "content": "invalid rule content"}`,
			mockValidateError: errors.New("invalid rule syntax"),
			expectedError:     true,
			expectedEngine:    model.EngineNameElastAlert,
			expectedLanguage:  model.SigLangSigma,
		},
		{
			name:             "extract details error",
			params:           `{"language": "sigma", "license": "DRL", "content": "title: Test"}`,
			mockExtractError: errors.New("failed to extract details"),
			expectedError:    true,
			expectedEngine:   model.EngineNameElastAlert,
			expectedLanguage: model.SigLangSigma,
		},
		{
			name:             "user retrieval error",
			params:           `{"language": "sigma", "license": "DRL", "content": "title: Test"}`,
			mockUserError:    errors.New("user not found"),
			expectedError:    true,
			expectedEngine:   model.EngineNameElastAlert,
			expectedLanguage: model.SigLangSigma,
		},
		{
			name:             "apply filters error",
			params:           `{"language": "sigma", "license": "DRL", "content": "title: Test"}`,
			mockApplyError:   errors.New("failed to apply filters"),
			expectedError:    true,
			expectedEngine:   model.EngineNameElastAlert,
			expectedLanguage: model.SigLangSigma,
			mockUser: &model.User{
				Id:        "test-user-id",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
			},
		},
		{
			name:               "detection store creation error",
			params:             `{"language": "sigma", "license": "DRL", "content": "title: Test"}`,
			mockDetectionError: errors.New("failed to create detection"),
			expectedError:      true,
			expectedEngine:     model.EngineNameElastAlert,
			expectedLanguage:   model.SigLangSigma,
			mockUser: &model.User{
				Id:        "test-user-id",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
			},
		},
		{
			name:             "sync local detections error",
			params:           `{"language": "sigma", "license": "DRL", "content": "title: Test"}`,
			mockSyncError:    errors.New("failed to sync"),
			expectedError:    true,
			expectedEngine:   model.EngineNameElastAlert,
			expectedLanguage: model.SigLangSigma,
			mockDetection: &model.Detection{
				PublicID: "test-detection-id",
				Title:    "Test Rule",
				Content:  "title: Test",
			},
			mockUser: &model.User{
				Id:        "test-user-id",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
			},
		},
		{
			name:             "sync local detections error map",
			params:           `{"language": "sigma", "license": "DRL", "content": "title: Test"}`,
			mockSyncErrMap:   map[string]string{"test-detection-id": "sync failed"},
			expectedError:    true,
			expectedEngine:   model.EngineNameElastAlert,
			expectedLanguage: model.SigLangSigma,
			mockDetection: &model.Detection{
				PublicID: "test-detection-id",
				Title:    "Test Rule",
				Content:  "title: Test",
			},
			mockUser: &model.User{
				Id:        "test-user-id",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
			},
		},
		{
			name:   "case insensitive language handling",
			params: `{"language": "SIGMA", "license": "DRL", "content": "title: Test Rule"}`,
			mockDetection: &model.Detection{
				PublicID: "test-detection-id",
				Title:    "Test Rule",
				Content:  "title: Test Rule",
			},
			mockUser: &model.User{
				Id:        "test-user-id",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test@example.com",
			},
			expectedEngine:   model.EngineNameElastAlert,
			expectedLanguage: model.SigLangSigma,
			expectedRuleset:  detections.RULESET_CUSTOM,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create mock stores
			mockDetectionstore := mock.NewMockDetectionstore(ctrl)
			mockUserstore := mock.NewMockUserstore(ctrl)
			mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

			// Create mock server
			mockServer := &server.Server{
				Detectionstore: mockDetectionstore,
				Userstore:      mockUserstore,
				Config: &config.ServerConfig{
					DeveloperEnabled: true,
				},
			}

			// Set up detection engine expectations if not expecting engine error
			if tc.mockEngineError == nil && !tc.expectedError {
				mockServer.DetectionEngines.Store(tc.expectedEngine, mockDetectionEngine)
			} else if tc.mockEngineError == nil && tc.expectedEngine != "" {
				mockServer.DetectionEngines.Store(tc.expectedEngine, mockDetectionEngine)
			}

			// Create context with user ID
			ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

			// Set up mock expectations based on test case
			if !tc.expectedError || tc.mockValidateError != nil || tc.mockExtractError != nil || tc.mockUserError != nil || tc.mockApplyError != nil || tc.mockDetectionError != nil || tc.mockSyncError != nil || tc.mockSyncErrMap != nil {
				if tc.mockValidateError != nil {
					mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("", tc.mockValidateError)
				} else if tc.mockExtractError != nil {
					mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
					mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(tc.mockExtractError)
				} else if tc.mockUserError != nil {
					mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
					mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
					mockUserstore.EXPECT().GetUserById(ctx, "test-user-id").Return(nil, tc.mockUserError)
				} else if tc.mockApplyError != nil {
					mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
					mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
					mockUserstore.EXPECT().GetUserById(ctx, "test-user-id").Return(tc.mockUser, nil)
					mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, tc.mockApplyError)
				} else if tc.mockDetectionError != nil {
					mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
					mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
					mockUserstore.EXPECT().GetUserById(ctx, "test-user-id").Return(tc.mockUser, nil)
					mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
					mockDetectionstore.EXPECT().CreateDetection(ctx, gomock.Any()).Return(nil, tc.mockDetectionError)
				} else if tc.mockSyncError != nil {
					mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
					mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
					mockUserstore.EXPECT().GetUserById(ctx, "test-user-id").Return(tc.mockUser, nil)
					mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
					mockDetectionstore.EXPECT().CreateDetection(ctx, gomock.Any()).Return(tc.mockDetection, nil)
					mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(nil, tc.mockSyncError)
				} else if tc.mockSyncErrMap != nil {
					mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
					mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
					mockUserstore.EXPECT().GetUserById(ctx, "test-user-id").Return(tc.mockUser, nil)
					mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
					mockDetectionstore.EXPECT().CreateDetection(ctx, gomock.Any()).Return(tc.mockDetection, nil)
					mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(tc.mockSyncErrMap, nil)
				} else {
					// Successful case
					mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
					mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
					mockUserstore.EXPECT().GetUserById(ctx, "test-user-id").Return(tc.mockUser, nil)
					mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
					mockDetectionstore.EXPECT().CreateDetection(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
						// Verify detection properties
						assert.Equal(t, tc.expectedLanguage, detect.Language)
						assert.Equal(t, tc.expectedEngine, detect.Engine)
						assert.Equal(t, tc.expectedRuleset, detect.Ruleset)
						assert.Equal(t, "DRL", detect.License)
						return tc.mockDetection, nil
					})
					mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)
				}
			}

			// Create tool and execute
			tool := &CreateDetectionTool{}
			result, err := tool.Execute(ctx, mockServer, tc.params, "")

			// Assert error expectations
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, "create_detection", result.ToolName)
			assert.Equal(t, "test-user-id", result.OnBehalfOfUser)
			assert.NotZero(t, result.TimeToExecute)

			// Verify result content
			assert.Equal(t, tc.mockDetection, result.Result)

			// Verify parameters were captured
			assert.NotNil(t, result.Parameters)
			args, ok := result.Parameters.(*createDetectionArgs)
			assert.True(t, ok)
			assert.NotNil(t, args)
		})
	}
}

func TestCreateDetectionTool_Execute_VerifyContextPropagation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	mockUserstore := mock.NewMockUserstore(ctrl)
	mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

	mockServer := &server.Server{
		Detectionstore: mockDetectionstore,
		Userstore:      mockUserstore,
		Config: &config.ServerConfig{
			DeveloperEnabled: true,
		},
	}
	mockServer.DetectionEngines.Store(model.EngineNameElastAlert, mockDetectionEngine)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-123")

	mockUser := &model.User{
		Id:        "test-user-123",
		FirstName: "Test",
		LastName:  "User",
		Email:     "test@example.com",
	}

	mockDetection := &model.Detection{
		PublicID: "test-detection-id",
		Title:    "Test Rule",
		Content:  "title: Test Rule",
	}

	// Set up expectations
	mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
	mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
	mockUserstore.EXPECT().GetUserById(ctx, "test-user-123").Return(mockUser, nil)
	mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
	mockDetectionstore.EXPECT().CreateDetection(ctx, gomock.Any()).Return(mockDetection, nil)
	mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)

	tool := &CreateDetectionTool{}
	_, err := tool.Execute(ctx, mockServer, `{"language": "sigma", "license": "DRL", "content": "title: Test Rule"}`, "")

	assert.NoError(t, err)
}

func TestCreateDetectionTool_Execute_OverrideTimestamps(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	mockUserstore := mock.NewMockUserstore(ctrl)
	mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

	mockServer := &server.Server{
		Detectionstore: mockDetectionstore,
		Userstore:      mockUserstore,
		Config: &config.ServerConfig{
			DeveloperEnabled: true,
		},
	}
	mockServer.DetectionEngines.Store(model.EngineNameElastAlert, mockDetectionEngine)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

	mockUser := &model.User{
		Id:        "test-user-id",
		FirstName: "Test",
		LastName:  "User",
		Email:     "test@example.com",
	}

	// Create a detection with overrides that have zero timestamps
	mockDetection := &model.Detection{
		PublicID: "test-detection-id",
		Title:    "Test Rule",
		Content:  "title: Test Rule",
		Overrides: []*model.Override{
			{
				Type:      model.OverrideTypeCustomFilter,
				IsEnabled: true,
				// CreatedAt and UpdatedAt are zero values
			},
		},
	}

	// Set up expectations
	mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
	mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
	mockUserstore.EXPECT().GetUserById(ctx, "test-user-id").Return(mockUser, nil)
	mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
	mockDetectionstore.EXPECT().CreateDetection(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
		// Verify that timestamps were set for overrides with zero values
		for _, override := range detect.Overrides {
			assert.False(t, override.CreatedAt.IsZero(), "CreatedAt should be set")
			assert.False(t, override.UpdatedAt.IsZero(), "UpdatedAt should be set")
			assert.WithinDuration(t, time.Now(), override.CreatedAt, time.Second)
			assert.WithinDuration(t, time.Now(), override.UpdatedAt, time.Second)
		}
		return mockDetection, nil
	})
	mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)

	tool := &CreateDetectionTool{}
	result, err := tool.Execute(ctx, mockServer, `{"language": "sigma", "license": "DRL", "content": "title: Test Rule"}`, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCreateDetectionTool_Execute_AuthorAssignment(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDetectionstore := mock.NewMockDetectionstore(ctrl)
	mockUserstore := mock.NewMockUserstore(ctrl)
	mockDetectionEngine := mock.NewMockDetectionEngine(ctrl)

	mockServer := &server.Server{
		Detectionstore: mockDetectionstore,
		Userstore:      mockUserstore,
		Config: &config.ServerConfig{
			DeveloperEnabled: true,
		},
	}
	mockServer.DetectionEngines.Store(model.EngineNameElastAlert, mockDetectionEngine)

	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "test-user-id")

	mockUser := &model.User{
		Id:        "test-user-id",
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
	}

	mockDetection := &model.Detection{
		PublicID: "test-detection-id",
		Title:    "Test Rule",
		Content:  "title: Test Rule",
	}

	// Set up expectations
	mockDetectionEngine.EXPECT().ValidateRule(gomock.Any()).Return("validated", nil)
	mockDetectionEngine.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
	mockUserstore.EXPECT().GetUserById(ctx, "test-user-id").Return(mockUser, nil)
	mockDetectionEngine.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
	mockDetectionstore.EXPECT().CreateDetection(ctx, gomock.Any()).DoAndReturn(func(ctx context.Context, detect *model.Detection) (*model.Detection, error) {
		// Verify that author was set using detections.MakeUser
		expectedAuthor := detections.MakeUser(mockUser)
		assert.Equal(t, expectedAuthor, detect.Author)
		return mockDetection, nil
	})
	mockDetectionEngine.EXPECT().SyncLocalDetections(ctx, gomock.Any()).Return(map[string]string{}, nil)

	tool := &CreateDetectionTool{}
	result, err := tool.Execute(ctx, mockServer, `{"language": "sigma", "license": "DRL", "content": "title: Test Rule"}`, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
}
