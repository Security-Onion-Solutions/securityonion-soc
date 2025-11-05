// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// Test helper functions
func setupPlaybookTest(t *testing.T, ctrl *gomock.Controller) (*Server, *PlaybookHandler) {
	srv := NewMockServer(t, ctrl, &config.ServerConfig{})
	srv.DetectionEngines = sync.Map{}
	h := NewPlaybookHandler(srv)
	return srv, h
}

func createTestRequest(ctx context.Context, method, url string) *http.Request {
	return httptest.NewRequestWithContext(ctx, method, url, nil)
}

func createTestContext(urlParams map[string]string) context.Context {
	rctx := chi.NewRouteContext()
	for key, val := range urlParams {
		rctx.URLParams.Add(key, val)
	}
	ctx := NewTestContext(rctx)
	ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "test")
	return ctx
}

func TestGetPlaybook(t *testing.T) {
	tests := []struct {
		name             string
		playbookId       string
		initMock         func(*Server, *gomock.Controller)
		expectedStatus   int
		validateResponse func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:       "Success - Returns playbook",
			playbookId: "test-playbook-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				testPlaybook := &model.Playbook{
					Name:        "Test Playbook",
					Description: "Test Description",
				}

				mockPlaybookStore.EXPECT().
					GetPlaybookById(gomock.Any(), "test-playbook-id").
					Return(testPlaybook, nil)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var playbook model.Playbook
				err := json.Unmarshal(w.Body.Bytes(), &playbook)
				require.NoError(t, err)
				assert.Equal(t, "Test Playbook", playbook.Name)
				assert.Equal(t, "Test Description", playbook.Description)
			},
		},
		{
			name:       "Missing playbook ID",
			playbookId: "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:       "Unauthorized - missing playbooks/read permission",
			playbookId: "test-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = false
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:       "Error retrieving playbook",
			playbookId: "error-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetPlaybookById(gomock.Any(), "error-id").
					Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:       "Playbook not found - nil returned",
			playbookId: "non-existent-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetPlaybookById(gomock.Any(), "non-existent-id").
					Return(nil, nil)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				// When nil is returned, web.Respond marshals it as empty body
				assert.Empty(t, w.Body.String())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			srv, h := setupPlaybookTest(t, ctrl)
			tt.initMock(srv, ctrl)

			ctx := createTestContext(map[string]string{"id": tt.playbookId})
			w := httptest.NewRecorder()
			r := createTestRequest(ctx, "GET", "/playbook/"+tt.playbookId)

			h.GetPlaybook(w, r)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}

func TestGetPlaybooksForDetection(t *testing.T) {
	tests := []struct {
		name             string
		detectionId      string
		rawParam         string
		initMock         func(*Server, *gomock.Controller)
		expectedStatus   int
		validateResponse func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:        "Success - Returns playbooks",
			detectionId: "test-detection-id",
			rawParam:    "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				mockDetectionStore := mock.NewMockDetectionstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Detectionstore = mockDetectionStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				testDetection := &model.Detection{
					PublicID: "test-detection-id",
					Category: "test-category",
					Engine:   model.EngineNameElastAlert,
				}

				mockDetectionStore.EXPECT().
					GetDetectionByPublicId(gomock.Any(), "test-detection-id").
					Return(testDetection, nil)

				testPlaybooks := []*model.Playbook{
					{
						Name:        "Playbook 1",
						Description: "Description 1",
					},
					{
						Name:        "Playbook 2",
						Description: "Description 2",
					},
				}

				mockPlaybookStore.EXPECT().
					GetPlaybooksForDetection(gomock.Any(), "test-detection-id", "test-category", model.EngineNameElastAlert).
					Return(testPlaybooks, nil)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var playbooks []*model.Playbook
				err := json.Unmarshal(w.Body.Bytes(), &playbooks)
				require.NoError(t, err)
				require.Len(t, playbooks, 2)
				assert.Equal(t, "Playbook 1", playbooks[0].Name)
				assert.Equal(t, "Description 1", playbooks[0].Description)
				assert.Equal(t, "Playbook 2", playbooks[1].Name)
				assert.Equal(t, "Description 2", playbooks[1].Description)
			},
		},
		{
			name:        "Success - Returns empty array when no playbooks",
			detectionId: "test-detection-id",
			rawParam:    "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				mockDetectionStore := mock.NewMockDetectionstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Detectionstore = mockDetectionStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				testDetection := &model.Detection{
					PublicID: "test-detection-id",
					Category: "test-category",
					Engine:   model.EngineNameElastAlert,
				}

				mockDetectionStore.EXPECT().
					GetDetectionByPublicId(gomock.Any(), "test-detection-id").
					Return(testDetection, nil)

				mockPlaybookStore.EXPECT().
					GetPlaybooksForDetection(gomock.Any(), "test-detection-id", "test-category", model.EngineNameElastAlert).
					Return([]*model.Playbook{}, nil)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var playbooks []*model.Playbook
				err := json.Unmarshal(w.Body.Bytes(), &playbooks)
				require.NoError(t, err)
				assert.Empty(t, playbooks)
			},
		},
		{
			name:        "Success - Returns raw YAML format",
			detectionId: "test-detection-id",
			rawParam:    "true",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				mockDetectionStore := mock.NewMockDetectionstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Detectionstore = mockDetectionStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				testDetection := &model.Detection{
					PublicID: "test-detection-id",
					Category: "test-category",
					Engine:   model.EngineNameElastAlert,
				}

				mockDetectionStore.EXPECT().
					GetDetectionByPublicId(gomock.Any(), "test-detection-id").
					Return(testDetection, nil)

				testPlaybooks := []*model.Playbook{
					{
						Name:        "Playbook 1",
						Description: "Description 1",
					},
				}

				mockPlaybookStore.EXPECT().
					GetPlaybooksForDetection(gomock.Any(), "test-detection-id", "test-category", model.EngineNameElastAlert).
					Return(testPlaybooks, nil)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				// Note: web.Respond may override Content-Type to application/json
				// but the content should still be YAML formatted
				body := w.Body.String()
				// The response body should contain YAML-formatted content
				assert.Contains(t, body, "name: Playbook 1")
				assert.Contains(t, body, "description: Description 1")
			},
		},
		{
			name:        "Success - Returns multiple playbooks in raw YAML with separator",
			detectionId: "test-detection-id",
			rawParam:    "true",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				mockDetectionStore := mock.NewMockDetectionstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Detectionstore = mockDetectionStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				testDetection := &model.Detection{
					PublicID: "test-detection-id",
					Category: "test-category",
					Engine:   model.EngineNameElastAlert,
				}

				mockDetectionStore.EXPECT().
					GetDetectionByPublicId(gomock.Any(), "test-detection-id").
					Return(testDetection, nil)

				testPlaybooks := []*model.Playbook{
					{
						Name:        "Playbook 1",
						Description: "Description 1",
					},
					{
						Name:        "Playbook 2",
						Description: "Description 2",
					},
				}

				mockPlaybookStore.EXPECT().
					GetPlaybooksForDetection(gomock.Any(), "test-detection-id", "test-category", model.EngineNameElastAlert).
					Return(testPlaybooks, nil)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				body := w.Body.String()
				// Verify YAML separator is present for multiple documents
				assert.Contains(t, body, "---")
				assert.Contains(t, body, "name: Playbook 1")
				assert.Contains(t, body, "name: Playbook 2")
			},
		},
		{
			name:        "Missing detection ID",
			detectionId: "",
			rawParam:    "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:        "Unauthorized - missing playbooks permission",
			detectionId: "test-id",
			rawParam:    "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = false
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:        "Detection not found",
			detectionId: "non-existent-id",
			rawParam:    "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				mockDetectionStore := mock.NewMockDetectionstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Detectionstore = mockDetectionStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockDetectionStore.EXPECT().
					GetDetectionByPublicId(gomock.Any(), "non-existent-id").
					Return(nil, nil)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:        "Error retrieving detection",
			detectionId: "error-id",
			rawParam:    "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				mockDetectionStore := mock.NewMockDetectionstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Detectionstore = mockDetectionStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockDetectionStore.EXPECT().
					GetDetectionByPublicId(gomock.Any(), "error-id").
					Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:        "Error retrieving playbooks",
			detectionId: "test-detection-id",
			rawParam:    "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				mockDetectionStore := mock.NewMockDetectionstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Detectionstore = mockDetectionStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				testDetection := &model.Detection{
					PublicID: "test-detection-id",
					Category: "test-category",
					Engine:   model.EngineNameElastAlert,
				}

				mockDetectionStore.EXPECT().
					GetDetectionByPublicId(gomock.Any(), "test-detection-id").
					Return(testDetection, nil)

				mockPlaybookStore.EXPECT().
					GetPlaybooksForDetection(gomock.Any(), "test-detection-id", "test-category", model.EngineNameElastAlert).
					Return(nil, errors.New("playbook retrieval error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			srv, h := setupPlaybookTest(t, ctrl)
			tt.initMock(srv, ctrl)

			ctx := createTestContext(map[string]string{"id": tt.detectionId})
			w := httptest.NewRecorder()
			url := "/playbook/detection/" + tt.detectionId
			if tt.rawParam != "" {
				url += "?raw=" + tt.rawParam
			}
			r := createTestRequest(ctx, "GET", url)

			h.GetPlaybooksForDetection(w, r)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}

func TestGetEventSpecificPlaybook(t *testing.T) {
	tests := []struct {
		name             string
		socId            string
		initMock         func(*Server, *gomock.Controller)
		expectedStatus   int
		validateResponse func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:  "Success - Returns event-specific playbooks",
			socId: "test-soc-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				testPlaybooks := []*model.Playbook{
					{
						Name:        "Event Playbook 1",
						Description: "Event Description 1",
					},
				}

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id").
					Return(testPlaybooks, nil)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var playbooks []*model.Playbook
				err := json.Unmarshal(w.Body.Bytes(), &playbooks)
				require.NoError(t, err)
				require.Len(t, playbooks, 1)
				assert.Equal(t, "Event Playbook 1", playbooks[0].Name)
				assert.Equal(t, "Event Description 1", playbooks[0].Description)
			},
		},
		{
			name:  "Success - Returns empty array when no playbooks",
			socId: "test-soc-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id").
					Return([]*model.Playbook{}, nil)
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var playbooks []*model.Playbook
				err := json.Unmarshal(w.Body.Bytes(), &playbooks)
				require.NoError(t, err)
				assert.Empty(t, playbooks)
			},
		},
		{
			name:  "Missing SOC ID",
			socId: "",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:  "Unauthorized - missing playbooks permission",
			socId: "test-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = false
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:  "Event not found",
			socId: "non-existent-soc-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "non-existent-soc-id").
					Return(nil, errors.New("no alert found for soc_id"))
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:  "Error retrieving event playbooks",
			socId: "error-id",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "error-id").
					Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			srv, h := setupPlaybookTest(t, ctrl)
			tt.initMock(srv, ctrl)

			ctx := createTestContext(map[string]string{"id": tt.socId})
			w := httptest.NewRecorder()
			r := createTestRequest(ctx, "GET", "/playbook/event/"+tt.socId)

			h.GetEventSpecificPlaybook(w, r)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}
