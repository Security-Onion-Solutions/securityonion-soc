// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
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
	neturl "net/url"
	"strings"
	"sync"
	"testing"
	"time"

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
		stage            string
		ts               string
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
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id", model.PlaybookStageFull, time.Time{}).
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
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id", model.PlaybookStageFull, time.Time{}).
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
			name:  "Success - skeleton stage is passed through",
			socId: "test-soc-id",
			stage: "skeleton",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id", model.PlaybookStageSkeleton, time.Time{}).
					Return([]*model.Playbook{}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:  "Success - convert stage is passed through",
			socId: "test-soc-id",
			stage: "convert",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id", model.PlaybookStageConvert, time.Time{}).
					Return([]*model.Playbook{}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:  "Success - unknown stage falls back to full",
			socId: "test-soc-id",
			stage: "bogus",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id", model.PlaybookStageFull, time.Time{}).
					Return([]*model.Playbook{}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:  "Success - ts is parsed and passed through",
			socId: "test-soc-id",
			ts:    "2026-07-02T20:33:57Z",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				expectedTs := time.Date(2026, 7, 2, 20, 33, 57, 0, time.UTC)

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id", model.PlaybookStageFull, expectedTs).
					Return([]*model.Playbook{}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:  "Success - unparseable ts falls back to zero time",
			socId: "test-soc-id",
			ts:    "not-a-timestamp",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					GetEventSpecificPlaybook(gomock.Any(), "test-soc-id", model.PlaybookStageFull, time.Time{}).
					Return([]*model.Playbook{}, nil)
			},
			expectedStatus: http.StatusOK,
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
					GetEventSpecificPlaybook(gomock.Any(), "non-existent-soc-id", model.PlaybookStageFull, time.Time{}).
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
					GetEventSpecificPlaybook(gomock.Any(), "error-id", model.PlaybookStageFull, time.Time{}).
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
			url := "/playbook/event/" + tt.socId + "?stage=" + tt.stage
			if tt.ts != "" {
				url += "&ts=" + neturl.QueryEscape(tt.ts)
			}
			r := createTestRequest(ctx, "GET", url)

			h.GetEventSpecificPlaybook(w, r)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}

func TestExecutePlaybookQuestion(t *testing.T) {
	validBody := `{"query":"aggregation: true\nquery: test","range":"-1h","oqlQuery":"hostname: test-host","fields":["source.ip"]}`
	validTs := "2026-07-02T20:33:57Z"

	tests := []struct {
		name             string
		ts               string
		body             string
		initMock         func(*Server, *gomock.Controller)
		expectedStatus   int
		validateResponse func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "Success - question is executed and returned with results",
			ts:   validTs,
			body: validBody,
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				expectedTs := time.Date(2026, 7, 2, 20, 33, 57, 0, time.UTC)

				mockPlaybookStore.EXPECT().
					ExecuteQuestionSearch(gomock.Any(), expectedTs, gomock.Any()).
					DoAndReturn(func(_ context.Context, _ time.Time, question *model.Question) error {
						assert.Equal(t, "hostname: test-host", question.OqlQuery)
						assert.Equal(t, []string{"source.ip"}, question.QueryFields)
						require.NotNil(t, question.Range)
						assert.Equal(t, "-1h", *question.Range)

						question.QueryResults = []*model.EventRecord{
							{Payload: map[string]interface{}{"Count": float64(3), "source.ip": "1.2.3.4"}},
						}
						return nil
					})
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var question model.Question
				err := json.Unmarshal(w.Body.Bytes(), &question)
				require.NoError(t, err)
				require.Len(t, question.QueryResults, 1)
				assert.Equal(t, "1.2.3.4", question.QueryResults[0].Payload["source.ip"])
			},
		},
		{
			name: "Missing ts",
			ts:   "",
			body: validBody,
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Unparseable ts",
			ts:   "not-a-timestamp",
			body: validBody,
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Success - ts without a timezone is accepted",
			ts:   "2026-07-02 20:33:57",
			body: validBody,
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				expectedTs := time.Date(2026, 7, 2, 20, 33, 57, 0, time.UTC)

				mockPlaybookStore.EXPECT().
					ExecuteQuestionSearch(gomock.Any(), expectedTs, gomock.Any()).
					Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Malformed body",
			ts:   validTs,
			body: "{not json",
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing range",
			ts:   validTs,
			body: `{"query":"query: test","oqlQuery":"hostname: test-host"}`,
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing oqlQuery",
			ts:   validTs,
			body: `{"query":"query: test","range":"-1h"}`,
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Unauthorized",
			ts:   validTs,
			body: validBody,
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = false
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "Store error",
			ts:   validTs,
			body: validBody,
			initMock: func(srv *Server, ctrl *gomock.Controller) {
				mockPlaybookStore := mock.NewMockPlaybookstore(ctrl)
				srv.Playbookstore = mockPlaybookStore
				srv.Authorizer.(*rbac.FakeAuthorizer).Authorized = true

				mockPlaybookStore.EXPECT().
					ExecuteQuestionSearch(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("search failed"))
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

			ctx := createTestContext(nil)
			w := httptest.NewRecorder()
			url := "/playbook/question"
			if tt.ts != "" {
				url += "?ts=" + neturl.QueryEscape(tt.ts)
			}
			r := httptest.NewRequestWithContext(ctx, "POST", url, strings.NewReader(tt.body))

			h.ExecutePlaybookQuestion(w, r)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.validateResponse != nil {
				tt.validateResponse(t, w)
			}
		})
	}
}
