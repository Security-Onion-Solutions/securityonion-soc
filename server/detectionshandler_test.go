// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/elastalert"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/strelka"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/suricata"
	"github.com/security-onion-solutions/securityonion-soc/util"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestPrepareForSave(t *testing.T) {
	now := time.Now()

	tests := []struct {
		Name        string
		Input       *model.Detection
		Output      *model.Detection
		InitMock    func(*servermock.MockDetectionstore)
		ExpectedErr *string
	}{
		{
			Name: "Simple Sunny Day",
			Input: &model.Detection{
				Auditable: model.Auditable{
					Id:   "12345",
					Kind: "detection",
				},
				PublicID: "67890",
				Engine:   model.EngineNameSuricata,
				Content:  `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
			},
			Output: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: util.Ptr(now),
				},
				PublicID: "67890",
				Engine:   model.EngineNameSuricata,
				Content:  `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				Title:    "test",
				Severity: model.SeverityUnknown,
			},
			InitMock: func(detStore *servermock.MockDetectionstore) {
				detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "67890").Return(&model.Detection{
					Auditable: model.Auditable{
						Id:         "12345",
						CreateTime: util.Ptr(now),
					},
				}, nil)
			},
		},
		{
			Name: "No Duplicate",
			Input: &model.Detection{
				Auditable: model.Auditable{
					Id:   "12345",
					Kind: "detection",
				},
				Engine:  model.EngineNameSuricata,
				Content: `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
			},
			Output: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: util.Ptr(now),
				},
				PublicID: "67890",
				Engine:   model.EngineNameSuricata,
				Content:  `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				Title:    "test",
				Severity: model.SeverityUnknown,
			},
			InitMock: func(detStore *servermock.MockDetectionstore) {
				detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "67890").Return(nil, nil)
				detStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{
					Auditable: model.Auditable{
						Id:         "12345",
						CreateTime: util.Ptr(now),
					},
				}, nil)
			},
		},
		{
			Name: "PublicId Duplicate",
			Input: &model.Detection{
				Auditable: model.Auditable{
					Id:   "12345",
					Kind: "detection",
				},
				Engine:  model.EngineNameSuricata,
				Content: `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
			},
			InitMock: func(detStore *servermock.MockDetectionstore) {
				detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "67890").Return(&model.Detection{
					Auditable: model.Auditable{
						Id:         "23456",
						CreateTime: util.Ptr(now),
					},
				}, nil)
			},
			ExpectedErr: util.Ptr("publicId already exists for this engine"),
		},
		{
			Name: "With New Override",
			Input: &model.Detection{
				Auditable: model.Auditable{
					Id:   "12345",
					Kind: "detection",
				},
				Engine:  model.EngineNameSuricata,
				Content: `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				Overrides: []*model.Override{
					{
						Type: model.OverrideTypeModify,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(".*"),
							Value: util.Ptr("test"),
						},
					},
				},
			},
			Output: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: util.Ptr(now),
				},
				PublicID: "67890",
				Engine:   model.EngineNameSuricata,
				Content:  `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				Title:    "test",
				Severity: model.SeverityUnknown,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						CreatedAt: now,
						UpdatedAt: now,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(".*"),
							Value: util.Ptr("test"),
						},
					},
				},
			},
			InitMock: func(detStore *servermock.MockDetectionstore) {
				detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "67890").Return(nil, nil)
				detStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{
					Auditable: model.Auditable{
						Id:         "12345",
						CreateTime: util.Ptr(now),
					},
				}, nil)
			},
		},
		{
			Name: "With Pre-existing Overrides",
			Input: &model.Detection{
				Auditable: model.Auditable{
					Id:   "12345",
					Kind: "detection",
				},
				Engine:  model.EngineNameSuricata,
				Content: `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						CreatedAt: now,
						UpdatedAt: now,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(".*"),
							Value: util.Ptr("test"),
						},
					},
				},
			},
			Output: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: util.Ptr(now),
				},
				PublicID: "67890",
				Engine:   model.EngineNameSuricata,
				Content:  `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				Title:    "test",
				Severity: model.SeverityUnknown,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						CreatedAt: now,
						UpdatedAt: now,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(".*"),
							Value: util.Ptr("test"),
						},
					},
				},
			},
			InitMock: func(detStore *servermock.MockDetectionstore) {
				detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "67890").Return(nil, nil)
				detStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{
					Auditable: model.Auditable{
						Id:         "12345",
						CreateTime: util.Ptr(now),
					},
					Overrides: []*model.Override{
						{
							Type:      model.OverrideTypeModify,
							CreatedAt: now,
							UpdatedAt: now,
							OverrideParameters: model.OverrideParameters{
								Regex: util.Ptr(".*"),
								Value: util.Ptr("test"),
							},
						},
					},
				}, nil)
			},
		},
		{
			Name: "Update to Community",
			Input: &model.Detection{
				Auditable: model.Auditable{
					Id: "12345",
				},
				IsCommunity: true,
				Engine:      model.EngineNameSuricata,
				Content:     `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
			},
			InitMock: func(detStore *servermock.MockDetectionstore) {
				detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "67890").Return(nil, nil)
				detStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{
					Auditable: model.Auditable{
						Id:         "12345",
						CreateTime: util.Ptr(now),
					},
				}, nil)
			},
			ExpectedErr: util.Ptr("cannot update an existing non-community detection to make it a community detection"),
		},
		{
			Name: "Update from Community",
			Input: &model.Detection{
				Auditable: model.Auditable{
					Id: "12345",
				},
				Engine:      model.EngineNameSuricata,
				IsEnabled:   true,
				IsReporting: true,
				Content:     `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						CreatedAt: now,
						UpdatedAt: now,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(".*"),
							Value: util.Ptr("test"),
						},
					},
				},
			},
			Output: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: util.Ptr(now),
				},
				PublicID:    "67890",
				IsEnabled:   true,
				IsCommunity: true,
				IsReporting: true,
				Engine:      model.EngineNameSuricata,
				Content:     `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				Title:       "test",
				Severity:    model.SeverityUnknown,
				Overrides: []*model.Override{
					{
						Type:      model.OverrideTypeModify,
						CreatedAt: now,
						UpdatedAt: now,
						OverrideParameters: model.OverrideParameters{
							Regex: util.Ptr(".*"),
							Value: util.Ptr("test"),
						},
					},
				},
			},
			InitMock: func(detStore *servermock.MockDetectionstore) {
				detStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "67890").Return(nil, nil)
				detStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{
					Auditable: model.Auditable{
						Id:         "12345",
						CreateTime: util.Ptr(now),
					},
					PublicID:    "67890",
					Title:       "test",
					Severity:    model.SeverityUnknown,
					IsEnabled:   true,
					IsCommunity: true,
					IsReporting: true,
					Engine:      model.EngineNameSuricata,
					Content:     `alert any any <> any any (msg: "test"; sid:67890; rev:1;)`,
				}, nil)
			},
		},
	}

	ctx := context.Background()
	ctrl := gomock.NewController(t)

	fakeSrv := server.NewFakeAuthorizedServer(nil)
	handler := server.NewDetectionHandler(fakeSrv)
	engines := map[model.EngineName]server.DetectionEngine{
		model.EngineNameElastAlert: elastalert.NewElastAlertEngine(fakeSrv),
		model.EngineNameStrelka:    strelka.NewStrelkaEngine(fakeSrv),
		model.EngineNameSuricata:   suricata.NewSuricataEngine(fakeSrv),
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			detStore := servermock.NewMockDetectionstore(ctrl)
			test.InitMock(detStore)

			fakeSrv.Detectionstore = detStore

			err := handler.PrepareForSave(ctx, test.Input, engines[test.Input.Engine])
			if test.ExpectedErr != nil {
				assert.Equal(t, *test.ExpectedErr, err.Error())
				return
			} else {
				assert.NoError(t, err)
			}

			actOverrides := test.Input.Overrides
			expOverrides := test.Output.Overrides

			test.Input.Overrides = nil
			test.Output.Overrides = nil

			assert.Equal(t, test.Output, test.Input)
			assert.Equal(t, len(expOverrides), len(actOverrides))

			if len(expOverrides) != 0 {
				for i := range expOverrides {
					assert.Equal(t, expOverrides[i].Type, actOverrides[i].Type)
					assert.Equal(t, expOverrides[i].OverrideParameters, actOverrides[i].OverrideParameters)
					assert.InDelta(t, now.Unix(), actOverrides[i].UpdatedAt.Unix(), 2)
				}
			}
		})
	}
}

func TestHandlerGetDetection(t *testing.T) {
	handled := NewEntryMatcher(LevelEq(log.InfoLevel), MessageEq("Handled request"))
	tests := []struct {
		Name           string
		Id             string
		InitMock       func(*server.Server, *gomock.Controller)
		Code           int
		Body           []byte
		BodyExactMatch bool
		Logs           []EntryMatcher
	}{
		{
			Name: "Sunny Day",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				det := &model.Detection{
					Engine: model.EngineNameSuricata,
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(det, nil)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = eng

				eng.EXPECT().MergeAuxiliaryData(det).Return(nil)
			},
			Code: 200,
			Body: []byte(`{"createTime":null,"userId":"","publicId":"","title":"","severity":"","author":"","description":"","content":"","isEnabled":false,"isReporting":false,"isCommunity":false,"engine":"suricata","language":"","overrides":null,"tags":null,"ruleset":"","license":"","sourceCreated":null,"sourceUpdated":null}`),
			Logs: []EntryMatcher{handled},
		},
		{
			Name: "Detection Not Found - 404",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(nil, errors.New("Object not found"))
			},
			Code: 404,
			Logs: []EntryMatcher{handled},
		},
		{
			Name: "ElasticSearch Error - 500",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(nil, errors.New("all shards failed"))
			},
			Code:           500,
			Body:           []byte(`The request could not be processed.`),
			BodyExactMatch: true,
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.WarnLevel), MessageContains("Request did not complete successfully")),
				handled,
			},
		},
		{
			Name: "Unexpected Engine",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{Engine: "FooBar"}, nil)
			},
			Code: 200,
			Body: []byte(`{"createTime":null,"userId":"","publicId":"","title":"","severity":"","author":"","description":"","content":"","isEnabled":false,"isReporting":false,"isCommunity":false,"engine":"FooBar","language":"","overrides":null,"tags":null,"ruleset":"","license":"","sourceCreated":null,"sourceUpdated":null}`),
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.ErrorLevel), MessageContains("retrieved detection with unsupported engine")),
				handled,
			},
		},
		{
			Name: "Merge Aux Data Problem",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				det := &model.Detection{
					Engine: model.EngineNameSuricata,
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(det, nil)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = eng

				eng.EXPECT().MergeAuxiliaryData(det).Return(errors.New("failed to merge"))
			},
			Code: 200,
			Body: []byte(`{"createTime":null,"userId":"","publicId":"","title":"","severity":"","author":"","description":"","content":"","isEnabled":false,"isReporting":false,"isCommunity":false,"engine":"suricata","language":"","overrides":null,"tags":null,"ruleset":"","license":"","sourceCreated":null,"sourceUpdated":null}`),
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.ErrorLevel), MessageContains("unable to merge auxiliary data into detection")),
				handled,
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			srv := server.NewMockServer(t, ctrl, &config.ServerConfig{})

			h := server.NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.Id)

			ctx := server.NewTestContext(rctx)
			mem, l := server.NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "GET", fmt.Sprintf("/detection/%s", test.Id), nil)

			h.GetDetection(w, r)

			assert.Equal(t, test.Code, w.Code)

			if test.Body != nil {
				if !test.BodyExactMatch {
					assert.JSONEq(t, string(test.Body), w.Body.String())
				} else {
					assert.Equal(t, test.Body, w.Body.Bytes())
				}
			} else {
				assert.Empty(t, w.Body.String())
			}

			if test.Logs != nil {
				if len(test.Logs) != len(mem.Entries) {
					t.Fatalf("Expected %d log entries, got %d", len(test.Logs), len(mem.Entries))
				}

				for i, matcher := range test.Logs {
					err := matcher.Validate(mem.Entries[i])
					if err != nil {
						t.Fatalf("Log entry %d is invalid: %s", i, err)
					}
				}
			}
		})
	}
}

func TestHandlerGetByPublicID(t *testing.T) {
	handled := NewEntryMatcher(LevelEq(log.InfoLevel), MessageEq("Handled request"))
	tests := []struct {
		Name           string
		PublicId       string
		InitMock       func(*server.Server, *gomock.Controller)
		Code           int
		Body           []byte
		BodyExactMatch bool
		Logs           []EntryMatcher
	}{
		{
			Name:     "Sunny Day",
			PublicId: "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				det := &model.Detection{
					Engine: model.EngineNameSuricata,
				}
				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(det, nil)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = eng

				eng.EXPECT().MergeAuxiliaryData(det).Return(nil)
			},
			Code: 200,
			Body: []byte(`{"createTime":null,"userId":"","publicId":"","title":"","severity":"","author":"","description":"","content":"","isEnabled":false,"isReporting":false,"isCommunity":false,"engine":"suricata","language":"","overrides":null,"tags":null,"ruleset":"","license":"","sourceCreated":null,"sourceUpdated":null}`),
			Logs: []EntryMatcher{handled},
		},
		{
			Name:     "Detection Not Found - 404",
			PublicId: "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(nil, errors.New("Object not found"))
			},
			Code: 404,
			Logs: []EntryMatcher{handled},
		},
		{
			Name:     "Detection Not Found 2 - 404",
			PublicId: "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(nil, nil)
			},
			Code: 404,
			Logs: []EntryMatcher{handled},
		},
		{
			Name:     "ElasticSearch Error - 500",
			PublicId: "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(nil, errors.New("all shards failed"))
			},
			Code:           500,
			Body:           []byte(`The request could not be processed.`),
			BodyExactMatch: true,
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.WarnLevel), MessageContains("Request did not complete successfully")),
				handled,
			},
		},
		{
			Name:     "Unexpected Engine",
			PublicId: "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(&model.Detection{Engine: "FooBar"}, nil)
			},
			Code: 200,
			Body: []byte(`{"createTime":null,"userId":"","publicId":"","title":"","severity":"","author":"","description":"","content":"","isEnabled":false,"isReporting":false,"isCommunity":false,"engine":"FooBar","language":"","overrides":null,"tags":null,"ruleset":"","license":"","sourceCreated":null,"sourceUpdated":null}`),
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.ErrorLevel), MessageContains("retrieved detection with unsupported engine")),
				handled,
			},
		},
		{
			Name:     "Merge Aux Data Problem",
			PublicId: "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				det := &model.Detection{
					Engine: model.EngineNameSuricata,
				}
				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(det, nil)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = eng

				eng.EXPECT().MergeAuxiliaryData(det).Return(errors.New("failed to merge"))
			},
			Code: 200,
			Body: []byte(`{"createTime":null,"userId":"","publicId":"","title":"","severity":"","author":"","description":"","content":"","isEnabled":false,"isReporting":false,"isCommunity":false,"engine":"suricata","language":"","overrides":null,"tags":null,"ruleset":"","license":"","sourceCreated":null,"sourceUpdated":null}`),
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.ErrorLevel), MessageContains("unable to merge auxiliary data into detection")),
				handled,
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			srv := server.NewMockServer(t, ctrl, &config.ServerConfig{})

			h := server.NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("publicid", test.PublicId)

			ctx := server.NewTestContext(rctx)
			mem, l := server.NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "GET", fmt.Sprintf("/detection/public/%s", test.PublicId), nil)

			h.GetByPublicId(w, r)

			assert.Equal(t, test.Code, w.Code)

			if test.Body != nil {
				if !test.BodyExactMatch {
					assert.JSONEq(t, string(test.Body), w.Body.String())
				} else {
					assert.Equal(t, test.Body, w.Body.Bytes())
				}
			} else {
				assert.Empty(t, w.Body.String())
			}

			if test.Logs != nil {
				if len(test.Logs) != len(mem.Entries) {
					t.Fatalf("Expected %d log entries, got %d", len(test.Logs), len(mem.Entries))
				}

				for i, matcher := range test.Logs {
					err := matcher.Validate(mem.Entries[i])
					if err != nil {
						t.Fatalf("Log entry %d is invalid: %s", i, err)
					}
				}
			}
		})
	}
}

func TestHandlerCreateDetection(t *testing.T) {
	handled := NewEntryMatcher(LevelEq(log.InfoLevel), MessageEq("Handled request"))
	specificTime := time.Now()

	tests := []struct {
		Name     string
		ReqBody  []byte
		InitMock func(*server.Server, *gomock.Controller)
		Code     int
		Response *model.Detection
		Logs     []EntryMatcher
	}{
		{
			Name:    "Sunny Day - Sigma",
			ReqBody: []byte(`{"language":"sigma","content":"test"}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().CreateDetection(gomock.Any(), "12345").DoAndReturn(func(ctx context.Context, det *model.Detection) error {
					det.Id = "12345"
					det.CreateTime = &specificTime
					det.UpdateTime = &specificTime
					return nil
				})

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng
			},
			Code:     200,
			Response: &model.Detection{},
			Logs:     []EntryMatcher{handled},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			srv := server.NewMockServer(t, ctrl, &config.ServerConfig{})

			h := server.NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			ctx := server.NewTestContext(nil)
			mem, l := server.NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "POST", "/detection", bytes.NewReader(test.ReqBody))

			h.CreateDetection(w, r)

			assert.Equal(t, test.Code, w.Code)

			if test.Response != nil {
				actual := &model.Detection{}
				err := json.Unmarshal(w.Body.Bytes(), actual)
				assert.NoError(t, err)
				assert.Equal(t, test.Response, actual)
			} else {
				assert.Empty(t, w.Body.String())
			}

			if test.Logs != nil {
				if len(test.Logs) != len(mem.Entries) {
					t.Fatalf("Expected %d log entries, got %d", len(test.Logs), len(mem.Entries))
				}

				for i, matcher := range test.Logs {
					err := matcher.Validate(mem.Entries[i])
					if err != nil {
						t.Fatalf("Log entry %d is invalid: %s", i, err)
					}
				}
			}
		})
	}
}
