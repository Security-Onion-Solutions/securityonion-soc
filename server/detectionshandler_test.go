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
	"github.com/security-onion-solutions/securityonion-soc/rbac"
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
		Name     string
		Id       string
		InitMock func(*server.Server, *gomock.Controller)
		Code     int
		Body     any
		Logs     []EntryMatcher
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
			Body: &model.Detection{
				Engine: model.EngineNameSuricata,
			},
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
			Code: 500,
			Body: []byte(`The request could not be processed.`),
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
			Body: &model.Detection{
				Engine: "FooBar",
			},
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
			Body: &model.Detection{
				Engine: model.EngineNameSuricata,
			},
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

			switch res := test.Body.(type) {
			case *model.Detection:
				actual := &model.Detection{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)

				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
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
		Name     string
		PublicId string
		InitMock func(*server.Server, *gomock.Controller)
		Code     int
		Body     any
		Logs     []EntryMatcher
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
			Body: &model.Detection{
				Engine: model.EngineNameSuricata,
			},
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
			Code: 500,
			Body: []byte(`The request could not be processed.`),
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
			Body: &model.Detection{
				Engine: "FooBar",
			},
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
			Body: &model.Detection{
				Engine: model.EngineNameSuricata,
			},
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

			switch res := test.Body.(type) {
			case *model.Detection:
				actual := &model.Detection{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)

				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
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
	didNotComplete := NewEntryMatcher(LevelEq(log.WarnLevel), MessageContains("Request did not complete successfully"))
	specificTime := time.Date(2025, 1, 1, 12, 30, 0, 0, time.UTC)

	tests := []struct {
		Name     string
		ReqBody  []byte
		InitMock func(*server.Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name:    "Sunny Day",
			ReqBody: []byte(`{"language":"sigma","content":"test", "overrides": [{}]}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mUserStore := srv.Userstore.(*servermock.MockUserstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mUserStore.EXPECT().GetUserById(gomock.Any(), "00000000-0000-0000-0000-000000000000").Return(&model.User{
					FirstName: "First",
					LastName:  "Last",
				}, nil)

				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				mDetStore.EXPECT().CreateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					det.Id = "12345"
					det.CreateTime = &specificTime
					det.UpdateTime = &specificTime

					return det, nil
				})

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).Return(nil, nil)
			},
			Code: 200,
			Response: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: &specificTime,
					UpdateTime: &specificTime,
				},
				Author:   "First Last",
				Content:  "test",
				Engine:   model.EngineNameElastAlert,
				Language: "sigma",
				Ruleset:  "__custom__",
				Overrides: []*model.Override{
					{
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
			},
			Logs: []EntryMatcher{handled},
		},
		{
			Name:     "Reject Creating a Community Rule",
			ReqBody:  []byte(`{"language":"sigma","content":"test","isCommunity":true}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:     "Bad Request Body",
			ReqBody:  []byte(`detection JSON goes here`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:     "Unsupported Language/Engine",
			ReqBody:  []byte(`{"language": "FooBar"}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "Invalid Rule",
			ReqBody: []byte(`{"language":"suricata","content":"test"}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", errors.New("something went wrong"))
			},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "Modified By Filters",
			ReqBody: []byte(`{"language":"yara","content":"test"}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mUserStore := srv.Userstore.(*servermock.MockUserstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mUserStore.EXPECT().GetUserById(gomock.Any(), "00000000-0000-0000-0000-000000000000").Return(&model.User{
					Email: "user@company.com",
				}, nil)

				eng.EXPECT().ApplyFilters(gomock.Any()).DoAndReturn(func(det *model.Detection) (bool, error) {
					det.IsEnabled = true

					return false, nil
				})

				mDetStore.EXPECT().CreateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					det.Id = "12345"
					det.CreateTime = &specificTime
					det.UpdateTime = &specificTime

					return det, nil
				})

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).Return(nil, nil)
			},
			Code: 205,
			Response: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: &specificTime,
					UpdateTime: &specificTime,
				},
				Author:    "user@company.com",
				Content:   "test",
				IsEnabled: true,
				Engine:    model.EngineNameStrelka,
				Language:  "yara",
				Ruleset:   "__custom__",
			},
			Logs: []EntryMatcher{handled},
		},
		{
			Name:    "Extract Details Failure - No Public ID",
			ReqBody: []byte(`{"language":"sigma","content":"test"}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ExtractDetails(gomock.Any()).Return(errors.New("rule does not contain a public Id"))
			},
			Code:     400,
			Response: []byte(`"missingPublicIdErr"`),
			Logs:     []EntryMatcher{handled},
		},
		{
			Name:    "Extract Details Failure - Other",
			ReqBody: []byte(`{"language":"sigma","content":"test"}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ExtractDetails(gomock.Any()).Return(errors.New("something went wrong"))
			},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "Detection Already Exists",
			ReqBody: []byte(`{"language":"sigma","content":"test"}`),
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mUserStore := srv.Userstore.(*servermock.MockUserstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mUserStore.EXPECT().GetUserById(gomock.Any(), "00000000-0000-0000-0000-000000000000").Return(&model.User{
					FirstName: "First",
					LastName:  "Last",
				}, nil)

				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				mDetStore.EXPECT().CreateDetection(gomock.Any(), gomock.Any()).Return(nil, errors.New("already exists"))
			},
			Code:     409,
			Response: []byte(`"publicIdConflictErr"`),
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

			switch res := test.Response.(type) {
			case *model.Detection:
				actual := &model.Detection{}
				err := json.Unmarshal(w.Body.Bytes(), actual)
				assert.NoError(t, err)

				assert.Equal(t, len(res.Overrides), len(actual.Overrides))

				// check the timestamps separately
				for i, override := range res.Overrides {
					assert.InDelta(t, override.CreatedAt.Unix(), actual.Overrides[i].CreatedAt.Unix(), 2)
					assert.InDelta(t, override.UpdatedAt.Unix(), actual.Overrides[i].UpdatedAt.Unix(), 2)

					// once checked, clear for full object comparison
					override.CreatedAt = time.Time{}
					actual.Overrides[i].CreatedAt = time.Time{}
					override.UpdatedAt = time.Time{}
					actual.Overrides[i].UpdatedAt = time.Time{}
				}

				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
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

func TestHandlerGetDetectionHistory(t *testing.T) {
	handled := NewEntryMatcher(LevelEq(log.InfoLevel), MessageEq("Handled request"))
	didNotComplete := NewEntryMatcher(LevelEq(log.WarnLevel), MessageContains("Request did not complete successfully"))

	tests := []struct {
		Name     string
		Id       string
		InitMock func(*server.Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name: "Sunny Day",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionHistory(gomock.Any(), "12345").Return([]any{"Hello", "World"}, nil)
			},
			Code:     200,
			Response: []byte(`["Hello","World"]`),
			Logs:     []EntryMatcher{handled},
		},
		{
			Name: "Not Found",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionHistory(gomock.Any(), "12345").Return(nil, errors.New("something went wrong"))
			},
			Code:     404,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
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
			r := httptest.NewRequestWithContext(ctx, "POST", fmt.Sprintf("/detection/%s/history", test.Id), nil)

			h.GetDetectionHistory(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
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

func TestHandlerDuplicateDetection(t *testing.T) {
	handled := NewEntryMatcher(LevelEq(log.InfoLevel), MessageEq("Handled request"))
	didNotComplete := NewEntryMatcher(LevelEq(log.WarnLevel), MessageContains("Request did not complete successfully"))

	tests := []struct {
		Name     string
		Id       string
		InitMock func(*server.Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name: "Sunny Day",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				orig := &model.Detection{
					PublicID: "Original",
					Engine:   model.EngineNameElastAlert,
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(orig, nil)

				dupe := &model.Detection{
					PublicID: "Duplicate",
					Engine:   model.EngineNameElastAlert,
				}
				eng.EXPECT().DuplicateDetection(gomock.Any(), gomock.Any()).Return(dupe, nil)

				mDetStore.EXPECT().CreateDetection(gomock.Any(), dupe).Return(dupe, nil)
			},
			Code: 200,
			Response: &model.Detection{
				PublicID: "Duplicate",
				Engine:   model.EngineNameElastAlert,
			},
			Logs: []EntryMatcher{handled},
		},
		{
			Name: "Not Found",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(nil, errors.New("not found"))
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name: "Unsupported Engine",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				orig := &model.Detection{
					Engine: "FooBar",
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(orig, nil)
			},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name: "Failed to Duplicate",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				orig := &model.Detection{
					PublicID: "Original",
					Engine:   model.EngineNameElastAlert,
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(orig, nil)

				eng.EXPECT().DuplicateDetection(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed to duplicate"))
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name: "Failed to Create",
			Id:   "12345",
			InitMock: func(srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				orig := &model.Detection{
					PublicID: "Original",
					Engine:   model.EngineNameElastAlert,
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(orig, nil)

				dupe := &model.Detection{
					PublicID: "Duplicate",
					Engine:   model.EngineNameElastAlert,
				}
				eng.EXPECT().DuplicateDetection(gomock.Any(), gomock.Any()).Return(dupe, nil)

				mDetStore.EXPECT().CreateDetection(gomock.Any(), dupe).Return(nil, errors.New("failed to create"))
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
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
			r := httptest.NewRequestWithContext(ctx, "POST", fmt.Sprintf("/detection/%s/duplicate", test.Id), nil)

			h.DuplicateDetection(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case *model.Detection:
				actual := &model.Detection{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)

				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
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

func TestHandlerUpdateDetection(t *testing.T) {
	handled := NewEntryMatcher(LevelEq(log.InfoLevel), MessageEq("Handled request"))
	didNotComplete := NewEntryMatcher(LevelEq(log.WarnLevel), MessageContains("Request did not complete successfully"))
	specificTime := time.Date(2025, 1, 1, 12, 30, 0, 0, time.UTC)

	tests := []struct {
		Name     string
		ReqBody  []byte
		InitMock func(*testing.T, *server.Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name:    "Sunny Day",
			ReqBody: []byte(`{"id":"12345","publicId":"publicID","language":"sigma","engine":"elastalert","content":"test"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "publicID").Return(nil, nil)
				orig := &model.Detection{
					Auditable: model.Auditable{
						CreateTime: &specificTime,
					},
					Author:  "First Last",
					Ruleset: "__custom__",
					License: "DRL",
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(orig, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					det.UpdateTime = &specificTime

					return det, nil
				})

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].PersistChange)

					return nil, nil
				})

				eng.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)
			},
			Code: 200,
			Response: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: &specificTime,
					UpdateTime: &specificTime,
				},
				PublicID: "publicID",
				Author:   "First Last",
				Content:  "test",
				Language: "sigma",
				Ruleset:  "__custom__",
				License:  "DRL",
				Engine:   model.EngineNameElastAlert,
			},
			Logs: []EntryMatcher{handled},
		},
		{
			Name:    "Sunny Day - Fail to Merge Aux Data",
			ReqBody: []byte(`{"id":"12345","publicId":"publicID","language":"sigma","engine":"elastalert","content":"test"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "publicID").Return(nil, nil)
				orig := &model.Detection{
					Auditable: model.Auditable{
						CreateTime: &specificTime,
					},
					Author:  "First Last",
					Ruleset: "__custom__",
					License: "DRL",
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(orig, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					det.UpdateTime = &specificTime

					return det, nil
				})

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].PersistChange)

					return nil, nil
				})

				eng.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(errors.New("something went wrong"))
			},
			Code: 200,
			Response: &model.Detection{
				Auditable: model.Auditable{
					Id:         "12345",
					CreateTime: &specificTime,
					UpdateTime: &specificTime,
				},
				PublicID: "publicID",
				Author:   "First Last",
				Content:  "test",
				Language: "sigma",
				Ruleset:  "__custom__",
				License:  "DRL",
				Engine:   model.EngineNameElastAlert,
			},
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.ErrorLevel), MessageEq("unable to merge auxiliary data into detection")),
				handled,
			},
		},
		{
			Name:     "Bad Body",
			ReqBody:  []byte(`not even close to JSON`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:     "Invalid Detection - Basic",
			ReqBody:  []byte(`{"engine":"foobar"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "Invalid Detection - Engine",
			ReqBody: []byte(`{"engine":"suricata","content":"test"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", errors.New("something went wrong"))
			},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "PrepareForSave - Not Found",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(nil, errors.New("Object not found"))
			},
			Code: 404,
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:    "PrepareForSave - Public ID Exists",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","publicId":"publicID"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "publicID").Return(&model.Detection{
					Auditable: model.Auditable{
						Id: "67890",
					},
				}, nil)
			},
			Code:     409,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "PrepareForSave - Missing Public ID",
			ReqBody: []byte(`{"engine":"strelka","content":"test"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(errors.New("rule does not contain a public Id"))
			},
			Code:     400,
			Response: []byte(`"missingPublicIdErr"`),
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:    "PrepareForSave - Other Errors",
			ReqBody: []byte(`{"engine":"strelka","content":"test"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(errors.New("something else went wrong"))
			},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "UpdateDetection - Cannot Update IsCommunity",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","isCommunity":true}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{}, nil)
			},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "UpdateDetection - Not Found",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345"}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{}, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).Return(nil, errors.New("Object not found"))
			},
			Code:     404,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "UpdateDetection - Successful Disable After Bad Sync",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","isEnabled":true}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{IsEnabled: true}, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					assert.True(t, det.IsEnabled)
					return det, nil
				})

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).Return(nil, errors.New("something went wrong"))

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					assert.False(t, det.IsEnabled)
					return det, nil
				})

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).Return(nil, nil)

				eng.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)
			},
			Code: 206,
			Response: &model.Detection{
				Auditable: model.Auditable{
					Id: "12345",
				},
				Content: "test",
				Engine:  model.EngineNameStrelka,
			},
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.ErrorLevel), MessageContains("unable to sync detection; attempting to disable and resync")),
				handled,
			},
		},
		{
			Name:    "UpdateDetection - Unsuccessful Disable After Bad Sync",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","isEnabled":true}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{IsEnabled: true}, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					assert.True(t, det.IsEnabled)
					return det, nil
				})

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).Return(nil, errors.New("something went wrong"))

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					assert.False(t, det.IsEnabled)
					return nil, errors.New("something went wrong")
				})
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				NewEntryMatcher(LevelEq(log.ErrorLevel), MessageContains("unable to sync detection; attempting to disable and resync")),
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "Modified By Filters, Bad Sync",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","isEnabled":true}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).DoAndReturn(func(det *model.Detection) (bool, error) {
					det.IsEnabled = false
					return true, nil
				})

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{IsEnabled: true}, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					assert.False(t, det.IsEnabled)
					return det, nil
				})

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).Return(nil, errors.New("something went wrong"))
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "Modified By Filters, Good Sync",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","isEnabled":true}`),
			InitMock: func(t *testing.T, srv *server.Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).DoAndReturn(func(det *model.Detection) (bool, error) {
					det.IsEnabled = false
					return true, nil
				})

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{IsEnabled: true}, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					assert.False(t, det.IsEnabled)
					return det, nil
				})

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).Return(nil, nil)

				eng.EXPECT().MergeAuxiliaryData(gomock.Any()).Return(nil)
			},
			Code: 205,
			Response: &model.Detection{
				Auditable: model.Auditable{
					Id: "12345",
				},
				Content: "test",
				Engine:  model.EngineNameStrelka,
			},
			Logs: []EntryMatcher{
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

			test.InitMock(t, srv, ctrl)

			ctx := server.NewTestContext(nil)
			mem, l := server.NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "PUT", "/detection", bytes.NewReader(test.ReqBody))

			h.UpdateDetection(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case *model.Detection:
				actual := &model.Detection{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)

				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
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
