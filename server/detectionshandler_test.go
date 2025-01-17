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
	"sync"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	. "github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/elastalert"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/strelka"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/suricata"
	"github.com/security-onion-solutions/securityonion-soc/util"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var (
	handled        = NewEntryMatcher(LogLevelEq(log.InfoLevel), LogMessageEq("Handled request"))
	didNotComplete = NewEntryMatcher(LogLevelEq(log.WarnLevel), LogMessageContains("Request did not complete successfully"))
	specificTime   = time.Date(2025, 1, 1, 12, 30, 0, 0, time.UTC)
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

	fakeSrv := NewFakeAuthorizedServer(nil)
	handler := NewDetectionHandler(fakeSrv)
	engines := map[model.EngineName]DetectionEngine{
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
	tests := []struct {
		Name     string
		Id       string
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Body     any
		Logs     []EntryMatcher
	}{
		{
			Name: "Sunny Day",
			Id:   "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(nil, errors.New("Object not found"))
			},
			Code: 404,
			Logs: []EntryMatcher{handled},
		},
		{
			Name: "ElasticSearch Error - 500",
			Id:   "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(nil, errors.New("all shards failed"))
			},
			Code: 500,
			Body: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				NewEntryMatcher(LogLevelEq(log.WarnLevel), LogMessageContains("Request did not complete successfully")),
				handled,
			},
		},
		{
			Name: "Unexpected Engine",
			Id:   "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{Engine: "FooBar"}, nil)
			},
			Code: 200,
			Body: &model.Detection{
				Engine: "FooBar",
			},
			Logs: []EntryMatcher{
				NewEntryMatcher(LogLevelEq(log.ErrorLevel), LogMessageContains("retrieved detection with unsupported engine")),
				handled,
			},
		},
		{
			Name: "Merge Aux Data Problem",
			Id:   "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
				NewEntryMatcher(LogLevelEq(log.ErrorLevel), LogMessageContains("unable to merge auxiliary data into detection")),
				handled,
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.Id)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerGetByPublicId(t *testing.T) {
	tests := []struct {
		Name     string
		PublicId string
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Body     any
		Logs     []EntryMatcher
	}{
		{
			Name:     "Sunny Day",
			PublicId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(nil, errors.New("Object not found"))
			},
			Code: 404,
			Logs: []EntryMatcher{handled},
		},
		{
			Name:     "Detection Not Found 2 - 404",
			PublicId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(nil, nil)
			},
			Code: 404,
			Logs: []EntryMatcher{handled},
		},
		{
			Name:     "ElasticSearch Error - 500",
			PublicId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(nil, errors.New("all shards failed"))
			},
			Code: 500,
			Body: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				NewEntryMatcher(LogLevelEq(log.WarnLevel), LogMessageContains("Request did not complete successfully")),
				handled,
			},
		},
		{
			Name:     "Unexpected Engine",
			PublicId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetectionByPublicId(gomock.Any(), "12345").Return(&model.Detection{Engine: "FooBar"}, nil)
			},
			Code: 200,
			Body: &model.Detection{
				Engine: "FooBar",
			},
			Logs: []EntryMatcher{
				NewEntryMatcher(LogLevelEq(log.ErrorLevel), LogMessageContains("retrieved detection with unsupported engine")),
				handled,
			},
		},
		{
			Name:     "Merge Aux Data Problem",
			PublicId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
				NewEntryMatcher(LogLevelEq(log.ErrorLevel), LogMessageContains("unable to merge auxiliary data into detection")),
				handled,
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("publicid", test.PublicId)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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
	tests := []struct {
		Name     string
		ReqBody  []byte
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name:    "Sunny Day",
			ReqBody: []byte(`{"language":"sigma","content":"test", "overrides": [{}]}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {},
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {},
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {},
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			ctx := NewTestContext(nil)
			mem, l := NewInMemoryLogger()

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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
	tests := []struct {
		Name     string
		Id       string
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name: "Sunny Day",
			Id:   "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.Id)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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
	tests := []struct {
		Name     string
		Id       string
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name: "Sunny Day",
			Id:   "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.Id)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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
	tests := []struct {
		Name     string
		ReqBody  []byte
		InitMock func(*testing.T, *Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name:    "Sunny Day",
			ReqBody: []byte(`{"id":"12345","publicId":"publicID","language":"sigma","engine":"elastalert","content":"test"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
				NewEntryMatcher(LogLevelEq(log.ErrorLevel), LogMessageEq("unable to merge auxiliary data into detection")),
				handled,
			},
		},
		{
			Name:     "Bad Body",
			ReqBody:  []byte(`not even close to JSON`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {},
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {},
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			Name:    "UpdateDetection - Unexpected Error",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().ValidateRule(gomock.Any()).Return("", nil)
				eng.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				eng.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{}, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).Return(nil, errors.New("something went wrong"))
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "UpdateDetection - Successful Disable After Bad Sync",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","isEnabled":true}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
				NewEntryMatcher(LogLevelEq(log.ErrorLevel), LogMessageContains("unable to sync detection; attempting to disable and resync")),
				handled,
			},
		},
		{
			Name:    "UpdateDetection - Unsuccessful Disable After Bad Sync",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","isEnabled":true}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
				NewEntryMatcher(LogLevelEq(log.ErrorLevel), LogMessageContains("unable to sync detection; attempting to disable and resync")),
				didNotComplete,
				handled,
			},
		},
		{
			Name:    "Modified By Filters, Bad Sync",
			ReqBody: []byte(`{"engine":"strelka","content":"test","id":"12345","isEnabled":true}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(t, srv, ctrl)

			ctx := NewTestContext(nil)
			mem, l := NewInMemoryLogger()

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerUpdateOverrideNote(t *testing.T) {
	tests := []struct {
		Name          string
		DetectionId   string
		OverrideIndex string
		ReqBody       []byte
		InitMock      func(*testing.T, *Server, *gomock.Controller)
		Code          int
		Response      any
		Logs          []EntryMatcher
	}{
		{
			Name:          "Sunny Day",
			DetectionId:   "12345",
			OverrideIndex: "0",
			ReqBody:       []byte(`{"note":"note goes here"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{
					Overrides: []*model.Override{
						{},
					},
				}, nil)

				mDetStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, det *model.Detection) (*model.Detection, error) {
					assert.True(t, modcontext.ReadSkipAudit(ctx))
					assert.Equal(t, "note goes here", det.Overrides[0].Note)

					return det, nil
				})
			},
			Code: 200,
			Logs: []EntryMatcher{handled},
		},
		{
			Name:          "Bad Params",
			DetectionId:   "12345",
			OverrideIndex: "first",
			ReqBody:       []byte(`{"note":"note goes here"}`),
			InitMock:      func(t *testing.T, srv *Server, ctrl *gomock.Controller) {},
			Code:          400,
			Response:      []byte("The request could not be processed."),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:          "Bad Body",
			DetectionId:   "12345",
			OverrideIndex: "0",
			ReqBody:       []byte(`JSON goes here`),
			InitMock:      func(t *testing.T, srv *Server, ctrl *gomock.Controller) {},
			Code:          400,
			Response:      []byte("The request could not be processed."),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:          "Note Too Long",
			DetectionId:   "12345",
			OverrideIndex: "0",
			ReqBody:       []byte(`{"note":"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam rhoncus efficitur lectus. Aenean a feugiat odio, sit amet tempus ligula viverra fusce."}`),
			InitMock:      func(t *testing.T, srv *Server, ctrl *gomock.Controller) {},
			Code:          400,
			Response:      []byte("The request could not be processed."),
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(t, srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.DetectionId)
			rctx.URLParams.Add("overrideIndex", test.OverrideIndex)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("/detection/%s/override/%s/note", test.DetectionId, test.OverrideIndex), bytes.NewReader(test.ReqBody))

			h.UpdateOverrideNote(w, r)

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerDeleteDetection(t *testing.T) {
	tests := []struct {
		Name        string
		DetectionId string
		InitMock    func(*testing.T, *Server, *gomock.Controller)
		Code        int
		Response    any
		Logs        []EntryMatcher
	}{
		{
			Name:        "Sunny Day",
			DetectionId: "12345",
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				orig := &model.Detection{
					PublicID: "Original",
					Engine:   model.EngineNameElastAlert,
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(orig, nil)

				mDetStore.EXPECT().DeleteDetection(gomock.Any(), "12345").Return(orig, nil)

				mAuth.Authorized = true

				eng.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].PendingDelete)

					return nil, nil
				})
			},
			Code: 200,
			Logs: []EntryMatcher{handled},
		},
		{
			Name:        "Unable to Delete Community Detection",
			DetectionId: "12345",
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				orig := &model.Detection{
					IsCommunity: true,
				}
				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(orig, nil)
			},
			Code:     400,
			Response: []byte(`"ERROR_DELETE_COMMUNITY"`),
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:        "Detection Not Found",
			DetectionId: "12345",
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(nil, errors.New("Object not found"))
			},
			Code: 404,
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:        "Unable to Get Detection",
			DetectionId: "12345",
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(nil, errors.New("something went wrong"))
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:        "Unable to Delete Detection",
			DetectionId: "12345",
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{}, nil)

				mDetStore.EXPECT().DeleteDetection(gomock.Any(), "12345").Return(nil, errors.New("something went wrong"))
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:        "Unable to Sync After Delete",
			DetectionId: "12345",
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{}, nil)

				mDetStore.EXPECT().DeleteDetection(gomock.Any(), "12345").Return(&model.Detection{Engine: model.EngineNameElastAlert}, nil)

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
			Name:        "Unauthorized",
			DetectionId: "12345",
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				mDetStore.EXPECT().GetDetection(gomock.Any(), "12345").Return(&model.Detection{}, nil)

				mDetStore.EXPECT().DeleteDetection(gomock.Any(), "12345").Return(nil, model.NewUnauthorized("", "write", "detections"))
			},
			Code:     401,
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(t, srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.DetectionId)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("/detection/%s", test.DetectionId), nil)

			h.DeleteDetection(w, r)

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerBulkUpdateDetection(t *testing.T) {
	tests := []struct {
		Name       string
		NewStatus  string
		ReqBody    []byte
		InitMock   func(*testing.T, *Server, *gomock.Controller) (*sync.WaitGroup, *MockBroadcaster)
		Code       int
		Response   any
		Logs       []EntryMatcher
		Broadcasts []BroadcastMatcher
	}{
		{
			Name:      "Sunny Day - IDs",
			NewStatus: "enable",
			ReqBody:   []byte(`{"ids":["123","456","789"]}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) (*sync.WaitGroup, *MockBroadcaster) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)
				mHostAuth := srv.Host.Authorizer.(*rbac.FakeAuthorizer)

				engElastAlert := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = engElastAlert

				engSuricata := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = engSuricata

				engStrelka := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = engStrelka

				mAuth.Authorized = true

				mDetStore.EXPECT().GetDetection(gomock.Any(), "123").Return(&model.Detection{
					Auditable: model.Auditable{
						Id: "123",
					},
					Engine: model.EngineNameElastAlert,
				}, nil)
				mDetStore.EXPECT().GetDetection(gomock.Any(), "456").Return(&model.Detection{
					Auditable: model.Auditable{
						Id: "456",
					},
					Engine: model.EngineNameSuricata,
				}, nil)
				mDetStore.EXPECT().GetDetection(gomock.Any(), "789").Return(&model.Detection{
					Auditable: model.Auditable{
						Id: "789",
					},
					Engine: model.EngineNameStrelka,
				}, nil)

				docIndexer := servermock.NewMockBulkIndexer(ctrl)

				mDetStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(docIndexer, nil)

				engElastAlert.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
				engSuricata.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
				engStrelka.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				engElastAlert.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
				engSuricata.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
				engStrelka.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), true, nil, nil).Times(3).Return([]byte("doc"), "so-detection", nil)

				docIndexer.EXPECT().Add(gomock.Any(), gomock.Any()).Times(3).DoAndReturn(func(ctx context.Context, work esutil.BulkIndexerItem) error {
					assert.Equal(t, "update", work.Action)
					work.OnSuccess(ctx, work, esutil.BulkIndexerResponseItem{
						DocumentID: work.DocumentID,
					})

					return nil
				})

				docIndexer.EXPECT().Close(gomock.Any()).Return(nil)

				auditIndexer := servermock.NewMockBulkIndexer(ctrl)

				mDetStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(auditIndexer, nil)

				mDetStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), false, util.Ptr("123"), util.Ptr("update")).Return([]byte("doc"), "so-detectionhistory", nil)
				mDetStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), false, util.Ptr("456"), util.Ptr("update")).Return([]byte("doc"), "so-detectionhistory", nil)
				mDetStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), false, util.Ptr("789"), util.Ptr("update")).Return([]byte("doc"), "so-detectionhistory", nil)

				auditIndexer.EXPECT().Add(gomock.Any(), gomock.Any()).Times(3).DoAndReturn(func(ctx context.Context, work esutil.BulkIndexerItem) error {
					assert.Equal(t, "create", work.Action)
					assert.Equal(t, "so-detectionhistory", work.Index)
					work.OnSuccess(ctx, work, esutil.BulkIndexerResponseItem{})

					return nil
				})

				auditIndexer.EXPECT().Close(gomock.Any()).Return(nil)

				engElastAlert.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].IsEnabled)
					assert.True(t, dets[0].PersistChange)

					return nil, nil
				})
				engSuricata.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].IsEnabled)
					assert.True(t, dets[0].PersistChange)

					return nil, nil
				})
				engStrelka.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].IsEnabled)
					assert.True(t, dets[0].PersistChange)

					return nil, nil
				})

				mHostAuth.Authorized = true

				wg := &sync.WaitGroup{}
				wg.Add(1)

				mb := MockBroadcast(t, srv, func(bm BroadcastMessage) {
					wg.Done()
				})

				return wg, mb
			},
			Code:     202,
			Response: []byte(`{"count":3}`),
			Logs: []EntryMatcher{
				// pre-async portion of work
				handled,
				// async portion of work
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageEq("bulk operation complete"),
					LogFieldEq("bulkUpdated", 3),
					LogFieldEq("bulkAudited", 3),
					LogFieldEq("bulkUpdate", true),
				),
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageEq("post-bulk sync finished"),
				),
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageEq("bulk action Detections finished"),
					LogFieldEq("deleted", 0),
					LogFieldEq("filtered", 0),
					LogFieldEq("modified", 3),
					LogFieldEq("total", 3),
					LogFieldExists("updateTime"),
					LogFieldExists("syncTime"),
					LogFieldExists("totalTime"),
				),
			},
			Broadcasts: []BroadcastMatcher{
				NewBroadcastMatcher(
					BroadcastKindEq("detections:bulkUpdate"),
					BroadcastObjectFieldEq("error", 0),
					BroadcastObjectFieldEq("filtered", 0),
					BroadcastObjectFieldEq("modified", 3),
					BroadcastObjectFieldEq("total", 3),
					BroadcastObjectFieldEq("verb", "update"),
					BroadcastObjectFieldExists("time"),
				),
			},
		},
		{
			Name:      "Sunny Day - Query",
			NewStatus: "enable",
			ReqBody:   []byte(`{"query":"severity: low AND ruleset: ETOPEN"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) (*sync.WaitGroup, *MockBroadcaster) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)
				mHostAuth := srv.Host.Authorizer.(*rbac.FakeAuthorizer)

				engElastAlert := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = engElastAlert

				engSuricata := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = engSuricata

				engStrelka := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = engStrelka

				mAuth.Authorized = true

				mDetStore.EXPECT().Query(gomock.Any(), `(severity: low AND ruleset: ETOPEN) AND _index:"*:so-detection" AND so_kind:detection`, -1).Return([]interface{}{
					&model.Detection{
						Auditable: model.Auditable{
							Id: "123",
						},
						Engine: model.EngineNameElastAlert,
					},
					&model.Detection{
						Auditable: model.Auditable{
							Id: "456",
						},
						Engine: model.EngineNameSuricata,
					},
					&model.Detection{
						Auditable: model.Auditable{
							Id: "789",
						},
						Engine: model.EngineNameStrelka,
					},
				}, nil)

				docIndexer := servermock.NewMockBulkIndexer(ctrl)

				mDetStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(docIndexer, nil)

				engElastAlert.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
				engSuricata.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)
				engStrelka.EXPECT().ApplyFilters(gomock.Any()).Return(false, nil)

				engElastAlert.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
				engSuricata.EXPECT().ExtractDetails(gomock.Any()).Return(nil)
				engStrelka.EXPECT().ExtractDetails(gomock.Any()).Return(nil)

				mDetStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), true, nil, nil).Times(3).Return([]byte("doc"), "so-detection", nil)

				docIndexer.EXPECT().Add(gomock.Any(), gomock.Any()).Times(3).DoAndReturn(func(ctx context.Context, work esutil.BulkIndexerItem) error {
					assert.Equal(t, "update", work.Action)
					work.OnSuccess(ctx, work, esutil.BulkIndexerResponseItem{
						DocumentID: work.DocumentID,
					})

					return nil
				})

				docIndexer.EXPECT().Close(gomock.Any()).Return(nil)

				auditIndexer := servermock.NewMockBulkIndexer(ctrl)

				mDetStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(auditIndexer, nil)

				mDetStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), false, util.Ptr("123"), util.Ptr("update")).Return([]byte("doc"), "so-detectionhistory", nil)
				mDetStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), false, util.Ptr("456"), util.Ptr("update")).Return([]byte("doc"), "so-detectionhistory", nil)
				mDetStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), false, util.Ptr("789"), util.Ptr("update")).Return([]byte("doc"), "so-detectionhistory", nil)

				auditIndexer.EXPECT().Add(gomock.Any(), gomock.Any()).Times(3).DoAndReturn(func(ctx context.Context, work esutil.BulkIndexerItem) error {
					assert.Equal(t, "create", work.Action)
					assert.Equal(t, "so-detectionhistory", work.Index)
					work.OnSuccess(ctx, work, esutil.BulkIndexerResponseItem{})

					return nil
				})

				auditIndexer.EXPECT().Close(gomock.Any()).Return(nil)

				engElastAlert.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].IsEnabled)
					assert.True(t, dets[0].PersistChange)

					return nil, nil
				})
				engSuricata.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].IsEnabled)
					assert.True(t, dets[0].PersistChange)

					return nil, nil
				})
				engStrelka.EXPECT().SyncLocalDetections(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, dets []*model.Detection) (map[string]string, error) {
					assert.True(t, dets[0].IsEnabled)
					assert.True(t, dets[0].PersistChange)

					return nil, nil
				})

				mHostAuth.Authorized = true

				wg := &sync.WaitGroup{}
				wg.Add(1)

				mb := MockBroadcast(t, srv, func(bm BroadcastMessage) {
					wg.Done()
				})

				return wg, mb
			},
			Code:     202,
			Response: []byte(`{"count":3}`),
			Logs: []EntryMatcher{
				// pre-async portion of work
				handled,
				// async portion of work
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageEq("bulk operation complete"),
					LogFieldEq("bulkUpdated", 3),
					LogFieldEq("bulkAudited", 3),
					LogFieldEq("bulkUpdate", true),
				),
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageEq("post-bulk sync finished"),
				),
				NewEntryMatcher(
					LogLevelEq(log.InfoLevel),
					LogMessageEq("bulk action Detections finished"),
					LogFieldEq("deleted", 0),
					LogFieldEq("filtered", 0),
					LogFieldEq("modified", 3),
					LogFieldEq("total", 3),
					LogFieldExists("updateTime"),
					LogFieldExists("syncTime"),
					LogFieldExists("totalTime"),
				),
			},
			Broadcasts: []BroadcastMatcher{
				NewBroadcastMatcher(
					BroadcastKindEq("detections:bulkUpdate"),
					BroadcastObjectFieldEq("error", 0),
					BroadcastObjectFieldEq("filtered", 0),
					BroadcastObjectFieldEq("modified", 3),
					BroadcastObjectFieldEq("total", 3),
					BroadcastObjectFieldEq("verb", "update"),
					BroadcastObjectFieldExists("time"),
				),
			},
		},
		{
			Name:      "Cannot Delete Community Rules - Ids",
			NewStatus: "delete",
			ReqBody:   []byte(`{"ids":["123","456","789"]}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) (*sync.WaitGroup, *MockBroadcaster) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				mAuth.Authorized = true

				mDetStore.EXPECT().GetDetection(gomock.Any(), "123").Return(&model.Detection{
					Auditable: model.Auditable{
						Id: "123",
					},
					Engine: model.EngineNameElastAlert,
				}, nil)
				mDetStore.EXPECT().GetDetection(gomock.Any(), "456").Return(&model.Detection{
					Auditable: model.Auditable{
						Id: "456",
					},
					Engine:      model.EngineNameSuricata,
					IsCommunity: true,
				}, nil)
				// the 3rd detection is not retrieved because the handler will quit
				// immediately after a community detection is retrieved

				return nil, nil
			},
			Code:     400,
			Response: []byte(`"ERROR_BULK_COMMUNITY"`),
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:      "Cannot Delete Community Rules - Query",
			NewStatus: "delete",
			ReqBody:   []byte(`{"query":"severity: low AND ruleset: ETOPEN"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) (*sync.WaitGroup, *MockBroadcaster) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				mAuth.Authorized = true

				mDetStore.EXPECT().Query(gomock.Any(), `(severity: low AND ruleset: ETOPEN) AND _index:"*:so-detection" AND so_kind:detection`, -1).Return([]interface{}{
					&model.Detection{
						Auditable: model.Auditable{
							Id: "123",
						},
						Engine: model.EngineNameElastAlert,
					},
					&model.Detection{
						Auditable: model.Auditable{
							Id: "456",
						},
						Engine:      model.EngineNameSuricata,
						IsCommunity: true,
					},
					&model.Detection{
						Auditable: model.Auditable{
							Id: "789",
						},
						Engine: model.EngineNameStrelka,
					},
				}, nil)

				return nil, nil
			},
			Code:     400,
			Response: []byte(`"ERROR_BULK_COMMUNITY"`),
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:      "Query Failure",
			NewStatus: "enable",
			ReqBody:   []byte(`{"query":"severity: low AND ruleset: ETOPEN"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) (*sync.WaitGroup, *MockBroadcaster) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				mAuth.Authorized = true

				mDetStore.EXPECT().Query(gomock.Any(), `(severity: low AND ruleset: ETOPEN) AND _index:"*:so-detection" AND so_kind:detection`, -1).Return(nil, errors.New("something went wrong"))

				return nil, nil
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:      "Unauthorized",
			NewStatus: "disable",
			ReqBody:   []byte(`{"query":"severity: low AND ruleset: ETOPEN"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) (*sync.WaitGroup, *MockBroadcaster) {
				return nil, nil
			},
			Code:     401,
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			wg, mb := test.InitMock(t, srv, ctrl)
			if mb != nil {
				defer mb.Close()
			}

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("newStatus", test.NewStatus)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			ctx = context.WithValue(ctx, web.ContextKeyRunAsUsername, "test")

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("/detection/bulk/%s", test.NewStatus), bytes.NewReader(test.ReqBody))

			h.BulkUpdateDetection(w, r)
			if wg != nil {
				wg.Wait()
			}

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
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

			if test.Broadcasts != nil {
				if mb == nil {
					t.Fatalf("Expected broadcast messages, but no broadcaster was created")
				}
				if len(test.Broadcasts) != len(mb.Messages) {
					t.Fatalf("Expected %d broadcast messages, got %d", len(test.Broadcasts), len(mb.Messages))
				}

				for i, matcher := range test.Broadcasts {
					err := matcher.Validate(mb.Messages[i])
					if err != nil {
						t.Fatalf("Broadcast message %d is invalid: %s", i, err)
					}
				}
			}
		})
	}
}

func TestHandlerCreateComment(t *testing.T) {
	tests := []struct {
		Name        string
		DetectionId string
		ReqBody     []byte
		InitMock    func(*testing.T, *Server, *gomock.Controller)
		Code        int
		Response    any
		Logs        []EntryMatcher
	}{
		{
			Name:        "Sunny Day",
			DetectionId: "12345",
			ReqBody:     []byte(`{"value":"This is a comment"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().CreateComment(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, comment *model.DetectionComment) (*model.DetectionComment, error) {
					return comment, nil
				})
			},
			Code: 200,
			Response: &model.DetectionComment{
				DetectionId: "12345",
				Value:       "This is a comment",
			},
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:        "Detection Not Found",
			DetectionId: "12345",
			ReqBody:     []byte(`{"value":"This is a comment"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().CreateComment(gomock.Any(), gomock.Any()).Return(nil, errors.New("Object not found"))
			},
			Code:     404,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:        "Unable to Create Comment",
			DetectionId: "12345",
			ReqBody:     []byte(`{"value":"This is a comment"}`),
			InitMock: func(t *testing.T, srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().CreateComment(gomock.Any(), gomock.Any()).Return(nil, errors.New("something went wrong"))
			},
			Code:     500,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:        "Request Error",
			DetectionId: "12345",
			ReqBody:     []byte(`JSON`),
			InitMock:    func(t *testing.T, srv *Server, ctrl *gomock.Controller) {},
			Code:        400,
			Response:    []byte(`The request could not be processed.`),
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})

			h := NewDetectionHandler(srv)

			test.InitMock(t, srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.DetectionId)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "POST", fmt.Sprintf("/detection/comment/%s", test.DetectionId), bytes.NewReader(test.ReqBody))

			h.CreateComment(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case *model.DetectionComment:
				actual := &model.DetectionComment{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)

				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerGetDetectionComment(t *testing.T) {
	tests := []struct {
		Name     string
		Id       string
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name: "Sunny Day",
			Id:   "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mDetStore.EXPECT().GetComment(gomock.Any(), "12345").Return(&model.DetectionComment{
					Auditable: model.Auditable{
						Id: "12345",
					},
					DetectionId: "det123",
					Value:       "Test comment",
				}, nil)
			},
			Code: 200,
			Response: &model.DetectionComment{
				Auditable: model.Auditable{
					Id: "12345",
				},
				DetectionId: "det123",
				Value:       "Test comment",
			},
			Logs: []EntryMatcher{handled},
		},
		{
			Name: "Comment Not Found",
			Id:   "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mDetStore.EXPECT().GetComment(gomock.Any(), "12345").Return(nil, errors.New("Object not found"))
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})
			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.Id)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "GET", fmt.Sprintf("/detection/comment/%s", test.Id), nil)

			h.GetDetectionComment(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case *model.DetectionComment:
				actual := &model.DetectionComment{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)
				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerUpdateComment(t *testing.T) {
	tests := []struct {
		Name      string
		CommentId string
		ReqBody   []byte
		InitMock  func(*Server, *gomock.Controller)
		Code      int
		Response  any
		Logs      []EntryMatcher
	}{
		{
			Name:      "Sunny Day",
			CommentId: "12345",
			ReqBody:   []byte(`{"value":"Test comment"}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mDetStore.EXPECT().UpdateComment(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, comment *model.DetectionComment) (*model.DetectionComment, error) {
					comment.Id = "12345"
					comment.DetectionId = "det123"

					return comment, nil
				})
			},
			Code: 200,
			Response: &model.DetectionComment{
				Auditable: model.Auditable{
					Id: "12345",
				},
				DetectionId: "det123",
				Value:       "Test comment",
			},
			Logs: []EntryMatcher{handled},
		},
		{
			Name:      "Bad Request",
			CommentId: "12345",
			ReqBody:   []byte(`JSON`),
			InitMock:  func(srv *Server, ctrl *gomock.Controller) {},
			Code:      400,
			Response:  []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:      "Detection Not Found",
			CommentId: "12345",
			ReqBody:   []byte(`{"value":"Test comment"}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().UpdateComment(gomock.Any(), gomock.Any()).Return(nil, errors.New("Object not found"))
			},
			Code:     404,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:      "Unexpected Error",
			CommentId: "12345",
			ReqBody:   []byte(`{"value":"Test comment"}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().UpdateComment(gomock.Any(), gomock.Any()).Return(nil, errors.New("something went wrong"))
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})
			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.CommentId)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("/detection/comment/%s", test.CommentId), bytes.NewReader(test.ReqBody))

			h.UpdateComment(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case *model.DetectionComment:
				actual := &model.DetectionComment{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)
				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerDeleteComment(t *testing.T) {
	tests := []struct {
		Name      string
		CommentId string
		InitMock  func(*Server, *gomock.Controller)
		Code      int
		Response  any
		Logs      []EntryMatcher
	}{
		{
			Name:      "Sunny Day",
			CommentId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mDetStore.EXPECT().DeleteComment(gomock.Any(), "12345").Return(nil)
			},
			Code: 200,
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:      "Not Found",
			CommentId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mDetStore.EXPECT().DeleteComment(gomock.Any(), "12345").Return(errors.New("Object not found"))
			},
			Code:     404,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:      "Unexpected Error",
			CommentId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)
				mDetStore.EXPECT().DeleteComment(gomock.Any(), "12345").Return(errors.New("something went wrong"))
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})
			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.CommentId)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("/detection/comment/%s", test.CommentId), nil)

			h.DeleteComment(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case *model.DetectionComment:
				actual := &model.DetectionComment{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)
				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerGetDetectionComments(t *testing.T) {
	tests := []struct {
		Name     string
		DetectId string
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name:     "Sunny Day",
			DetectId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetComments(gomock.Any(), "12345").Return([]*model.DetectionComment{
					{
						Auditable: model.Auditable{
							Id: "123",
						},
						Value: "Test comment",
					},
					{
						Auditable: model.Auditable{
							Id: "456",
						},
						Value: "Another comment",
					},
				}, nil)
			},
			Code: 200,
			Response: []model.DetectionComment{
				{
					Auditable: model.Auditable{
						Id: "123",
					},
					Value: "Test comment",
				},
				{
					Auditable: model.Auditable{
						Id: "456",
					},
					Value: "Another comment",
				},
			},
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:     "Not Found",
			DetectId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetComments(gomock.Any(), "12345").Return(nil, errors.New("Object not found"))
			},
			Code:     404,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:     "Unexpected Error",
			DetectId: "12345",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mDetStore := srv.Detectionstore.(*servermock.MockDetectionstore)

				mDetStore.EXPECT().GetComments(gomock.Any(), "12345").Return(nil, errors.New("something went wrong"))
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})
			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", test.DetectId)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("/detection/comment/%s", test.DetectId), nil)

			h.GetDetectionComments(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case []model.DetectionComment:
				actual := []model.DetectionComment{}
				err := json.NewDecoder(w.Body).Decode(&actual)
				assert.NoError(t, err)
				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerConvertContent(t *testing.T) {
	tests := []struct {
		Name     string
		ReqBody  []byte
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name:    "Sunny Day",
			ReqBody: []byte(`{"content": "sigma goes here", "engine": "elastalert"}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ConvertRule(gomock.Any(), &model.Detection{Content: "sigma goes here", Engine: model.EngineNameElastAlert}).Return("converted query", nil)
			},
			Code: 200,
			Response: &ConvertContentResp{
				Query: "converted query",
			},
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:     "Bad Request",
			ReqBody:  []byte(`JSON`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:     "Bad Engine",
			ReqBody:  []byte(`{"engine": "suricata"}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			// when creating a new detection, the engine isn't specified yet, but language is
			Name:    "Good Language",
			ReqBody: []byte(`{"language": "sigma", "content": "sigma goes here"}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ConvertRule(gomock.Any(), &model.Detection{Content: "sigma goes here", Language: model.SigLangSigma}).Return("converted query", nil)
			},
			Code: 200,
			Response: &ConvertContentResp{
				Query: "converted query",
			},
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:    "Unknown Error",
			ReqBody: []byte(`{"engine": "elastalert", "content": "sigma goes here"}`),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().ConvertRule(gomock.Any(), &model.Detection{Content: "sigma goes here", Engine: model.EngineNameElastAlert}).Return("", errors.New("something went wrong"))
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})
			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			ctx := NewTestContext(nil)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "POST", "/detection/convert/", bytes.NewReader(test.ReqBody))

			h.ConvertContent(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case *ConvertContentResp:
				actual := &ConvertContentResp{}
				err := json.NewDecoder(w.Body).Decode(actual)
				assert.NoError(t, err)
				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerSyncEngineDetections(t *testing.T) {
	tests := []struct {
		Name     string
		Engine   string
		SyncType string
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name:     "Sunny Day",
			Engine:   string(model.EngineNameElastAlert),
			SyncType: "full",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				mAuth.Authorized = true

				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().InterruptSync(true, true)
			},
			Code: 200,
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:     "Sunny Day - Sync All",
			Engine:   "all",
			SyncType: "update",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				mAuth.Authorized = true

				engElastAlert := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = engElastAlert

				engSuricata := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameSuricata] = engSuricata

				engStrelka := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = engStrelka

				// all means all
				engWhatever := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines["whatever"] = engWhatever

				engElastAlert.EXPECT().InterruptSync(false, true)
				engSuricata.EXPECT().InterruptSync(false, true)
				engStrelka.EXPECT().InterruptSync(false, true)
				engWhatever.EXPECT().InterruptSync(false, true)
			},
			Code: 200,
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:     "Unauthorized",
			Engine:   string(model.EngineNameElastAlert),
			SyncType: "full",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {},
			Code:     401,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:     "Unknown Engine",
			Engine:   "foobar",
			SyncType: "full",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				mAuth := srv.Authorizer.(*rbac.FakeAuthorizer)

				mAuth.Authorized = true
			},
			Code:     400,
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})
			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("engine", test.Engine)
			rctx.URLParams.Add("type", test.SyncType)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "POST", fmt.Sprintf("/detection/sync/%s/%s", test.Engine, test.SyncType), nil)

			h.SyncEngineDetections(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case []model.DetectionComment:
				actual := []model.DetectionComment{}
				err := json.NewDecoder(w.Body).Decode(&actual)
				assert.NoError(t, err)
				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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

func TestHandlerGenPublicId(t *testing.T) {
	tests := []struct {
		Name     string
		Engine   string
		InitMock func(*Server, *gomock.Controller)
		Code     int
		Response any
		Logs     []EntryMatcher
	}{
		{
			Name:   "Sunny Day",
			Engine: string(model.EngineNameElastAlert),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameElastAlert] = eng

				eng.EXPECT().GenerateUnusedPublicId(gomock.Any()).Return("unused-public-id", nil)
			},
			Code: 200,
			Response: GenPublicIdResp{
				PublicId: "unused-public-id",
			},
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:     "Unknown Engine",
			Engine:   "foobar",
			InitMock: func(srv *Server, ctrl *gomock.Controller) {},
			Code:     400,
			Response: []byte(`The request could not be processed.`),
			Logs: []EntryMatcher{
				didNotComplete,
				handled,
			},
		},
		{
			Name:   "Engine Doesn't Support Traditional Ids",
			Engine: string(model.EngineNameStrelka),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().GenerateUnusedPublicId(gomock.Any()).Return("", errors.New("not implemented"))
			},
			Code: 501,
			Logs: []EntryMatcher{
				handled,
			},
		},
		{
			Name:   "Unexpected Error",
			Engine: string(model.EngineNameStrelka),
			InitMock: func(srv *Server, ctrl *gomock.Controller) {
				eng := servermock.NewMockDetectionEngine(ctrl)
				srv.DetectionEngines[model.EngineNameStrelka] = eng

				eng.EXPECT().GenerateUnusedPublicId(gomock.Any()).Return("", errors.New("something went wrong"))
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
			srv := NewMockServer(t, ctrl, &config.ServerConfig{})
			h := NewDetectionHandler(srv)

			test.InitMock(srv, ctrl)

			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("engine", test.Engine)

			ctx := NewTestContext(rctx)
			mem, l := NewInMemoryLogger()

			ctx = log.NewContext(ctx, l)

			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(ctx, "POST", fmt.Sprintf("/detection/%s/genpublicid", test.Engine), nil)

			h.GenPublicId(w, r)

			assert.Equal(t, test.Code, w.Code)

			switch res := test.Response.(type) {
			case GenPublicIdResp:
				actual := GenPublicIdResp{}
				err := json.NewDecoder(w.Body).Decode(&actual)
				assert.NoError(t, err)
				assert.Equal(t, res, actual)
			case []byte:
				assert.Equal(t, res, w.Body.Bytes())
			case nil:
				assert.Empty(t, w.Body.String())
			default:
				t.Log("unexpected response type in test")
				t.Fail()
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
