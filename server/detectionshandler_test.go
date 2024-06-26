// Copyright 2020-2024 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/elastalert"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/strelka"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/suricata"
	"github.com/security-onion-solutions/securityonion-soc/util"
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
