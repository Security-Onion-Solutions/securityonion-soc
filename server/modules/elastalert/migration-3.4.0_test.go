// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	modcontext "github.com/security-onion-solutions/securityonion-soc/server/modules/context"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const m340StatePath = "/opt/so/conf/soc/migrations/elastalert-migration-3.4.0"

// as returned by the store
func m340Loaded(publicId string, content string) *model.Detection {
	return &model.Detection{
		Auditable: model.Auditable{Id: publicId, Kind: "detection", Operation: "update"},
		PublicID:  publicId,
		Content:   content,
	}
}

// untypedElastAlertDetections matches the query options selecting ElastAlert detections stored without a rule type.
var untypedElastAlertDetections = gomock.Cond(func(x any) bool {
	opts, ok := x.([]model.GetAllOption)
	if !ok {
		return false
	}

	query := ""
	for _, opt := range opts {
		query = opt(query, "so_")
	}

	return query == ` AND so_detection.engine:"elastalert" AND NOT _exists_:so_detection.ruleType`
})

func m340Engine(detStore *servermock.MockDetectionstore, iom *mock.MockIOManager) *ElastAlertEngine {
	return &ElastAlertEngine{
		srv: &server.Server{
			Context:        context.Background(),
			Detectionstore: detStore,
		},
		IOManager: iom,
	}
}

func TestMigration340AlreadyApplied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile(m340StatePath).Return([]byte("1"), nil)

	err := m340Engine(servermock.NewMockDetectionstore(ctrl), iom).Migration340(m340StatePath)
	assert.NoError(t, err)
}

func TestMigration340(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile(m340StatePath).Return([]byte("0"), nil)
	iom.EXPECT().WriteFile(m340StatePath, []byte("1"), fs.FileMode(0644)).Return(nil)

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().GetAllDetections(gomock.Any(), untypedElastAlertDetections).Return(map[string]*model.Detection{
		"11111111-1111-1111-1111-111111111111": m340Loaded("11111111-1111-1111-1111-111111111111", testCorrelationContent),
		"c":                                    m340Loaded("c", "not: [valid"),
	}, nil)
	// only the correlation is saved, without a history entry
	detStore.EXPECT().UpdateDetection(
		gomock.Cond(func(x any) bool { return modcontext.ReadSkipAudit(x.(context.Context)) }),
		gomock.Cond(func(x any) bool {
			det := x.(*model.Detection)
			return det.Kind == "" && det.Operation == "" &&
				det.RuleType == model.RuleTypeCorrelation && det.CorrelationType == "value_count" && det.CorrelationTimespan == "10m"
		})).Return(nil, nil).Times(1)

	err := m340Engine(detStore, iom).Migration340(m340StatePath)
	assert.NoError(t, err)
}

func TestMigration340StoreError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile(m340StatePath).Return([]byte("0"), nil)

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().GetAllDetections(gomock.Any(), untypedElastAlertDetections).Return(map[string]*model.Detection{
		"11111111-1111-1111-1111-111111111111": m340Loaded("11111111-1111-1111-1111-111111111111", testCorrelationContent),
	}, nil)
	detStore.EXPECT().UpdateDetection(gomock.Any(), gomock.Any()).Return(nil, errors.New("unavailable"))

	// the state file is not marked done, so the migration is retried
	err := m340Engine(detStore, iom).Migration340(m340StatePath)
	assert.EqualError(t, err, "unavailable")
}

func TestMigration340Errors(t *testing.T) {
	t.Run("Unreadable State File", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().ReadFile(m340StatePath).Return(nil, errors.New("missing"))

		err := m340Engine(servermock.NewMockDetectionstore(ctrl), iom).Migration340(m340StatePath)
		assert.EqualError(t, err, "missing")
	})

	t.Run("Detection Query Fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().ReadFile(m340StatePath).Return([]byte("0"), nil)

		detStore := servermock.NewMockDetectionstore(ctrl)
		detStore.EXPECT().GetAllDetections(gomock.Any(), untypedElastAlertDetections).Return(nil, errors.New("unavailable"))

		// not marked done, so the migration is retried
		err := m340Engine(detStore, iom).Migration340(m340StatePath)
		assert.EqualError(t, err, "unavailable")
	})

	t.Run("State File Cannot Be Marked Done", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		iom := mock.NewMockIOManager(ctrl)
		iom.EXPECT().ReadFile(m340StatePath).Return([]byte("0"), nil)
		iom.EXPECT().WriteFile(m340StatePath, []byte("1"), fs.FileMode(0644)).Return(errors.New("read-only"))

		detStore := servermock.NewMockDetectionstore(ctrl)
		detStore.EXPECT().GetAllDetections(gomock.Any(), untypedElastAlertDetections).Return(map[string]*model.Detection{}, nil)

		err := m340Engine(detStore, iom).Migration340(m340StatePath)
		assert.EqualError(t, err, "read-only")
	})
}
