// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastalert

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	servermock "github.com/security-onion-solutions/securityonion-soc/server/mock"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"

	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const m340StatePath = "/opt/so/conf/soc/migrations/elastalert-migration-3.4.0"

// as returned by the store; the document id differs from the public id
func m340Loaded(publicId string, content string) *model.Detection {
	return &model.Detection{
		Auditable: model.Auditable{Id: "doc-" + publicId, Kind: "detection", Operation: "update"},
		PublicID:  publicId,
		Content:   content,
	}
}

// untypedElastAlertDetections matches the options selecting untyped ElastAlert detections.
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

func TestMigration340IsRegistered(t *testing.T) {
	assert.Contains(t, NewElastAlertEngine(&server.Server{}).migrations, "3.4.0")
}

func TestMigration340AlreadyApplied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile(m340StatePath).Return([]byte("1"), nil)

	err := m340Engine(servermock.NewMockDetectionstore(ctrl), iom).Migration340(m340StatePath)
	assert.NoError(t, err)
}

// expectMigrationBulk records the partial update each detection gets, by document id.
func expectMigrationBulk(ctrl *gomock.Controller, detStore *servermock.MockDetectionstore, count int) (*servermock.MockBulkIndexer, map[string]any) {
	bim := servermock.NewMockBulkIndexer(ctrl)
	updates := map[string]any{}

	detStore.EXPECT().BuildBulkIndexer(gomock.Any(), gomock.Any()).Return(bim, nil)
	detStore.EXPECT().ConvertObjectToDocument(gomock.Any(), "detection", gomock.Any(), gomock.Any(), true, gomock.Nil(), gomock.Nil()).
		DoAndReturn(func(ctx context.Context, kind string, obj any, auditable *model.Auditable, isEdit bool, auditDocId *string, op *string) ([]byte, string, error) {
			updates[auditable.Id] = obj
			return []byte(auditable.Id), "so-detection", nil
		}).Times(count)
	bim.EXPECT().Close(gomock.Any()).Return(nil)

	return bim, updates
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
		SimpleRuleSID:                          m340Loaded(SimpleRuleSID, SimpleRule),
		"c":                                    m340Loaded("c", "not: [valid"),
	}, nil)

	bim, updates := expectMigrationBulk(ctrl, detStore, 2)
	bim.EXPECT().Add(gomock.Any(), gomock.Cond(func(x any) bool {
		item := x.(esutil.BulkIndexerItem)
		return item.Action == "update" && item.Index == "so-detection" && strings.HasPrefix(item.DocumentID, "doc-")
	})).Return(nil).Times(2)

	err := m340Engine(detStore, iom).Migration340(m340StatePath)
	assert.NoError(t, err)

	// only the rule type fields are written; the unparseable rule is skipped
	assert.Equal(t, map[string]any{
		"doc-11111111-1111-1111-1111-111111111111": map[string]any{
			"ruleType":            model.RuleTypeCorrelation,
			"correlationType":     "value_count",
			"correlationTimespan": "10m",
		},
		"doc-" + SimpleRuleSID: map[string]any{"ruleType": model.RuleTypeSingle},
	}, updates)
}

func TestMigration340UpdateFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// no WriteFile: not marked done, so the next start retries
	iom := mock.NewMockIOManager(ctrl)
	iom.EXPECT().ReadFile(m340StatePath).Return([]byte("0"), nil)

	detStore := servermock.NewMockDetectionstore(ctrl)
	detStore.EXPECT().GetAllDetections(gomock.Any(), untypedElastAlertDetections).Return(map[string]*model.Detection{
		"11111111-1111-1111-1111-111111111111": m340Loaded("11111111-1111-1111-1111-111111111111", testCorrelationContent),
		SimpleRuleSID:                          m340Loaded(SimpleRuleSID, SimpleRule),
	}, nil)

	bim, _ := expectMigrationBulk(ctrl, detStore, 2)
	bim.EXPECT().Add(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, item esutil.BulkIndexerItem) error {
		if item.DocumentID == "doc-"+SimpleRuleSID {
			resp := esutil.BulkIndexerResponseItem{}
			resp.Error.Reason = "unavailable"
			item.OnFailure(ctx, item, resp, nil)
		}

		return nil
	}).Times(2)

	// one rejected detection does not fail the migration or block later ones
	err := m340Engine(detStore, iom).Migration340(m340StatePath)
	assert.NoError(t, err)
}
