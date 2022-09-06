// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package elastic

import (
	"context"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestApplyTemplate(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"case" AND _id:"myTemplateId"`
	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	casePayload["so_case.title"] = "myTemplateTitle {}"
	casePayload["so_case.description"] = "myTemplateDescription {}"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)

	socCase := model.NewCase()
	socCase.Template = "myTemplateId"
	socCase.Title = "extraTitle"
	socCase.Description = "extraDesc"

	obj := store.applyTemplate(ctx, socCase)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
	assert.Equal(tester, "myTemplateTitle extraTitle", obj.Title)
	assert.Equal(tester, "myTemplateDescription extraDesc", obj.Description)
}
