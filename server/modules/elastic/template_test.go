// Copyright 2019 Jason Ertel (jertel). All rights reserved.
// Copyright 2020-2021 Security Onion Solutions, LLC. All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

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
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND kind:"case" AND _id:"myTemplateId"`
	casePayload := make(map[string]interface{})
	casePayload["kind"] = "case"
	casePayload["case.title"] = "myTemplateTitle {}"
	casePayload["case.description"] = "myTemplateDescription {}"
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
