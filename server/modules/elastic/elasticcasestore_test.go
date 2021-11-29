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

func TestInit(tester *testing.T) {
	store := NewElasticCasestore(nil)
	store.Init("myIndex", "myAuditIndex", 45)
	assert.Equal(tester, "myIndex", store.index)
	assert.Equal(tester, "myAuditIndex", store.auditIndex)
	assert.Equal(tester, 45, store.maxAssociations)
}

func TestPrepareForSave(tester *testing.T) {
	store := NewElasticCasestore(nil)
	obj := &model.Auditable{
		Id: "myId",
	}
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	actualId := store.prepareForSave(ctx, obj)
	assert.Equal(tester, "myId", actualId)
	assert.Equal(tester, "myRequestorId", obj.UserId)
	assert.Equal(tester, "", obj.Id)
	assert.Nil(tester, obj.UpdateTime)
}

func TestSaveCreate(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	obj := model.NewCase()
	results, err := store.save(ctx, obj, "case", "")
	assert.NoError(tester, err)
	assert.Equal(tester, 2, len(fakeEventStore.InputIds))
	assert.Equal(tester, "", fakeEventStore.InputIds[0])
	assert.Equal(tester, "", fakeEventStore.InputIds[1])
	assert.Equal(tester, "myIndex", fakeEventStore.InputIndexes[0])
	assert.Equal(tester, "myAuditIndex", fakeEventStore.InputIndexes[1])
	assert.Equal(tester, 2, len(fakeEventStore.InputDocuments))
	assert.Equal(tester, "case", fakeEventStore.InputDocuments[0]["kind"])
	assert.Equal(tester, "create", fakeEventStore.InputDocuments[1]["operation"])
	assert.NotNil(tester, results)
}

func TestSaveUpdate(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	obj := model.NewCase()
	results, err := store.save(ctx, obj, "case", "myCaseId")
	assert.NoError(tester, err)
	assert.Equal(tester, 2, len(fakeEventStore.InputIds))
	assert.Equal(tester, "myCaseId", fakeEventStore.InputIds[0])
	assert.Equal(tester, "", fakeEventStore.InputIds[1])
	assert.Equal(tester, "myIndex", fakeEventStore.InputIndexes[0])
	assert.Equal(tester, "myAuditIndex", fakeEventStore.InputIndexes[1])
	assert.Equal(tester, 2, len(fakeEventStore.InputDocuments))
	assert.Equal(tester, "case", fakeEventStore.InputDocuments[0]["kind"])
	assert.Equal(tester, "update", fakeEventStore.InputDocuments[1]["operation"])
	assert.NotNil(tester, results)
}

func TestDelete(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	obj := model.NewCase()
	err := store.delete(ctx, obj, "case", "myCaseId")
	assert.NoError(tester, err)
	assert.Equal(tester, 2, len(fakeEventStore.InputIds))
	assert.Equal(tester, "myCaseId", fakeEventStore.InputIds[0])
	assert.Equal(tester, "", fakeEventStore.InputIds[1])
	assert.Equal(tester, "myIndex", fakeEventStore.InputIndexes[0])
	assert.Equal(tester, "myAuditIndex", fakeEventStore.InputIndexes[1])
	assert.Equal(tester, 1, len(fakeEventStore.InputDocuments))
	assert.Equal(tester, "case", fakeEventStore.InputDocuments[0]["kind"])
	assert.Equal(tester, "delete", fakeEventStore.InputDocuments[0]["operation"])
}

func TestGetAll(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := "some query"
	casePayload := make(map[string]interface{})
	casePayload["kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}

	commentPayload := make(map[string]interface{})
	commentPayload["kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
	}

	fakeEventStore.SearchResults.Events = append(fakeEventStore.SearchResults.Events, caseEvent)
	fakeEventStore.SearchResults.Events = append(fakeEventStore.SearchResults.Events, commentEvent)
	results, err := store.getAll(ctx, query, 123)
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Len(tester, results, 2)
}

func TestGet(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND kind:"case" AND _id:"myCaseId"`
	casePayload := make(map[string]interface{})
	casePayload["kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}
	fakeEventStore.SearchResults.Events = append(fakeEventStore.SearchResults.Events, caseEvent)
	obj, err := store.get(ctx, "myCaseId", "case")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestCreateError(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	myCase := model.NewCase()
	myCase.Id = "123"
	newCase, err := store.Create(ctx, myCase)
	assert.Error(tester, err)
	assert.Equal(tester, "Unexpected ID found in new case", err.Error())
	assert.NotNil(tester, newCase)
}

func TestUpdateError(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	myCase := model.NewCase()
	myCase.Id = ""
	newCase, err := store.Update(ctx, myCase)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing case ID", err.Error())
	assert.NotNil(tester, newCase)
}

func TestGetCase(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND kind:"case" AND _id:"myCaseId"`
	casePayload := make(map[string]interface{})
	casePayload["kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}
	fakeEventStore.SearchResults.Events = append(fakeEventStore.SearchResults.Events, caseEvent)
	obj, err := store.GetCase(ctx, "myCaseId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetCaseHistory(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myAuditIndex" AND (so_audit_doc_id:"myCaseId" OR comment.caseId:"myCaseId")`
	casePayload := make(map[string]interface{})
	casePayload["kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}
	fakeEventStore.SearchResults.Events = append(fakeEventStore.SearchResults.Events, caseEvent)
	results, err := store.GetCaseHistory(ctx, "myCaseId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Len(tester, results, 1)
}

func TestCreateCommentUnexpectedId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	comment := model.NewComment()
	comment.Id = "123"
	_, err := store.CreateComment(ctx, comment)
	assert.Error(tester, err)
	assert.Equal(tester, "Unexpected ID found in new comment", err.Error())
}

func TestCreateCommentMissingCaseId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	comment := model.NewComment()
	_, err := store.CreateComment(ctx, comment)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing Case ID in new comment", err.Error())
}

func TestGetComment(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND kind:"comment" AND _id:"myCommentId"`
	commentPayload := make(map[string]interface{})
	commentPayload["kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
	}
	fakeEventStore.SearchResults.Events = append(fakeEventStore.SearchResults.Events, commentEvent)
	obj, err := store.GetComment(ctx, "myCommentId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetComments(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND kind:"comment" AND comment.caseId:"myCaseId" | sortby comment.createTime^`
	commentPayload := make(map[string]interface{})
	commentPayload["kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
	}
	fakeEventStore.SearchResults.Events = append(fakeEventStore.SearchResults.Events, commentEvent)
	obj, err := store.GetComments(ctx, "myCaseId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestUpdateComment(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	comment := model.NewComment()
	_, err := store.UpdateComment(ctx, comment)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing comment ID", err.Error())
}

func TestDeleteComment(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND kind:"comment" AND _id:"myCommentId"`
	commentPayload := make(map[string]interface{})
	commentPayload["kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
		Id:      "myCommentId",
	}
	fakeEventStore.SearchResults.Events = append(fakeEventStore.SearchResults.Events, commentEvent)
	err := store.DeleteComment(ctx, "myCommentId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1) // Search to ensure it exists first
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Len(tester, fakeEventStore.InputIds, 2) // Delete and Index (for audit)
	assert.Equal(tester, "myCommentId", fakeEventStore.InputIds[0])
	assert.Equal(tester, "", fakeEventStore.InputIds[1])
}
