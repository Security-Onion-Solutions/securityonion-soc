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

func TestValidateIdInvalid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)

	var err error
	err = store.validateId("", "test")
	assert.Error(tester, err)

	err = store.validateId("1", "test")
	assert.Error(tester, err)

	err = store.validateId("a", "test")
	assert.Error(tester, err)

	err = store.validateId("this is invalid since it has spaces", "test")
	assert.Error(tester, err)

	err = store.validateId("'quotes'", "test")
	assert.Error(tester, err)

	err = store.validateId("\"dblquotes\"", "test")
	assert.Error(tester, err)

	err = store.validateId("123456789012345678901234567890123456789012345678901", "test")
	assert.Error(tester, err)
}

func TestValidateIdValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)

	var err error
	err = store.validateId("12345", "test")
	assert.NoError(tester, err)

	err = store.validateId("123456", "test")
	assert.NoError(tester, err)

	err = store.validateId("1-2-A-b", "test")
	assert.NoError(tester, err)

	err = store.validateId("1-2-a-b_2klj", "test")
	assert.NoError(tester, err)

	err = store.validateId("12345678901234567890123456789012345678901234567890", "test")
	assert.NoError(tester, err)
}

func TestValidateStringInvalid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)

	var err error
	err = store.validateString("1234567", 6, "test")
	assert.Error(tester, err)

	err = store.validateString("12345678", 6, "test")
	assert.Error(tester, err)
}

func TestValidateStringValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)

	var err error
	err = store.validateString("12345", 6, "test")
	assert.NoError(tester, err)

	err = store.validateString("123456", 6, "test")
	assert.NoError(tester, err)

	err = store.validateString("", 6, "test")
	assert.NoError(tester, err)
}

func TestValidateCaseInvalid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)

	var err error
	socCase := model.NewCase()

	socCase.Id = "this is an invalid id"
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "invalid ID for caseId")
	socCase.Id = ""

	socCase.UserId = "this is an invalid id"
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "invalid ID for userId")
	socCase.UserId = ""

	socCase.AssigneeId = "this is an invalid id"
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "invalid ID for assigneeId")
	socCase.AssigneeId = ""

	for x := 1; x < 5; x++ {
		socCase.Title += "this is my unreasonably long title\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "title is too long (140/100)")
	socCase.Title = "myTitle"

	for x := 1; x < 30000; x++ {
		socCase.Description += "this is my unreasonably long description\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "description is too long (1229959/1000000)")
	socCase.Description = "myDescription"

	socCase.Priority = -12
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "Invalid priority")
	socCase.Priority = 12

	socCase.Severity = -12
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "Invalid severity")
	socCase.Severity = 12

	for x := 1; x < 5; x++ {
		socCase.Tlp += "this is my unreasonably long tlp\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "tlp is too long (132/100)")
	socCase.Tlp = "myTlp"

	for x := 1; x < 5; x++ {
		socCase.Pap += "this is my unreasonably long pap\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "pap is too long (132/100)")
	socCase.Pap = "myPap"

	for x := 1; x < 5; x++ {
		socCase.Category += "this is my unreasonably long category\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "category is too long (152/100)")
	socCase.Category = "myCategory"

	for x := 1; x < 5; x++ {
		socCase.Template += "this is my unreasonably long template\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "template is too long (152/100)")
	socCase.Template = "myTemplate"

	for x := 1; x < 5; x++ {
		socCase.Status += "this is my unreasonably long status\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "status is too long (144/100)")
	socCase.Status = "myStatus"

	socCase.Kind = "myKind"
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "Field 'Kind' must not be specified")
	socCase.Kind = ""

	socCase.Operation = "myOperation"
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "Field 'Operation' must not be specified")
	socCase.Operation = ""

	tag := ""
	for x := 1; x < 5; x++ {
		tag += "this is my unreasonably long tag\n"
	}
	socCase.Tags = append(socCase.Tags, tag)
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "tag[0] is too long (132/100)")
	socCase.Tags = nil

	for x := 1; x < 500; x++ {
		socCase.Tags = append(socCase.Tags, "myTag")
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "Field 'Tags' contains excessive elements (499/50)")
	socCase.Tags = nil
}

func TestValidateCaseValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)

	var err error
	socCase := model.NewCase() // empty cases are valid cases
	err = store.validateCase(socCase)
	assert.NoError(tester, err)

	socCase.Id = "123456"
	socCase.Title = "this is my reasonable long title - nothing excessive, just a normal title"
	for x := 1; x < 500; x++ {
		socCase.Description += "this is my reasonably long description\n"
	}
	socCase.Priority = 123
	socCase.Severity = 1
	socCase.Tags = append(socCase.Tags, "tag1")
	socCase.Tags = append(socCase.Tags, "tag2")
	socCase.Tlp = "amber"
	socCase.Pap = "check"
	socCase.Category = "confirmed"
	socCase.Status = "in progress"
	socCase.Template = "tbd"
	socCase.UserId = "myUserId"
	socCase.AssigneeId = "myAssigneeId"
	err = store.validateCase(socCase)
	assert.NoError(tester, err)
}

func TestValidateCommentInvalid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)

	var err error
	comment := model.NewComment()

	comment.Id = "this is an invalid id"
	err = store.validateComment(comment)
	assert.EqualError(tester, err, "invalid ID for commentId")
	comment.Id = ""

	comment.CaseId = "this is an invalid id"
	err = store.validateComment(comment)
	assert.EqualError(tester, err, "invalid ID for caseId")
	comment.CaseId = ""

	comment.UserId = "this is an invalid id"
	err = store.validateComment(comment)
	assert.EqualError(tester, err, "invalid ID for userId")
	comment.UserId = ""

	for x := 1; x < 30000; x++ {
		comment.Description += "this is my unreasonably long description\n"
	}
	err = store.validateComment(comment)
	assert.EqualError(tester, err, "description is too long (1229959/1000000)")
	comment.Description = "myDescription"
}

func TestValidateCommentValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45)

	var err error
	comment := model.NewComment() // empty comments are valid comments
	err = store.validateComment(comment)
	assert.NoError(tester, err)

	comment.Id = "123456"
	comment.UserId = "myUserId"
	for x := 1; x < 500; x++ {
		comment.Description += "this is my reasonably long description\n"
	}
	err = store.validateComment(comment)
	assert.NoError(tester, err)
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
	assert.Equal(tester, "invalid ID for caseId", err.Error())
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
	comment.Id = "123444"
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
