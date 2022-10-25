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
	"time"
)

func TestInit(tester *testing.T) {
	store := NewElasticCasestore(nil)
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
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
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

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
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

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
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	err = store.validateString("1234567", 6, "test")
	assert.Error(tester, err)

	err = store.validateString("12345678", 6, "test")
	assert.Error(tester, err)
}

func TestValidateStringValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

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
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

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

	for x := 1; x < 5; x++ {
		socCase.Status += "this is my unreasonably long status\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "status is too long (144/100)")
	socCase.Status = "myStatus"

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

	for x := 1; x < 5; x++ {
		socCase.Severity += "this is my unreasonably long severity\n"
	}
	err = store.validateCase(socCase)
	assert.EqualError(tester, err, "severity is too long (156/100)")
	socCase.Severity = "medium"

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
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	socCase := model.NewCase()
	socCase.Title = "myTitle"
	socCase.Description = "myDescription"
	socCase.Status = "new"
	err = store.validateCase(socCase)
	assert.NoError(tester, err)

	socCase.Id = "123456"
	socCase.Title = "this is my reasonable long title - nothing excessive, just a normal title"
	for x := 1; x < 500; x++ {
		socCase.Description += "this is my reasonably long description\n"
	}
	socCase.Priority = 123
	socCase.Severity = "2"
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
	assert.Equal(tester, "medium", socCase.Severity)
}

func TestValidateRelatedEventInvalid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	event := model.NewRelatedEvent()

	event.Id = "this is an invalid id"
	err = store.validateRelatedEvent(event)
	assert.EqualError(tester, err, "invalid ID for relatedEventId")
	event.Id = "myEventId"

	event.CaseId = "this is an invalid id"
	err = store.validateRelatedEvent(event)
	assert.EqualError(tester, err, "invalid ID for caseId")
	event.CaseId = "myCaseId"

	event.UserId = "this is an invalid id"
	err = store.validateRelatedEvent(event)
	assert.EqualError(tester, err, "invalid ID for userId")
	event.UserId = "myUserId"

	event.Kind = "myKind"
	err = store.validateRelatedEvent(event)
	assert.EqualError(tester, err, "Field 'Kind' must not be specified")
	event.Kind = ""

	event.Operation = "myOperation"
	err = store.validateRelatedEvent(event)
	assert.EqualError(tester, err, "Field 'Operation' must not be specified")
	event.Operation = ""

	err = store.validateRelatedEvent(event)
	assert.EqualError(tester, err, "Related event fields cannot not be empty")
}

func TestValidateRelatedEventValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	event := model.NewRelatedEvent()
	event.Fields["foo"] = "bar"
	err = store.validateRelatedEvent(event)
	assert.NoError(tester, err)
}

func TestValidateCommentInvalid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

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

	comment.Kind = "myKind"
	err = store.validateComment(comment)
	assert.EqualError(tester, err, "Field 'Kind' must not be specified")
	comment.Kind = ""

	comment.Operation = "myOperation"
	err = store.validateComment(comment)
	assert.EqualError(tester, err, "Field 'Operation' must not be specified")
	comment.Operation = ""

	for x := 1; x < 30000; x++ {
		comment.Description += "this is my unreasonably long description\n"
	}
	err = store.validateComment(comment)
	assert.EqualError(tester, err, "description is too long (1229959/1000000)")
	comment.Description = "myDescription"
}

func TestValidateCommentValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	comment := model.NewComment()
	comment.Description = "myDesc"
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

func TestValidateArtifactInvalid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	artifact := model.NewArtifact()

	for x := 1; x < 30000; x++ {
		artifact.Value += "this is my unreasonably long value\n"
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "value is too long (1049965/1000000)")
	artifact.Value = "myValue"

	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "invalid ID for groupType")
	artifact.GroupType = "myGroupType"

	artifact.Id = "this is an invalid id"
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "invalid ID for artifactId")
	artifact.Id = "myArtifactId"

	artifact.UserId = "this is an invalid id"
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "invalid ID for userId")
	artifact.UserId = "myUserId"

	artifact.GroupId = "this is an invalid id"
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "invalid ID for groupId")
	artifact.GroupId = "myGroupId"

	artifact.CaseId = "this is an invalid id"
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "invalid ID for caseId")
	artifact.CaseId = "myCaseId"

	for x := 1; x < 5; x++ {
		artifact.ArtifactType += "this is my unreasonably long artifactType\n"
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "artifactType is too long (168/100)")
	artifact.ArtifactType = "myArtifactType"

	for x := 1; x < 30000; x++ {
		artifact.Description += "this is my unreasonably long description\n"
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "description is too long (1229959/1000000)")
	artifact.Description = "myDescription"

	artifact.StreamLen = 123
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "Invalid streamLength")
	artifact.StreamLen = 0

	for x := 1; x < 5; x++ {
		artifact.MimeType += "this is my unreasonably long str\n"
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "mimeType is too long (132/100)")
	artifact.MimeType = "image/jpg"

	for x := 1; x < 5; x++ {
		artifact.Md5 += "this is my unreasonably long str\n"
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "md5 is too long (132/100)")
	artifact.Md5 = "myMd5"

	for x := 1; x < 5; x++ {
		artifact.Sha1 += "this is my unreasonably long str\n"
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "sha1 is too long (132/100)")
	artifact.Sha1 = "mySha1"

	for x := 1; x < 5; x++ {
		artifact.Sha256 += "this is my unreasonably long str\n"
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "sha256 is too long (132/100)")
	artifact.Sha256 = "mySha256"

	for x := 1; x < 5; x++ {
		artifact.Tlp += "this is my unreasonably long tlp\n"
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "tlp is too long (132/100)")
	artifact.Tlp = "myTlp"

	artifact.Kind = "myKind"
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "Field 'Kind' must not be specified")
	artifact.Kind = ""

	artifact.Operation = "myOperation"
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "Field 'Operation' must not be specified")
	artifact.Operation = ""

	tag := ""
	for x := 1; x < 5; x++ {
		tag += "this is my unreasonably long tag\n"
	}
	artifact.Tags = append(artifact.Tags, tag)
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "tag[0] is too long (132/100)")
	artifact.Tags = nil

	for x := 1; x < 500; x++ {
		artifact.Tags = append(artifact.Tags, "myTag")
	}
	err = store.validateArtifact(artifact)
	assert.EqualError(tester, err, "Field 'Tags' contains excessive elements (499/50)")
	artifact.Tags = nil
}

func TestValidateArtifactValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	artifact := model.NewArtifact()
	artifact.Id = "123456"
	artifact.UserId = "myUserId"
	artifact.GroupType = "myGroupType"
	artifact.ArtifactType = "myArtifactType"
	for x := 1; x < 500; x++ {
		artifact.Value += "this is my reasonably long description\n"
	}
	err = store.validateArtifact(artifact)
	assert.NoError(tester, err)
}

func TestValidateArtifactStreamInvalid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	artifactstream := model.NewArtifactStream()

	artifactstream.Id = "this is an invalid id"
	err = store.validateArtifactStream(artifactstream)
	assert.EqualError(tester, err, "invalid ID for artifactStreamId")
	artifactstream.Id = ""

	artifactstream.UserId = "this is an invalid id"
	err = store.validateArtifactStream(artifactstream)
	assert.EqualError(tester, err, "invalid ID for userId")
	artifactstream.UserId = ""

	err = store.validateArtifactStream(artifactstream)
	assert.EqualError(tester, err, "Missing stream content")
}

func TestValidateArtifactStreamValid(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)

	var err error
	artifactstream := model.NewArtifactStream()
	artifactstream.Id = "123456"
	artifactstream.UserId = "myUserId"
	for x := 1; x < 500; x++ {
		artifactstream.Content += "this is my reasonably long description\n"
	}
	err = store.validateArtifactStream(artifactstream)
	assert.NoError(tester, err)
}

func TestSaveCreate(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
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
	assert.Equal(tester, "case", fakeEventStore.InputDocuments[0]["so_kind"])
	assert.Equal(tester, "create", fakeEventStore.InputDocuments[1]["so_operation"])
	assert.NotNil(tester, results)
}

func TestSaveUpdate(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
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
	assert.Equal(tester, "case", fakeEventStore.InputDocuments[0]["so_kind"])
	assert.Equal(tester, "update", fakeEventStore.InputDocuments[1]["so_operation"])
	assert.NotNil(tester, results)
}

func TestDelete(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
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
	assert.Equal(tester, "case", fakeEventStore.InputDocuments[0]["so_kind"])
	assert.Equal(tester, "delete", fakeEventStore.InputDocuments[0]["so_operation"])
}

func TestGetAll(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := "some query"
	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}

	commentPayload := make(map[string]interface{})
	commentPayload["so_kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
	}

	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, commentEvent)
	results, err := store.getAll(ctx, query, 123)
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Len(tester, results, 2)
}

func TestGet(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"case" AND _id:"myCaseId"`
	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)
	obj, err := store.get(ctx, "myCaseId", "case")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetNotFound(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	_, err := store.get(ctx, "myCaseId", "case")
	assert.EqualError(tester, err, "Object not found")
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
	myCase.Title = "myTitle"
	myCase.Description = "myDesc"
	myCase.Status = "myStatus"
	newCase, err := store.Update(ctx, myCase)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing case ID", err.Error())
	assert.NotNil(tester, newCase)
}

func TestGetCase(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"case" AND _id:"myCaseId"`
	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)
	obj, err := store.GetCase(ctx, "myCaseId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetCaseHistory(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myAuditIndex" AND (so_audit_doc_id:"myCaseId" OR so_comment.caseId:"myCaseId" OR so_related.caseId:"myCaseId" OR so_artifact.caseId:"myCaseId") | sortby @timestamp^`
	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)
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
	comment.Description = "myDesc"
	_, err := store.CreateComment(ctx, comment)
	assert.Error(tester, err)
	assert.Equal(tester, "Unexpected ID found in new comment", err.Error())
}

func TestCreateCommentMissingCaseId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	comment := model.NewComment()
	comment.Description = "myDesc"
	_, err := store.CreateComment(ctx, comment)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing Case ID in new comment", err.Error())
}

func TestCreateComment(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
		Id:      "123444",
	}
	commentPayload := make(map[string]interface{})
	commentPayload["so_kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)
	fakeEventStore.IndexResults[0].Success = true
	fakeEventStore.IndexResults[0].DocumentId = "myCaseId"
	commentSearchResults := model.NewEventSearchResults()
	commentSearchResults.Events = append(commentSearchResults.Events, commentEvent)
	fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, commentSearchResults)
	comment := model.NewComment()
	comment.CaseId = "123444"
	comment.Description = "Foo Bar"
	newComment, err := store.CreateComment(ctx, comment)
	assert.NoError(tester, err)
	assert.NotNil(tester, newComment)
}

func TestGetComment(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"comment" AND _id:"myCommentId"`
	commentPayload := make(map[string]interface{})
	commentPayload["so_kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, commentEvent)
	obj, err := store.GetComment(ctx, "myCommentId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetComments(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"comment" AND so_comment.caseId:"myCaseId" | sortby so_comment.createTime^`
	commentPayload := make(map[string]interface{})
	commentPayload["so_kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, commentEvent)
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
	comment.Description = "myDesc"
	_, err := store.UpdateComment(ctx, comment)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing comment ID", err.Error())
}

func TestDeleteComment(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"comment" AND _id:"myCommentId"`
	commentPayload := make(map[string]interface{})
	commentPayload["so_kind"] = "comment"
	commentEvent := &model.EventRecord{
		Payload: commentPayload,
		Id:      "myCommentId",
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, commentEvent)
	err := store.DeleteComment(ctx, "myCommentId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1) // Search to ensure it exists first
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Len(tester, fakeEventStore.InputIds, 2) // Delete and Index (for audit)
	assert.Equal(tester, "myCommentId", fakeEventStore.InputIds[0])
	assert.Equal(tester, "", fakeEventStore.InputIds[1])
}

func TestCreateRelatedEventUnexpectedId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	event := model.NewRelatedEvent()
	event.Id = "123444"
	event.Fields["foo"] = "bar"
	_, err := store.CreateRelatedEvent(ctx, event)
	assert.Error(tester, err)
	assert.Equal(tester, "Unexpected ID found in new related event", err.Error())
}

func TestCreateRelatedEventMissingCaseId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	event := model.NewRelatedEvent()
	event.Fields["foo"] = "bar"
	_, err := store.CreateRelatedEvent(ctx, event)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing Case ID in new related event", err.Error())
}

func TestCreateRelatedEventMissingFields(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	event := model.NewRelatedEvent()
	_, err := store.CreateRelatedEvent(ctx, event)
	assert.Error(tester, err)
	assert.Equal(tester, "Related event fields cannot not be empty", err.Error())
}

func TestCreateRelatedEvent(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
		Id:      "123444",
	}
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "related"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)
	fakeEventStore.IndexResults[0].Success = true
	fakeEventStore.IndexResults[0].DocumentId = "myCaseId"
	eventSearchResults := model.NewEventSearchResults()
	eventSearchResults.Events = append(eventSearchResults.Events, elasticEvent)
	fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, eventSearchResults)
	event := model.NewRelatedEvent()
	event.CaseId = "123444"
	event.Fields["foo"] = "bar"
	newEvent, err := store.CreateRelatedEvent(ctx, event)
	assert.NoError(tester, err)
	assert.NotNil(tester, newEvent)
}

func TestCreateRelatedEventAlreadyExists(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	// Mock the search for case cll
	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
		Id:      "123444",
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)

	// Mock the search for existing related events call
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "related"
	eventPayload["so_related.fields.soc_id"] = "myEventId"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	getRelatedEventsResults := model.NewEventSearchResults()
	getRelatedEventsResults.Events = append(getRelatedEventsResults.Events, elasticEvent)
	fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, getRelatedEventsResults)

	event := model.NewRelatedEvent()
	event.CaseId = "123444"
	event.Fields["soc_id"] = "myEventId"
	_, err := store.CreateRelatedEvent(ctx, event)
	assert.EqualError(tester, err, "ERROR_CASE_EVENT_ALREADY_ATTACHED")
}

func TestGetRelatedEvent(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"related" AND _id:"myEventId"`
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "related"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	obj, err := store.GetRelatedEvent(ctx, "myEventId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetRelatedEvents(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	// JBE: 10/20/2022 - Remove sortby and perform it manually due to ES issue with flattened fields
	//query := `_index:"myIndex" AND so_kind:"related" AND so_related.caseId:"myCaseId" | sortby so_related.fields.timestamp^`
	query := `_index:"myIndex" AND so_kind:"related" AND so_related.caseId:"myCaseId"`
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "related"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)

	// Add a related event with a timestamp field
	timeA, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	eventPayloadWithTimestamp := make(map[string]interface{})
	eventPayloadWithTimestamp["so_kind"] = "related"
	eventPayloadWithTimestamp["so_related.fields.timestamp"] = timeA
	elasticEventWithTimestamp := &model.EventRecord{
		Payload: eventPayloadWithTimestamp,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEventWithTimestamp)

	// Add another related event with an earlier timestamp field
	timeB, _ := time.Parse(time.RFC3339, "2006-01-01T15:04:05Z")
	eventPayloadWithTimestamp2 := make(map[string]interface{})
	eventPayloadWithTimestamp2["so_kind"] = "related"
	eventPayloadWithTimestamp2["so_related.fields.timestamp"] = timeB
	elasticEventWithTimestamp2 := &model.EventRecord{
		Payload: eventPayloadWithTimestamp2,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEventWithTimestamp2)

	obj, err := store.GetRelatedEvents(ctx, "myCaseId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)

	// Ensure manual sorting functions as expected (only has effect if the sortby claused is removed)
	assert.Len(tester, obj, 3)
	assert.Nil(tester, obj[0].Fields["timestamp"])
	assert.Equal(tester, timeB, obj[1].Fields["timestamp"])
	assert.Equal(tester, timeA, obj[2].Fields["timestamp"])
}

func TestDeleteRelatedEvent(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"related" AND _id:"myEventId"`
	elasticPayload := make(map[string]interface{})
	elasticPayload["so_kind"] = "related"
	elasticEvent := &model.EventRecord{
		Payload: elasticPayload,
		Id:      "myEventId",
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	err := store.DeleteRelatedEvent(ctx, "myEventId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1) // Search to ensure it exists first
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Len(tester, fakeEventStore.InputIds, 2) // Delete and Index (for audit)
	assert.Equal(tester, "myEventId", fakeEventStore.InputIds[0])
	assert.Equal(tester, "", fakeEventStore.InputIds[1])
}

func TestCreateArtifactUnexpectedId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	artifact := model.NewArtifact()
	artifact.Id = "123444"
	artifact.GroupType = "myGroupType"
	artifact.ArtifactType = "myArtifactType"
	artifact.Value = "Value"
	_, err := store.CreateArtifact(ctx, artifact)
	assert.Error(tester, err)
	assert.Equal(tester, "Unexpected ID found in new artifact", err.Error())
}

func TestCreateArtifactMissingCaseId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	artifact := model.NewArtifact()
	artifact.GroupType = "myGroupType"
	artifact.ArtifactType = "myArtifactType"
	artifact.Value = "Value"
	_, err := store.CreateArtifact(ctx, artifact)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing Case ID in new artifact", err.Error())
}

func TestCreateArtifactMissingGroupType(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	artifact := model.NewArtifact()
	artifact.Value = "myValue"
	_, err := store.CreateArtifact(ctx, artifact)
	assert.Error(tester, err)
	assert.Equal(tester, "invalid ID for groupType", err.Error())
}

func TestCreateArtifactMissingArtifactType(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	artifact := model.NewArtifact()
	artifact.GroupType = "myGroupType"
	artifact.CaseId = "12345"
	artifact.Value = "myValue"
	_, err := store.CreateArtifact(ctx, artifact)
	assert.Error(tester, err)
	assert.Equal(tester, "artifactType is too short (0/1)", err.Error())
}

func TestCreateArtifactMissingValue(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	artifact := model.NewArtifact()
	artifact.GroupType = "myGroupType"
	artifact.ArtifactType = "myArtifactType"
	artifact.CaseId = "12345"
	_, err := store.CreateArtifact(ctx, artifact)
	assert.Error(tester, err)
	assert.Equal(tester, "value is too short (0/1)", err.Error())
}

func TestCreateArtifact(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "case"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
		Id:      "123444",
	}
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "artifact"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)
	fakeEventStore.IndexResults[0].Success = true
	fakeEventStore.IndexResults[0].DocumentId = "myCaseId"
	eventSearchResults := model.NewEventSearchResults()
	eventSearchResults.Events = append(eventSearchResults.Events, elasticEvent)
	fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, eventSearchResults)
	artifact := model.NewArtifact()
	artifact.CaseId = "123444"
	artifact.GroupType = "myGroupType"
	artifact.ArtifactType = "myArtifactType"
	artifact.Value = "Value"
	newEvent, err := store.CreateArtifact(ctx, artifact)
	assert.NoError(tester, err)
	assert.NotNil(tester, newEvent)
}

func TestGetArtifact(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"artifact" AND _id:"myArtifactId"`
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "artifact"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	obj, err := store.GetArtifact(ctx, "myArtifactId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetArtifactsBadGroupType(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	_, err := store.GetArtifacts(ctx, "myCaseId", "myGroupType is invalid", "myGroupId")
	assert.EqualError(tester, err, "invalid ID for groupType")
}

func TestGetArtifactsBadGroupId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	_, err := store.GetArtifacts(ctx, "myCaseId", "myGroupType", "myGroupId is invalid")
	assert.EqualError(tester, err, "invalid ID for groupId")
}

func TestGetArtifactsNoGroupId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"artifact" AND so_artifact.caseId:"myCaseId" AND so_artifact.groupType:"myGroupType" | sortby so_artifact.createTime^`
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "artifact"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	obj, err := store.GetArtifacts(ctx, "myCaseId", "myGroupType", "")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetArtifacts(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"artifact" AND so_artifact.caseId:"myCaseId" AND so_artifact.groupType:"myGroupType" AND so_artifact.groupId:"myGroupId" | sortby so_artifact.createTime^`
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "artifact"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	obj, err := store.GetArtifacts(ctx, "myCaseId", "myGroupType", "myGroupId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestDeleteArtifact(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"artifact" AND _id:"myArtifactId"`
	elasticPayload := make(map[string]interface{})
	elasticPayload["so_kind"] = "artifact"
	elasticEvent := &model.EventRecord{
		Payload: elasticPayload,
		Id:      "myArtifactId",
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	err := store.DeleteArtifact(ctx, "myArtifactId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1) // Search to ensure it exists first
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Len(tester, fakeEventStore.InputIds, 2) // Delete and Index (for audit)
	assert.Equal(tester, "myArtifactId", fakeEventStore.InputIds[0])
	assert.Equal(tester, "", fakeEventStore.InputIds[1])
}

func TestCreateArtifactStreamUnexpectedId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	artifactstream := model.NewArtifactStream()
	artifactstream.Id = "123444"
	artifactstream.Content = "Value"
	_, err := store.CreateArtifactStream(ctx, artifactstream)
	assert.Error(tester, err)
	assert.Equal(tester, "Unexpected ID found in new artifactstream", err.Error())
}

func TestCreateArtifactStreamMissingValue(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	artifactstream := model.NewArtifactStream()
	artifactstream.Id = "123444"
	_, err := store.CreateArtifactStream(ctx, artifactstream)
	assert.Error(tester, err)
	assert.Equal(tester, "Missing stream content", err.Error())
}

func TestCreateArtifactStream(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	casePayload := make(map[string]interface{})
	casePayload["so_kind"] = "artifactstream"
	caseEvent := &model.EventRecord{
		Payload: casePayload,
		Id:      "123444",
	}
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "artifactstream"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, caseEvent)
	fakeEventStore.IndexResults[0].Success = true
	fakeEventStore.IndexResults[0].DocumentId = "myArtifactStreamId"
	eventSearchResults := model.NewEventSearchResults()
	eventSearchResults.Events = append(eventSearchResults.Events, elasticEvent)
	fakeEventStore.SearchResults = append(fakeEventStore.SearchResults, eventSearchResults)
	artifact := model.NewArtifactStream()
	artifact.Content = "Content"
	newEvent, err := store.CreateArtifactStream(ctx, artifact)
	assert.NoError(tester, err)
	assert.NotNil(tester, newEvent)
}

func TestGetArtifactStream(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"artifactstream" AND _id:"myArtifactStreamId"`
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "artifactstream"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	obj, err := store.GetArtifactStream(ctx, "myArtifactStreamId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.NotNil(tester, obj)
}

func TestGetArtifactStreamBadId(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	_, err := store.GetArtifactStream(ctx, "stream id is invalid")
	assert.EqualError(tester, err, "invalid ID for artifactStreamId")
}

func TestDeleteArtifactStream(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")
	query := `_index:"myIndex" AND so_kind:"artifactstream" AND _id:"myArtifactStreamId"`
	elasticPayload := make(map[string]interface{})
	elasticPayload["so_kind"] = "artifactstream"
	elasticEvent := &model.EventRecord{
		Payload: elasticPayload,
		Id:      "myArtifactStreamId",
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	err := store.DeleteArtifactStream(ctx, "myArtifactStreamId")
	assert.NoError(tester, err)
	assert.Len(tester, fakeEventStore.InputSearchCriterias, 1) // Search to ensure it exists first
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Len(tester, fakeEventStore.InputIds, 2) // Delete and Index (for audit)
	assert.Equal(tester, "myArtifactStreamId", fakeEventStore.InputIds[0])
	assert.Equal(tester, "", fakeEventStore.InputIds[1])
}

func TestUpdateArtifact(tester *testing.T) {
	store := NewElasticCasestore(server.NewFakeAuthorizedServer(nil))
	store.Init("myIndex", "myAuditIndex", 45, DEFAULT_CASE_SCHEMA_PREFIX)
	ctx := context.WithValue(context.Background(), web.ContextKeyRequestorId, "myRequestorId")

	fakeEventStore := server.NewFakeEventstore()
	store.server.Eventstore = fakeEventStore
	query := `_index:"myIndex" AND so_kind:"artifact" AND _id:"myArtifactId"`
	eventPayload := make(map[string]interface{})
	eventPayload["so_kind"] = "artifact"
	eventPayload["so_artifact.artifactType"] = "myArtifactType"
	eventPayload["so_artifact.groupType"] = "myGroupType"
	eventPayload["so_artifact.groupId"] = "myGroupId"
	eventPayload["so_artifact.value"] = "myValue"
	eventPayload["so_artifact.streamLength"] = 123.0
	eventPayload["so_artifact.mimeType"] = "myMimeType"
	eventPayload["so_artifact.md5"] = "myMd5"
	eventPayload["so_artifact.sha1"] = "mySha1"
	eventPayload["so_artifact.sha256"] = "mySha256"
	eventPayload["so_artifact.streamId"] = "myStreamId"
	eventPayload["so_artifact.description"] = "myDesc"
	elasticEvent := &model.EventRecord{
		Payload: eventPayload,
	}
	fakeEventStore.SearchResults[0].Events = append(fakeEventStore.SearchResults[0].Events, elasticEvent)
	fakeEventStore.IndexResults[0].DocumentId = "myArtifactId"

	artifact := model.NewArtifact()
	artifact.Value = "myNewValue"
	artifact.GroupType = "myNewGroupType"
	artifact.GroupId = "myNewGroupId"
	artifact.ArtifactType = "file"
	artifact.GroupId = "myNewGroupId"
	artifact.MimeType = "myNewMimeType"
	artifact.Md5 = "myNewMd5"
	artifact.Sha1 = "myNewSha1"
	artifact.Sha256 = "myNewSha256"
	artifact.StreamId = "myNewStreamId"
	artifact.StreamLen = 456
	artifact.Description = "myNewDesc"

	_, err := store.UpdateArtifact(ctx, artifact)
	assert.Equal(tester, "Missing artifact ID", err.Error())

	artifact.Id = "myArtifactId"
	_, err = store.UpdateArtifact(ctx, artifact)
	assert.NoError(tester, err)
	assert.Equal(tester, query, fakeEventStore.InputSearchCriterias[0].RawQuery)
	assert.Equal(tester, "update", fakeEventStore.InputDocuments[0]["so_operation"])

	newArtifact := fakeEventStore.InputDocuments[0]["so_artifact"].(*model.Artifact)
	assert.Equal(tester, "myNewDesc", newArtifact.Description)

	// Should have preserved read-only props
	assert.Equal(tester, "myArtifactType", newArtifact.ArtifactType)
	assert.Equal(tester, "myGroupType", newArtifact.GroupType)
	assert.Equal(tester, "myGroupId", newArtifact.GroupId)
	assert.Equal(tester, "myStreamId", newArtifact.StreamId)
	assert.Equal(tester, "myMimeType", newArtifact.MimeType)
	assert.Equal(tester, "myMd5", newArtifact.Md5)
	assert.Equal(tester, "mySha1", newArtifact.Sha1)
	assert.Equal(tester, "mySha256", newArtifact.Sha256)
	assert.Equal(tester, "myValue", newArtifact.Value)
	assert.Equal(tester, 123, newArtifact.StreamLen)
}
