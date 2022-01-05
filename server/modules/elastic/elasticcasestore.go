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
  "errors"
  "fmt"
  "github.com/apex/log"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "github.com/security-onion-solutions/securityonion-soc/server"
  "github.com/security-onion-solutions/securityonion-soc/web"
  "regexp"
  "strconv"
  "time"
)

const AUDIT_DOC_ID = "so_audit_doc_id"
const SHORT_STRING_MAX = 100
const LONG_STRING_MAX = 1000000
const MAX_ARRAY_ELEMENTS = 50

type ElasticCasestore struct {
  server          *server.Server
  index           string
  auditIndex      string
  maxAssociations int
}

func NewElasticCasestore(srv *server.Server) *ElasticCasestore {
  return &ElasticCasestore{
    server: srv,
  }
}

func (store *ElasticCasestore) Init(index string, auditIndex string, maxAssociations int) error {
  store.index = index
  store.auditIndex = auditIndex
  store.maxAssociations = maxAssociations
  return nil
}

func (store *ElasticCasestore) validateId(id string, label string) error {
  var err error

  isValidId := regexp.MustCompile(`^[A-Za-z0-9-_]{5,50}$`).MatchString
  if !isValidId(id) {
    err = errors.New(fmt.Sprintf("invalid ID for %s", label))
  }
  return err
}

func (store *ElasticCasestore) validateString(str string, max int, label string) error {
  return store.validateStringRequired(str, 0, max, label)
}

func (store *ElasticCasestore) validateStringRequired(str string, min int, max int, label string) error {
  var err error
  length := len(str)
  if length > max {
    err = errors.New(fmt.Sprintf("%s is too long (%d/%d)", label, length, max))
  } else if length < min {
    err = errors.New(fmt.Sprintf("%s is too short (%d/%d)", label, length, min))
  }
  return err
}

func (store *ElasticCasestore) validateStringArray(array []string, maxLen int, maxElements int, label string) error {
  var err error
  length := len(array)
  if length > maxElements {
    err = errors.New(fmt.Sprintf("Field 'Tags' contains excessive elements (%d/%d)", length, maxElements))
  } else {
    for idx, tag := range array {
      err = store.validateString(tag, maxLen, fmt.Sprintf("tag[%d]", idx))
      if err != nil {
        break
      }
    }
  }
  return err
}

func (store *ElasticCasestore) validateCase(socCase *model.Case) error {
  var err error

  if err == nil && socCase.Id != "" {
    err = store.validateId(socCase.Id, "caseId")
  }
  if err == nil && socCase.UserId != "" {
    err = store.validateId(socCase.UserId, "userId")
  }
  if err == nil && socCase.AssigneeId != "" {
    err = store.validateId(socCase.AssigneeId, "assigneeId")
  }
  if err == nil && socCase.Priority < 0 {
    err = errors.New("Invalid priority")
  }
  if err == nil {
    socCase.Severity = convertSeverity(socCase.Severity)
    err = store.validateString(socCase.Severity, SHORT_STRING_MAX, "severity")
  }
  if err == nil && len(socCase.Kind) > 0 {
    err = errors.New("Field 'Kind' must not be specified")
  }
  if err == nil && len(socCase.Operation) > 0 {
    err = errors.New("Field 'Operation' must not be specified")
  }
  if err == nil {
    err = store.validateStringRequired(socCase.Title, 1, SHORT_STRING_MAX, "title")
  }
  if err == nil {
    err = store.validateString(socCase.Category, SHORT_STRING_MAX, "category")
  }
  if err == nil {
    err = store.validateStringRequired(socCase.Status, 1, SHORT_STRING_MAX, "status")
  }
  if err == nil {
    err = store.validateString(socCase.Template, SHORT_STRING_MAX, "template")
  }
  if err == nil {
    err = store.validateString(socCase.Tlp, SHORT_STRING_MAX, "tlp")
  }
  if err == nil {
    err = store.validateString(socCase.Pap, SHORT_STRING_MAX, "pap")
  }
  if err == nil {
    err = store.validateStringRequired(socCase.Description, 1, LONG_STRING_MAX, "description")
  }
  if err == nil {
    err = store.validateStringArray(socCase.Tags, SHORT_STRING_MAX, MAX_ARRAY_ELEMENTS, "tags")
  }
  return err
}

func (store *ElasticCasestore) validateRelatedEvent(event *model.RelatedEvent) error {
  var err error

  if err == nil && event.Id != "" {
    err = store.validateId(event.Id, "relatedEventId")
  }
  if err == nil && event.CaseId != "" {
    err = store.validateId(event.CaseId, "caseId")
  }
  if err == nil && event.UserId != "" {
    err = store.validateId(event.UserId, "userId")
  }
  if err == nil && len(event.Kind) > 0 {
    err = errors.New("Field 'Kind' must not be specified")
  }
  if err == nil && len(event.Operation) > 0 {
    err = errors.New("Field 'Operation' must not be specified")
  }
  if err == nil && len(event.Fields) == 0 {
    err = errors.New("Related event fields cannot not be empty")
  }
  return err
}

func (store *ElasticCasestore) validateComment(comment *model.Comment) error {
  var err error

  if err == nil && comment.Id != "" {
    err = store.validateId(comment.Id, "commentId")
  }
  if err == nil && comment.CaseId != "" {
    err = store.validateId(comment.CaseId, "caseId")
  }
  if err == nil && comment.UserId != "" {
    err = store.validateId(comment.UserId, "userId")
  }
  if err == nil && len(comment.Kind) > 0 {
    err = errors.New("Field 'Kind' must not be specified")
  }
  if err == nil && len(comment.Operation) > 0 {
    err = errors.New("Field 'Operation' must not be specified")
  }
  if err == nil {
    err = store.validateStringRequired(comment.Description, 1, LONG_STRING_MAX, "description")
  }
  return err
}

func (store *ElasticCasestore) validateArtifact(artifact *model.Artifact) error {
  var err error

  if err == nil && artifact.Id != "" {
    err = store.validateId(artifact.Id, "artifactId")
  }
  if err == nil && artifact.UserId != "" {
    err = store.validateId(artifact.UserId, "userId")
  }
  if err == nil && artifact.CaseId != "" {
    err = store.validateId(artifact.CaseId, "caseId")
  }
  if err == nil && artifact.StreamLen != 0 && artifact.ArtifactType != "file" {
    err = errors.New("Invalid streamLength")
  }
  if err == nil && len(artifact.Kind) > 0 {
    err = errors.New("Field 'Kind' must not be specified")
  }
  if err == nil && len(artifact.Operation) > 0 {
    err = errors.New("Field 'Operation' must not be specified")
  }
  if err == nil {
    err = store.validateStringRequired(artifact.Value, 1, LONG_STRING_MAX, "value")
  }
  if err == nil {
    err = store.validateId(artifact.GroupType, "groupType")
  }
  if err == nil && len(artifact.GroupId) > 0 {
    err = store.validateId(artifact.GroupId, "groupId")
  }
  if err == nil {
    err = store.validateStringRequired(artifact.ArtifactType, 1, SHORT_STRING_MAX, "artifactType")
  }
  if err == nil {
    err = store.validateString(artifact.Tlp, SHORT_STRING_MAX, "tlp")
  }
  if err == nil {
    err = store.validateString(artifact.MimeType, SHORT_STRING_MAX, "mimeType")
  }
  if err == nil {
    err = store.validateString(artifact.Description, LONG_STRING_MAX, "description")
  }
  if err == nil {
    err = store.validateStringArray(artifact.Tags, SHORT_STRING_MAX, MAX_ARRAY_ELEMENTS, "tags")
  }
  if err == nil {
    err = store.validateString(artifact.Md5, SHORT_STRING_MAX, "md5")
  }
  if err == nil {
    err = store.validateString(artifact.Sha1, SHORT_STRING_MAX, "sha1")
  }
  if err == nil {
    err = store.validateString(artifact.Sha256, SHORT_STRING_MAX, "sha256")
  }
  return err
}

func (store *ElasticCasestore) validateArtifactStream(artifactstream *model.ArtifactStream) error {
  var err error

  if err == nil && artifactstream.Id != "" {
    err = store.validateId(artifactstream.Id, "artifactStreamId")
  }
  if err == nil && artifactstream.UserId != "" {
    err = store.validateId(artifactstream.UserId, "userId")
  }
  if err == nil && len(artifactstream.Content) == 0 {
    err = errors.New("Missing stream content")
  }
  if err == nil && len(artifactstream.Kind) > 0 {
    err = errors.New("Field 'Kind' must not be specified")
  }
  if err == nil && len(artifactstream.Operation) > 0 {
    err = errors.New("Field 'Operation' must not be specified")
  }
  return err
}

func (store *ElasticCasestore) prepareForSave(ctx context.Context, obj *model.Auditable) string {
  obj.UserId = ctx.Value(web.ContextKeyRequestorId).(string)

  // Don't waste space by saving the these values which are already part of ES documents
  id := obj.Id
  obj.Id = ""
  obj.UpdateTime = nil

  return id
}

func (store *ElasticCasestore) save(ctx context.Context, obj interface{}, kind string, id string) (*model.EventIndexResults, error) {
  var results *model.EventIndexResults
  var err error

  if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
    document := convertObjectToDocumentMap(kind, obj)
    document["kind"] = kind
    results, err = store.server.Eventstore.Index(ctx, store.index, document, id)
    if err == nil {
      document[AUDIT_DOC_ID] = results.DocumentId
      if id == "" {
        document["operation"] = "create"
      } else {
        document["operation"] = "update"
      }
      _, err = store.server.Eventstore.Index(ctx, store.auditIndex, document, "")
      if err != nil {
        log.WithFields(log.Fields{
          "documentId": results.DocumentId,
          "kind":       kind,
        }).WithError(err).Error("Object indexed successfully however audit record failed to index")
      }
    }
  }

  return results, err
}

func (store *ElasticCasestore) delete(ctx context.Context, obj interface{}, kind string, id string) error {
  var err error

  if err = store.server.CheckAuthorized(ctx, "write", "cases"); err == nil {
    err = store.server.Eventstore.Delete(ctx, store.index, id)
    if err == nil {
      document := convertObjectToDocumentMap(kind, obj)
      document[AUDIT_DOC_ID] = id
      document["kind"] = kind
      document["operation"] = "delete"
      _, err = store.server.Eventstore.Index(ctx, store.auditIndex, document, "")
      if err != nil {
        log.WithFields(log.Fields{
          "documentId": id,
          "kind":       kind,
        }).WithError(err).Error("Object deleted successfully however audit record failed to index")
      }
    }
  }

  return err
}

func (store *ElasticCasestore) get(ctx context.Context, id string, kind string) (interface{}, error) {
  query := fmt.Sprintf(`_index:"%s" AND kind:"%s" AND _id:"%s"`, store.index, kind, id)
  objects, err := store.getAll(ctx, query, 1)
  if err == nil {
    if len(objects) > 0 {
      return objects[0], err
    }
    err = errors.New("Object not found")
  }
  return nil, err
}

func (store *ElasticCasestore) getAll(ctx context.Context, query string, max int) ([]interface{}, error) {
  var err error
  var objects []interface{}

  if err = store.server.CheckAuthorized(ctx, "read", "cases"); err == nil {
    criteria := model.NewEventSearchCriteria()
    format := "2006-01-02 3:04:05 PM"
    var zeroTime time.Time
    zeroTimeStr := zeroTime.Format(format)
    now := time.Now()
    endTime := now.Format(format)
    zone := now.Location().String()
    err = criteria.Populate(query,
      zeroTimeStr+" - "+endTime, // timeframe range
      format,                    // timeframe format
      zone,                      // timezone
      "0",                       // no metrics
      strconv.Itoa(max))

    if err == nil {
      var results *model.EventSearchResults
      results, err = store.server.Eventstore.Search(ctx, criteria)
      if err == nil {
        for _, event := range results.Events {
          var obj interface{}
          obj, err = convertElasticEventToObject(event)
          if err == nil {
            objects = append(objects, obj)
          } else {
            log.WithField("event", event).WithError(err).Error("Unable to convert case object")
          }
        }
      }
    }
  }

  return objects, err
}

func (store *ElasticCasestore) Create(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  var err error

  socCase.Status = model.CASE_STATUS_NEW
  err = store.validateCase(socCase)
  if err == nil {
    if socCase.Id != "" {
      err = errors.New("Unexpected ID found in new case")
    } else {
      socCase = store.applyTemplate(ctx, socCase)
      now := time.Now()
      socCase.CreateTime = &now
      var results *model.EventIndexResults
      results, err = store.save(ctx, socCase, "case", store.prepareForSave(ctx, &socCase.Auditable))
      if err == nil {
        // Read object back to get new modify date, etc
        socCase, err = store.GetCase(ctx, results.DocumentId)
      }
    }
  }
  return socCase, err
}

func (store *ElasticCasestore) Update(ctx context.Context, socCase *model.Case) (*model.Case, error) {
  var err error

  err = store.validateCase(socCase)
  if err == nil {
    if socCase.Id == "" {
      err = errors.New("Missing case ID")
    } else {
      var oldCase *model.Case
      oldCase, err = store.GetCase(ctx, socCase.Id)
      if err == nil {
        // Preserve read-only fields
        socCase.CreateTime = oldCase.CreateTime
        socCase.CompleteTime = oldCase.CompleteTime
        socCase.StartTime = oldCase.StartTime
        var results *model.EventIndexResults
        results, err = store.save(ctx, socCase, "case", store.prepareForSave(ctx, &socCase.Auditable))
        if err == nil {
          // Read object back to get new modify date, etc
          socCase, err = store.GetCase(ctx, results.DocumentId)
        }
      }
    }
  }
  return socCase, err
}

func (store *ElasticCasestore) GetCase(ctx context.Context, id string) (*model.Case, error) {
  var err error
  var socCase *model.Case

  err = store.validateId(id, "caseId")
  if err == nil {
    var obj interface{}
    obj, err = store.get(ctx, id, "case")
    if err == nil {
      socCase = obj.(*model.Case)
    }
  }
  return socCase, err
}

func (store *ElasticCasestore) GetCaseHistory(ctx context.Context, caseId string) ([]interface{}, error) {
  var err error
  var history []interface{}

  err = store.validateId(caseId, "caseId")
  if err == nil {
    query := fmt.Sprintf(`_index:"%s" AND (%s:"%s" OR comment.caseId:"%s" OR related.caseId:"%s" OR artifact.caseId:"%s") | sortby @timestamp^`,
      store.auditIndex, AUDIT_DOC_ID, caseId, caseId, caseId, caseId)
    history, err = store.getAll(ctx, query, store.maxAssociations)
  }
  return history, err
}

func (store *ElasticCasestore) CreateRelatedEvent(ctx context.Context, event *model.RelatedEvent) (*model.RelatedEvent, error) {
  var err error

  err = store.validateRelatedEvent(event)
  if err == nil {
    if event.Id != "" {
      return nil, errors.New("Unexpected ID found in new related event")
    } else if event.CaseId == "" {
      return nil, errors.New("Missing Case ID in new related event")
    } else {
      _, err = store.GetCase(ctx, event.CaseId)
      if err == nil {
        var newId string
        if value, ok := event.Fields["soc_id"]; ok {
          newId = value.(string)
          var existingEvents []*model.RelatedEvent
          existingEvents, err = store.GetRelatedEvents(ctx, event.CaseId)
          for _, existingEvent := range existingEvents {
            if value, ok := existingEvent.Fields["soc_id"]; ok {
              existingId := value.(string)
              if existingId == newId {
                err = errors.New(fmt.Sprintf("Event ID '%s' has already been attached to this case", existingId))
                break
              }
            }
          }
        }
        if err == nil {
          var results *model.EventIndexResults
          results, err = store.save(ctx, event, "related", store.prepareForSave(ctx, &event.Auditable))
          if err == nil {
            // Read object back to get new modify date, etc
            event, err = store.GetRelatedEvent(ctx, results.DocumentId)
          }
        }
      }
    }
  }

  return event, err
}

func (store *ElasticCasestore) GetRelatedEvent(ctx context.Context, id string) (*model.RelatedEvent, error) {
  var err error
  var event *model.RelatedEvent

  err = store.validateId(id, "relatedEventId")
  if err == nil {
    var obj interface{}
    obj, err = store.get(ctx, id, "related")
    if err == nil {
      event = obj.(*model.RelatedEvent)
    }
  }
  return event, err
}

func (store *ElasticCasestore) GetRelatedEvents(ctx context.Context, caseId string) ([]*model.RelatedEvent, error) {
  var err error
  var events []*model.RelatedEvent

  err = store.validateId(caseId, "caseId")
  if err == nil {
    events = make([]*model.RelatedEvent, 0)
    query := fmt.Sprintf(`_index:"%s" AND kind:"related" AND related.caseId:"%s" | sortby related.fields.timestamp^`, store.index, caseId)
    var objects []interface{}
    objects, err = store.getAll(ctx, query, store.maxAssociations)
    if err == nil {
      for _, obj := range objects {
        events = append(events, obj.(*model.RelatedEvent))
      }
    }
  }
  return events, err
}

func (store *ElasticCasestore) DeleteRelatedEvent(ctx context.Context, id string) error {
  var err error

  var event *model.RelatedEvent
  err = store.validateId(id, "relatedEventId")
  if err == nil {
    event, err = store.GetRelatedEvent(ctx, id)
    if err == nil {
      err = store.delete(ctx, event, "related", store.prepareForSave(ctx, &event.Auditable))
    }
  }

  return err
}

func (store *ElasticCasestore) CreateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  var err error

  err = store.validateComment(comment)
  if err == nil {
    if comment.Id != "" {
      return nil, errors.New("Unexpected ID found in new comment")
    } else if comment.CaseId == "" {
      return nil, errors.New("Missing Case ID in new comment")
    } else {
      _, err = store.GetCase(ctx, comment.CaseId)
      if err == nil {
        now := time.Now()
        comment.CreateTime = &now
        var results *model.EventIndexResults
        results, err = store.save(ctx, comment, "comment", store.prepareForSave(ctx, &comment.Auditable))
        if err == nil {
          // Read object back to get new modify date, etc
          comment, err = store.GetComment(ctx, results.DocumentId)
        }
      }
    }
  }
  return comment, err
}

func (store *ElasticCasestore) GetComment(ctx context.Context, id string) (*model.Comment, error) {
  var err error
  var comment *model.Comment

  err = store.validateId(id, "commentId")
  if err == nil {
    var obj interface{}
    obj, err = store.get(ctx, id, "comment")
    if err == nil {
      comment = obj.(*model.Comment)
    }
  }
  return comment, err
}

func (store *ElasticCasestore) GetComments(ctx context.Context, caseId string) ([]*model.Comment, error) {
  var err error
  var comments []*model.Comment

  err = store.validateId(caseId, "caseId")
  if err == nil {
    comments = make([]*model.Comment, 0)
    query := fmt.Sprintf(`_index:"%s" AND kind:"comment" AND comment.caseId:"%s" | sortby comment.createTime^`, store.index, caseId)
    var objects []interface{}
    objects, err = store.getAll(ctx, query, store.maxAssociations)
    if err == nil {
      for _, obj := range objects {
        comments = append(comments, obj.(*model.Comment))
      }
    }
  }
  return comments, err
}

func (store *ElasticCasestore) UpdateComment(ctx context.Context, comment *model.Comment) (*model.Comment, error) {
  var err error

  err = store.validateComment(comment)
  if err == nil {
    if comment.Id == "" {
      err = errors.New("Missing comment ID")
    } else {
      var old *model.Comment
      old, err = store.GetComment(ctx, comment.Id)
      if err == nil {
        // Preserve read-only fields
        comment.CreateTime = old.CreateTime
        var results *model.EventIndexResults
        results, err = store.save(ctx, comment, "comment", store.prepareForSave(ctx, &comment.Auditable))
        if err == nil {
          // Read object back to get new modify date, etc
          comment, err = store.GetComment(ctx, results.DocumentId)
        }
      }
    }
  }
  return comment, err
}

func (store *ElasticCasestore) DeleteComment(ctx context.Context, id string) error {
  var err error

  var comment *model.Comment
  comment, err = store.GetComment(ctx, id)
  if err == nil {
    err = store.delete(ctx, comment, "comment", store.prepareForSave(ctx, &comment.Auditable))
  }

  return err
}

func (store *ElasticCasestore) CreateArtifact(ctx context.Context, artifact *model.Artifact) (*model.Artifact, error) {
  var err error

  err = store.validateArtifact(artifact)
  if err == nil {
    if artifact.Id != "" {
      return nil, errors.New("Unexpected ID found in new artifact")
    } else if artifact.CaseId == "" {
      return nil, errors.New("Missing Case ID in new artifact")
    } else if artifact.GroupType == "" {
      return nil, errors.New("Missing GroupType in new artifact")
    } else {
      _, err = store.GetCase(ctx, artifact.CaseId)
      if err == nil {
        now := time.Now()
        artifact.CreateTime = &now
        var results *model.EventIndexResults
        results, err = store.save(ctx, artifact, "artifact", store.prepareForSave(ctx, &artifact.Auditable))
        if err == nil {
          // Read object back to get new modify date, etc
          artifact, err = store.GetArtifact(ctx, results.DocumentId)
        }
      }
    }
  }
  return artifact, err
}

func (store *ElasticCasestore) GetArtifact(ctx context.Context, id string) (*model.Artifact, error) {
  var err error
  var artifact *model.Artifact

  err = store.validateId(id, "artifactId")
  if err == nil {
    var obj interface{}
    obj, err = store.get(ctx, id, "artifact")
    if err == nil {
      artifact = obj.(*model.Artifact)
    }
  }
  return artifact, err
}

func (store *ElasticCasestore) GetArtifacts(ctx context.Context, caseId string, groupType string, groupId string) ([]*model.Artifact, error) {
  var err error
  var artifacts []*model.Artifact

  err = store.validateId(caseId, "caseId")
  if err == nil {
    err = store.validateId(groupType, "groupType") // It's not technically an ID but the possible values confirm to an ID, so let's validate it as an ID.
    if err == nil {
      if len(groupId) > 0 {
        // groupId is optional, since some group won't have multiple groups per case.
        err = store.validateId(groupId, "groupId")
      }
      if err == nil {
        artifacts = make([]*model.Artifact, 0)
        var groupIdTerm string
        if len(groupId) > 0 {
          groupIdTerm = fmt.Sprintf(`AND artifact.groupId:"%s" `, groupId)
        }
        query := fmt.Sprintf(`_index:"%s" AND kind:"artifact" AND artifact.caseId:"%s" AND artifact.groupType:"%s" %s| sortby artifact.createTime^`, store.index, caseId, groupType, groupIdTerm)
        var objects []interface{}
        objects, err = store.getAll(ctx, query, store.maxAssociations)
        if err == nil {
          for _, obj := range objects {
            artifacts = append(artifacts, obj.(*model.Artifact))
          }
        }
      }
    }
  }
  return artifacts, err
}

func (store *ElasticCasestore) UpdateArtifact(ctx context.Context, artifact *model.Artifact) (*model.Artifact, error) {
  var err error

  err = store.validateArtifact(artifact)
  if err == nil {
    if artifact.Id == "" {
      err = errors.New("Missing artifact ID")
    } else {
      var old *model.Artifact
      old, err = store.GetArtifact(ctx, artifact.Id)
      if err == nil {
        // Preserve read-only fields
        artifact.CreateTime = old.CreateTime
        artifact.ArtifactType = old.ArtifactType
        artifact.Value = old.Value
        artifact.GroupType = old.GroupType
        artifact.GroupId = old.GroupId
        artifact.StreamLen = old.StreamLen
        artifact.MimeType = old.MimeType
        artifact.StreamId = old.StreamId
        artifact.Md5 = old.Md5
        artifact.Sha1 = old.Sha1
        artifact.Sha256 = old.Sha256
        var results *model.EventIndexResults
        results, err = store.save(ctx, artifact, "artifact", store.prepareForSave(ctx, &artifact.Auditable))
        if err == nil {
          // Read object back to get new modify date, etc
          artifact, err = store.GetArtifact(ctx, results.DocumentId)
        }
      }
    }
  }
  return artifact, err
}

func (store *ElasticCasestore) DeleteArtifact(ctx context.Context, id string) error {
  artifact, err := store.GetArtifact(ctx, id)
  if err == nil {
    if len(artifact.StreamId) > 0 {
      err = store.DeleteArtifactStream(ctx, artifact.StreamId)
      if err != nil {
        log.WithFields(log.Fields{
          "artifactStreamId": artifact.StreamId,
          "artifactId":       artifact.Id,
        }).Error("Unable to delete artifact stream; proceeding with artifact deletion anyway")
      }
    }
    err = store.delete(ctx, artifact, "artifact", store.prepareForSave(ctx, &artifact.Auditable))
  }

  return err
}

func (store *ElasticCasestore) CreateArtifactStream(ctx context.Context, artifactstream *model.ArtifactStream) (string, error) {
  var id string
  err := store.validateArtifactStream(artifactstream)
  if err == nil {
    if artifactstream.Id != "" {
      return "", errors.New("Unexpected ID found in new artifactstream")
    } else {
      now := time.Now()
      artifactstream.CreateTime = &now
      var results *model.EventIndexResults
      results, err = store.save(ctx, artifactstream, "artifactstream", store.prepareForSave(ctx, &artifactstream.Auditable))
      if err == nil {
        id = results.DocumentId
      }
    }
  }
  return id, err
}

func (store *ElasticCasestore) GetArtifactStream(ctx context.Context, id string) (*model.ArtifactStream, error) {
  var err error
  var artifactstream *model.ArtifactStream

  err = store.validateId(id, "artifactStreamId")
  if err == nil {
    var obj interface{}
    obj, err = store.get(ctx, id, "artifactstream")
    if err == nil {
      artifactstream = obj.(*model.ArtifactStream)
    }
  }
  return artifactstream, err
}

func (store *ElasticCasestore) DeleteArtifactStream(ctx context.Context, id string) error {
  artifactstream, err := store.GetArtifactStream(ctx, id)
  if err == nil {
    err = store.delete(ctx, artifactstream, "artifactstream", store.prepareForSave(ctx, &artifactstream.Auditable))
  }

  return err
}
